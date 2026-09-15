import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import NodeCache from 'node-cache';
import { URLSearchParams } from 'url';
import { LEGITIMATE_DOMAINS } from '../common/constants/legit-domains';

export interface MaliciousSiteCheckResult {
  url: string;
  domain: string;
  isMalicious: boolean;
  threat?: {
    type: 'malware' | 'phishing' | 'spam' | 'defacement' | 'exploit' | 'unknown';
    firstSeen?: string;
    lastSeen?: string;
    sources?: string[];
    status?: string;
  };
  detector: string;
  confidence: 'high' | 'medium' | 'low';
  recommendations?: string[];
}

@Injectable()
export class MaliciousSiteDetectionService {
  private readonly logger = new Logger(MaliciousSiteDetectionService.name);
  private cache: NodeCache;
  private readonly urlhausUrl = 'https://urlhaus-api.abuse.ch/v1/url/';
  private readonly urlhausHostUrl = 'https://urlhaus-api.abuse.ch/v1/host/';
  private readonly apiKey: string;

  /**
   * Brand families mapped to their official domain groups.
   * Used for sender-aware link analysis: if the sender belongs to a brand
   * family, links that resolve to any domain in the same family are treated
   * as trusted (e.g. a google.com sender with googleusercontent.com links).
   */
  private readonly brandDomainGroups: Record<string, string[]> = {
    google: ['google.com', 'googleusercontent.com', 'gstatic.com', 'gmail.com', 'googleapis.com', 'ggpht.com'],
    amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.ca', 'amazon.in'],
    apple: ['apple.com', 'icloud.com', 'apple-cloud.com'],
    microsoft: ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'msn.com', 'windows.com', 'azure.com', 'azureedge.net'],
    paypal: ['paypal.com', 'paypal.me'],
    netflix: ['netflix.com', 'nflxvideo.net'],
    facebook: ['facebook.com', 'fb.com', 'fbcdn.net', 'fbsbx.com', 'instagram.com', 'whatsapp.com'],
    linkedin: ['linkedin.com', 'licdn.com', 'lynda.com'],
    github: ['github.com', 'githubusercontent.com', 'githubassets.com'],
  };

  /**
   * Resolve a domain to the brand group key it belongs to, if any.
   */
  private resolveBrandGroup(domain: string): string | null {
    const lowerDomain = domain.toLowerCase();
    for (const [brand, domains] of Object.entries(this.brandDomainGroups)) {
      const isMatch = domains.some(
        (trusted) => lowerDomain === trusted || lowerDomain.endsWith('.' + trusted),
      );
      if (isMatch) return brand;
    }
    return null;
  }

  constructor(private readonly configService: ConfigService) {
    this.cache = new NodeCache({ stdTTL: 86400, checkperiod: 3600 });
    this.apiKey = this.configService.get<string>('URLHAUS_API_KEY') || '';
  }

  async checkUrl(url: string): Promise<MaliciousSiteCheckResult> {
    try {
      let normalizedUrl = url;
      if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
      }

      const urlObj = new URL(normalizedUrl);
      const domain = urlObj.hostname;

      // Fix: Cache key uses full normalized URL to avoid collisions across different paths on the same domain
      const cacheKey = `malicious_url_${normalizedUrl}`;
      const cached = this.cache.get<MaliciousSiteCheckResult>(cacheKey);
      if (cached) {
        this.logger.debug(`Cache hit for URL ${normalizedUrl}`);
        return cached;
      }

      // Short-circuit for trusted domains: skip aggressive heuristic checks
      // Google infrastructure (googleusercontent.com, gstatic.com, google.com) etc.
      // should never be flagged by heuristics that scan paths/query params for mixed case
      if (this.isTrustedDomain(domain)) {
        const urlhausResult = await this.checkURLhaus(normalizedUrl, domain);
        if (urlhausResult.isMalicious) {
          this.cache.set(cacheKey, urlhausResult);
          return urlhausResult;
        }
        // Return safe result for trusted domains even if URLhaus check fails
        const safeResult: MaliciousSiteCheckResult = {
          url,
          domain,
          isMalicious: false,
          detector: 'Trusted Domain + URLhaus',
          confidence: 'high',
          recommendations: ['✅ URL belongs to a trusted domain'],
        };
        this.cache.set(cacheKey, safeResult);
        return safeResult;
      }

      const urlhausResult = await this.checkURLhaus(normalizedUrl, domain);
      
      if (urlhausResult.isMalicious) {
        this.cache.set(cacheKey, urlhausResult);
        return urlhausResult;
      }

      const heuristicResult = this.checkUrlHeuristics(normalizedUrl);
      if (heuristicResult.isMalicious) {
        this.logger.log(`Heuristic detection flagged: ${domain} as ${heuristicResult.threat?.type}`);
        this.cache.set(cacheKey, heuristicResult);
        return heuristicResult;
      }

      this.cache.set(cacheKey, urlhausResult);
      return urlhausResult;
    } catch (error) {
      this.logger.error(`Error checking URL ${url}: ${error}`);
      // If we got an error but the domain is trusted, return safe to avoid false positives
      try {
        const urlObj = new URL(url.startsWith('http') ? url : 'https://' + url);
        if (this.isTrustedDomain(urlObj.hostname)) {
          return {
            url,
            domain: urlObj.hostname,
            isMalicious: false,
            detector: 'Trusted Domain (error fallback)',
            confidence: 'medium',
            recommendations: ['✅ URL belongs to a trusted domain'],
          };
        }
      } catch {
        // ignore parsing errors in fallback
      }
      return this.checkUrlHeuristics(url);
    }
  }

  async checkDomain(domain: string): Promise<MaliciousSiteCheckResult> {
    try {
      const cacheKey = `malicious_domain_${domain}`;
      const cached = this.cache.get<MaliciousSiteCheckResult>(cacheKey);
      if (cached) {
        this.logger.debug(`Cache hit for domain ${domain}`);
        return cached;
      }

      const result = await this.checkURLhausDomain(domain);
      this.cache.set(cacheKey, result);
      return result;
    } catch (error) {
      this.logger.error(`Error checking domain ${domain}: ${error}`);
      return {
        url: domain,
        domain,
        isMalicious: false,
        detector: 'error',
        confidence: 'low',
      };
    }
  }

  async checkLinksInContent(
    content: string,
    senderDomain?: string,
  ): Promise<MaliciousSiteCheckResult[]> {
    const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]*)/g;
    const matches = content.match(urlRegex) || [];

    if (matches.length === 0) {
      return [];
    }

    const uniqueUrls = [...new Set(matches)];

    // Resolve the sender's brand group once (if provided).
    // Example: sender = accounts.google.com -> brand group 'google'.
    const senderBrandGroup = senderDomain
      ? this.resolveBrandGroup(senderDomain)
      : null;

    return Promise.all(
      uniqueUrls.map((url) => {
        // If the sender is a known brand (e.g. google.com) and the link belongs
        // to the same brand family (e.g. googleusercontent.com, gstatic.com),
        // treat it as safe without aggressive checks.
        if (senderBrandGroup) {
          try {
            const cleanUrl = url.startsWith('http') ? url : 'https://' + url;
            const linkDomain = new URL(cleanUrl).hostname;
            if (this.resolveBrandGroup(linkDomain) === senderBrandGroup) {
              return this.buildSafeResult(
                url,
                linkDomain,
                `✅ URL belongs to the same trusted brand family as the sender (${senderBrandGroup})`,
              );
            }
          } catch {
            // fall through to standard check if URL cannot be parsed
          }
        }

        return this.checkUrl(url);
      }),
    );
  }

  /**
   * Builds a non-malicious result for a URL that is known to be safe.
   */
  private buildSafeResult(
    url: string,
    domain: string,
    reason: string,
  ): MaliciousSiteCheckResult {
    return {
      url,
      domain,
      isMalicious: false,
      detector: 'Sender Brand Match',
      confidence: 'high',
      recommendations: [reason],
    };
  }

  private async checkURLhaus(url: string, domain: string): Promise<MaliciousSiteCheckResult> {
    try {
      this.logger.log(`Checking URLhaus for URL: ${url}`);

      const params = new URLSearchParams();
      params.append('url', url);

      const response = await axios.post(
        this.urlhausUrl,
        params,
        {
          timeout: 5000,
          headers: {
            'Auth-Key': this.apiKey, // Fix: Auth-Key header required by URLhaus v1 API
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          },
        },
      ).catch((error) => {
        this.logger.warn(`URLhaus URL check error: ${error.response?.status || error.message}`);
        return null;
      });

      if (!response) {
        return {
          url,
          domain,
          isMalicious: false,
          detector: 'URLhaus (API error)',
          confidence: 'low',
          recommendations: ['Could not verify URL against URLhaus'],
        };
      }

      // Fix: Read response directly from response.data (URLhaus does not put /v1/url/ data in a result array)
      if (response.data?.query_status === 'ok') {
        const data = response.data;

        if (data.threat) {
          this.logger.warn(`Malicious site detected: ${domain} - Threat: ${data.threat}`);

          return {
            url,
            domain,
            isMalicious: true,
            threat: {
              type: this.mapThreatType(data.threat),
              firstSeen: data.date_added,
              lastSeen: data.last_seen,
              status: data.url_status,
            },
            detector: 'URLhaus',
            confidence: 'high',
            recommendations: [
              '🚨 This URL is known to host malware or phishing content',
              'Do NOT click this link',
              'Do NOT download anything from this site',
            ],
          };
        }
      }

      // If URL check didn't hit, check domain-level host status
      const domainResult = await this.checkURLhausDomain(domain);
      if (domainResult.isMalicious) {
        return domainResult;
      }

      return {
        url,
        domain,
        isMalicious: false,
        detector: 'URLhaus',
        confidence: 'high',
        recommendations: ['URL is not in URLhaus threat database'],
      };
    } catch (error) {
      this.logger.error(`URLhaus check failed for ${domain}: ${error}`);
      return {
        url,
        domain,
        isMalicious: false,
        detector: 'URLhaus (error)',
        confidence: 'low',
      };
    }
  }

  private async checkURLhausDomain(domain: string): Promise<MaliciousSiteCheckResult> {
    try {
      this.logger.log(`Checking URLhaus domain: ${domain}`);

      const params = new URLSearchParams();
      params.append('host', domain);

      const response = await axios.post(
        this.urlhausHostUrl,
        params,
        {
          timeout: 5000,
          headers: {
            'Auth-Key': this.apiKey, // Fix: Auth-Key header required
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          },
        },
      ).catch((error) => {
        this.logger.warn(`URLhaus domain check error for ${domain}: ${error.response?.status || error.message}`);
        return null;
      });

      if (!response) {
        return {
          url: domain,
          domain,
          isMalicious: false,
          detector: 'URLhaus (API error)',
          confidence: 'low',
        };
      }

      if (response.data?.query_status === 'ok' && response.data?.urls?.length > 0) {
        const urls = response.data.urls;

        return {
          url: domain,
          domain,
          isMalicious: true,
          threat: {
            type: 'malware',
            status: `${urls.length} malicious URLs found on this domain`,
          },
          detector: 'URLhaus Host Check',
          confidence: 'high',
          recommendations: [
            '⚠️ This domain has hosted malicious content',
            'Do not click links from this domain',
          ],
        };
      }

      return {
        url: domain,
        domain,
        isMalicious: false,
        detector: 'URLhaus',
        confidence: 'high',
      };
    } catch (error) {
      this.logger.error(`URLhaus domain check failed for ${domain}: ${error}`);
      return {
        url: domain,
        domain,
        isMalicious: false,
        detector: 'URLhaus (error)',
        confidence: 'low',
      };
    }
  }

  /**
   * Checks whether a domain is in the trusted legitimate domains list.
   * This prevents heuristic false-positives on well-known services like Google CDN.
   */
  private isTrustedDomain(domain: string): boolean {
    const lowerDomain = domain.toLowerCase();
    return LEGITIMATE_DOMAINS.some(
      (trusted) => lowerDomain === trusted || lowerDomain.endsWith('.' + trusted),
    );
  }

  private mapThreatType(threat: string): 'malware' | 'phishing' | 'spam' | 'defacement' | 'exploit' | 'unknown' {
    const threatLower = threat.toLowerCase();
    if (threatLower.includes('phishing')) return 'phishing';
    if (threatLower.includes('malware')) return 'malware';
    if (threatLower.includes('spam')) return 'spam';
    if (threatLower.includes('defacement')) return 'defacement';
    if (threatLower.includes('exploit')) return 'exploit';
    return 'unknown';
  }

  private checkUrlHeuristics(url: string): MaliciousSiteCheckResult {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname || url;
      const pathname = urlObj.pathname || '';

      const suspiciousPatterns = [
        { pattern: /paypal.*verify|verify.*paypal/i, threat: 'phishing', reason: 'Fake PayPal verification' },
        { pattern: /amazon.*verify|verify.*amazon/i, threat: 'phishing', reason: 'Fake Amazon verification' },
        { pattern: /\.tk$|\.ml$|\.ga$|\.cf$/i, threat: 'malware', reason: 'High-risk TLD' },
        { pattern: /rn-9gle|goog1e|gmail-security|paypa1/i, threat: 'phishing', reason: 'Lookalike domain' },
      ];

      const fullUrl = domain + pathname;
      for (const { pattern, threat, reason } of suspiciousPatterns) {
        if (pattern.test(fullUrl)) {
          return {
            url,
            domain,
            isMalicious: true,
            threat: { type: threat as any, status: reason },
            detector: 'Heuristic Analysis',
            confidence: 'medium',
            recommendations: [`⚠️ ${reason}`, 'Do not click this link'],
          };
        }
      }

      const domainSuspicion = this.checkDomainReputation(url, domain);
      if (domainSuspicion.isSuspicious) {
        return {
          url,
          domain,
          isMalicious: true,
          threat: { type: 'phishing', status: domainSuspicion.reason },
          detector: 'Domain Analysis',
          confidence: 'medium',
          recommendations: [`⚠️ ${domainSuspicion.reason}`],
        };
      }

      return {
        url,
        domain,
        isMalicious: false,
        detector: 'Heuristic Analysis',
        confidence: 'medium',
      };
    } catch {
      return {
        url,
        domain: url,
        isMalicious: false,
        detector: 'Heuristic (error)',
        confidence: 'low',
      };
    }
  }

  private checkDomainReputation(rawUrl: string, domain: string): { isSuspicious: boolean; reason: string } {
    const lowerDomain = domain.toLowerCase();

    if ((lowerDomain.match(/-/g) || []).length > 4) {
      return { isSuspicious: true, reason: 'Domain has excessive hyphens' };
    }

    if (/^\d+\.\d+\.\d+\.\d+$/.test(lowerDomain)) {
      return { isSuspicious: true, reason: 'Raw IP address used as domain' };
    }

    if (lowerDomain.length > 40) {
      return { isSuspicious: true, reason: 'Domain name is unusually long' };
    }

    // Fix: Test mixed casing ONLY on the domain portion — NOT the full URL.
    // Many legitimate services use mixed-case paths, query params, or base64-encoded
    // data (e.g. Google user content, googleusercontent.com, redirect URLs).
    // Phishers typically obfuscate the domain itself, not the path/query.
    // Since the URL object already lowercased the hostname during parsing,
    // we check the raw domain from the URL before it was normalized.
    if (/[a-z]/.test(domain) && /[A-Z]/.test(domain)) {
      return { isSuspicious: true, reason: 'Mixed case domain (potential obfuscation)' };
    }

    return { isSuspicious: false, reason: '' };
  }
}