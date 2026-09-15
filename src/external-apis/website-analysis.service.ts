import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import * as net from 'net';
import { MaliciousSiteDetectionService } from './malicious-site-detection.service';

export interface WebsiteSecurityAnalysis {
  url: string;
  isReachable: boolean;
  hasSSL: boolean;
  sslGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' | 'Unknown';
  redirectChain: string[];
  securityHeaders: Record<string, string>;
  suspiciousIndicators: string[];
  riskLevel: 'safe' | 'moderate' | 'suspicious' | 'dangerous';
  isMalicious?: boolean;
  maliciousThreat?: string;
  recommendations: string[];
}

@Injectable()
export class WebsiteAnalysisService {
  private readonly logger = new Logger(WebsiteAnalysisService.name);

  constructor(private readonly maliciousSiteDetection: MaliciousSiteDetectionService) {}

  async analyzeWebsite(url: string): Promise<WebsiteSecurityAnalysis> {
    this.logger.log(`Analyzing website: ${url}`);

    try {
      // 1. Normalize and parse URL
      let normalizedUrl = url.trim();
      if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
      }

      const urlObj = new URL(normalizedUrl);
      const domain = urlObj.hostname;

      // 2. SSRF Protection: Block private/internal IPs and localhost
      if (this.isPrivateOrInternalHost(domain)) {
        this.logger.warn(`SSRF Blocked: Attempted scan of internal target ${domain}`);
        return this.buildUnreachableResponse(normalizedUrl, [
          'Scan blocked: Target resolves to a private or loopback IP address (SSRF Protection).',
        ]);
      }

      // 3. Check if URL is in known malicious databases (URLhaus, etc.)
      const maliciousCheckResult = await this.maliciousSiteDetection.checkUrl(normalizedUrl);

      if (maliciousCheckResult.isMalicious) {
        this.logger.warn(`⚠️ MALICIOUS SITE DETECTED: ${domain}`);
        return {
          url: normalizedUrl,
          isReachable: true,
          hasSSL: false,
          sslGrade: 'F',
          redirectChain: [normalizedUrl],
          securityHeaders: {},
          suspiciousIndicators: [
            `🚨 KNOWN MALICIOUS SITE - ${maliciousCheckResult.threat?.type || 'malware'}`,
            `Threat Type: ${maliciousCheckResult.threat?.type || 'unknown'}`,
            `Status: ${maliciousCheckResult.threat?.status || 'Active threat'}`,
            'This URL/domain is listed in known threat intelligence databases.',
          ],
          isMalicious: true,
          maliciousThreat: maliciousCheckResult.threat?.type,
          riskLevel: 'dangerous',
          recommendations: [
            '🚨 DO NOT VISIT OR INTERACT WITH THIS SITE',
            '🚨 DO NOT DOWNLOAD ANY FILES OR ENTER CREDENTIALS',
            'Report this link to your security team or email provider immediately',
          ],
        };
      }

      // 4. Perform SSL and Connectivity Checks
      const sslInfo = await this.checkSSL(urlObj);

      // Fail fast if site is unreachable to prevent redundant connection timeouts
      if (!sslInfo.reachable) {
        return this.buildUnreachableResponse(normalizedUrl, ['Website could not be reached or connection timed out']);
      }

      // 5. Fetch Security Headers & Trace Redirects
      const [headers, redirectChain] = await Promise.all([
        this.fetchSecurityHeaders(normalizedUrl),
        this.checkRedirects(normalizedUrl),
      ]);

      // 6. Analyze domain indicators (Impersonation, TLDs, Hyphens)
      const suspicious = this.checkDomainSuspicion(domain);

      // Add SSL certificate warnings if TLS validation failed
      if (sslInfo.certError) {
        suspicious.push(`SSL Certificate Error: ${sslInfo.certError}`);
      }

      // 7. Overall risk assessment & recommendations
      const riskLevel = this.calculateRiskLevel(sslInfo, headers, suspicious);
      const recommendations = this.generateRecommendations(sslInfo, headers, suspicious, riskLevel);

      return {
        url: normalizedUrl,
        isReachable: sslInfo.reachable,
        hasSSL: sslInfo.hasSSL,
        sslGrade: sslInfo.grade,
        redirectChain,
        securityHeaders: headers,
        suspiciousIndicators: suspicious,
        riskLevel,
        isMalicious: false,
        recommendations,
      };
    } catch (error) {
      this.logger.error(`Error analyzing website ${url}: ${error}`);
      return this.buildUnreachableResponse(url, ['Invalid URL format or DNS lookup failure']);
    }
  }

  /**
   * Evaluates SSL/TLS configuration including strict certificate verification.
   */
  private async checkSSL(
    urlObj: URL,
): Promise<{ reachable: boolean; hasSSL: boolean; grade: WebsiteSecurityAnalysis['sslGrade']; certError?: string }> {
    const isHttps = urlObj.protocol === 'https:';

    if (!isHttps) {
      return { reachable: true, hasSSL: false, grade: 'F' };
    }

    try {
      // First attempt: Strict TLS checking (reject unauthorized certs).
      // Allow redirects so CDN-backed URLs (e.g. Google's googleusercontent.com,
      // gstatic.com) that redirect through their edge network are validated properly
      // instead of being incorrectly flagged as SSL failures.
      const response = await axios.get(urlObj.toString(), {
        timeout: 5000,
        maxRedirects: 5,
        validateStatus: () => true, // Accept any HTTP response code
      });

      // If we reached a final response after following redirects, TLS is valid.
      return { reachable: true, hasSSL: true, grade: response.status < 400 ? 'A' : 'B' };
    } catch (error: any) {
      // Handle SSL/TLS errors explicitly (e.g. expired or untrusted certs)
      if (error.code && error.code.startsWith('ERR_TLS_') || error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || error.code === 'CERT_HAS_EXPIRED') {
        this.logger.debug(`SSL cert validation error for ${urlObj.hostname}: ${error.code}`);
        return {
          reachable: true,
          hasSSL: false,
          grade: 'F',
          certError: error.code,
        };
      }

      // Check if reachable regardless of non-SSL connection errors
      if (error.response) {
        return { reachable: true, hasSSL: true, grade: 'B' };
      }

      return { reachable: false, hasSSL: false, grade: 'Unknown' };
    }
  }

  /**
   * Fetches key HTTP security response headers using HEAD with GET fallback.
   */
  private async fetchSecurityHeaders(url: string): Promise<Record<string, string>> {
    const importantHeaders = [
      'content-security-policy',
      'x-content-type-options',
      'x-frame-options',
      'strict-transport-security',
      'x-xss-protection',
      'referrer-policy',
      'permissions-policy',
    ];

    try {
      // Attempt HEAD first
      let response = await axios.head(url, {
        timeout: 4000,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // Fallback to GET if server rejects HEAD (405 or 403)
      if (response.status === 405 || response.status === 403) {
        response = await axios.get(url, {
          timeout: 4000,
          maxRedirects: 0,
          validateStatus: () => true,
        });
      }

      const headers: Record<string, string> = {};
      for (const header of importantHeaders) {
        if (response.headers[header]) {
          headers[header] = String(response.headers[header]);
        }
      }

      return headers;
    } catch (error) {
      this.logger.debug(`Could not fetch security headers for ${url}: ${error}`);
      return {};
    }
  }

  /**
   * Traces HTTP redirect chain up to maxRedirects.
   */
  private async checkRedirects(url: string, maxRedirects: number = 5): Promise<string[]> {
    const chain: string[] = [url];

    try {
      let currentUrl = url;
      for (let i = 0; i < maxRedirects; i++) {
        const response = await axios.get(currentUrl, {
          timeout: 4000,
          maxRedirects: 0,
          validateStatus: (status) => (status >= 300 && status < 400) || status === 200,
        });

        if (response.status === 200 || !response.headers.location) {
          break;
        }

        const redirectFull = new URL(response.headers.location, currentUrl).toString();
        chain.push(redirectFull);
        currentUrl = redirectFull;
      }
    } catch (error) {
      this.logger.debug(`Redirect trace stopped: ${error}`);
    }

    return chain;
  }

/**
   * Checks for domain impersonation, typosquatting, and suspicious structure.
   */
  private checkDomainSuspicion(domain: string): string[] {
    const indicators: string[] = [];
    const lowerDomain = domain.toLowerCase();

    // Known target brands with official domain suffixes
    const targetBrands = [
      { name: 'PayPal', keyword: 'paypal', official: 'paypal.com' },
      { name: 'Amazon', keyword: 'amazon', official: 'amazon.com' },
      { name: 'Apple', keyword: 'apple', official: 'apple.com' },
      { name: 'Microsoft', keyword: 'microsoft', official: 'microsoft.com' },
      { name: 'Google', keyword: 'google', official: 'google.com' },
      { name: 'Netflix', keyword: 'netflix', official: 'netflix.com' },
    ];

    // Official brand infrastructure subdomains that legitimately contain the brand
    // keyword but are NOT impersonation (e.g. googleusercontent.com, gstatic.com,
    // accounts.google.com, myaccount.google.com). These are Google's own CDN/auth domains.
    const officialBrandDomains: Record<string, string[]> = {
      google: ['google.com', 'googleusercontent.com', 'gstatic.com', 'gmail.com', 'googleapis.com', 'ggpht.com'],
      apple: ['apple.com', 'icloud.com', 'apple-cloud.com'],
      microsoft: ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'msn.com', 'windows.com', 'azure.com', 'azureedge.net'],
      amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.ca', 'amazon.in'],
      paypal: ['paypal.com', 'paypal.me'],
      netflix: ['netflix.com', 'nflxvideo.net'],
    };

    // Fix: Brand impersonation check — exempt official brand infrastructure domains
    for (const brand of targetBrands) {
      if (!lowerDomain.includes(brand.keyword)) continue;

      const officialDomains = officialBrandDomains[brand.keyword] || [brand.official];
      const isOfficial = officialDomains.some(
        (official) => lowerDomain === official || lowerDomain.endsWith('.' + official),
      );

      if (!isOfficial) {
        indicators.push(`Domain potential impersonation of ${brand.name}`);
      }
    }

    // Suspicious keywords in subdomains/domain
    if (lowerDomain.includes('-secure') || lowerDomain.includes('secure-')) {
      indicators.push('Suspicious "secure" prefix/suffix in domain');
    }
    if (lowerDomain.includes('-verify') || lowerDomain.includes('verify-')) {
      indicators.push('Suspicious "verify" prefix/suffix in domain');
    }
    if (lowerDomain.includes('login') && !targetBrands.some((b) => lowerDomain.endsWith(b.official))) {
      indicators.push('Domain contains "login" keywords');
    }

    // Excessive hyphenation
    if ((lowerDomain.match(/-/g) || []).length >= 3) {
      indicators.push('Domain contains an unusually high number of hyphens');
    }

    // High-risk TLDs frequently used in phishing/malware
    if (/\.(xyz|tk|ml|ga|cf|gq|top|work|buzz|icu)$/.test(lowerDomain)) {
      indicators.push('Uses high-risk or free Top-Level Domain (TLD)');
    }

    // Unusually long domain length
    if (domain.length > 35) {
      indicators.push('Domain length is unusually long');
    }

    return indicators;
  }

  private calculateRiskLevel(
    ssl: { reachable: boolean; hasSSL: boolean; certError?: string },
    headers: Record<string, string>,
    suspicious: string[],
  ): WebsiteSecurityAnalysis['riskLevel'] {
    let riskScore = 0;

    if (!ssl.hasSSL) riskScore += 2;
    if (ssl.certError) riskScore += 3;
    if (!headers['strict-transport-security']) riskScore += 1;
    if (!headers['content-security-policy']) riskScore += 1;

    riskScore += suspicious.length * 2;

    if (riskScore >= 6 || suspicious.length >= 2) return 'dangerous';
    if (riskScore >= 3) return 'suspicious';
    if (riskScore >= 1) return 'moderate';
    return 'safe';
  }

  private generateRecommendations(
    ssl: { hasSSL: boolean; certError?: string },
    headers: Record<string, string>,
    suspicious: string[],
    riskLevel: WebsiteSecurityAnalysis['riskLevel'],
  ): string[] {
    const recommendations: string[] = [];

    if (!ssl.hasSSL) {
      recommendations.push('⚠️ Website does not enforce HTTPS — data transmitted is unencrypted.');
    }
    if (ssl.certError) {
      recommendations.push(`🚨 SSL Certificate Invalid (${ssl.certError}) — Do NOT enter credentials.`);
    }
    if (!headers['strict-transport-security']) {
      recommendations.push('Missing HSTS (Strict-Transport-Security) header.');
    }
    if (!headers['content-security-policy']) {
      recommendations.push('Missing Content-Security-Policy (CSP) header.');
    }

    if (riskLevel === 'dangerous') {
      recommendations.unshift('🚨 HIGH RISK: Significant safety warnings detected. Avoid visiting or sharing data.');
    } else if (riskLevel === 'suspicious') {
      recommendations.unshift('⚠️ SUSPICIOUS: Exercise caution before logging in or making transactions.');
    } else if (riskLevel === 'safe') {
      recommendations.push('✅ Site shows standard security configurations.');
    }

    return recommendations;
  }

  private isPrivateOrInternalHost(host: string): boolean {
    const lowerHost = host.toLowerCase();
    if (lowerHost === 'localhost' || lowerHost.endsWith('.local') || lowerHost.endsWith('.internal')) {
      return true;
    }

    if (net.isIP(host)) {
      // Check private IPv4 ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
      return (
        /^127\./.test(host) ||
        /^10\./.test(host) ||
        /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host) ||
        /^192\.168\./.test(host) ||
        /^169\.254\./.test(host)
      );
    }

    return false;
  }

  private buildUnreachableResponse(url: string, indicators: string[]): WebsiteSecurityAnalysis {
    return {
      url,
      isReachable: false,
      hasSSL: false,
      sslGrade: 'Unknown',
      redirectChain: [],
      securityHeaders: {},
      suspiciousIndicators: indicators,
      riskLevel: 'suspicious',
      recommendations: [
        'Website is currently unreachable or blocking automated scans',
        'Verify the URL address is correct',
        'Exercise caution if this link was received unsolicited',
      ],
    };
  }
}