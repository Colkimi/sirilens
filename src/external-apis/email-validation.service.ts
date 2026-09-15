import { Injectable, Logger } from '@nestjs/common';
import { resolveMx, resolveTxt } from 'dns/promises';
import { WebsiteAnalysisService } from 'src/external-apis/website-analysis.service';

export interface EmailValidation {
  isValid: boolean;
  domain: string;
  hasMXRecords: boolean;
  hasSpfRecord: boolean;
  hasDmarcRecord: boolean;
  suspicionLevel: 'safe' | 'suspicious' | 'dangerous';
  reasons: string[];
  suggestions: string[];
}

@Injectable()
export class EmailValidationService {
  private readonly logger = new Logger(EmailValidationService.name);

  // Known target brands mapped to their official root domains
  private readonly brandMap = [
    { brand: 'paypal', officialDomains: ['paypal.com', 'paypal.me'] },
    { brand: 'amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de'] },
    { brand: 'apple', officialDomains: ['apple.com', 'icloud.com'] },
    { brand: 'microsoft', officialDomains: ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com'] },
    { brand: 'google', officialDomains: ['google.com', 'gmail.com'] },
    { brand: 'netflix', officialDomains: ['netflix.com'] },
  ];

  private readonly suspiciousKeywords = [
    'secure-login',
    'verify-account',
    'confirm-identity',
    'update-info',
    'security-verify',
    'account-alert',
  ];

  constructor(private readonly websiteAnalysisService?: WebsiteAnalysisService) {}

  async validateEmailSender(email: string): Promise<EmailValidation> {
    this.logger.log(`Validating email sender: ${email}`);

    // 1. Strict Email Format & Syntax Parsing
    const parsed = this.extractAndValidateDomain(email);
    if (!parsed.valid || !parsed.domain) {
      return {
        isValid: false,
        domain: parsed.domain || '',
        hasMXRecords: false,
        hasSpfRecord: false,
        hasDmarcRecord: false,
        suspicionLevel: 'dangerous',
        reasons: ['Invalid email address format'],
        suggestions: ['Ensure the email address follows the standard format (user@domain.com)'],
      };
    }

    const domain = parsed.domain;

    try {
      // 2. Parallel Fast DNS & Static Suspicion Checks (Target ~100ms)
      const [hasMX, spfRecord, dmarcRecord, suspicion] = await Promise.all([
        this.checkMXRecords(domain),
        this.checkSPFRecord(domain),
        this.checkDMARCRecord(domain),
        Promise.resolve(this.checkDomainSuspicion(domain)),
      ]);

      const reasons: string[] = [];
      const suggestions: string[] = [];

      if (!hasMX) {
        reasons.push('Domain has no valid mail servers (MX) or publishes a Null MX record');
        suggestions.push('This domain cannot receive or legitimately send emails.');
      }

      if (!spfRecord) {
        reasons.push('Domain lacks an SPF (Sender Policy Framework) record');
        suggestions.push('Legitimate organizations publish SPF records to prevent email spoofing.');
      }

      if (!dmarcRecord) {
        reasons.push('Domain lacks a DMARC policy record');
        suggestions.push('Absence of DMARC leaves the domain vulnerable to domain impersonation.');
      }

      if (suspicion.suspicious) {
        reasons.push(`Suspicious domain indicator: ${suspicion.reason}`);
        suggestions.push('Exercise caution with links or attachments from this domain.');
      }

      // 3. Optional Website Check (Non-blocking fallback)
      let isMaliciousWeb = false;
      if (this.websiteAnalysisService && (suspicion.suspicious || !hasMX)) {
        isMaliciousWeb = await this.checkWebsiteSafety(domain);
        if (isMaliciousWeb) {
          reasons.push('Domain host is flagged in active threat databases');
          suggestions.push('DO NOT click any links or download attachments from this sender.');
        }
      }

      // 4. Calculate Final Suspicion Level
      let suspicionLevel: 'safe' | 'suspicious' | 'dangerous' = 'safe';

      if (!hasMX || suspicion.dangerous || isMaliciousWeb) {
        suspicionLevel = 'dangerous';
      } else if (reasons.length > 0 || suspicion.suspicious) {
        suspicionLevel = 'suspicious';
      }

      return {
        isValid: hasMX,
        domain,
        hasMXRecords: hasMX,
        hasSpfRecord: spfRecord,
        hasDmarcRecord: dmarcRecord,
        suspicionLevel,
        reasons,
        suggestions,
      };
    } catch (error: any) {
      this.logger.error(`Error validating email ${email}: ${error.message}`);
      return {
        isValid: false,
        domain,
        hasMXRecords: false,
        hasSpfRecord: false,
        hasDmarcRecord: false,
        suspicionLevel: 'suspicious',
        reasons: ['Failed to execute DNS or authentication verification'],
        suggestions: ['Verify domain connectivity or attempt validation later'],
      };
    }
  }

  /**
   * Validates syntax and extracts clean domain string.
   */
  private extractAndValidateDomain(email: string): { valid: boolean; domain?: string } {
    if (!email || typeof email !== 'string') return { valid: false };

    const cleanEmail = email.trim().toLowerCase();
    const atIndex = cleanEmail.lastIndexOf('@');

    // Email must contain '@' and cannot start or end with '@'
    if (atIndex <= 0 || atIndex === cleanEmail.length - 1) {
      return { valid: false };
    }

    const domainPart = cleanEmail.substring(atIndex + 1).split('/')[0].split(':')[0].trim();

    // Basic FQDN check
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-2]{2,}$/i;
    if (!domainRegex.test(domainPart)) {
      return { valid: false, domain: domainPart };
    }

    return { valid: true, domain: domainPart };
  }

  /**
   * Resolves MX records, correctly ignoring RFC 7505 Null MX records ("0 .").
   */
  private async checkMXRecords(domain: string): Promise<boolean> {
    try {
      const mxRecords = await this.withTimeout(resolveMx(domain), 3000);
      if (!mxRecords || mxRecords.length === 0) return false;

      // RFC 7505: Filter out Null MX records (exchange === "." or empty)
      const validMx = mxRecords.filter((mx) => mx.exchange && mx.exchange !== '.');
      return validMx.length > 0;
    } catch {
      this.logger.debug(`MX lookup failed or returned no records for domain: ${domain}`);
      return false;
    }
  }

  /**
   * Checks for a valid SPF record (v=spf1).
   */
  private async checkSPFRecord(domain: string): Promise<boolean> {
    try {
      const txtRecords = await this.withTimeout(resolveTxt(domain), 3000);
      return txtRecords.some((chunks) => {
        const fullRecord = chunks.join('').trim().toLowerCase();
        return fullRecord.startsWith('v=spf1');
      });
    } catch {
      return false;
    }
  }

  /**
   * Checks for a valid DMARC record (_dmarc.domain).
   */
  private async checkDMARCRecord(domain: string): Promise<boolean> {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      const txtRecords = await this.withTimeout(resolveTxt(dmarcDomain), 3000);
      return txtRecords.some((chunks) => {
        const fullRecord = chunks.join('').trim().toLowerCase();
        return fullRecord.startsWith('v=dmarc1');
      });
    } catch {
      return false;
    }
  }

  /**
   * Accurate brand impersonation and typo-squatting detection.
   */
  private checkDomainSuspicion(domain: string): { suspicious: boolean; dangerous: boolean; reason?: string } {
    const lowerDomain = domain.toLowerCase();

    // 1. Check Brand Impersonation against allowed official domains
    for (const { brand, officialDomains } of this.brandMap) {
      if (lowerDomain.includes(brand)) {
        const isOfficial = officialDomains.some(
          (official) => lowerDomain === official || lowerDomain.endsWith('.' + official),
        );

        if (!isOfficial) {
          return {
            suspicious: true,
            dangerous: true,
            reason: `Domain contains "${brand}" but is not an official ${brand} domain`,
          };
        }
      }
    }

    // 2. Check Suspicious Keyword Combinations
    for (const keyword of this.suspiciousKeywords) {
      if (lowerDomain.includes(keyword)) {
        return {
          suspicious: true,
          dangerous: false,
          reason: `Domain contains high-risk keyword: "${keyword}"`,
        };
      }
    }

    // 3. Excessive hyphenation (common in phishing infrastructure)
    if ((lowerDomain.match(/-/g) || []).length >= 3) {
      return {
        suspicious: true,
        dangerous: false,
        reason: `Domain contains an unusually high number of hyphens`,
      };
    }

    return { suspicious: false, dangerous: false };
  }

  /**
   * Optional helper to check website status safely without hanging DNS.
   */
  private async checkWebsiteSafety(domain: string): Promise<boolean> {
    try {
      const result = await this.websiteAnalysisService?.analyzeWebsite(domain);
      return result?.isMalicious === true;
    } catch {
      return false;
    }
  }

  /**
   * Prevents DNS resolution hangs by wrapping promises in a strict timeout.
   */
  private withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`DNS Operation Timed Out after ${ms}ms`)), ms),
    );
    return Promise.race([promise, timeout]);
  }
}