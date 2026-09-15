import { Injectable } from '@nestjs/common';
import { LEGITIMATE_DOMAINS } from '../constants/legit-domains';

@Injectable()
export class DomainValidatorService {
  private readonly trustedDomainsSet = new Set<string>(LEGITIMATE_DOMAINS);

  extractDomain(input: string): string {
    if (!input) return '';

    let cleaned = input.trim().toLowerCase();

    // 1. Extract domain from email address if present
    if (cleaned.includes('@')) {
      const atIndex = cleaned.lastIndexOf('@');
      cleaned = cleaned.substring(atIndex + 1);
    }

    // 2. Strip protocol (http/https)
    cleaned = cleaned.replace(/^https?:\/\//, '');

    // 3. Strip paths, queries, and ports
    cleaned = cleaned.split('/')[0].split(':')[0].split('?')[0];

    // 4. Strip leading 'www.'
    cleaned = cleaned.replace(/^www\./, '');

    return cleaned;
  }

  /**
   * Performs strict domain checking.
   * Prevents spoofing attacks like "evilamazon.com" or "amazon.com.attacker.com"
   */
  isLegitimateDomain(input: string): boolean {
    const targetDomain = this.extractDomain(input);
    if (!targetDomain) return false;

    for (const trustedDomain of this.trustedDomainsSet) {
      // Must be an EXACT match (amazon.com) OR a proper SUBDOMAIN (.amazon.com)
      if (
        targetDomain === trustedDomain ||
        targetDomain.endsWith(`.${trustedDomain}`)
      ) {
        return true;
      }
    }

    return false;
  }
}