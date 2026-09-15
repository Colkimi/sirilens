import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { CVEDto } from '../vulnerability/dto/cve.dto';

export interface CisaKevItem {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
  cwes?: string[];
}

interface CisaKevResponse {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CisaKevItem[];
}

@Injectable()
export class CisaApiService {
  private readonly logger = new Logger(CisaApiService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly CACHE_TTL = 3600;

  // Primary CISA feed + GitHub mirror fallback
  private readonly cisaOfficialUrl =
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  private readonly cisaGithubMirrorUrl =
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';

  constructor() {
    this.apiClient = axios.create({
      timeout: 10000,
      headers: {
        'User-Agent': 'NestJS-Vulnerability-Scanner/1.0',
      },
    });
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  private async fetchRawCatalog(): Promise<CisaKevItem[]> {
    const cacheKey = 'cisa:kev:raw';
    const cached = this.cache.get<CisaKevItem[]>(cacheKey);
    if (cached) {
      this.logger.debug('Cache hit for CISA KEV catalog');
      return cached;
    }

    // Try official CISA feed first
    try {
      this.logger.log('Fetching CISA KEV catalog from official feed');
      const response = await this.apiClient.get<CisaKevResponse>(this.cisaOfficialUrl);
      const vulnerabilities = response.data?.vulnerabilities || [];
      if (vulnerabilities.length > 0) {
        this.cache.set(cacheKey, vulnerabilities);
        return vulnerabilities;
      }
    } catch (error) {
      this.logger.warn(
        `Official CISA feed failed (${error}). Trying GitHub mirror fallback.`,
      );
    }

    // Fallback to GitHub Mirror
    try {
      const response = await this.apiClient.get<CisaKevResponse>(this.cisaGithubMirrorUrl);
      const vulnerabilities = response.data?.vulnerabilities || [];
      this.cache.set(cacheKey, vulnerabilities);
      return vulnerabilities;
    } catch (error) {
      this.logger.error(`Error fetching CISA KEV catalog: ${error}`);
      return [];
    }
  }

  /**
   * Get recent known exploited vulnerabilities (sorted descending)
   */
  async getKnownExploitedVulnerabilities(limit: number = 50): Promise<CVEDto[]> {
    const raw = await this.fetchRawCatalog();
    const sorted = this.sortByDateDescending(raw);
    return sorted.slice(0, limit).map((vuln) => this.parseCisaVulnerability(vuln));
  }

  async searchCisaAdvisories(productName: string, limit: number = 5): Promise<CVEDto[]> {
    if (!productName) return [];

    const raw = await this.fetchRawCatalog();
    const query = productName.toLowerCase();

    const filtered = raw.filter((vuln) => {
      const vendor = (vuln.vendorProject || '').toLowerCase();
      const product = (vuln.product || '').toLowerCase();
      const name = (vuln.vulnerabilityName || '').toLowerCase();
      const cve = (vuln.cveID || '').toLowerCase();
      return (
        vendor.includes(query) ||
        product.includes(query) ||
        name.includes(query) ||
        cve.includes(query)
      );
    });

    const sorted = this.sortByDateDescending(filtered);
    return sorted.slice(0, limit).map((vuln) => this.parseCisaVulnerability(vuln));
  }

  async getCisaAlerts(limit: number = 20): Promise<CVEDto[]> {
    const raw = await this.fetchRawCatalog();
    const sorted = this.sortByDateDescending(raw);
    return sorted.slice(0, limit).map((vuln) => this.parseCisaVulnerability(vuln));
  }

  async getCriticalVulnerabilities(days: number = 30): Promise<CVEDto[]> {
    try {
      this.logger.log(`Fetching CISA vulnerabilities added in last ${days} days`);
      const raw = await this.fetchRawCatalog();

      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - days);

      const recent = raw.filter((vuln) => {
        if (!vuln.dateAdded) return false;
        const entryDate = new Date(vuln.dateAdded);
        return !isNaN(entryDate.getTime()) && entryDate >= cutoffDate;
      });

      // Fix: Sort descending so the latest threats in the date window appear first
      const sorted = this.sortByDateDescending(recent);
      return sorted.slice(0, 20).map((vuln) => this.parseCisaVulnerability(vuln));
    } catch (error) {
      this.logger.error(`Error fetching critical vulnerabilities: ${error}`);
      return [];
    }
  }

  private sortByDateDescending(items: CisaKevItem[]): CisaKevItem[] {
    return [...items].sort((a, b) => {
      const timeA = new Date(a.dateAdded).getTime() || 0;
      const timeB = new Date(b.dateAdded).getTime() || 0;
      return timeB - timeA;
    });
  }

  private parseCisaVulnerability(vuln: CisaKevItem, isExploited = true): CVEDto {
    const dateAddedStr = vuln.dateAdded || '';

    // Fix: Extract actual CVE year from cveID (e.g. CVE-2021-44228 -> 2021)
    let year = new Date().getFullYear();
    if (vuln.cveID) {
      const match = vuln.cveID.match(/CVE-(\d{4})-/i);
      if (match && match[1]) {
        year = parseInt(match[1], 10);
      }
    }

    const affected = [vuln.vendorProject, vuln.product].filter(Boolean).join(' ');

    // Fix: Extract valid URLs from notes using regex instead of splitting by semicolon
    const urlRegex = /(https?:\/\/[^\s;]+)/g;
    const extractedUrls = vuln.notes ? vuln.notes.match(urlRegex) || [] : [];
    const references = extractedUrls.map((url) => ({
      url: url.replace(/[.,;]$/, ''),
      source: 'CISA Notes',
    }));

    return {
      id: vuln.cveID || 'UNKNOWN',
      publishedDate: dateAddedStr,
      published: year,
      description: vuln.shortDescription || vuln.vulnerabilityName || 'No description available',
      affectedProducts: affected ? [affected] : [],
      references,
      nvdUrl: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
      isExploited,
    };
  }

  clearCache(): void {
    this.cache.flushAll();
    this.logger.log('CISA API cache cleared');
  }
}