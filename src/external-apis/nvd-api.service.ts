import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { CVEDto } from '../vulnerability/dto/cve.dto';

@Injectable()
export class NvdApiService {
  private readonly logger = new Logger(NvdApiService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly CACHE_TTL = 3600; // 1 hour

  constructor(private readonly configService: ConfigService) {
    const apiKey = this.configService.get<string>('NVD_API_KEY');

    this.apiClient = axios.create({
      baseURL: this.NVD_BASE_URL,
      timeout: 15000,
      headers: {
        'User-Agent': 'NestJS-Vulnerability-Scanner/1.0',
        ...(apiKey ? { apiKey } : {}), // Fix: Pass API key if configured
      },
    });

    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  /**
   * Fetch exact CVE by ID (e.g. CVE-2021-44228)
   */
  async getCVEById(cveId: string): Promise<CVEDto | null> {
    const normalizedCveId = cveId.trim().toUpperCase();
    const cacheKey = `nvd:${normalizedCveId}`;
    const cached = this.cache.get<CVEDto>(cacheKey);

    if (cached) {
      this.logger.debug(`Cache hit for ${normalizedCveId}`);
      return cached;
    }

    try {
      this.logger.log(`Fetching CVE ${normalizedCveId} from NVD`);
      // Fix: Use 'cveId' parameter for exact single lookup
      const response = await this.apiClient.get('', {
        params: {
          cveId: normalizedCveId,
        },
      });

      const cve = this.parseNvdResponse(response.data);
      if (cve) {
        this.cache.set(cacheKey, cve);
        return cve;
      }
      return null;
    } catch (error) {
      this.logger.error(`Error fetching CVE ${normalizedCveId}: ${error}`);
      return null;
    }
  }

  /**
   * Search CVEs by keyword query
   */
  async searchCVEs(query: string, limit: number = 5): Promise<CVEDto[]> {
    const cacheKey = `nvd:search:${query}:${limit}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for search: ${query}`);
      return cached;
    }

    try {
      this.logger.log(`Searching NVD for: ${query}`);
      const response = await this.apiClient.get('', {
        params: {
          keywordSearch: query,
          resultsPerPage: limit,
        },
      });

      const cves = (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseNvdVulnerability(vuln))
        .slice(0, limit);

      this.cache.set(cacheKey, cves);
      return cves;
    } catch (error) {
      this.logger.error(`Error searching NVD for ${query}: ${error}`);
      return [];
    }
  }

  /**
   * Fetch CVEs for a specific product name
   */
  async getCVEsByProduct(productName: string, limit: number = 10): Promise<CVEDto[]> {
    const cacheKey = `nvd:product:${productName}:${limit}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for product: ${productName}`);
      return cached;
    }

    try {
      this.logger.log(`Fetching CVEs for product: ${productName}`);
      const response = await this.apiClient.get('', {
        params: {
          keywordSearch: productName,
          resultsPerPage: Math.min(limit * 2, 50),
        },
      });

      const queryLower = productName.toLowerCase();
      const cves = (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseNvdVulnerability(vuln))
        .filter((cve: CVEDto) => {
          const combinedText = [
            cve.description,
            ...(cve.affectedProducts || []),
            cve.id,
          ]
            .join(' ')
            .toLowerCase();
          return combinedText.includes(queryLower);
        })
        .slice(0, limit);

      this.cache.set(cacheKey, cves);
      return cves;
    } catch (error) {
      this.logger.error(`Error fetching CVEs for product ${productName}: ${error}`);
      return [];
    }
  }

  /**
   * Fetch recent CVEs published in the last N days
   */
  async getRecentCVEs(days: number = 7, limit: number = 20): Promise<CVEDto[]> {
    try {
      const now = new Date();
      const dateStart = new Date();
      dateStart.setDate(now.getDate() - days);

      // Fix: Both pubStartDate and pubEndDate are REQUIRED by NVD API v2.0
      const pubStartDate = dateStart.toISOString();
      const pubEndDate = now.toISOString();

      this.logger.log(`Fetching CVEs published between ${pubStartDate} and ${pubEndDate}`);
      const response = await this.apiClient.get('', {
        params: {
          pubStartDate,
          pubEndDate,
          resultsPerPage: limit,
        },
      });

      return (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseNvdVulnerability(vuln))
        .slice(0, limit);
    } catch (error) {
      this.logger.error(`Error fetching recent CVEs: ${error}`);
      return [];
    }
  }

  private parseNvdResponse(data: any): CVEDto | null {
    if (!data?.vulnerabilities || data.vulnerabilities.length === 0) {
      return null;
    }
    return this.parseNvdVulnerability(data.vulnerabilities[0]);
  }

  private parseNvdVulnerability(vuln: any): CVEDto {
    const cveData = vuln?.cve || {};
    const publishedDate = cveData?.published || new Date().toISOString();
    
    // Extract published year safely
    const parsedYear = new Date(publishedDate).getFullYear();
    const publishedYear = isNaN(parsedYear) ? new Date().getFullYear() : parsedYear;

    // Extract CVSS metrics (v4.0 -> v3.1 -> v3.0 -> v2.0 fallback)
    const metrics = this.extractMetrics(cveData?.metrics);

    return {
      id: cveData?.id || 'UNKNOWN',
      publishedDate,
      published: publishedYear,
      description:
        cveData?.descriptions?.find((d: any) => d.lang === 'en')?.value ||
        cveData?.descriptions?.[0]?.value ||
        'No description available',
      metrics,
      affectedProducts: this.extractAffectedProducts(cveData?.configurations),
      references: (cveData?.references || []).map((ref: any) => ({
        url: ref.url,
        source: ref.source || 'NVD',
        tags: ref.tags || [],
      })),
      nvdUrl: `https://nvd.nist.gov/vuln/detail/${cveData?.id}`,
      isExploited: false,
    };
  }

  /**
   * Safely extract CVSS metrics across v4.0, v3.1, v3.0, and v2.0
   */
  private extractMetrics(metricsObj: any): { cvssV31Score?: number; cvssV31Severity?: string } {
    if (!metricsObj) return {};

    // Check CVSS v4.0
    const v40 = metricsObj.cvssMetricV40?.[0]?.cvssData;
    if (v40) return { cvssV31Score: v40.baseScore, cvssV31Severity: v40.baseSeverity };

    // Check CVSS v3.1
    const v31 = metricsObj.cvssMetricV31?.[0]?.cvssData;
    if (v31) return { cvssV31Score: v31.baseScore, cvssV31Severity: v31.baseSeverity };

    // Check CVSS v3.0
    const v30 = metricsObj.cvssMetricV30?.[0]?.cvssData;
    if (v30) return { cvssV31Score: v30.baseScore, cvssV31Severity: v30.baseSeverity };

    // Check CVSS v2.0 fallback
    const v20 = metricsObj.cvssMetricV2?.[0]?.cvssData;
    if (v20) return { cvssV31Score: v20.baseScore, cvssV31Severity: v20.baseSeverity };

    return {};
  }

  /**
   * Extract unique affected vendor:product pairs from CPE criteria
   */
  private extractAffectedProducts(configurations: any[]): string[] {
    const products: Set<string> = new Set();

    if (!configurations || !Array.isArray(configurations)) {
      return [];
    }

    configurations.forEach((config: any) => {
      if (config?.nodes && Array.isArray(config.nodes)) {
        config.nodes.forEach((node: any) => {
          if (node?.cpeMatch && Array.isArray(node.cpeMatch)) {
            node.cpeMatch.forEach((match: any) => {
              if (match?.criteria) {
                // CPE format: cpe:2.3:a:vendor:product:version:...
                const parts = match.criteria.split(':');
                if (parts.length >= 5) {
                  const vendor = parts[3];
                  const product = parts[4];
                  products.add(`${vendor}:${product}`);
                }
              }
            });
          }
        });
      }
    });

    return Array.from(products).slice(0, 10);
  }

  clearCache(): void {
    this.cache.flushAll();
    this.logger.log('NVD cache cleared');
  }
}