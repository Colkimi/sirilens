import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { CVEDto } from '../vulnerability/dto/cve.dto';

export type SupportedEcosystem =
  | 'npm'
  | 'pip'
  | 'maven'
  | 'rust'
  | 'composer'
  | 'nuget'
  | 'go'
  | 'rubygems'
  | 'cargo'
  | 'actions';

@Injectable()
export class GitHubSecurityApiService {
  private readonly logger = new Logger(GitHubSecurityApiService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly CACHE_TTL = 3600;

  constructor() {
    const githubToken = process.env.GITHUB_TOKEN;
    this.apiClient = axios.create({
      baseURL: 'https://api.github.com',
      timeout: 10000,
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(githubToken ? { Authorization: `Bearer ${githubToken}` } : {}),
      },
    });
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  /**
   * Search advisories by CVE ID, GHSA ID, or package string.
   */
  async searchAdvisories(query: string, limit: number = 5): Promise<CVEDto[]> {
    const cacheKey = `github:search:${query}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for GitHub search: ${query}`);
      return cached;
    }

    try {
      this.logger.log(`Searching GitHub Security Advisories for: ${query}`);
      const trimmedQuery = query.trim();
      const params: Record<string, any> = {
        type: 'reviewed',
        per_page: limit,
      };

      if (trimmedQuery.toUpperCase().startsWith('CVE-')) {
        params.cve_id = trimmedQuery.toUpperCase();
      } else if (trimmedQuery.toUpperCase().startsWith('GHSA-')) {
        params.ghsa_id = trimmedQuery;
      } else {
        params.affects = trimmedQuery;
      }

      const response = await this.apiClient.get('/advisories', { params });
      const rawData = Array.isArray(response.data) ? response.data : [];

      const advisories = rawData
        .map((adv: any) => this.parseGitHubAdvisory(adv))
        .slice(0, limit);

      this.cache.set(cacheKey, advisories);
      return advisories;
    } catch (error) {
      this.logger.warn(`Error searching GitHub advisories: ${error}`);
      return [];
    }
  }

  /**
   * Fetch advisories for a specific package and ecosystem.
   */
  async getAdvisoriesByPackage(
    packageName: string,
    ecosystem: SupportedEcosystem = 'npm',
    limit: number = 5,
  ): Promise<CVEDto[]> {
    const cacheKey = `github:${ecosystem}:${packageName}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for GitHub package: ${packageName}`);
      return cached;
    }

    try {
      this.logger.log(`Fetching GitHub advisories for ${ecosystem} package: ${packageName}`);
      const response = await this.apiClient.get('/advisories', {
        params: {
          type: 'reviewed',
          ecosystem: ecosystem === ('cargo' as any) ? 'rust' : ecosystem,
          affects: packageName,
          sort: 'updated',
          direction: 'desc',
          per_page: limit,
        },
      });

      const rawData = Array.isArray(response.data) ? response.data : [];
      const advisories = rawData
        .map((adv: any) => this.parseGitHubAdvisory(adv))
        .slice(0, limit);

      this.cache.set(cacheKey, advisories);
      return advisories;
    } catch (error) {
      this.logger.warn(`Error fetching GitHub advisories for ${packageName}: ${error}`);
      return [];
    }
  }

  /**
   * Get recent global security advisories.
   */
  async getRecentAdvisories(limit: number = 20): Promise<CVEDto[]> {
    const cacheKey = `github:recent:${limit}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug('Cache hit for recent GitHub advisories');
      return cached;
    }

    try {
      this.logger.log('Fetching recent GitHub advisories');
      const response = await this.apiClient.get('/advisories', {
        params: {
          type: 'reviewed',
          sort: 'published',
          direction: 'desc',
          per_page: limit,
        },
      });

      const rawData = Array.isArray(response.data) ? response.data : [];
      const advisories = rawData
        .map((adv: any) => this.parseGitHubAdvisory(adv))
        .slice(0, limit);

      this.cache.set(cacheKey, advisories);
      return advisories;
    } catch (error) {
      this.logger.warn(`Error fetching recent GitHub advisories: ${error}`);
      return [];
    }
  }

  private parseGitHubAdvisory(advisory: any): CVEDto {
    const publishedAt = advisory.published_at || advisory.created_at || new Date().toISOString();
    const references = Array.isArray(advisory.references) ? advisory.references : [];

    return {
      id: advisory.cve_id || advisory.ghsa_id || 'UNKNOWN',
      publishedDate: publishedAt,
      published: new Date(publishedAt).getFullYear(),
      description: advisory.summary || advisory.description || 'No description available',
      metrics: {
        cvssV31Score: advisory.cvss?.score ?? null,
        cvssV31Severity: advisory.cvss?.vector_string || advisory.severity || 'UNKNOWN',
      },
      affectedProducts:
        advisory.vulnerabilities?.map(
          (v: any) => `${v.package?.name || 'unknown'}:${v.vulnerable_version_range || 'all'}`,
        ) || [],
      references: references.map((ref: any) => {
        const url = typeof ref === 'string' ? ref : ref.url;
        return {
          url,
          source: 'GitHub Security Advisory',
          tags: ['github-advisory', advisory.severity?.toLowerCase()].filter(Boolean),
        };
      }),
      githubAdvisoryUrl: advisory.html_url || `https://github.com/advisories/${advisory.ghsa_id}`,
      isExploited: references.some((ref: any) => {
        const url = typeof ref === 'string' ? ref : ref.url;
        return url?.toLowerCase().includes('exploit');
      }),
    };
  }

  clearCache(): void {
    this.cache.flushAll();
    this.logger.log('GitHub Security API cache cleared');
  }
}