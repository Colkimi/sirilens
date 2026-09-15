import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';

export interface BreachInfo {
  name: string;
  breachDate: string;
  addedDate?: string;
  description?: string;
  count?: number;
  dataClasses?: string[]; 
}

interface LeakCheckSource {
  name: string;
  date?: string;
}

interface LeakCheckResponse {
  success: boolean;
  found?: number;
  fields?: string[]; 
  sources?: LeakCheckSource[];
  error?: string;
}

@Injectable()
export class BreachCheckService {
  private readonly logger = new Logger(BreachCheckService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly LEAKCHECK_BASE_URL = 'https://leakcheck.io/api';
  private readonly CACHE_TTL = 86400; // 24 hours

  constructor() {
    this.apiClient = axios.create({
      baseURL: this.LEAKCHECK_BASE_URL,
      timeout: 10000,
      headers: {
        'User-Agent': 'sirilens-SecurityChat',
      },
    });
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  private async queryLeakCheck(target: string, cacheKey: string): Promise<BreachInfo[]> {
    const cached = this.cache.get<BreachInfo[]>(cacheKey);
    if (cached !== undefined) {
      this.logger.debug(`Cache hit for breach check: ${target}`);
      return cached;
    }

    try {
      this.logger.log(`Checking LeakCheck database for: ${target}`);
      const response = await this.apiClient.get<LeakCheckResponse>('/public', {
        params: { check: target },
      });

      if (!response.data || !response.data.success || !response.data.sources) {
        this.logger.log(`No breaches found for: ${target}`);
        this.cache.set(cacheKey, []);
        return [];
      }

      const exposedFields = response.data.fields || [];

      // Map LeakCheck response to BreachInfo
      const breaches: BreachInfo[] = response.data.sources.map((source) => ({
        name: source.name || 'Unknown Source',
        breachDate: source.date || 'Unknown',
        addedDate: source.date || 'Unknown',
        description: exposedFields.length > 0
          ? `Exposed data: ${exposedFields.join(', ')}`
          : `Exposed in ${source.name || 'data breach'}`,
        count: response.data.found || 1,
        dataClasses: exposedFields,
      }));

      this.cache.set(cacheKey, breaches);
      return breaches;
    } catch (error: any) {
      if (error.response?.status === 404) {
        this.logger.log(`No breaches found for: ${target}`);
        this.cache.set(cacheKey, []);
        return [];
      }

      this.logger.error(`Error checking breaches for ${target}: ${error.message || error}`);
      return [];
    }
  }

  async checkEmail(email: string): Promise<BreachInfo[]> {
    return this.queryLeakCheck(email, `breach:email:${email}`);
  }

  async checkUsername(username: string): Promise<BreachInfo[]> {
    return this.queryLeakCheck(username, `breach:user:${username}`);
  }

  clearCache(): void {
    this.logger.log('Clearing breach check cache');
    this.cache.flushAll();
  }
}