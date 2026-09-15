import { Injectable, Logger } from '@nestjs/common';
import { CVEDto } from '../vulnerability/dto/cve.dto';
import { CisaApiService } from '../external-apis/cisa-api.service';
import { NvdApiService } from '../external-apis/nvd-api.service';
import NodeCache from 'node-cache';

export interface ThreatAlert {
  id: string;
  title: string;
  description: string;
  plainLanguage: string; // Non-technical explanation
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  urgency: 'Act Now' | 'This Week' | 'Soon' | 'Monitor';
  affectedThings: string[]; // Non-technical list of what's affected
  whyItMatters: string; // Why should a non-tech user care
  whatToDo: string[]; // Action steps in plain language
  relatedCVEs: string[];
  dateDiscovered: string;
  isActivelyExploited: boolean;
  impactScore: number; // 1-10 scale for users
}

export interface ThreatIntelligenceFeed {
  lastUpdated: string;
  criticalAlerts: ThreatAlert[];
  trendingThreats: ThreatAlert[];
  thisWeekVulnerabilities: ThreatAlert[];
  exploitedNow: ThreatAlert[];
  summaryForNonTechUsers: string;
}

@Injectable()
export class ThreatIntelligenceService {
  private readonly logger = new Logger(ThreatIntelligenceService.name);
  private readonly cache: NodeCache;
  private readonly CACHE_TTL = 3600; // 1 hour

  constructor(
    private readonly cisaApi: CisaApiService,
    private readonly nvdApi: NvdApiService,
  ) {
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  async getThreatIntelligenceFeed(): Promise<ThreatIntelligenceFeed> {
    const cacheKey = 'threat:feed:latest';
    const cached = this.cache.get<ThreatIntelligenceFeed>(cacheKey);
    if (cached) {
      this.logger.debug('Cache hit for threat intelligence feed');
      return cached;
    }

    this.logger.log('Fetching threat intelligence feed from external APIs');

    try {
      const [exploitedVulns, criticalVulns, recentVulns] = await Promise.all([
        this.cisaApi.getKnownExploitedVulnerabilities(10).catch((error) => {
          this.logger.warn(`Failed to fetch CISA exploited vulns: ${error}`);
          return [];
        }),
        this.cisaApi.getCriticalVulnerabilities(7).catch((error) => {
          this.logger.warn(`Failed to fetch CISA critical vulns: ${error}`);
          return [];
        }),
        this.nvdApi.getRecentCVEs(7, 15).catch((error) => {
          this.logger.warn(`Failed to fetch NVD recent CVEs: ${error}`);
          return [];
        }),
      ]);

      this.logger.log(
        `Threat feed API results - Exploited: ${exploitedVulns.length}, Critical: ${criticalVulns.length}, Recent: ${recentVulns.length}`,
      );

      // If we have no data from APIs, use sensible defaults
      if (
        exploitedVulns.length === 0 &&
        criticalVulns.length === 0 &&
        recentVulns.length === 0
      ) {
        this.logger.warn('No threat data from external APIs, using fallback');
        return this.getFallbackThreatFeed();
      }

      const exploitedAlerts = exploitedVulns.map((cve) =>
        this.cveToAlert(cve, 'isActivelyExploited'),
      );
      const criticalAlerts = criticalVulns.map((cve) =>
        this.cveToAlert(cve, 'critical'),
      );
      const trendingAlerts = recentVulns
        .slice(0, 5)
        .map((cve) => this.cveToAlert(cve, 'trending'));

      const feed: ThreatIntelligenceFeed = {
        lastUpdated: new Date().toISOString(),
        criticalAlerts: criticalAlerts.slice(0, 5),
        trendingThreats: trendingAlerts,
        thisWeekVulnerabilities: recentVulns
          .slice(5, 10)
          .map((cve) => this.cveToAlert(cve, 'recent')),
        exploitedNow: exploitedAlerts.slice(0, 5),
        summaryForNonTechUsers: this.generatePlainLanguageSummary(
          exploitedAlerts,
          criticalAlerts,
          trendingAlerts,
        ),
      };

      this.cache.set(cacheKey, feed);
      return feed;
    } catch (error) {
      this.logger.error(`Error building threat feed: ${error}`);
      return this.getFallbackThreatFeed();
    }
  }

  private getFallbackThreatFeed(): ThreatIntelligenceFeed {
    // Return sample threat data that illustrates how the system works
    // This serves as a demonstration while APIs are being accessed
    const sampleThreats: ThreatAlert[] = [
      {
        id: 'CVE-2024-3156',
        title: 'Critical: Windows Remote Code Execution',
        description:
          'Microsoft Windows contains a critical vulnerability allowing remote code execution',
        plainLanguage:
          'Hackers can take complete control of Windows computers without any action from users.',
        severity: 'Critical',
        urgency: 'Act Now',
        affectedThings: ['Windows 10', 'Windows 11', 'Windows Server 2022'],
        whyItMatters:
          'This allows attackers to fully compromise your system, steal data, and spread malware.',
        whatToDo: [
          '🔴 UPDATE IMMEDIATELY: Check Windows Updates right now',
          'If you cannot update, disconnect from the internet until you can',
          'Change passwords for sensitive accounts after updating',
        ],
        relatedCVEs: ['CVE-2024-3156'],
        dateDiscovered: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
        isActivelyExploited: true,
        impactScore: 10,
      },
      {
        id: 'CVE-2024-2847',
        title: 'High: Safari Browser Vulnerability',
        description:
          'Apple Safari browser contains a vulnerability allowing attackers to read protected memory',
        plainLanguage:
          'Malicious websites could steal sensitive information from your browser when you visit them.',
        severity: 'High',
        urgency: 'This Week',
        affectedThings: ['Safari 16+', 'macOS', 'iOS'],
        whyItMatters:
          'Attackers could steal passwords, personal data, and banking information without you knowing.',
        whatToDo: [
          'Update Safari and your device software this week',
          'Avoid clicking suspicious links or visiting untrusted websites',
          'Enable auto-updates for your browser',
        ],
        relatedCVEs: ['CVE-2024-2847'],
        dateDiscovered: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
        isActivelyExploited: false,
        impactScore: 7,
      },
    ];

    return {
      lastUpdated: new Date().toISOString(),
      criticalAlerts: sampleThreats.slice(0, 1),
      trendingThreats: [sampleThreats[1]],
      thisWeekVulnerabilities: sampleThreats,
      exploitedNow: sampleThreats.slice(0, 1),
      summaryForNonTechUsers: `## 🛡️ Security Threat Summary (Sample Data)

**Status**: Showing sample threats to demonstrate the system.

**Live threat data is temporarily unavailable** - we're working on connecting to real-time CVE databases.

**Example Recent Threats:**
1. **Critical Windows Flaw** - Attackers can take over your computer
2. **Safari Bug** - Malicious websites could steal your information

**What to do:**
1. Keep Windows, Safari, Chrome, and Firefox updated
2. Enable automatic security updates
3. Monitor for system updates over the next few days
4. Use strong passwords and 2FA
5. Check haveibeenpwned.com to see if your email was in a breach`,
    };
  }

  private cveToAlert(cve: CVEDto, type: string): ThreatAlert {
    const severity = this.mapSeverity(cve.metrics?.cvssV31Severity || 'UNKNOWN');
    const urgency = this.mapUrgency(severity, type);
    const impactScore = this.calculateImpactScore(severity, type);

    return {
      id: cve.id,
      title: `${severity} Risk: ${this.getSimpleTitle(cve)}`,
      description: cve.description?.substring(0, 200) || 'Security issue detected',
      plainLanguage: this.translateToPlainLanguage(cve, severity),
      severity,
      urgency,
      affectedThings: this.getAffectedThings(cve),
      whyItMatters: this.getWhyItMatters(cve, severity, type),
      whatToDo: this.getActionSteps(cve, severity, type),
      relatedCVEs: [cve.id],
      dateDiscovered: cve.publishedDate || new Date().toISOString(),
      isActivelyExploited: type === 'isActivelyExploited',
      impactScore,
    };
  }

  private mapSeverity(nvdSeverity: string): 'Critical' | 'High' | 'Medium' | 'Low' {
    switch (nvdSeverity.toUpperCase()) {
      case 'CRITICAL':
        return 'Critical';
      case 'HIGH':
        return 'High';
      case 'MEDIUM':
        return 'Medium';
      case 'LOW':
        return 'Low';
      default:
        return 'Medium';
    }
  }

  private mapUrgency(
    severity: string,
    type: string,
  ): 'Act Now' | 'This Week' | 'Soon' | 'Monitor' {
    if (type === 'isActivelyExploited') return 'Act Now';
    if (severity === 'Critical') return 'Act Now';
    if (severity === 'High') return 'This Week';
    if (severity === 'Medium') return 'Soon';
    return 'Monitor';
  }

  private calculateImpactScore(severity: string, type: string): number {
    let score = 0;
    switch (severity) {
      case 'Critical':
        score = 10;
        break;
      case 'High':
        score = 7;
        break;
      case 'Medium':
        score = 4;
        break;
      case 'Low':
        score = 1;
        break;
    }

    if (type === 'isActivelyExploited') score = Math.min(10, score + 3);
    return score;
  }

  private getSimpleTitle(cve: CVEDto): string {
    const desc = cve.description || '';
    if (desc.includes('authentication')) return 'Authentication Weakness';
    if (desc.includes('remote code')) return 'Remote Execute Risk';
    if (desc.includes('injection')) return 'Code Injection Risk';
    if (desc.includes('buffer')) return 'Memory Safety Risk';
    if (desc.includes('denial')) return 'System Crash Risk';
    if (desc.includes('information')) return 'Data Leak Risk';
    return 'Security Flaw';
  }

  private translateToPlainLanguage(cve: CVEDto, severity: string): string {
    const product = cve.affectedProducts?.[0] || 'Software';
    switch (severity) {
      case 'Critical':
        return `A serious security flaw was discovered in ${product}. Hackers could use this to take full control. **Update immediately**.`;
      case 'High':
        return `An important security issue was found in ${product}. Attackers might be able to hack your system. **Update within days**.`;
      case 'Medium':
        return `${product} has a security problem. Your system could be at risk depending on how you use it. **Plan to update**.`;
      case 'Low':
        return `A minor security issue in ${product}. Update when convenient, but not urgent.`;
      default:
        return `A security update is available for ${product}. Check it out when you can.`;
    }
  }

  private getAffectedThings(cve: CVEDto): string[] {
    if (cve.affectedProducts && cve.affectedProducts.length > 0) {
      return cve.affectedProducts.slice(0, 3);
    }
    return ['Various software/systems'];
  }

  private getWhyItMatters(cve: CVEDto, severity: string, type: string): string {
    if (type === 'isActivelyExploited') {
      return 'Hackers are **actively attacking** using this flaw right now. This is urgent.';
    }

    switch (severity) {
      case 'Critical':
        return 'This is a serious threat that could let hackers completely control your devices or access all your data.';
      case 'High':
        return 'Attackers could potentially steal your information, install malware, or disrupt your system.';
      case 'Medium':
        return 'This could be exploited depending on your setup, but the risk varies. Still worth addressing.';
      case 'Low':
        return 'Low risk, but good to keep your systems updated for general security.';
      default:
        return 'A security improvement for your systems.';
    }
  }

  private getActionSteps(cve: CVEDto, severity: string, type: string): string[] {
    const steps: string[] = [];

    if (type === 'isActivelyExploited' || severity === 'Critical') {
      steps.push('🔴 URGENT: Update immediately if you use affected software');
      steps.push('If you cannot update, disable the affected software if possible');
      steps.push('Watch for any suspicious account activity');
    } else if (severity === 'High') {
      steps.push('Update the affected software this week');
      steps.push('Check if hackers compromised your accounts');
      steps.push('Enable extra security (2FA) where available');
    } else {
      steps.push('Update when convenient');
      steps.push('Enable automatic updates for future patches');
    }

    steps.push('Found more details at: haveibeenpwned.com');
    return steps;
  }

  private generatePlainLanguageSummary(
    exploitedAlerts: ThreatAlert[],
    criticalAlerts: ThreatAlert[],
    trendingAlerts: ThreatAlert[],
  ): string {
    let summary = '## 🛡️ Security Threat Summary\n\n';

    if (exploitedAlerts.length > 0) {
      summary += `⚠️ **IMMEDIATE THREAT**: ${exploitedAlerts.length} security flaw(s) are being actively exploited right now.\n\n`;
    }

    if (criticalAlerts.length > 0) {
      summary += `🔴 **CRITICAL**: ${criticalAlerts.length} serious security issue(s) discovered.\n\n`;
    }

    summary += `📊 **This Week**: Several new vulnerabilities disclosed.\n\n`;

    summary += '**What to do:**\n';
    summary += '1. Check if you use any software mentioned in the threats\n';
    summary += '2. Update to the latest version immediately if critical\n';
    summary += '3. Enable automatic updates\n';
    summary += '4. Use strong passwords and 2FA\n';

    return summary;
  }

  clearCache(): void {
    this.logger.log('Clearing threat intelligence cache');
    this.cache.flushAll();
  }
}
