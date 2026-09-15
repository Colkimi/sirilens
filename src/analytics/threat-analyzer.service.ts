import { Injectable, Logger } from '@nestjs/common';
import { CVEDto } from '../vulnerability/dto/cve.dto';

export interface ThreatAnalysis {
  threatLevel: 'critical' | 'high' | 'medium' | 'low';
  riskScore: number;
  patterns: string[];
  affectedCount: number;
  exploitableCount: number;
  recommendations: string[];
}

export interface PatternMatch {
  pattern: string;
  severity: string;
  relatedCVEs: string[];
  frequency: number;
}

@Injectable()
export class ThreatAnalyzerService {
  private readonly logger = new Logger(ThreatAnalyzerService.name);

  analyzeThreatPatterns(cves: CVEDto[], systemInfo?: Record<string, any>): ThreatAnalysis {
    const criticalCount = cves.filter(
      (c) => c.metrics?.cvssV31Severity === 'CRITICAL',
    ).length;
    const highCount = cves.filter(
      (c) => c.metrics?.cvssV31Severity === 'HIGH',
    ).length;
    const exploitedCount = cves.filter((c) => c.isExploited).length;

    const riskScore = this.calculateRiskScore(cves, exploitedCount);
    const threatLevel = this.determineThreatLevel(riskScore, criticalCount);
    const patterns = this.detectPatterns(cves, systemInfo);
    const recommendations = this.generateRecommendations(threatLevel, cves);

    this.logger.log(
      `Threat analysis: ${threatLevel} (score: ${riskScore}), ${cves.length} CVEs, ${exploitedCount} exploited`,
    );

    return {
      threatLevel,
      riskScore: Math.round(riskScore * 100) / 100,
      patterns,
      affectedCount: cves.length,
      exploitableCount: exploitedCount,
      recommendations,
    };
  }

  detectPatterns(cves: CVEDto[], systemInfo?: Record<string, any>): string[] {
    const patterns: string[] = [];

    // Pattern 1: Multiple critical vulnerabilities
    const criticalCves = cves.filter((c) => c.metrics?.cvssV31Severity === 'CRITICAL');
    if (criticalCves.length >= 3) {
      patterns.push('Multiple critical vulnerabilities detected');
    }

    // Pattern 2: Known exploited vulnerabilities
    const exploitedCves = cves.filter((c) => c.isExploited);
    if (exploitedCves.length > 0) {
      patterns.push(`${exploitedCves.length} known exploited vulnerabilities detected`);
    }

    // Pattern 3: Privilege escalation vectors
    const privEscCves = cves.filter((c) =>
      c.description?.toLowerCase().includes('privilege escalation'),
    );
    if (privEscCves.length > 0) {
      patterns.push('Privilege escalation vulnerabilities detected');
    }

    // Pattern 4: Remote code execution
    const rceCves = cves.filter((c) =>
      c.description?.toLowerCase().includes('remote code execution') ||
      c.description?.toLowerCase().includes('rce'),
    );
    if (rceCves.length > 0) {
      patterns.push('Remote code execution vulnerabilities possible');
    }

    // Pattern 5: Denial of service
    const dosCves = cves.filter((c) =>
      c.description?.toLowerCase().includes('denial of service') ||
      c.description?.toLowerCase().includes('dos'),
    );
    if (dosCves.length > 0) {
      patterns.push('Denial of service attack vectors present');
    }

    // Pattern 6: Recent vulnerabilities (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentCves = cves.filter((c) => {
      const pubDate = new Date(c.publishedDate || '');
      return pubDate > thirtyDaysAgo;
    });
    if (recentCves.length >= 2) {
      patterns.push(`${recentCves.length} recently published vulnerabilities detected`);
    }

    return patterns;
  }

  private calculateRiskScore(cves: CVEDto[], exploitedCount: number): number {
    let baseScore = 0;

    // Base score from severity distribution
    cves.forEach((cve) => {
      const severity = cve.metrics?.cvssV31Severity;
      switch (severity) {
        case 'CRITICAL':
          baseScore += 10;
          break;
        case 'HIGH':
          baseScore += 7;
          break;
        case 'MEDIUM':
          baseScore += 4;
          break;
        case 'LOW':
          baseScore += 2;
          break;
      }
    });

    // Exploit multiplier
    const exploitMultiplier = 1 + exploitedCount * 0.3;

    // Normalize to 0-100 scale
    const normalizedScore = Math.min(100, baseScore * 2);
    return normalizedScore * exploitMultiplier;
  }

  private determineThreatLevel(
    riskScore: number,
    criticalCount: number,
  ): 'critical' | 'high' | 'medium' | 'low' {
    if (criticalCount >= 2 || riskScore >= 80) {
      return 'critical';
    }
    if (riskScore >= 60 || criticalCount === 1) {
      return 'high';
    }
    if (riskScore >= 30) {
      return 'medium';
    }
    return 'low';
  }

  private generateRecommendations(
    threatLevel: string,
    cves: CVEDto[],
  ): string[] {
    const recommendations: string[] = [];

    if (threatLevel === 'critical') {
      recommendations.push('IMMEDIATE: Isolate affected systems');
      recommendations.push('IMMEDIATE: Prepare for emergency patching');
      recommendations.push('IMMEDIATE: Enable enhanced monitoring');
    }

    const exploited = cves.filter((c) => c.isExploited);
    if (exploited.length > 0) {
      recommendations.push(`Apply available patches for ${exploited.length} known exploited CVEs`);
    }

    const patches = cves.filter((c) =>
      c.references?.some((r) => r.tags?.includes?.('vendor advisory')),
    );
    if (patches.length > 0) {
      recommendations.push(`Review ${patches.length} vendor advisories for patches`);
    }

    if (threatLevel === 'high' || threatLevel === 'critical') {
      recommendations.push('Enable WAF rules if applicable');
      recommendations.push('Review firewall rules and access controls');
    }

    recommendations.push('Subscribe to security advisories for affected products');

    return recommendations;
  }

  getPatternSummary(patterns: string[]): string {
    if (patterns.length === 0) {
      return 'No significant threat patterns detected.';
    }
    return `Detected: ${patterns.join('; ')}.`;
  }
}
