import { Injectable, Logger } from '@nestjs/common';
import { CVEDto, SecurityRecommendationDto } from '../vulnerability/dto/cve.dto';

export interface RiskAssessment {
  cveId: string;
  cvssScore?: number;
  severity: string;
  exploitability: 'high' | 'medium' | 'low';
  priority: 'critical' | 'immediate' | 'high' | 'medium' | 'low';
  remediationType: 'Patch' | 'Workaround' | 'Mitigation' | 'No Fix Available';
  estimatedEffort: string;
  affectedCount: number;
}

@Injectable()
export class RiskCalculatorService {
  private readonly logger = new Logger(RiskCalculatorService.name);

  assessVulnerability(cve: CVEDto, affectedSystemsCount: number = 1): RiskAssessment {
    const severity = cve.metrics?.cvssV31Severity || 'UNKNOWN';
    const cvssScore = cve.metrics?.cvssV31Score || 0;
    const isExploited = cve.isExploited || false;

    const exploitability = this.determineExploitability(cve, isExploited);
    const priority = this.determinePriority(severity, exploitability, affectedSystemsCount);
    const remediationType = this.determineRemediationType(cve);
    const estimatedEffort = this.estimateEffort(priority, remediationType);

    this.logger.log(
      `Risk assessment for ${cve.id}: ${priority} priority, ${exploitability} exploitability`,
    );

    return {
      cveId: cve.id,
      cvssScore,
      severity,
      exploitability,
      priority,
      remediationType,
      estimatedEffort,
      affectedCount: affectedSystemsCount,
    };
  }

  generateRecommendation(
    cve: CVEDto,
    affectedSystemCount: number = 1,
  ): SecurityRecommendationDto {
    const assessment = this.assessVulnerability(cve, affectedSystemCount);
    
    const recommendation = this.buildRecommendationText(cve, assessment);
    const additionalSteps = this.getAdditionalSteps(cve, assessment.priority);

    return {
      cveId: cve.id,
      priority: assessment.priority,
      recommendation,
      remediationType: assessment.remediationType,
      estimatedEffort: assessment.estimatedEffort,
      additionalSteps,
    };
  }

  prioritizeVulnerabilities(cves: CVEDto[]): SecurityRecommendationDto[] {
    const recommendations = cves.map((cve) => this.generateRecommendation(cve));

    const priorityOrder = {
      critical: 0,
      immediate: 1,
      high: 2,
      medium: 3,
      low: 4,
    };

    recommendations.sort(
      (a, b) => 
        (priorityOrder[a.priority as keyof typeof priorityOrder] || 5) -
        (priorityOrder[b.priority as keyof typeof priorityOrder] || 5)
    );

    return recommendations;
  }

  private determineExploitability(cve: CVEDto, isExploited: boolean): 'high' | 'medium' | 'low' {
    if (isExploited) {
      return 'high';
    }

    const description = (cve.description || '').toLowerCase();
    if (
      description.includes('remote code execution') ||
      description.includes('rce') ||
      description.includes('unauthenticated') ||
      description.includes('network')
    ) {
      return 'high';
    }

    if (
      description.includes('privilege escalation') ||
      description.includes('authentication bypass') ||
      description.includes('cross-site')
    ) {
      return 'medium';
    }

    return 'low';
  }

  private determinePriority(
    severity: string,
    exploitability: string,
    affectedCount: number,
  ): 'critical' | 'immediate' | 'high' | 'medium' | 'low' {
    // Critical if affects many systems with critical severity
    if (severity === 'CRITICAL') {
      if (exploitability === 'high' || affectedCount > 5) {
        return 'critical';
      }
      return 'immediate';
    }

    // High severity, high exploitability
    if (severity === 'HIGH' && exploitability === 'high') {
      if (affectedCount > 3) {
        return 'immediate';
      }
      return 'high';
    }

    if (severity === 'HIGH') {
      return 'high';
    }

    if (severity === 'MEDIUM') {
      return exploitability === 'high' ? 'high' : 'medium';
    }

    return 'low';
  }

  private determineRemediationType(cve: CVEDto): 'Patch' | 'Workaround' | 'Mitigation' | 'No Fix Available' {
    const hasReferences = (cve.references || []).length > 0;
    const hasVendorAdvisory = (cve.references || []).some((ref) =>
      ref.source?.toLowerCase().includes('vendor'),
    );

    if (hasVendorAdvisory) {
      return 'Patch';
    }

    if (cve.description?.toLowerCase().includes('no patch')) {
      return 'No Fix Available';
    }

    if (hasReferences) {
      return 'Workaround';
    }

    // Default based on severity
    if (cve.metrics?.cvssV31Severity === 'CRITICAL') {
      return 'Mitigation';
    }

    return 'Workaround';
  }

  private estimateEffort(
    priority: string,
    remediationType: string,
  ): string {
    if (remediationType === 'Patch') {
      if (priority === 'critical' || priority === 'immediate') {
        return '1-2 hours';
      }
      if (priority === 'high') {
        return '4-8 hours';
      }
      return '1-2 days';
    }

    if (remediationType === 'Mitigation') {
      if (priority === 'critical' || priority === 'immediate') {
        return '30 minutes';
      }
      return '2-4 hours';
    }

    if (remediationType === 'Workaround') {
      return '2-4 hours';
    }

    return 'Varies';
  }

  private buildRecommendationText(cve: CVEDto, assessment: RiskAssessment): string {
    const parts: string[] = [];

    if (assessment.remediationType === 'Patch') {
      parts.push(`Apply available security patch for ${cve.id}`);

      if (cve.references && cve.references.length > 0) {
        const vendorRef = cve.references.find((r) =>
          r.source?.toLowerCase().includes('vendor'),
        );
        if (vendorRef) {
          parts.push(`Follow vendor advisory at ${vendorRef.url}`);
        }
      }
    } else if (assessment.remediationType === 'Workaround') {
      parts.push(`Implement workaround for ${cve.id}`);
      if (cve.references && cve.references.length > 0) {
        parts.push(`Review mitigation details at ${cve.references[0].url}`);
      }
    } else if (assessment.remediationType === 'Mitigation') {
      parts.push(`Implement compensating controls for ${cve.id}`);
      parts.push('Monitor for exploitation attempts');
    } else {
      parts.push(`No patch available for ${cve.id}`);
      parts.push('Focus on detection and monitoring');
    }

    if (assessment.affectedCount > 1) {
      parts.push(`Affects ${assessment.affectedCount} systems in your environment`);
    }

    return parts.join('. ');
  }

  private getAdditionalSteps(cve: CVEDto, priority: string): string[] {
    const steps: string[] = [];

    if (priority === 'critical' || priority === 'immediate') {
      steps.push('Enable temporary access restrictions');
      steps.push('Increase logging and monitoring');
    }

    if (cve.isExploited) {
      steps.push('Check logs for exploitation attempts');
      steps.push('Review network traffic for suspicious activity');
    }

    if (cve.description?.toLowerCase().includes('privilege escalation')) {
      steps.push('Review user privileges and access controls');
    }

    if (cve.description?.toLowerCase().includes('authentication')) {
      steps.push('Force password reset for affected users');
      steps.push('Enable MFA if not already enabled');
    }

    steps.push('Subscribe to vendor security updates');

    return steps.slice(0, 5); // Return top 5 steps
  }
}
