import { Module } from '@nestjs/common';
import { ThreatAnalyzerService } from './threat-analyzer.service';
import { RiskCalculatorService } from './risk-calculator.service';
import { ThreatIntelligenceService } from './threat-intelligence.service';
import { ExternalApisModule } from '../external-apis/external-apis.module';

@Module({
  imports: [ExternalApisModule],
  providers: [ThreatAnalyzerService, RiskCalculatorService, ThreatIntelligenceService],
  exports: [ThreatAnalyzerService, RiskCalculatorService, ThreatIntelligenceService],
})
export class AnalyticsModule {}
