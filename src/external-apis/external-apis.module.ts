import { Module } from '@nestjs/common';
import { NvdApiService } from './nvd-api.service';
import { GitHubSecurityApiService } from './github-security.service';
import { CisaApiService } from './cisa-api.service';
import { BreachCheckService } from './breach-check.service';
import { EmailValidationService } from './email-validation.service';
import { WebsiteAnalysisService } from './website-analysis.service';
import { MaliciousSiteDetectionService } from './malicious-site-detection.service';
import { ConfigService } from '@nestjs/config';

@Module({
  providers: [
    NvdApiService,
    GitHubSecurityApiService,
    CisaApiService,
    BreachCheckService,
    EmailValidationService,
    WebsiteAnalysisService,
    MaliciousSiteDetectionService,
    ConfigService,
  ],
  exports: [
    NvdApiService,
    GitHubSecurityApiService,
    CisaApiService,
    BreachCheckService,
    EmailValidationService,
    WebsiteAnalysisService,
    MaliciousSiteDetectionService,
  ],
})
export class ExternalApisModule {}
