import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ChatbotModule } from './chatbot/chatbot.module';
import { VulnerabilityModule } from './vulnerability/vulnerability.module';
import { ExternalApisModule } from './external-apis/external-apis.module';
import { AnalyticsModule } from './analytics/analytics.module';
import { LlmModule } from './llm/llm.module';

@Module({
  imports: [ChatbotModule, VulnerabilityModule, ExternalApisModule, AnalyticsModule, LlmModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
