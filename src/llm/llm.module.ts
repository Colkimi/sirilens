import { Module } from '@nestjs/common';
import { LlmService } from './llm.service';
import { ConfigService } from '@nestjs/config';

@Module({
  providers: [LlmService, ConfigService],
  exports: [LlmService],
})
export class LlmModule {}
