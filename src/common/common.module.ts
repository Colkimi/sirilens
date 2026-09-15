import { Module, Global } from '@nestjs/common';
import { DomainValidatorService } from './services/domain-validator';

@Global()
@Module({
  providers: [DomainValidatorService],
  exports: [DomainValidatorService],
})
export class CommonModule {}