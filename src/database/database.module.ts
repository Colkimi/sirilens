import { Module } from '@nestjs/common';
import { DatabaseController } from './database.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [DatabaseController],
})
export class DatabaseModule {}
