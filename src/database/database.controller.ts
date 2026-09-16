import { Controller, Post, HttpCode, Logger, ForbiddenException, UseGuards } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
// import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { UserRole } from 'src/users/entities/user.entity';
import { Roles } from 'src/auth/decorators/roles.decorator';
// import { seedDatabase } from './seed';

@ApiTags('database')
@ApiBearerAuth('JWT-auth')
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('database')
export class DatabaseController {
  private readonly logger = new Logger(DatabaseController.name);

  constructor(
    @InjectDataSource() private dataSource: DataSource,
    private configService: ConfigService,
  ) {}

  @Roles(UserRole.ADMIN)
  @Post('reset')
  @HttpCode(200)
  async resetDatabase() {
    // Only allow in development
    const nodeEnv = this.configService.get<string>('NODE_ENV');
    if (nodeEnv === 'production') {
      throw new ForbiddenException('Database reset is disabled in production');
    }

    try {
      // Drop all tables
      await this.dataSource.query('DROP SCHEMA public CASCADE');
      await this.dataSource.query('CREATE SCHEMA public');
      await this.dataSource.query('GRANT ALL ON SCHEMA public TO postgres');
      await this.dataSource.query('GRANT ALL ON SCHEMA public TO public');
      
      this.logger.log('✅ Database schema dropped and recreated');

      // Enable UUID extension
      await this.dataSource.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
      this.logger.log('✅ UUID extension enabled');

      // Synchronize to recreate tables
      await this.dataSource.synchronize();
      this.logger.log('✅ Tables synchronized');

      // Run seed
      // await seedDatabase(this.dataSource);
      // this.logger.log('✅ Database seeded');

      return {
        success: true,
        message: 'Database reset successfully',
        adminEmail: this.configService.get<string>('ADMIN_EMAIL'),
      };
    } catch (error) {
      this.logger.error('Error resetting database:', error);
      return {
        success: false,
        message: 'Failed to reset database',
        error: error,
      };
    }
  }

  @Roles(UserRole.ADMIN)
  @Post('sync')
  @HttpCode(200)
  async syncDatabase() {
    try {
      this.logger.log('🔄 Starting database synchronization...');
      
      // Synchronize schema without dropping
      await this.dataSource.synchronize(false);
      
      this.logger.log('✅ Database schema synchronized successfully');

      return {
        success: true,
        message: 'Database schema synchronized successfully. New columns have been added.',
      };
    } catch (error) {
      this.logger.error('Error synchronizing database:', error);
      return {
        success: false,
        message: 'Failed to synchronize database',
        error: error,
      };
    }
  }
}

