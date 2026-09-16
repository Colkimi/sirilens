import { DataSource } from 'typeorm';
import { Logger } from '@nestjs/common';

async function initializeDatabase() {
  const logger = new Logger('DatabaseInit');

  const databaseUrl = process.env.DATABASE_URL;
  
  let dataSourceOptions: any;
  
  if (databaseUrl) {
    dataSourceOptions = {
      type: 'postgres',
      url: databaseUrl,
      entities: [__dirname + '/../**/*.entity{.ts,.js}'],
      synchronize: true, // This will create tables
      ssl: { rejectUnauthorized: false },
    };
  } else {
    dataSourceOptions = {
      type: 'postgres',
      host: process.env.DATABASE_HOST,
      port: parseInt(process.env.DATABASE_PORT || '5432'),
      username: process.env.DATABASE_USER,
      password: process.env.DATABASE_PASSWORD,
      database: process.env.DATABASE_NAME,
      entities: [__dirname + '/../**/*.entity{.ts,.js}'],
      synchronize: true, // This will create tables
    };
  }

  const dataSource = new DataSource(dataSourceOptions);

  try {
    await dataSource.initialize();
    logger.log('✅ Database connection established');
    
    // Wait a moment for synchronize to complete
    await new Promise(resolve => setTimeout(resolve, 2000));
        
    logger.log('✅ Database initialization complete');
    await dataSource.destroy();
    process.exit(0);
  } catch (error) {
    logger.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

initializeDatabase();
