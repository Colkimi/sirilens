import * as dotenv from 'dotenv';
import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

// Load environment variables at the very start
dotenv.config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS for frontend communication
  const allowedOrigins = [
    'http://localhost:5173',
    'https://vuln-ai.geniushackers.guru',
    'http://vuln-ai.geniushackers.guru',
    process.env.CORS_ORIGIN,
  ].filter(Boolean);

  app.enableCors({
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Setup Swagger documentation
  const config = new DocumentBuilder()
    .setTitle('sirilens - Cybersecurity Vulnerability Analysis')
    .setDescription(
      'AI-powered vulnerability analysis and security recommendations. Analyze CVEs from NVD, GitHub Security Advisories, and CISA using intelligent threat detection and risk assessment.',
    )
    .setVersion('1.0.0')
    .addTag(
      'Security Analysis',
      'Analyze vulnerabilities, threats, and get security recommendations',
    )
    .setContact(
      'sirilens Support',
      'https://github.com/colki/sirilens',
      'support@sirilens.dev',
    )
    .setLicense('UNLICENSED', 'https://github.com/colki/sirilens')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
    customCss: `.topbar { display: none !important; }`,
  });

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  console.log(`sirilens Server running on http://localhost:${port}`);
  console.log(`Swagger documentation available at http://localhost:${port}/api`);
}

bootstrap();
