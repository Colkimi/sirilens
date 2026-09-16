import * as dotenv from 'dotenv';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './http-exception.filter';
import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import 'reflect-metadata';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { ValidationPipe } from '@nestjs/common';


// Load environment variables at the very start
dotenv.config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useWebSocketAdapter(new IoAdapter() as any);

  app.use(
    helmet({
      contentSecurityPolicy: false, // Disables CSP restrictions that break Swagger UI JS/CSS
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.useGlobalPipes(new ValidationPipe({
    transform: true,
    whitelist: true,
    forbidNonWhitelisted: true,
    transformOptions: {
      enableImplicitConversion: true,
    },
  }));

  const { httpAdapter } = app.get(HttpAdapterHost);
  app.useGlobalFilters(new AllExceptionsFilter(httpAdapter));

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
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'JWT',
        description: 'Enter JWT token',
        in: 'header',
      },
      'JWT-auth',
    )
    .addTag('auth', 'Authentication - User registration and login')
    .addTag('users', 'User management - Admin and profile operations')
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
