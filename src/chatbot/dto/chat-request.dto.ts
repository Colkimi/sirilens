import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ChatRequestDto {
  @ApiProperty({
    description: 'Your security question or CVE ID',
    example: 'Should I trust this email asking for my password?',
  })
  message: string;

  @ApiPropertyOptional({
    description: 'Additional context for your question (will be remembered in the conversation)',
    example: 'The email is from someone claiming to be from my bank',
  })
  context?: string;

  @ApiPropertyOptional({
    description: 'Session ID to maintain conversation history across requests. If not provided, a new session is created.',
    example: 'session-abc123def456',
  })
  sessionId?: string;

  @ApiPropertyOptional({
    description: 'Type of vulnerability you want to check',
    enum: ['phishing', 'email_trust', 'link_safety', 'attachment_safety', 'website_trust', 'social_engineering', 'password_breach', 'account_security', 'general'],
    example: 'phishing',
  })
  vulnerabilityType?: string;
}

export class ChatResponseDto {
  @ApiProperty({
    description: 'The response explaining the vulnerability in simple terms',
    example: 'This appears to be a phishing email...',
  })
  response: string;

  @ApiProperty({
    description: 'Session ID for continuing the conversation',
    example: 'session-abc123def456',
  })
  sessionId: string;
}
