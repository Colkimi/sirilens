import { Injectable, Logger, ServiceUnavailableException, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import OpenAI from 'openai';

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LLMOptions {
  temperature?: number;
  maxTokens?: number;
  model?: string;
}

@Injectable()
export class LlmService {
  private readonly logger = new Logger(LlmService.name);
  private readonly openrouterClient?: OpenAI;
  private readonly primaryModel: string;
  private readonly fallbackModel: string;

  constructor(private readonly configService: ConfigService) {
    const openrouterKey = this.configService.get<string>('OPENROUTER_API_KEY');
    this.primaryModel = this.configService.get<string>('LLM_PRIMARY_MODEL', 'openai/gpt-4o');
    this.fallbackModel = this.configService.get<string>('LLM_FALLBACK_MODEL', 'openai/gpt-4o-mini');

    if (openrouterKey) {
      this.openrouterClient = new OpenAI({
        apiKey: openrouterKey,
        baseURL: 'https://openrouter.io/api/v1',
        timeout: 15000, // 15-second strict timeout
        defaultHeaders: {
          'HTTP-Referer': this.configService.get<string>('APP_URL', 'https://sirilens.local'),
          'X-Title': 'sirilens',
        },
      });
      this.logger.log('LlmService initialized with OpenRouter provider');
    } else {
      this.logger.warn('OPENROUTER_API_KEY not configured. LLM features are disabled.');
    }
  }

  /**
   * Returns whether the LLM service has valid credentials configured.
   */
  isConfigured(): boolean {
    return !!this.openrouterClient;
  }

  /**
   * Primary completion driver with automatic fallback model recovery.
   */
  async generateResponse(
    messages: LLMMessage[],
    systemPrompt?: string,
    options: LLMOptions = {},
  ): Promise<string> {
    if (!this.openrouterClient) {
      throw new ServiceUnavailableException('LLM service is not configured. Missing OPENROUTER_API_KEY.');
    }

    const payloadMessages: LLMMessage[] = [];

    if (systemPrompt) {
      payloadMessages.push({ role: 'system', content: systemPrompt });
    }

    // Limit conversation history to prevent context window overflow (last 10 turns)
    const recentMessages = messages.slice(-10);
    payloadMessages.push(...recentMessages);

    const temperature = options.temperature ?? 0.7;
    const maxTokens = options.maxTokens ?? 2000;

    // Attempt primary model, falling back to secondary if it fails
    try {
      return await this.callOpenRouter(
        options.model || this.primaryModel,
        payloadMessages,
        temperature,
        maxTokens,
      );
    } catch (error: any) {
      this.logger.warn(`Primary model (${this.primaryModel}) failed: ${error.message}. Attempting fallback...`);

      try {
        return await this.callOpenRouter(
          this.fallbackModel,
          payloadMessages,
          temperature,
          maxTokens,
        );
      } catch (fallbackError: any) {
        this.logger.error(`Both primary and fallback models failed: ${fallbackError.message}`);
        throw new InternalServerErrorException('Failed to generate response from AI provider');
      }
    }
  }

  private async callOpenRouter(
    model: string,
    messages: LLMMessage[],
    temperature: number,
    maxTokens: number,
  ): Promise<string> {
    if (!this.openrouterClient) throw new Error('OpenAI client missing');

    const response = await this.openrouterClient.chat.completions.create({
      model,
      messages: messages as OpenAI.Chat.ChatCompletionMessageParam[],
      temperature,
      max_tokens: maxTokens,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error(`Empty response returned from model ${model}`);
    }

    return content;
  }

  async generateSecurityResponse(
    userMessage: string,
    vulnerabilityData: string,
    conversationHistory: LLMMessage[] = [],
  ): Promise<string> {
    const systemPrompt = `You are sirilens, a professional cybersecurity vulnerability analysis assistant. 
Your role is to help users understand security vulnerabilities, their risks, and mitigation strategies.

Guidelines:
- Provide clear, concise explanations of technical security concepts
- Always prioritize critical security information
- Use markdown formatting for readability
- Reference CVE IDs, CVSS scores, and severity levels
- Suggest practical remediation steps

Vulnerability Context:
${vulnerabilityData}`;

    const messages: LLMMessage[] = [
      ...conversationHistory,
      { role: 'user', content: userMessage },
    ];

    return this.generateResponse(messages, systemPrompt);
  }

  async enhanceVulnerabilityResponse(
    cveId: string,
    vulnerability: Record<string, any>,
    analysis: Record<string, any>,
  ): Promise<string> {
    const payload = JSON.stringify(
      {
        id: cveId,
        description: vulnerability.description,
        severity: vulnerability.metrics?.cvssV31Severity,
        cvss_score: vulnerability.metrics?.cvssV31Score,
        affected_products: vulnerability.affectedProducts?.slice(0, 5),
        is_exploited: vulnerability.isExploited,
        references: vulnerability.references?.slice(0, 3),
        analysis,
      },
      null,
      2,
    );

    const prompt = `Analyze this CVE payload and provide a plain-language summary:

${payload}

Structure your response into:
1. Overview (plain terms)
2. Affected Systems
3. Primary Security Risks
4. Immediate Remediation
5. Urgency & Timeline`;

    return this.generateResponse(
      [{ role: 'user', content: prompt }],
      'You are a cybersecurity expert explaining vulnerability assessments clearly and professionally.',
      { temperature: 0.3 }, // Lower temperature for more consistent, factual security reporting
    );
  }

  async generateThreatReport(threatData: Record<string, any>): Promise<string> {
    const prompt = `Generate a comprehensive threat landscape report based on this data:\n${JSON.stringify(threatData, null, 2)}`;

    return this.generateResponse(
      [{ role: 'user', content: prompt }],
      'You are a senior security intelligence analyst creating an executive threat assessment report.',
      { temperature: 0.4, maxTokens: 3000 },
    );
  }

  async summarizeVulnerabilities(
    cves: Array<{ id: string; severity: string; cvssScore?: number }>,
  ): Promise<string> {
    const summary = cves
      .map((c) => `- ${c.id}: ${c.severity} (CVSS: ${c.cvssScore || 'N/A'})`)
      .join('\n');

    const prompt = `Summarize these findings and prioritize patching efforts:\n\n${summary}`;

    return this.generateResponse(
      [{ role: 'user', content: prompt }],
      'You are a Security Operations Center (SOC) lead establishing operational priorities.',
      { temperature: 0.2 },
    );
  }

  async generateSimpleSecurityResponse(
    userMessage: string,
    contextData: string,
    conversationHistory: LLMMessage[] = [],
    systemPrompt?: string,
  ): Promise<string> {
    const defaultSystemPrompt = `You are a helpful security advisor explaining security issues to non-technical users.
Keep explanations jargon-free, practical, short, and reassuring.

Context:
${contextData}`;

    const messages: LLMMessage[] = [
      ...conversationHistory,
      { role: 'user', content: userMessage },
    ];

    return this.generateResponse(messages, systemPrompt || defaultSystemPrompt, { temperature: 0.5 });
  }
}