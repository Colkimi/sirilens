import { Injectable, Logger } from '@nestjs/common';
import { VulnerabilityService } from '../vulnerability/vulnerability.service';
import { RealWorldScenario, RealWorldVulnerabilityService } from '../vulnerability/real-world-vulnerability.service';
// import { ThreatAnalyzerService } from '../analytics/threat-analyzer.service';
import { RiskCalculatorService } from '../analytics/risk-calculator.service';
import { LlmService } from '../llm/llm.service';
import { EmailValidationService } from '../external-apis/email-validation.service';
import { SecurityRecommendationDto } from '../vulnerability/dto/cve.dto';
import NodeCache from 'node-cache';
// import { WebsiteAnalysisService } from 'src/external-apis/website-analysis.service';
import { CVEDto } from '../vulnerability/dto/cve.dto';
import { SecurityIntent } from 'src/types/intent';
import { DomainValidatorService } from 'src/common/services/domain-validator';

export type FollowUpAction =
  | 'REPORT_PHISHING'
  | 'EMAIL_CHECKLIST'
  | 'CHECK_LINK'
  | 'SCAN_FILE'
  | 'VERIFY_WEBSITE'
  | 'SOCIAL_ENGINEERING'
  | 'LEAKED_PASSWORD'
  | 'PASSWORD_SECURITY';

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
}

export interface SessionData {
  history: ChatMessage[];
  pendingFollowUpAction?: FollowUpAction;
}

@Injectable()
export class ChatbotService {
  private readonly logger = new Logger(ChatbotService.name);
  private conversationContext = new Map<string, SessionData>();
  private sessionCache: NodeCache; // 30 minute TTL for sessions

  constructor(
    private readonly vulnerabilityService: VulnerabilityService,
    private readonly realWorldVulnService: RealWorldVulnerabilityService,
    // private readonly threatAnalyzer: ThreatAnalyzerService,
    private readonly riskCalculator: RiskCalculatorService,
    private readonly llmService: LlmService,
    private readonly emailValidationService: EmailValidationService,
    // private readonly websiteAnalysisService: WebsiteAnalysisService,
    private readonly DomainValidatorService: DomainValidatorService,
  ) {
    this.sessionCache = new NodeCache({ stdTTL: 1800, checkperiod: 600 });
  }

  async chat(sessionId: string, message: string, context?: string): Promise<string> {
    try {
      this.logger.log(`Chat request for session ${sessionId}: ${message}`);
      
      const fullMessage = context ? `${message}\nContext: ${context}` : message;
      
      this.addToContext(sessionId, { role: 'user', content: fullMessage, timestamp: new Date() });
      this.sessionCache.set(sessionId, { lastActivity: new Date() });

      const lowerMessage = message.toLowerCase().trim();
      
      const greetingResponse = this.detectGreeting(lowerMessage);
      if (greetingResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: greetingResponse, timestamp: new Date() });
        return greetingResponse;
      }

      const maliciousResponse = this.detectMaliciousIntent(lowerMessage);
      if (maliciousResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: maliciousResponse, timestamp: new Date() });
        return maliciousResponse;
      }
      
      const realWorldScenario = await this.realWorldVulnService.analyzeRealWorldScenarioWithLLM(message);
      if (realWorldScenario) {
        const response = await this.handleRealWorldScenario(sessionId, message, realWorldScenario);
        this.addToContext(sessionId, { role: 'assistant', content: response, timestamp: new Date() });
        return response;
      }

      if (this.isNonSecurityQuery(lowerMessage)) {
        const response = `I'm sorry I can't help with that\n I'm a security assistant focused on cybersecurity topics. I can help with:\n\n• Email and link safety\n• Phishing detection\n• File and attachment safety\n• Website legitimacy\n• Password security\n• CVE and vulnerability research\n\nDo you have any security questions I can help with?`;
        this.addToContext(sessionId, { role: 'assistant', content: response, timestamp: new Date() });
        return response;
      }

      const vagueQueryResponse = this.detectVagueSecurityQuery(lowerMessage);
      if (vagueQueryResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: vagueQueryResponse, timestamp: new Date() });
        return vagueQueryResponse;
      }

      const yesNoResponse = this.detectYesNoResponse(lowerMessage, sessionId);
      if (yesNoResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: yesNoResponse, timestamp: new Date() });
        return yesNoResponse;
      }

      const intent = this.detectSecurityIntent(lowerMessage);
      let response: string;

      switch (intent) {
        case 'cveSearch':
          response = await this.handleCVESearch(sessionId, message);
          break;
        case 'productVulnerability':
          response = await this.handleProductVulnerability(sessionId, message);
          break;
        case 'threatAnalysis':
          response = await this.handleThreatAnalysis(sessionId, message);
          break;
        case 'exploitedVulnerabilities':
          response = await this.handleExploitedVulnerabilities(sessionId);
          break;
        case 'recentVulnerabilities':
          response = await this.handleRecentVulnerabilities(sessionId);
          break;
        case 'dependencyScan':
          response = await this.handleDependencyScan(sessionId, message);
          break;
        case 'criticalAlerts':
          response = await this.handleCriticalAlerts(sessionId);
          break;
        case 'help':
          response = this.getHelpMessage();
          break;
        default:
          response = await this.handleGeneralSecurityQuery(sessionId, message);
      }

      this.addToContext(sessionId, { role: 'assistant', content: response, timestamp: new Date() });
      return response;
    } catch (error) {
      this.logger.error(`Error in chat: ${error}`);
      return `**Error:** Unable to process your request. Please try again later.`;
    }
  }

  private async handleCVESearch(sessionId: string, message: string): Promise<string> {
    // Extract CVE ID from message (e.g., CVE-2024-1234)
    const cveMatch = message.match(/CVE-\d{4}-\d{4,}/i);
    if (!cveMatch) {
      return `Please provide a CVE ID in the format CVE-YYYY-NNNN (e.g., CVE-2024-1234 or CVE-2023-44487)`;
    }

    const cveId = cveMatch[0].toUpperCase();
    this.logger.log(`Searching for CVE: ${cveId}`);
    
    const cveData = await this.vulnerabilityService.getCVEDetails(cveId);

    if (!cveData) {
      return `❌ **CVE Not Found**: No details found for **${cveId}** in the NVD database.\n\nThis could mean:\n• The CVE ID doesn't exist\n• It's a very recent CVE not yet in NVD\n• The format might be incorrect\n\nTry:\n• Searching for a product instead: "OpenSSL vulnerabilities"\n• Checking recent CVEs: "Recent vulnerabilities"\n• Or search for known exploited vulnerabilities: "Show exploited CVEs"`;
    }

    // Get recommendation from risk calculator
    const recommendation = this.riskCalculator.generateRecommendation(cveData);

    // Prepare structured data for LLM
    const vulnerabilityContext = JSON.stringify(
      {
        cveId: cveData.id,
        description: cveData.description,
        severity: cveData.metrics?.cvssV31Severity,
        cvssScore: cveData.metrics?.cvssV31Score,
        affected: cveData.affectedProducts?.slice(0, 5),
        isExploited: cveData.isExploited,
        recommendation: recommendation.recommendation,
        additionalSteps: recommendation.additionalSteps,
        nvdUrl: cveData.nvdUrl,
      },
      null,
      2,
    );

    // Get conversation history for context
    const history = this.getContextMessages(sessionId, 3);

    try {
      // Use LLM to generate natural response
      const response = await this.llmService.generateSecurityResponse(
        `Analyze this CVE in detail: ${cveId}`,
        vulnerabilityContext,
        history,
      );

      // Append reference links
      return response + `\n\n🔗 [View on NVD](${cveData.nvdUrl})`;
    } catch (error) {
      this.logger.error(`LLM generation failed, falling back to template: ${error}`);
      // Fallback to template response if LLM fails
      return this.generateCVETemplateResponse(cveId, cveData, recommendation);
    }
  }

  private generateCVETemplateResponse(
    cveId: string,
    cveData: any,
    recommendation: SecurityRecommendationDto,
  ): string {
    let response = `✅ **${cveId} Analysis**\n\n`;
    response += `**📋 Description:**\n${cveData.description || 'N/A'}\n\n`;
    
    if (cveData.metrics?.cvssV31Score) {
      response += `**⚠️ Severity:**\n`;
      response += `• CVSS v3.1 Score: ${cveData.metrics.cvssV31Score}/10\n`;
      response += `• Severity: **${cveData.metrics.cvssV31Severity}**\n\n`;
    }

    if (cveData.affectedProducts && cveData.affectedProducts.length > 0) {
      response += `**🎯 Affected Products:**\n`;
      cveData.affectedProducts.slice(0, 5).forEach((product) => {
        response += `• ${product}\n`;
      });
      if (cveData.affectedProducts.length > 5) {
        response += `• ... and ${cveData.affectedProducts.length - 5} more\n`;
      }
      response += '\n';
    }

    if (cveData.isExploited) {
      response += `🚨 **KNOWN EXPLOITED VULNERABILITY** - Active exploitation detected\n\n`;
    }

    if (cveData.references && cveData.references.length > 0) {
      response += `**🔗 References:**\n`;
      cveData.references.slice(0, 3).forEach((ref, idx) => {
        response += `${idx + 1}. [${ref.source || 'Link'}](${ref.url})\n`;
      });
      response += '\n';
    }

    response += `**💡 Recommendation:**\n${recommendation.recommendation}\n`;
    if (recommendation.additionalSteps && recommendation.additionalSteps.length > 0) {
      response += `\n**Additional Steps:**\n`;
      recommendation.additionalSteps.forEach((step) => {
        response += `• ${step}\n`;
      });
    }

    response += `\n🔗 [View on NVD](${cveData.nvdUrl})`;
    return response;
  }

  private getContextMessages(sessionId: string, count: number): ChatMessage[] {
  const session = this.conversationContext.get(sessionId);
  return session ? session.history.slice(-count) : [];
}

  private async handleProductVulnerability(sessionId: string, message: string): Promise<string> {
    // Extract product name - look for patterns like "product vulnerabilities" or "check product"
    const productMatch = message.match(/(?:for|in|product\s+|check\s+|analyze\s+|(?:find|get|list|show|search)\s+)?([a-zA-Z0-9\s._-]+?)(?:\s+(?:vulnerabilities|cves|vulns|bugs)|$)/i);
    
    if (!productMatch || !productMatch[1].trim()) {
      return `Please specify a product name (e.g., "OpenSSL vulnerabilities", "Apache CVEs", "Nginx vulnerabilities")`;
    }

    const productName = productMatch[1].trim();
    this.logger.log(`Searching for vulnerabilities in product: ${productName}`);
    
    const vulnerabilities = await this.vulnerabilityService.getVulnerableProducts(productName, 10);

    if (vulnerabilities.length === 0) {
      return `❌ **No vulnerabilities found** for product: **${productName}**\n\nThis could mean:\n• The product name might not be in the database\n• The spelling might be different\n• There are no known vulnerabilities for this product\n\nTry:\n• Using alternative product name: "OpenSSL" instead of "OpenSSL vulnerabilities"\n• Searching for similar products\n• Using the specific CVE ID if you know it`;
    }

    let response = `🔍 **Vulnerabilities for ${productName}**\n\n`;
    response += `Found: **${vulnerabilities.length}** vulnerabilities\n\n`;

    vulnerabilities.slice(0, 5).forEach((vuln) => {
      response += `**${vuln.id}** [${vuln.metrics?.cvssV31Severity || 'UNKNOWN'}]\n`;
      response += `• Score: ${vuln.metrics?.cvssV31Score || 'N/A'}/10\n`;
      if (vuln.affectedProducts && vuln.affectedProducts.length > 0) {
        response += `• Affected: ${vuln.affectedProducts[0]}\n`;
      }
      response += '\n';
    });

    const analysis = await this.vulnerabilityService.analyzeThreat(vulnerabilities);
    response += `**📊 Threat Analysis:**\n`;
    response += `• Threat Level: **${analysis.threatLevel.toUpperCase()}**\n`;
    response += `• Risk Score: ${analysis.riskScore}/100\n`;
    response += `• Exploitable CVEs: ${analysis.exploitableCount}\n\n`;

    response += `**🎯 Top Recommendations:**\n`;
    analysis.recommendations.slice(0, 3).forEach((rec) => {
      response += `• ${rec}\n`;
    });

    return response;
  }

  private async handleThreatAnalysis(sessionId: string, message: string): Promise<string> {
    // Get recent critical vulnerabilities for general threat analysis
    const criticalCves = await this.vulnerabilityService.getCriticalVulnerabilities(30);

    if (criticalCves.length === 0) {
      return `No critical vulnerabilities detected in the last 30 days.`;
    }

    const analysis = await this.vulnerabilityService.analyzeThreat(criticalCves.slice(0, 10));

    let response = `🛡️ **Threat Landscape Analysis (Last 30 Days)**\n\n`;
    response += `**📊 Overview:**\n`;
    response += `• Threat Level: **${analysis.threatLevel.toUpperCase()}**\n`;
    response += `• Aggregate Risk Score: ${analysis.riskScore}/100\n`;
    response += `• Critical CVEs Found: ${analysis.affectedCount}\n`;
    response += `• Known Exploited: ${analysis.exploitableCount}\n\n`;

    if (analysis.patterns.length > 0) {
      response += `**⚠️ Detected Patterns:**\n`;
      analysis.patterns.forEach((pattern) => {
        response += `• ${pattern}\n`;
      });
      response += '\n';
    }

    response += `**💡 Key Recommendations:**\n`;
    analysis.recommendations.slice(0, 5).forEach((rec) => {
      response += `• ${rec}\n`;
    });

    return response;
  }

  private async handleExploitedVulnerabilities(sessionId: string): Promise<string> {
    const exploitedCves = await this.vulnerabilityService.getKnownExploitedVulnerabilities(20);

    if (exploitedCves.length === 0) {
      return `No known exploited vulnerabilities currently tracked.`;
    }

    let response = `🚨 **Known Exploited Vulnerabilities**\n\n`;
    response += `Found: **${exploitedCves.length}** actively exploited CVEs\n\n`;

    const recommendations = await this.vulnerabilityService.getSecurityRecommendations(
      exploitedCves.slice(0, 5),
    );

    recommendations.forEach((rec, idx) => {
      response += `**${idx + 1}. ${rec.cveId}**\n`;
      response += `   Priority: **${rec.priority.toUpperCase()}**\n`;
      response += `   ${rec.recommendation}\n\n`;
    });

    response += `⚠️ **IMMEDIATE ACTION REQUIRED** - These vulnerabilities are actively being exploited`;

    return response;
  }

  private async handleRecentVulnerabilities(sessionId: string): Promise<string> {
    const recentCves = await this.vulnerabilityService.getRecentVulnerabilities(7, 15);

    if (recentCves.length === 0) {
      return `No new vulnerabilities published in the last 7 days.`;
    }

    let response = `📅 **Recent Vulnerabilities (Last 7 Days)**\n\n`;
    response += `Found: **${recentCves.length}** new CVEs\n\n`;

    const criticalCount = recentCves.filter((c) => c.metrics?.cvssV31Severity === 'CRITICAL').length;
    const highCount = recentCves.filter((c) => c.metrics?.cvssV31Severity === 'HIGH').length;

    response += `**📊 Breakdown:**\n`;
    response += `• Critical: ${criticalCount}\n`;
    response += `• High: ${highCount}\n`;
    response += `• Medium/Low: ${recentCves.length - criticalCount - highCount}\n\n`;

    response += `**Top Recent CVEs:**\n`;
    recentCves.slice(0, 5).forEach((cve) => {
      response += `• **${cve.id}** [${cve.metrics?.cvssV31Severity}] - ${cve.description?.substring(0, 80)}...\n`;
    });

    return response;
  }

  // private async showSeverity(severity: string){
  //   switch(severity.toUpperCase()) {
  //     case 'CRITICAL': return '🔴 **CRITICAL**';
  //     case 'HIGH':     return '🟠 **HIGH**';
  //     case 'MODERATE': return '🟡 **MODERATE**';
  //     case 'LOW':      return '🔵 **LOW**';
  //     default:         return '⚪ **UNKNOWN**';
  //   }
  // }
  private async handleDependencyScan(sessionId: string, message: string): Promise<string> {
    const regex = /scan\s+([a-zA-Z0-9\-_]+)\s+dependenc(?:y|ies):\s*(@?[a-zA-Z0-9\-_]+(?:\/[a-zA-Z0-9\-_]+)?)@([vV]?\d+\.\d+\.\d+[\w.-]*)/i;
    const match = message.match(regex);
    if (!match) {
      return `Please provide dependencies in the format: "Scan npm dependencies: express@4.17.1"`;
    }
    type Ecosystem = 'npm' | 'pip' | 'maven' | 'cargo' | 'composer' | 'nuget';
    const ecosystem = match[1].toLowerCase();
    const name = match[2];
    const version = match[3];
    const ECOSYSTEM_MAP: Record<string, Ecosystem> = {
    npm: 'npm', yarn: 'npm', pnpm: 'npm',
    pip: 'pip', pypi: 'pip', python: 'pip',
    maven: 'maven', gradle: 'maven',
    cargo: 'cargo', rust: 'cargo',
    composer: 'composer', packagist: 'composer',
    nuget: 'nuget', dotnet: 'nuget',
  };
    const target_ecosystem = ECOSYSTEM_MAP[ecosystem] || 'npm';
    try{
    const dependencyScan = await this.vulnerabilityService.analyzeDependencies([{name, version}], target_ecosystem);
    
    if (!dependencyScan || dependencyScan.length == 0){
      return `✅ No known vulnerabilities found for ${name}@${version} in ${target_ecosystem} ecosystem.`;
    }
    return `**Dependency Scan Results for ${name}@${version} (${target_ecosystem})**\n\n${dependencyScan}`
    }
    catch(error){
      return `Sorry, I ran into an error while scanning \`${name}@${version}\`. Please verify the package name and version exist.`;    
    }
  }

  private async handleCriticalAlerts(sessionId: string): Promise<string> {
    const criticalCves = await this.vulnerabilityService.getCriticalVulnerabilities(7);

    if (criticalCves.length === 0) {
      return `✅ No critical alerts from the past 7 days.`;
    }

    let response = `🚨 **CRITICAL SECURITY ALERTS**\n\n`;
    response += `⚠️ **${criticalCves.length}** Critical vulnerabilities detected\n\n`;

    criticalCves.slice(0, 3).forEach((cve) => {
      response += `**${cve.id}**\n`;
      response += `• Severity: **CRITICAL**\n`;
      response += `• Published: ${new Date(cve.publishedDate || '').toLocaleDateString()}\n`;
      if (cve.isExploited) {
        response += `• Status: 🔴 **ACTIVELY EXPLOITED**\n`;
      }
      response += '\n';
    });

    response += `**🎯 IMMEDIATE ACTIONS REQUIRED:**\n`;
    response += `1. Identify affected systems in your environment\n`;
    response += `2. Check vendor security advisories\n`;
    response += `3. Plan emergency patching if applicable\n`;
    response += `4. Implement compensating controls\n`;
    response += `5. Monitor for exploitation attempts`;

    return response;
  }

private async handleGeneralSecurityQuery(sessionId: string, message: string): Promise<string> {
  const history = this.getContextMessages(sessionId, 2);

  // 1. Detect direct CVE patterns (e.g., CVE-2024-1234)
  const cveMatch = message.match(/CVE-\d{4}-\d{4,7}/i);

  // 2. Narrow vulnerability intent check (exclude general terms like 'security' or 'risk')
  const isExplicitVulnQuery =
    !!cveMatch ||
    /\b(cve|cves|vulnerability|vulnerabilities|exploit|exploited|zero-day|advisory|patch)\b/i.test(message);

  let searchResults: CVEDto[] = [];
  let cveContext = '';

  // 3. Fetch CVE Context ONLY when explicitly relevant
  if (isExplicitVulnQuery) {
    try {
      // If user typed a direct CVE ID, query that specifically; otherwise use the query string
      const searchQuery = cveMatch ? cveMatch[0] : message;
      searchResults = await this.vulnerabilityService.searchVulnerabilities(searchQuery, 5);

      if (searchResults.length > 0) {
        cveContext = searchResults
          .map(
            (r) =>
              `• ${r.id} | Severity: ${r.metrics?.cvssV31Severity || 'UNKNOWN'} (Score: ${
                r.metrics?.cvssV31Score ?? 'N/A'
              })\n  Description: ${r.description?.substring(0, 160)}...`,
          )
          .join('\n\n');
      }
    } catch (err) {
      this.logger.warn(`Vulnerability search pre-fetch failed: ${err}`);
    }
  }

  // 4. Single Unified LLM Generation Flow
  if (this.llmService.isConfigured()) {
    try {
      let systemInstruction = 'Answer this general cybersecurity query with concise, actionable, and accurate technical guidance.';

      if (cveContext) {
        systemInstruction = `Use the following matching CVE records to inform your response. Summarize key risks, severity, and remediation steps:\n\n${cveContext}`;
      } else if (isExplicitVulnQuery) {
        systemInstruction = 'The user is asking about vulnerabilities, but no exact CVE records were found in the database. Provide general technical security advice for the requested product/topic.';
      }

      return await this.llmService.generateSecurityResponse(message, systemInstruction, history);
    } catch (error) {
      this.logger.error(`LLM response generation failed: ${error}`);
      // Fall through to fallback templates below
    }
  }

  // 5. Fallback Templates (When LLM is unconfigured or fails)
  if (searchResults.length > 0) {
    let response = `🔍 **Vulnerability Search Results**\n\n`;
    searchResults.forEach((r) => {
      const score = r.metrics?.cvssV31Score ? ` (${r.metrics.cvssV31Score})` : '';
      response += `• **${r.id}** [${r.metrics?.cvssV31Severity || 'UNKNOWN'}${score}]\n`;
      response += `  ${r.description?.substring(0, 120) || 'No description available'}...\n\n`;
    });
    response += `*Tip: Type a specific CVE ID for detailed analysis.*`;
    return response;
  }

  return (
    `I'm having trouble processing that query right now. Try one of these options:\n\n` +
    `• **Search a specific CVE:** "CVE-2024-21626"\n` +
    `• **Search software flaws:** "Log4j vulnerabilities"\n` +
    `• **Check security advisories:** "Recent CISA alerts"\n` +
    `• Type **"help"** for available commands.`
  );
}

  private getHelpMessage(): string {
    let help = `**🛡️ sirilens Security Assistant - Help Guide**\n\n`;
    
    help += `**📱 Real-World Security Questions (Non-Technical)**\n\n`;
    help += `Ask about everyday security concerns in plain language:\n\n`;
    
    help += `**1. Email Safety**\n`;
    help += `   Examples: "Should I trust this email?", "Is this email safe?", "Can I reply with my password?"\n`;
    help += `   I'll explain if the email looks suspicious and what to do.\n\n`;
    
    help += `**2. Phishing Detection**\n`;
    help += `   Examples: "Is this phishing?", "This email asks for my password usually how it's sent"\n`;
    help += `   I'll help you spot warning signs.\n\n`;
    
    help += `**3. Link Safety**\n`;
    help += `   Examples: "Is this link safe?", "Should I click this?", "Can I trust this URL?"\n`;
    help += `   I'll let you know if it seems suspicious.\n\n`;
    
    help += `**4. Attachment Safety**\n`;
    help += `   Examples: "Is it safe to open this file?", "Should I download this?"\n`;
    help += `   Tips on suspicious attachments.\n\n`;
    
    help += `**5. Website Trust**\n`;
    help += `   Examples: "Is this website legitimate?", "Should I buy from here?", "Is it a fake site?"\n`;
    help += `   I'll help you verify website legitimacy.\n\n`;
    
    help += `**6. Account Security**\n`;
    help += `   Examples: "My password was leaked, what should I do?", "I got a suspicious login alert"\n`;
    help += `   Practical steps to protect your account.\n\n`;
    
    help += `**7. Social Engineering**\n`;
    help += `   Examples: "Someone is asking weird questions about my job", "This message seems off"\n`;
    help += `   Learn to recognize manipulation attempts.\n\n`;
    
    help += `---\n\n`;
    help += `**🔍 Technical Vulnerability Queries**\n\n`;
    help += `Search for CVEs and technical vulnerabilities:\n\n`;
    
    help += `**1. Search CVE**\n`;
    help += `   Examples: "CVE-2024-1234", "Show details for CVE-2024-1234"\n`;
    help += `   Shows: Description, CVSS score, affected products, remediation\n\n`;
    
    help += `**2. Product Vulnerabilities**\n`;
    help += `   Examples: "OpenSSL vulnerabilities", "Apache CVEs", "Check MySQL"\n`;
    help += `   Shows: All CVEs for the product, threat analysis, recommendations\n\n`;
    
    help += `**3. Threat Analysis**\n`;
    help += `   Examples: "Analyze threats", "Threat landscape", "Current threats"\n`;
    help += `   Shows: Threat level, risk score, detected patterns\n\n`;
    
    help += `**4. Exploited Vulnerabilities**\n`;
    help += `   Examples: "Known exploited vulnerabilities", "Show actively exploited CVEs"\n`;
    help += `   Shows: CVEs with active exploitation, remediation priorities\n\n`;
    
    help += `**5. Recent CVEs**\n`;
    help += `   Examples: "Recent vulnerabilities", "New CVEs this week"\n`;
    help += `   Shows: Latest published vulnerabilities\n\n`;
    
    help += `**6. Critical Alerts**\n`;
    help += `   Examples: "Critical alerts", "Show critical vulnerabilities"\n`;
    help += `   Shows: Critical vulnerabilities from the last 7 days\n\n`;
    
    help += `**7. General Search**\n`;
    help += `   Just ask about any vulnerability or security topic\n\n`;
    
    help += `---\n\n`;
    help += `**💡 Tips:**\n`;
    help += `• For real-world questions, be as specific as possible (what does the email say?)\n`;
    help += `• For technical queries, mention product names or CVE IDs\n`;
    help += `• I'll explain everything in simple language you can understand\n\n`;
    
    help += `**Need specific help?** Ask your question and I'll assist!`;
    
    return help;
  }

  getHelp(): string {
    return this.getHelpMessage();
  }

private async handleRealWorldScenario(
    sessionId: string,
    message: string,
    scenario: RealWorldScenario,
  ): Promise<string> {
    this.logger.log(`Handling real-world scenario: ${scenario.type}`);

    // 1. Record incoming user message to session context upfront
    this.addToContext(sessionId, {
      role: 'user',
      content: message,
      timestamp: new Date(),
    });

    let finalResponse = '';

    try {
      // 2. Specialized Handler: Bare Email or Domain Validation (e.g. from Chrome extension)
      if (scenario.type === 'email_trust' && this.isBareEmailOrDomain(message)) {
        finalResponse = await this.handleEmailSenderValidation(message);
        this.addToContext(sessionId, {
          role: 'assistant',
          content: finalResponse,
          timestamp: new Date(),
        });
        return finalResponse;
      }

      // 3. Fetch CVE Context if scenario configuration requests it
      let cveContext = '';
      if (scenario.config.showCvesInSummary && scenario.relatedCVEs.length > 0) {
        cveContext = await this.buildCveContext(scenario.relatedCVEs);
      }

      // 4. Construct Prompt Context and Call LLM
      const userContext = this.buildUserPromptContext(message, scenario, cveContext);
      const history = this.getContextMessages(sessionId, 4);

      const llmResponse = await this.llmService.generateSimpleSecurityResponse(
        message,
        userContext,
        history,
        scenario.config.systemPromptRole,
      );

      // 5. Standardized Output Construction (Data-Driven Loop using Scenario Metadata)
      finalResponse = `${llmResponse}\n\n**${scenario.config.actionHeader}**\n`;

      const limit = scenario.config.maxRecommendations;
      scenario.recommendations.slice(0, limit).forEach((rec, idx) => {
        finalResponse += `${idx + 1}. ${rec}\n`;
      });

      // Append summary metadata if configured
      if (scenario.config.showCvesInSummary) {
        finalResponse += `\n**Summary:**\n`;
        finalResponse += `• Type of Issue: ${scenario.description}\n`;
        finalResponse += `• Risk Level: **${scenario.riskLevel.toUpperCase()}**\n`;
        if (scenario.relatedCVEs.length > 0) {
          finalResponse += `• Related Official CVEs: ${scenario.relatedCVEs.join(', ')}\n`;
        }
      }
    } catch (error) {
      this.logger.error(`Error handling scenario ${scenario.type}: ${error}`);
      finalResponse = this.buildFallbackResponse(scenario);
    }

    // 6. Append Follow-Up Suggestions
    const followUp = this.getFollowUpSuggestions(scenario.type);
    finalResponse += `\n\n**${followUp}**`;

    // 7. Save final assistant response to context before returning
    this.addToContext(sessionId, {
      role: 'assistant',
      content: finalResponse,
      timestamp: new Date(),
    });
    return finalResponse;
  }
  private async handleEmailSenderValidation(message: string): Promise<string> {
    const trimmedMessage = message.trim();
    let emailToCheck = trimmedMessage;

    if (!emailToCheck.includes('@')) {
      emailToCheck = `support@${emailToCheck}`;
    }

    this.logger.log(`Validating email sender: ${emailToCheck}`);
    const validation = await this.emailValidationService.validateEmailSender(emailToCheck);

    // Centralized Domain Check via DomainValidatorService
    const isLegitDomain = await this.DomainValidatorService.isLegitimateDomain(validation.domain);

    let response = '';

    if (isLegitDomain || validation.suspicionLevel === 'safe') {
      response = `✅ **Email Sender Appears Legitimate**\n\n`;
      response += `**Domain:** ${validation.domain}\n`;
      response += `**Valid Mail Server:** ${validation.hasMXRecords ? 'Yes ✓' : 'No ✗'}\n`;
      response += `**Email Authentication (SPF):** ${validation.hasSpfRecord ? 'Yes ✓' : 'No ✗'}\n`;
      response += `**Email Policy (DMARC):** ${validation.hasDmarcRecord ? 'Yes ✓' : 'No ✗'}\n\n`;
      response += `This email domain appears to be legitimate and properly configured for email. It's generally safe to trust emails from this sender, but always verify unexpected requests.`;
    } else if (validation.suspicionLevel === 'suspicious') {
      response = `⚠️ **Email Sender Shows Some Red Flags**\n\n`;
      response += `**Domain:** ${validation.domain}\n`;
      response += `**Concerns:**\n`;
      validation.reasons.forEach((reason) => {
        response += `• ${reason}\n`;
      });
      response += `\n**Recommendations:**\n`;
      validation.suggestions.forEach((suggestion) => {
        response += `• ${suggestion}\n`;
      });
    } else {
      response = `🚨 **Email Sender Appears Suspicious**\n\n`;
      response += `**Domain:** ${validation.domain}\n`;
      response += `**Red Flags:**\n`;
      validation.reasons.forEach((reason) => {
        response += `• ${reason}\n`;
      });
      response += `\n**What you should do:**\n`;
      response += `• Do NOT reply with personal information\n`;
      response += `• Do NOT click links in emails from this sender\n`;
      response += `• Contact the company directly using a phone number from their official website\n`;
      if (validation.suggestions.length > 0) {
        response += `\n**Additional Steps:**\n`;
        validation.suggestions.forEach((suggestion) => {
          response += `• ${suggestion}\n`;
        });
      }
    }

    const followUp = this.getFollowUpSuggestions('email_trust');
    return `${response}\n\n**${followUp}**`;
  }

  /**
   * Fetches CVE details for related CVE IDs and formats them into a prompt context string
   */
  private async buildCveContext(cveIds: string[]): Promise<string> {
    const cveDetails = await Promise.all(
      cveIds.map((cveId) =>
        this.vulnerabilityService.getCVEDetails(cveId).catch(() => null),
      ),
    );

    const validCves = cveDetails.filter((d) => d !== null);
    if (validCves.length === 0) return '';

    return validCves
      .map(
        (cve) =>
          `CVE: ${cve.id}\nSeverity: ${cve.metrics?.cvssV31Severity || 'Unknown'}\nScore: ${
            cve.metrics?.cvssV31Score || 'N/A'
          }/10\nDescription: ${cve.description?.substring(0, 200) || 'N/A'}`,
      )
      .join('\n\n');
  }

  /**
   * Formats user context string sent to the LLM
   */
  private buildUserPromptContext(
    message: string,
    scenario: RealWorldScenario,
    cveContext: string,
  ): string {
    return `
The user asked about: "${message}"

This relates to: ${scenario.description}

Warning signs to look for:
${scenario.indicators.map((ind) => `- ${ind}`).join('\n')}

Potential risks:
${scenario.relatedCVEs.map((cveId) => `- ${cveId}`).join('\n')}

Risk level: ${scenario.riskLevel}

What they should do:
${scenario.recommendations.map((rec) => `- ${rec}`).join('\n')}

${cveContext ? `Technical details (for reference):\n${cveContext}` : ''}
`;
  }

  /**
   * Fallback response builder if LLM generation fails
   */
  private buildFallbackResponse(scenario: RealWorldScenario): string {
    let response = `**${scenario.description}**\n\n**Watch out for:**\n`;
    scenario.indicators.slice(0, 3).forEach((ind) => {
      response += `• ${ind}\n`;
    });

    response += `\n**${scenario.config.actionHeader}**\n`;
    const limit = scenario.config.maxRecommendations;
    scenario.recommendations.slice(0, limit).forEach((rec, idx) => {
      response += `${idx + 1}. ${rec}\n`;
    });

    if (scenario.config.showCvesInSummary && scenario.relatedCVEs.length > 0) {
      response += `\n**More info:** Related to official CVEs: ${scenario.relatedCVEs.join(', ')}\n`;
    }

    return response;
  }

  /**
   * Checks if a message is a bare email address or domain string
   */
  private isBareEmailOrDomain(message: string): boolean {
    const clean = message.trim();
    return (
      /^[a-z0-9.-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean) ||
      (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean) && !clean.includes('/') && !clean.includes('http'))
    );
  }



private detectSecurityIntent(message: string): SecurityIntent {

  const cleanMessage = message.trim();
  const lowerMessage = cleanMessage.toLowerCase();

  // 1. Exact CVE Identifier Search (e.g., CVE-2024-1234, cve 2024 12345)
  if (/\bCVE-?\d{4}-?\d{4,7}\b/i.test(cleanMessage)) {
    this.logger.debug(`Detected CVE search intent: ${cleanMessage}`);
    return 'cveSearch';
  }

  // 2. System Commands / Help Request (Strict context to prevent "How can an attacker..." collisions)
  if (
    /^(help|\?|commands)$/i.test(cleanMessage) ||
    /\b(what can you do|how do i use this|show help|list commands|available options)\b/i.test(lowerMessage)
  ) {
    return 'help';
  }

  // 3. Dependency / Package File Scanning
  if (
    /\b(package\.json|requirements\.txt|pom\.xml|go\.mod|lockfile|npm audit)\b/i.test(lowerMessage) ||
    /\b(scan|check|analyze)\s+(dependencies|packages|npm|pip|maven|gemfile)\b/i.test(lowerMessage)
  ) {
    return 'dependencyScan';
  }

  // 4. Actively Exploited Vulnerabilities (CISA KEV Catalog)
  if (
    /\b(actively|known|active)\s+exploited\b/i.test(lowerMessage) ||
    /\b(cisa\s+kev|kev\s+catalog|known\s+exploits?)\b/i.test(lowerMessage)
  ) {
    return 'exploitedVulnerabilities';
  }

  // 5. Recent Vulnerabilities / New CVE Feed
  if (
    /\b(recent|latest|new|newest)\s+(cves?|vulnerabilities|exploits|flaws)\b/i.test(lowerMessage) ||
    /\b(cves?|vulnerabilities)\s+(from|added)\s+(recently|this\s+week|last\s+30\s+days)\b/i.test(lowerMessage)
  ) {
    return 'recentVulnerabilities';
  }

  // 6. Critical Security Alerts / Advisories
  if (
    /\b(critical\s+alerts?|cisa\s+alerts?|emergency\s+advisor(y|ies))\b/i.test(lowerMessage) ||
    /\b(top|latest)\s+critical\s+(cves?|vulnerabilities)\b/i.test(lowerMessage)
  ) {
    return 'criticalAlerts';
  }

  // 7. Threat Intelligence & Landscape Analysis
  if (
    /\bthreat\s+(analysis|landscape|level|assessment|model(ing)?|intel(ligence)?)\b/i.test(lowerMessage)
  ) {
    return 'threatAnalysis';
  }

  // 8. Targeted Software Product Lookup (e.g., "OpenSSL vulnerabilities", "CVEs in Apache")
  const hasProductQuery =
    /\b(cves?|vulnerabilities|flaws)\s+(in|for|affecting|on)\s+[a-z0-9_\-\.]+/i.test(lowerMessage) ||
    /^[a-z0-9_\-\.]+\s+(vulnerabilities|cves|vulns)$/i.test(lowerMessage);

  const isGenericContext = /\b(my|our|this|code|system|app|application|web|software)\b/i.test(lowerMessage);

  if (hasProductQuery && !isGenericContext) {
    return 'productVulnerability';
  }

  // 9. Catch-All for Conceptual, Technical, or General Questions
  return 'generalSearch';
}

private detectGreeting(message: string): string | null {
  // Normalize string and strip trailing punctuation (e.g., "hi!", "hello...")
  const cleanMessage = message.trim().replace(/[!.,?]+$/, '').toLowerCase();

  // Map user inputs to their corresponding mirrored response opener
  const greetingMap: Record<string, string> = {
    'hi': 'Hi there!',
    'hello': 'Hello!',
    'hey': 'Hey there!',
    'greetings': 'Greetings!',
    'yo': 'Yo!',
    'howdy': 'Howdy!',
    'good morning': 'Good morning!',
    'good afternoon': 'Good afternoon!',
    'good evening': 'Good evening!',
  };

  const matchedOpener = greetingMap[cleanMessage];

  if (!matchedOpener) {
    return null; // Return null if it's not a greeting so intent detection can take over
  }

  return `👋 **${matchedOpener} Welcome to sirilens Security Assistant!**

I'm here to help you with security questions. I can assist with:

**For everyday security concerns** (simple language):
- "Should I trust this email?"
- "Is this link safe to click?"
- "Is it safe to open this file?"
- "Should I buy from this website?"

**For technical security information**:
- "CVE-2024-1234" (search for CVE details)
- "OpenSSL vulnerabilities" (check product security)
- "Recent CVEs" (see latest vulnerabilities)

Type "help" for detailed information about all available commands, or just ask your question and I'll guide you!`;
}

private hasSecurityKeywords(message: string): boolean {
  // Regex with word boundaries (\b) prevents false substring matches like "cve" in "receive"
  const securityRegex =
    /\b(email|password|passwords|secure|security|hack|hacked|hacking|hacker|virus|viruses|malware|phishing|phish|link|links|url|urls|attachment|attachments|file|files|trust|trusted|cve|cves|vulnerability|vulnerabilities|vuln|vulns|attack|attacker|attacks|risk|risks|threat|threats|safe|safety|breach|breached|breaches|data|encrypt|encryption|decryption|firewall|auth|authentication|authorization|xss|sqli|csrf|exploit|exploits|patch|payload|ransomware|spyware|trojan|adware|zero-day|zeroday|cisa|nvd|owasp)\b/i;

  return securityRegex.test(message);
}

private isNonSecurityQuery(message: string): boolean {
  const cleanMessage = message.trim().toLowerCase();

  // 1. SECURITY OVERRIDE: If the query contains ANY security keywords, it is NEVER off-topic.
  // Example: "Is this pizza delivery email a scam?" -> Has 'email' -> Returns false (It IS a security query)
  if (this.hasSecurityKeywords(cleanMessage)) {
    return false;
  }

  // 2. Pure off-topic domains (Notice: generic question stems like "what is" or "definition" are removed)
  const offTopicRegex =
    /\b(shopping|buy|pizza|burger|food|restaurant|movie|movies|cinema|film|music|song|songs|game|games|gaming|sports|football|basketball|soccer|weather|temperature|forecast|travel|hotel|flight|recipe|cooking|cook|bake|dating|tinder|love|joke|jokes|riddle|capital\s+of|math|equation|calculate|calculator|solve|translate|translation)\b/i;

  if (offTopicRegex.test(cleanMessage)) {
    return true;
  }

  // 3. Short generic queries (< 10 chars) without security keywords default to false 
  // so they can be handled by general LLM or greeting/intent routing.
  return false;
}

private detectMaliciousIntent(message: string): string | null {
  const cleanMessage = message.trim();
  const lowerMessage = cleanMessage.toLowerCase();

  // 1. DEFENSIVE / VICTIM OVERRIDE
  // If the user is asking about detection, recovery, or self-defense, let it pass through to the LLM.
  const defensivePatterns = [
    /\bhow\s+(do|can)\s+i\s+(know|tell|check|find\s+out)\b/i,
    /\b(am\s+i|was\s+i|have\s+i\s+been|got)\s+(hacked|compromised|pwned|breached)\b/i,
    /\bhow\s+to\s+(protect|defend|secure|recover|fix|stop|prevent)\b/i,
    /\bsigns\s+of\s+(being\s+hacked|a\s+hack|compromise|malware)\b/i,
    /\bwhat\s+to\s+do\s+if\s+(i\s+get|i'm|i\s+was)\s+(hacked|compromised)\b/i,
  ];

  if (defensivePatterns.some((pattern) => pattern.test(lowerMessage))) {
    return null; // Safe: Pass to LLM / general query handler
  }

  // 2. ACTIVE ATTACKER INTENT DETECTION
  // Match explicit offensive phrasing (asking how to carry out an attack or generate malware)
  const offensivePatterns = [
    // Direct requests to attack someone/something: "how to hack wifi", "can you hack an instagram account"
    /\b(how\s+to|can\s+you|help\s+me)\s+(hack|crack|phish|ddos|dox|nuke|break\s+into)\b/i,

    // Specific attack actions against targets: "hack into a server", "exploit this website"
    /\b(hack|crack|break)\s+(into|a|an|the|someone|my\s+ex|my\s+friend|facebook|instagram|wifi|router|server|database)\b/i,

    // Credential cracking / Auth bypass
    /\b(crack|brute\s*force|bypass)\s+(password|passwords|hash|hashes|login|otp|2fa|mfa|authentication)\b/i,

    // Malware / Exploit payload creation
    /\b(write|create|build|generate|make)\s+(a\s+)?(exploit|payload|ransomware|keylogger|stealer|botnet|rootkit|trojan)\b/i,

    // Unauthorized escalation
    /\b(gain|get)\s+(unauthorized|illegal|admin|root)\s+access\b/i,
  ];

  for (const pattern of offensivePatterns) {
    if (pattern.test(lowerMessage)) {
      return (
        `I can't assist with requests to perform unauthorized access, hack systems, or develop malicious tools.\n\n` +
        `I'd be happy to help with defensive security instead, such as:\n` +
        `• How to harden systems and secure accounts\n` +
        `• How to identify if a device or account has been compromised\n` +
        `• Learning how common vulnerabilities work and how to fix them`
      );
    }
  }

  return null;
}

private detectVagueSecurityQuery(message: string): string | null {
  const cleanMessage = message.trim();
  const lowerMessage = cleanMessage.toLowerCase();
  const wordCount = cleanMessage.split(/\s+/).length;

  // 1. DETAIL GUARD: If the message is detailed (> 12 words or > 70 chars)
  // or contains specific entities (URLs, email addresses, domain names), it is NOT vague.
  const hasSpecifics =
    wordCount > 12 ||
    cleanMessage.length > 70 ||
    /https?:\/\/|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b[a-zA-Z0-9-]+\.(com|org|net|io|gov)\b/i.test(cleanMessage);

  if (hasSpecifics) {
    return null; // Let detailed queries pass through to the LLM or security handlers
  }

  // 2. ULTRA-SHORT "IS IT SAFE?" / "SHOULD I?" (Only check on short messages)
  if (/^(is\s+it\s+safe|is\s+this\s+safe)\??$/i.test(cleanMessage)) {
    return (
      `I'd be glad to check that for you! Could you share what you're asking about?\n\n` +
      `• An email, text message, or website link?\n` +
      `• A specific file or application download?\n\n` +
      `Paste the text, link, or details here and I'll analyze it.`
    );
  }

  if (/^(should\s+i\s+(click|open|trust|buy|pay|reply|download))\??$/i.test(cleanMessage) || /^\s*should\s+i\??\s*$/i.test(cleanMessage)) {
    return (
      `I can help you decide if it's safe! Could you provide a bit more context?\n\n` +
      `• What are you considering clicking, opening, or doing?\n` +
      `• Where did you receive or see it?\n\n` +
      `Sharing the message or link details helps me give you accurate advice.`
    );
  }

  // 3. VAGUE "SOMEONE SENT ME A MESSAGE" (Short queries without message body)
  if (/\b(someone|got\s+a)\s+(sent|contacted|messaged|message|email|text)\b/i.test(lowerMessage)) {
    return (
      `I can analyze that for you! To give you the best advice, could you tell me:\n\n` +
      `• What did the message say or ask you to do?\n` +
      `• Who sent it (or what email domain/number did it come from)?\n` +
      `• Did it include any links or attachments?\n\n` +
      `Paste the content here and I'll break down the risk.`
    );
  }

  return null;
}

private detectYesNoResponse(message: string, sessionId: string): string | null {
  const cleanMessage = message.trim().toLowerCase();

  const FOLLOW_UP_RESPONSES: Record<string, string> = {
    phishing: `**How to Report Phishing:**\n\n**To your email provider:**...`,
    email_trust: `**Email Legitimacy Checklist:**\n\n**Sender Information:**...`,
    link_safety: `**How to Safely Check Links:**\n\n**Before Clicking:**...`,
    attachment_safety: `**How to Safely Scan Files Before Opening:**...`,
    website_trust: `**How to Verify a Website is Real Before Shopping:**...`,
    social_engineering: `**Common Social Engineering Tactics to Watch For:**...`,
    password_breach: `**How to Check If Your Password Was Leaked:**...`,
    account_security: `**Password Security Checklist:**\n\n**Create Strong Passwords:**...`,
  };


  // 1. Broadened Yes/No Intent Detection
  const isYes = /^(yes|yeah|yep|sure|ok|okay|please|go ahead|do it|i do|i would|i want|i'd like|sure thing|yes please)\b/i.test(cleanMessage);
  const isNo = /^(no|nope|nah|not now|later|skip|no thanks|nah im good)\b/i.test(cleanMessage);

  if (!isYes && !isNo) {
    return null;
  }

  // 2. Retrieve state-driven pending action rather than regex-scraping text
  const session = this.conversationContext.get(sessionId);
  const pendingAction = session?.pendingFollowUpAction;

  if (!session || !pendingAction) {
    return null;
  }

  // Clear pending action once consumed
  session.pendingFollowUpAction = undefined;

  // 3. Handle Negative Response
  if (isNo) {
    return `No problem! Feel free to ask me anything else about security.`;
  }

  // 4. Return Pre-mapped Response
  return FOLLOW_UP_RESPONSES[pendingAction] || `Thanks for your interest! Feel free to ask any other security questions.`;
}

  private getFollowUpSuggestions(scenarioType: string): string {
    const suggestions: Record<string, string> = {
      phishing: '💡 Next: Would you like to know how to report this phishing attempt?',
      email_trust: '💡 Next: Want a checklist to verify if a company email is legitimate?',
      link_safety: '💡 Next: Would you like tips on how to safely check where a link actually goes?',
      attachment_safety: '💡 Next: Want to know how to safely scan files before opening them?',
      website_trust: '💡 Next: Would you like to know how to verify if a website is real before shopping?',
      social_engineering: '💡 Next: Want to learn common social engineering tactics to watch out for?',
      password_breach: '💡 Next: Would you like to know how to check if your password was leaked?',
      account_security: '💡 Next: Want a step-by-step password security checklist?',
    };

    return suggestions[scenarioType] || '💡 Next: Ask me anything about security and I\'ll help!';
  }

  resetConversation(sessionId: string): void {
    this.conversationContext.delete(sessionId);
    this.logger.log(`Conversation reset for session ${sessionId}`);
  }

private getOrCreateSession(sessionId: string): SessionData {
  let session = this.conversationContext.get(sessionId);
  if (!session) {
    session = { history: [] };
    this.conversationContext.set(sessionId, session);
  }
  return session;
}
private addToContext(sessionId: string, message: ChatMessage): void {
  const session = this.getOrCreateSession(sessionId);
  session.history.push(message);

  if (session.history.length > 20) {
    session.history.shift();
  }
}
}
