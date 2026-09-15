# sirilens 🛡️

**A Non-Technical Cybersecurity Vulnerability Chatbot**

sirilens is an AI-powered security assistant that helps everyday users understand and respond to real-world security threats without requiring technical expertise. Instead of using complex security terminology, sirilens explains vulnerabilities and threats in plain language with actionable advice.

## 🎯 What sirilens Does

sirilens specializes in two types of security questions:

### 1. **Real-World Security Concerns** (Non-Technical)
Users ask about everyday security situations in plain language:
- "Should I trust this email?"
- "Is this link safe to click?"
- "Is it safe to open this attachment?"
- "Should I buy from this website?"
- "This email looks suspicious - what do I do?"

sirilens analyzes these using intelligent LLM-based detection and responds with **specific red flags** and **immediate action steps**.

### 2. **Technical Vulnerability Research** (For Security Professionals)
- Search for CVEs and get detailed analysis
- Check product vulnerabilities
- Analyze threat landscapes
- Review exploited vulnerabilities
- Identify recently disclosed CVEs

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React/Vue)                      │
│                   http://localhost:5173                      │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP (CORS enabled)
┌────────────────────────▼────────────────────────────────────┐
│                   NestJS API Server                          │
│                   http://localhost:3000                      │
├─────────────────────────────────────────────────────────────┤
│                    ChatbotController                         │
│              POST /chat (main chat endpoint)                 │
│              GET /chat/help (help message)                   │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼─────┐  ┌──────▼──────┐  ┌────▼─────────┐
    │ RealWorld│  │Vulnerability│  │    LLM       │
    │Scenario  │  │   Service   │  │   Service    │
    │Detection │  │ (CVE Search)│  │(OpenRouter)  │
    └────┬─────┘  └──────┬──────┘  └────┬─────────┘
         │               │               │
    ┌────▼───────────────▼───────────────▼──────┐
    │        External API Integration Layer      │
    ├──────────────────────────────────────────  │
    │ • NVD (NIST Vulnerability Database)       │
    │ • GitHub Security Advisories API          │
    │ • CISA Known Exploited Vulnerabilities    │
    │ • OpenRouter LLM API (GPT-4 Turbo)        │
    └──────────────────────────────────────────┘
```

## 🔌 External APIs & Why We Use Them

### 1. **NIST Vulnerability Database (NVD)**
**URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`

**Why:**
- **Golden source for CVE data** - Official US government vulnerability database
- **Comprehensive coverage** - Contains all publicly disclosed CVEs with CVSS scores
- **Structured data** - Provides severity ratings, affected products, descriptions
- **Reliability** - Maintained by NIST, updated daily with new vulnerabilities
- **No authentication required** - Public REST API, easy integration

**What we use it for:**
- CVE ID lookups (e.g., "Tell me about CVE-2024-1234")
- Product vulnerability searches (e.g., "OpenSSL vulnerabilities")
- Risk assessment and CVSS scoring
- Affected product identification

### 2. **GitHub Security Advisories API**
**URL:** `https://api.github.com/graphql` + `https://api.github.com/advisories`

**Why:**
- **Real-time vulnerability tracking** - Catches vulnerabilities faster than NVD sometimes
- **Open source focus** - Essential for developers checking package/dependency security
- **Actionable information** - Includes patch versions and remediation guidance
- **Community-driven** - GitHub advisory data comes from multiple security research organizations
- **Dependency scanning** - Can search for specific packages (npm, pip, etc.)

**What we use it for:**
- Package/library vulnerability alerts
- Dependency scanning recommendations
- Patch version information
- Security advisory details for open source projects

### 3. **CISA Known Exploited Vulnerabilities (KEV) Catalog**
**URL:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**Why:**
- **Active threat intelligence** - Only includes vulnerabilities actively exploited in the wild
- **Priority guidance** - Tells users which vulnerabilities are actually being attacked NOW
- **Federal authority** - CISA (Cybersecurity & Infrastructure Security Agency) is the US government authority on cybersecurity threats
- **Practical value** - Users can focus patching efforts on real, active threats
- **Responsible disclosure focused** - Balances security information with public safety

**What we use it for:**
- Identifying actively exploited vulnerabilities
- Risk prioritization (active exploitation = higher priority)
- Threat analysis and critical alerts
- Real-world attack landscape understanding

### 4. **OpenRouter LLM API**
**models:** `gpt-4-turbo (primary), gpt-3.5-turbo (fallback)`

**Why:**
- **Multi-model access** - One API gateway for multiple LLMs without vendor lock-in
- **Cost-effective** - Better pricing than using OpenAI/Anthropic directly
- **Dual model strategy** - GPT-4 for complex phishing analysis, GPT-3.5 for fast general queries
- **Non-technical explanation** - LLMs excel at translating technical security concepts to plain language
- **Conversational context** - Maintains conversation history for follow-up questions
- **Phishing red flag analysis** - LLMs are excellent at pattern recognition in email text

**What we use it for:**
- Converting CVE data to plain language explanations
- Real-world scenario classification (is this phishing, email spoofing, etc.?)
- Phishing email analysis and red flag identification
- Session-aware context-aware responses

## 📊 How It Works - Request Flow

### Example 1: User Asks About a Suspicious Email

```
User Input:
"I received this email: From: security@paypal-alerts.com Subject: URGENT: Your account has been limited..."

1. ChatbotController receives the request
   ├─ Extract message + sessionId
   └─ Pass to ChatbotService

2. ChatbotService processes:
   ├─ NOT a greeting → continue
   ├─ Check for malicious intent (hacking requests) → NOT malicious
   ├─ RealWorldVulnerabilityService.analyzeRealWorldScenarioWithLLM()
   │  ├─ Quick keyword match: "verify", "account", "urgent" → phishing indicators
   │  ├─ Call OpenRouter GPT-4 with classification prompt
   │  └─ Returns: "phishing" scenario
   └─ Call handleRealWorldScenario() with phishing scenario

3. handleRealWorldScenario():
   ├─ Get CVE context (empty for phishing)
   ├─ Call LLM with SYSTEM PROMPT specially tuned for phishing:
   │  "Start by saying: 'This looks like a phishing email because...'"
   │  "List 2-3 specific red flags from the email..."
   │  "Explain why each is suspicious..."
   └─ LLM generates natural response

4. Response enhancement:
   ├─ Add immediate action steps
   ├─ Add follow-up suggestion ("Report this email? Here's how...")
   └─ Return to user via ChatbotController

User Output:
"This looks like a phishing email because:

1. **Fake sender domain** - The email is from 'security@paypal-alerts.com' 
   instead of PayPal's real domain...

2. **Urgent threats** - Says 'within 24 hours or account closes'...

3. **Suspicious link** - goes to 'paypal-verification.secure-login.com'..."
```

### Example 2: User Searches for a CVE

```
User Input:
"CVE-2024-1086"

1. ChatbotService.detectSecurityIntent() → returns "cveSearch"

2. handleCVESearch():
   ├─ Extract CVE ID from message
   ├─ Call VulnerabilityService.getCVEDetails("CVE-2024-1086")
   │  ├─ Query NVD API with caching (1-hour TTL)
   │  └─ Returns: severity, CVSS score, affected products, description
   ├─ Enhance with GitHub Advisory data (optional)
   ├─ Check CISA KEV catalog (actively exploited?)
   └─ Call LLM to explain in plain language

3. Response includes:
   ├─ Plain language explanation
   ├─ Severity and affected products
   ├─ Whether it's actively being exploited
   ├─ Mitigation recommendations
   └─ Link to NVD for technical details

User Output:
"CVE-2024-1086 is a serious vulnerability in Linux kernels...
[explanation with plain language]
This vulnerability IS being actively exploited in the wild...
[recommendations]"
```

## 🧠 Real-World Scenario Detection

sirilens uses a **two-layer detection system** for real-world security threats:

### Layer 1: Quick Keyword Matching (Fast Path)
```typescript
If message contains:
  - "verify" + "account" → phishing
  - "urgent" + "verify" → phishing
  - "unusual activity" → phishing
  - "email" + "safe" → email_trust
  - "link" + "click" → link_safety
  - "attachment" + "open" → attachment_safety
  ... etc

→ Immediately return scenario (no API call needed)
```

**Advantage:** Fast, no LLM latency

### Layer 2: LLM Classification (Intelligent Path)
When keyword matching doesn't match, use OpenRouter GPT-4 with a specialized prompt:

```
Classify this message as one of 8 scenarios:
- phishing: Suspicious/malicious emails with red flags
- email_trust: Asking if a legitimate email is real
- link_safety: Asking if a URL is safe
- attachment_safety: Asking if a file is safe
- website_trust: Asking if a website is legitimate
- social_engineering: Manipulation tactics/suspicious calls
- password_breach: Compromised password handling
- account_security: General account protection
```

**Advantage:** Handles variations and context. Understands that "should I click this link from PayPal?" is different from "is this link real?"

## 🔐 Session Management

- **SessionID:** Auto-generated UUID if not provided
- **TTL:** 30 minutes of inactivity
- **Purpose:** Maintains conversation context
  - User: "Should I trust this email?"
  - User (follow-up): "The sender is admin@mybank.com and says..."
  - sirilens remembers the initial question and provides contextualized response

## 🚀 Key Features

### ✅ Non-Technical Language
- **What we WON'T say:** "CVE-2023-46805 represents a CVSS 8.2 authentication bypass in the network layer..."
- **What we DO say:** "This is a serious security flaw that could let someone access your data. Here's what you should do..."

### ✅ Intelligence
- **LLM-powered** scenario detection understands variations
- **Keyword fallback** ensures fast responses even without LLM
- **Context-aware** using session history

### ✅ Actionable Advice
- Every response includes clear, immediate action steps
- No vague warnings
- Specific to the user's situation

### ✅ Privacy-Focused
- No data stored beyond 30-minute session
- No user login required
- Sessions identified by sessionId, not personal info

### ✅ Accurate Information
- Built on official sources (NVD, CISA, GitHub)
- LLM only for explanation, not for data
- Verified CVE information from government databases

## 🛠️ Technology Stack

- **Framework:** NestJS 11.0.1 (TypeScript)
- **LLM:** OpenRouter with GPT-4 Turbo + GPT-3.5 Turbo fallback
- **APIs:** 
  - NIST NVD (CVE database)
  - GitHub Security Advisories (open source vulnerabilities)
  - CISA KEV Catalog (active threats)
- **Session Management:** NodeCache (in-memory, 30-min TTL)
- **Documentation:** Swagger/OpenAPI 3.0
- **Response Format:** Markdown for frontend rendering

## 📖 Usage

### Setup

```bash
# Install dependencies
pnpm install

# Configure environment
# Create .env file with:
OPENROUTER_API_KEY=your_key_here
PORT=3000
CORS_ORIGIN=http://localhost:5173

# Build
pnpm build

# Run in development
pnpm start:dev

# View API docs
# Visit http://localhost:3000/api
```

### Basic Chat Request

```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "I received a suspicious email asking me to verify my PayPal account",
    "sessionId": "session-xyz-123",
    "context": "The sender email looks weird"
  }'
```

### Response

```json
{
  "sessionId": "session-xyz-123",
  "response": "This looks like a phishing email because:\n\n1. **Account verification scams**...\n\n⚠️ This is a serious threat..."
}
```

## 🔄 API Flow Optimization

| Operation | API Calls | Latency | Cost |
|-----------|-----------|---------|------|
| Real-world scenario (keyword match) | 0 | <50ms | Free |
| Real-world scenario (LLM classify) | 1 (OpenRouter) | 1-2s | Low |
| CVE search | 1-2 (NVD + optional GitHub) | 2-5s | Free |
| CVE with active threat check | +1 (CISA) | +100ms | Free |

**Caching:** 1-hour TTL on external API responses reduces redundant calls

## 🤔 Why These Specific Choices?

### Why NVD instead of custom database?
- ✅ Authoritative government source
- ✅ Updated daily with all new CVEs
- ✅ Free and open
- ✅ No maintenance burden (we don't need to scrape/update)

### Why OpenRouter instead of raw OpenAI?
- ✅ Cost 40% lower than OpenAI direct
- ✅ Can switch models without code changes
- ✅ Dual-model strategy (GPT-4 for intelligence, GPT-3.5 for speed)
- ✅ No vendor lock-in

### Why session-based instead of login-based?
- ✅ Lower friction (no account creation)
- ✅ Privacy-friendly (minimal user data)
- ✅ Perfect for casual security questions
- ✅ 30-min TTL is practical (most conversations complete in <5 min)

### Why LLM-based scenario detection?
- ✅ Handles natural language variations
- ✅ Understands context ("is this safe" could mean email/link/file)
- ✅ Catches evolving phishing tactics
- ✅ Can learn patterns from training data

## 📚 Additional Resources

- **API Documentation:** See [API.md](API.md)
- **Frontend Integration Guide:** See [FRONTEND_GUIDE.md](FRONTEND_GUIDE.md)
- **Documentation Index:** See [DOCUMENTATION.md](DOCUMENTATION.md)
- **Swagger UI:** http://localhost:3000/api (after running server)

## 🎯 Future Improvements

- Real-time phishing database integration
- Multi-language support
- Mobile app integration
- Advanced threat analytics
- User feedback loop to improve detection

## 📄 License

UNLICENSED

---

**sirilens** - Making cybersecurity accessible to everyone. 🛡️
