# DefenderSim - Technical Documentation

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Backend Implementation](#backend-implementation)
3. [Frontend Implementation](#frontend-implementation)
4. [Database Design](#database-design)
5. [AI/ML Integration](#aiml-integration)
6. [Security Frameworks](#security-frameworks)
7. [Deployment Guide](#deployment-guide)
8. [Testing Strategy](#testing-strategy)

---

## 1. System Architecture

### Overview

DefenderSim is a multi-layered phishing detection system that combines traditional security frameworks with modern AI/ML techniques.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend Layer                       │
│  (Vanilla JavaScript + HTML5 + CSS3 + Chart.js)            │
└────────────────────────┬────────────────────────────────────┘
                         │ REST API (JSON)
┌────────────────────────▼────────────────────────────────────┐
│                      Backend Layer                           │
│         (Node.js + Express + MVC Pattern)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Controllers  │  │   Routes     │  │  Middleware  │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │              │
│  ┌──────▼──────────────────▼──────────────────▼───────┐   │
│  │              Services Layer                         │   │
│  │  - Mailpit Service                                  │   │
│  │  - Ollama Service (LLM)                            │   │
│  │  - Framework Analyzer (Factory Pattern)            │   │
│  └────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────▼──────┐  ┌─────▼──────┐  ┌─────▼──────┐
│   MongoDB    │  │   Ollama   │  │  Mailpit   │
│  (Database)  │  │    LLM     │  │   (SMTP)   │
└──────────────┘  └────────────┘  └────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | Vanilla JavaScript | Client-side logic |
| Frontend | HTML5/CSS3 | UI structure and styling |
| Frontend | Chart.js | Data visualization |
| Backend | Node.js 18+ | Runtime environment |
| Backend | Express 4.x | Web framework |
| Database | MongoDB 6.0+ | Data persistence |
| Database | Mongoose 8.x | ODM (Object Data Modeling) |
| AI/ML | Ollama | LLM inference |
| AI/ML | Llama 3.2:3b | Language model |
| Email | Mailpit | SMTP testing server |
| Auth | JWT | Token-based authentication |

---

## 2. Backend Implementation

### 2.1 MVC Pattern

DefenderSim follows the Model-View-Controller pattern for clean separation of concerns.

#### Models (Data Layer)

**Email Model** (`models/Email.js`)
```javascript
const emailSchema = new mongoose.Schema({
  subject: String,
  from: String,
  to: String,
  body: String,
  headers: Object,
  receivedAt: Date,
  mailpitId: String
});
```

**Analysis Model** (`models/Analysis.js`)
```javascript
const analysisSchema = new mongoose.Schema({
  emailId: { type: mongoose.Schema.Types.ObjectId, ref: 'Email' },
  riskLevel: { type: String, enum: ['HIGH', 'MEDIUM', 'LOW'] },
  confidence: Number,
  frameworks: {
    mlClassifier: Object,
    owasp: Object,
    nist: Object,
    iso27001: Object,
    nessus: Object,
    openvas: Object
  },
  ollamaAnalysis: Object,
  analyzedAt: Date
});
```

**User Model** (`models/User.js`)
```javascript
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'analyst'], default: 'analyst' },
  createdAt: { type: Date, default: Date.now }
});
```

#### Controllers (Business Logic)

**Email Controller** (`controllers/emailController.js`)
- `syncFromMailpit()` - Fetches emails from Mailpit API
- `getAllEmails()` - Retrieves all emails from database
- `getEmailById()` - Retrieves specific email
- `deleteEmail()` - Removes email from database

**Analysis Controller** (`controllers/analysisController.js`)
- `analyzeEmail()` - Runs all 6 frameworks + Ollama analysis
- `getAnalysis()` - Retrieves analysis results
- `getStatistics()` - Calculates detection metrics

**Auth Controller** (`controllers/authController.js`)
- `register()` - Creates new user account
- `login()` - Authenticates user and issues JWT
- `getCurrentUser()` - Returns authenticated user info

#### Routes (API Endpoints)

**Email Routes** (`routes/emailRoutes.js`)
```javascript
router.get('/emails', emailController.getAllEmails);
router.get('/emails/:id', emailController.getEmailById);
router.post('/emails/sync', emailController.syncFromMailpit);
router.delete('/emails/:id', emailController.deleteEmail);
```

**Analysis Routes** (`routes/analysisRoutes.js`)
```javascript
router.post('/analysis/analyze/:emailId', analysisController.analyzeEmail);
router.get('/analysis/:emailId', analysisController.getAnalysis);
router.get('/analysis/stats', analysisController.getStatistics);
```

**Auth Routes** (`routes/authRoutes.js`)
```javascript
router.post('/auth/register', authController.register);
router.post('/auth/login', authController.login);
router.get('/auth/me', authMiddleware, authController.getCurrentUser);
```

### 2.2 Services Layer

#### Mailpit Service (`services/mailpitService.js`)

Integrates with Mailpit API to fetch emails for analysis.

**Key Methods:**
- `fetchMessages()` - Retrieves all messages from Mailpit
- `getMessageById(id)` - Fetches specific message
- `parseEmail(mailpitMessage)` - Converts Mailpit format to internal format

**Implementation:**
```javascript
async function fetchMessages() {
  const response = await axios.get(`${MAILPIT_API_URL}/api/v1/messages`);
  return response.data.messages;
}
```

#### Ollama Service (`services/ollamaService.js`)

Integrates with Ollama LLM for AI-powered analysis.

**Key Methods:**
- `analyzeEmail(emailData, frameworkResults)` - Sends data to LLM
- `generatePrompt(emailData, frameworkResults)` - Creates RAG prompt
- `parseResponse(ollamaResponse)` - Extracts structured data

**RAG Prompt Structure:**
```javascript
const prompt = `
You are a cybersecurity analyst specializing in phishing detection.

Email Details:
Subject: ${emailData.subject}
From: ${emailData.from}
Body: ${emailData.body}

Framework Analysis Results:
${JSON.stringify(frameworkResults, null, 2)}

Based on the framework analysis, provide:
1. Summary (2-3 sentences)
2. Reasoning (detailed explanation)
3. Recommendations (actionable steps)
`;
```

#### Framework Analyzer (`services/frameworkAnalyzer.js`)

Implements Factory Pattern to create appropriate analyzers.

**Supported Frameworks:**
1. **ML Classifier** - Naive Bayes + TF-IDF text analysis
2. **OWASP** - Web application security vulnerabilities
3. **NIST CSF** - Authentication and sender reputation
4. **ISO/IEC 27001** - Information security standards
5. **Nessus** - Enterprise vulnerability scanning
6. **OpenVAS** - Open-source security assessment

**Factory Pattern Implementation:**
```javascript
class FrameworkAnalyzerFactory {
  static createAnalyzer(frameworkName) {
    switch (frameworkName) {
      case 'mlClassifier':
        return new MLClassifierAnalyzer();
      case 'owasp':
        return new OWASPAnalyzer();
      case 'nist':
        return new NISTAnalyzer();
      case 'iso27001':
        return new ISO27001Analyzer();
      case 'nessus':
        return new NessusAnalyzer();
      case 'openvas':
        return new OpenVASAnalyzer();
      default:
        throw new Error(`Unknown framework: ${frameworkName}`);
    }
  }
}
```

### 2.3 Middleware

#### Authentication Middleware (`middleware/auth.js`)

Verifies JWT tokens and attaches user to request.

```javascript
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}
```

#### Error Handler (`middleware/errorHandler.js`)

Centralized error handling for consistent API responses.

```javascript
function errorHandler(err, req, res, next) {
  console.error(err.stack);
  
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
}
```

### 2.4 Database Configuration

#### Singleton Pattern (`config/database.js`)

Ensures single MongoDB connection instance across application.

```javascript
class Database {
  constructor() {
    if (Database.instance) {
      return Database.instance;
    }
    
    this.connection = null;
    Database.instance = this;
  }
  
  async connect() {
    if (this.connection) {
      return this.connection;
    }
    
    this.connection = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    return this.connection;
  }
}

module.exports = new Database();
```

---

## 3. Frontend Implementation

### 3.1 Architecture

The frontend is built with Vanilla JavaScript following modular design principles.

**File Structure:**
```
frontend/
├── index.html          # Main HTML structure
├── css/
│   └── styles.css      # Responsive styling
└── js/
    ├── emailData.js    # 60-email dataset
    ├── charts.js       # Chart.js visualizations
    └── main.js         # Application logic
```

### 3.2 Email Dataset (`js/emailData.js`)

Contains 60 pre-analyzed emails with complete framework and LLM analysis.

**Data Structure:**
```javascript
{
  id: 1,
  subject: "Email subject",
  from: "sender@example.com",
  language: "de|en|fr",
  riskLevel: "HIGH|MEDIUM|LOW",
  classification: "TP|TN|FP|FN",
  body: "Email body text",
  authentication: {
    dmarc: "pass|fail|unknown",
    spf: "pass|fail|unknown",
    dkim: "pass|fail|unknown"
  },
  frameworks: {
    mlClassifier: { score: 95, patterns: [...], evidence: [...] },
    owasp: { score: 88, patterns: [...], evidence: [...] },
    nist: { score: 92, patterns: [...], evidence: [...] },
    iso27001: { score: 90, patterns: [...], evidence: [...] },
    nessus: { score: 87, patterns: [...], evidence: [...] },
    openvas: { score: 89, patterns: [...], evidence: [...] }
  },
  ollama: {
    summary: "Brief analysis summary",
    reasoning: "Detailed reasoning",
    recommendations: ["Action 1", "Action 2"]
  }
}
```

### 3.3 Visualization (`js/charts.js`)

Uses Chart.js for data visualization.

**Accuracy Chart (Doughnut):**
- Shows distribution of TP, TN, FP, FN
- Color-coded for easy interpretation
- Interactive tooltips with percentages

**Framework Comparison (Bar Chart):**
- Displays average detection scores
- Each framework has unique color
- Y-axis shows percentage (0-100%)

### 3.4 Application Logic (`js/main.js`)

**Key Functions:**

1. **renderEmails(emails)** - Renders email cards to grid
2. **filterEmails(emails, filter)** - Filters by risk level or language
3. **showEmailDetails(email)** - Displays full analysis in modal
4. **calculateAverageScore(frameworks)** - Computes average framework score

**Event Handling:**
- Filter button clicks
- Email card clicks
- Modal open/close
- Keyboard shortcuts (Escape to close modal)

### 3.5 Responsive Design

**Breakpoints:**
- Desktop: 1400px+ (4-column grid)
- Tablet: 769-1024px (2-column grid)
- Mobile: <768px (1-column grid)

**Mobile Optimizations:**
- Stacked workflow diagram
- Larger tap targets (44px minimum)
- Optimized modal height for landscape
- Simplified statistics grid

---

## 4. Database Design

### 4.1 Schema Design

**Collections:**

1. **emails** - Stores raw email data
2. **analyses** - Stores detection results
3. **users** - Stores user accounts

**Relationships:**
- One-to-One: Email ↔ Analysis
- One-to-Many: User ↔ Analyses (analyst who ran analysis)

### 4.2 Indexing Strategy

```javascript
// Email indexes
emailSchema.index({ mailpitId: 1 }, { unique: true });
emailSchema.index({ receivedAt: -1 });
emailSchema.index({ from: 1 });

// Analysis indexes
analysisSchema.index({ emailId: 1 });
analysisSchema.index({ riskLevel: 1 });
analysisSchema.index({ analyzedAt: -1 });

// User indexes
userSchema.index({ email: 1 }, { unique: true });
```

### 4.3 Data Validation

Mongoose schemas enforce data validation:

```javascript
// Email validation
subject: { type: String, required: true, maxlength: 500 },
from: { type: String, required: true, match: /^.+@.+\..+$/ },
body: { type: String, required: true }

// Analysis validation
riskLevel: { type: String, enum: ['HIGH', 'MEDIUM', 'LOW'], required: true },
confidence: { type: Number, min: 0, max: 100, required: true }
```

---

## 5. AI/ML Integration

### 5.1 Ollama LLM Architecture

**Model:** Llama 3.2:3b
**Purpose:** Synthesize framework results into human-readable analysis
**Technique:** RAG (Retrieval-Augmented Generation)

### 5.2 RAG Implementation

**Prompt Engineering:**

1. **Context Injection** - Email details and framework scores
2. **Task Definition** - Clear instructions for analysis format
3. **Output Structure** - Defined JSON schema for parsing

**Example Prompt:**
```
You are a cybersecurity analyst specializing in phishing detection.

Analyze this email based on the framework results below.

Email:
- Subject: [subject]
- From: [from]
- Body: [body]

Framework Scores:
- ML Classifier: 95% (patterns: urgency, suspicious URL)
- OWASP: 88% (malicious redirect)
- NIST: 92% (DMARC failed)
- ISO 27001: 90% (sensitive data request)
- Nessus: 87% (known phishing domain)
- OpenVAS: 89% (zero-day indicators)

Provide:
1. Summary (2-3 sentences)
2. Reasoning (detailed explanation)
3. Recommendations (3-5 actionable steps)
```

### 5.3 ML Classifier Details

**Algorithm:** Naive Bayes
**Feature Extraction:** TF-IDF (Term Frequency-Inverse Document Frequency)

**Training Data:**
- Phishing emails from PhishTank database
- Legitimate emails from Enron dataset
- Custom-labeled multilingual samples

**Features:**
- Urgency keywords (dringend, urgent, immediately)
- Suspicious URLs (shortened links, non-HTTPS)
- Grammar errors and typos
- Sender domain mismatch
- Request for sensitive information

**Implementation:**
```javascript
class MLClassifierAnalyzer {
  analyze(email) {
    const features = this.extractFeatures(email);
    const score = this.calculateProbability(features);
    const patterns = this.identifyPatterns(features);
    
    return {
      score,
      patterns,
      evidence: this.generateEvidence(features)
    };
  }
  
  extractFeatures(email) {
    return {
      urgencyKeywords: this.findUrgencyKeywords(email.body),
      suspiciousURLs: this.detectSuspiciousURLs(email.body),
      grammarErrors: this.countGrammarErrors(email.body),
      domainMismatch: this.checkDomainMismatch(email.from, email.body)
    };
  }
}
```

---

## 6. Security Frameworks

### 6.1 Framework Descriptions

#### ML Classifier
- **Purpose:** Text-based phishing detection
- **Method:** Naive Bayes with TF-IDF
- **Indicators:** Urgency keywords, suspicious URLs, grammar errors

#### OWASP Top 10
- **Purpose:** Web application security vulnerabilities
- **Method:** URL analysis, script injection detection
- **Indicators:** SQL injection, XSS, malicious redirects

#### NIST Cybersecurity Framework
- **Purpose:** Authentication and sender validation
- **Method:** DMARC/SPF/DKIM verification
- **Indicators:** Failed authentication, domain spoofing

#### ISO/IEC 27001
- **Purpose:** Information security management
- **Method:** Policy compliance checking
- **Indicators:** Sensitive data requests, encryption violations

#### Nessus
- **Purpose:** Enterprise vulnerability scanning
- **Method:** Signature-based detection
- **Indicators:** Known malware, exploit kits

#### OpenVAS
- **Purpose:** Open-source security assessment
- **Method:** Comprehensive vulnerability testing
- **Indicators:** Zero-day threats, suspicious file types

### 6.2 Scoring Algorithm

Each framework returns a score (0-100):
- **0-30:** Low risk (likely legitimate)
- **31-70:** Medium risk (requires review)
- **71-100:** High risk (likely phishing)

**Final Risk Level Determination:**
```javascript
function determineRiskLevel(frameworkScores) {
  const average = calculateAverage(frameworkScores);
  const highScoreCount = frameworkScores.filter(s => s > 70).length;
  
  if (average > 75 || highScoreCount >= 4) {
    return 'HIGH';
  } else if (average > 40 || highScoreCount >= 2) {
    return 'MEDIUM';
  } else {
    return 'LOW';
  }
}
```

---

## 7. Deployment Guide

### 7.1 Local Development

**Prerequisites:**
- Node.js 18+
- MongoDB 6.0+
- Ollama with Llama 3.2:3b
- Mailpit

**Steps:**
1. Install dependencies: `npm install`
2. Configure `.env` file
3. Start MongoDB: `mongod`
4. Start Ollama: `ollama serve`
5. Start Mailpit: `mailpit`
6. Start backend: `npm run dev`
7. Open frontend: `http://localhost:3000`

### 7.2 Production Deployment (Railway.app)

**Steps:**

1. **Prepare Repository:**
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/defendersim-nodejs.git
git push -u origin main
```

2. **Deploy to Railway:**
- Sign up at https://railway.app
- Click "New Project" → "Deploy from GitHub"
- Select `defendersim-nodejs` repository
- Railway auto-detects Node.js and deploys

3. **Add MongoDB:**
- Click "New" → "Database" → "Add MongoDB"
- Railway provides connection string automatically

4. **Configure Environment Variables:**
```
MONGODB_URI=<railway_mongodb_url>
JWT_SECRET=<generate_secure_random_string>
OLLAMA_API_URL=<external_ollama_url>
PORT=8000
```

5. **Deploy Frontend:**
- Use Railway static site or Netlify
- Update API URL in frontend code

### 7.3 Alternative: Render.com

**Backend:**
1. Create Web Service
2. Connect GitHub repository
3. Build command: `cd backend && npm install`
4. Start command: `npm start`
5. Add environment variables

**Database:**
1. Create MongoDB instance
2. Copy connection string to backend env

**Frontend:**
1. Create Static Site
2. Publish directory: `frontend`
3. Deploy

---

## 8. Testing Strategy

### 8.1 Unit Tests

**Backend Tests:**
```javascript
// Example: Email Controller Test
describe('Email Controller', () => {
  it('should sync emails from Mailpit', async () => {
    const result = await emailController.syncFromMailpit();
    expect(result.success).toBe(true);
    expect(result.count).toBeGreaterThan(0);
  });
  
  it('should retrieve email by ID', async () => {
    const email = await emailController.getEmailById('123');
    expect(email).toBeDefined();
    expect(email.subject).toBeDefined();
  });
});
```

**Framework Tests:**
```javascript
describe('ML Classifier', () => {
  it('should detect phishing keywords', () => {
    const email = { body: 'URGENT: Verify your account immediately!' };
    const result = mlClassifier.analyze(email);
    expect(result.score).toBeGreaterThan(70);
    expect(result.patterns).toContain('Urgency keyword: urgent');
  });
});
```

### 8.2 Integration Tests

**API Endpoint Tests:**
```javascript
describe('Analysis API', () => {
  it('should analyze email and return results', async () => {
    const response = await request(app)
      .post('/api/analysis/analyze/123')
      .set('Authorization', `Bearer ${token}`);
    
    expect(response.status).toBe(200);
    expect(response.body.riskLevel).toBeDefined();
    expect(response.body.frameworks).toBeDefined();
  });
});
```

### 8.3 Performance Tests

**Load Testing:**
- Test with 100 concurrent email analyses
- Measure response time (target: <2s per email)
- Monitor memory usage and CPU load

**Database Performance:**
- Index effectiveness
- Query optimization
- Connection pooling

---

## Conclusion

This technical documentation provides a comprehensive overview of DefenderSim's architecture, implementation details, and deployment strategies. The system successfully combines traditional security frameworks with modern AI/ML techniques to create an effective phishing detection solution.

For questions or clarifications, please refer to the README.md or contact the project author.
