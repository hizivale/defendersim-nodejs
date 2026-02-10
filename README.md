# DefenderSim - AI-Powered Phishing Detection System

A comprehensive phishing email detection system combining 6 security frameworks with Ollama LLM (Llama 3.2:3b) for intelligent threat analysis.

## Architecture

**Frontend:** Vanilla JavaScript with modular design
**Backend:** Node.js with Express (MVC Pattern)
**Database:** MongoDB with Mongoose ODM
**AI/ML:** Ollama LLM (Llama 3.2:3b) with RAG
**Design Patterns:** MVC, Singleton (DB connection), Factory (Framework analyzers)

## Features

- **Multi-Framework Detection:** 6 security frameworks analyze each email independently
  - ML Classifier (Naive Bayes + TF-IDF)
  - OWASP Top 10
  - NIST Cybersecurity Framework
  - ISO/IEC 27001
  - Nessus Vulnerability Scanner
  - OpenVAS Security Scanner

- **AI-Powered Analysis:** Ollama LLM synthesizes framework results using RAG
- **Multilingual Support:** German, English, French
- **Comprehensive Dataset:** 60 emails with all classification types (TP, TN, FP, FN)
- **Real-time Email Sync:** Integration with Mailpit for live email analysis
- **Authentication:** JWT-based user authentication
- **Responsive Design:** Works on desktop, tablet, and mobile

## System Requirements

- Node.js 18+ and npm/pnpm
- MongoDB 6.0+
- Ollama with Llama 3.2:3b model
- Mailpit (for live email testing)

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/defendersim-nodejs.git
cd defendersim-nodejs
```

### 2. Install Dependencies

```bash
cd backend
npm install
```

### 3. Configure Environment

Create `.env` file in backend directory:

```env
# MongoDB
MONGODB_URI=mongodb://localhost:27017/defendersim

# Server
PORT=8000
NODE_ENV=development

# JWT
JWT_SECRET=your_secure_random_secret_here

# Ollama
OLLAMA_API_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b

# Mailpit
MAILPIT_API_URL=http://localhost:8025
```

### 4. Start Services

**Terminal 1 - MongoDB:**
```bash
mongod
```

**Terminal 2 - Ollama:**
```bash
ollama serve
ollama pull llama3.2:3b
```

**Terminal 3 - Mailpit:**
```bash
mailpit
```

**Terminal 4 - Backend:**
```bash
cd backend
npm run dev
```

### 5. Open Frontend

Open `frontend/index.html` in your browser or serve it:

```bash
cd frontend
python3 -m http.server 3000
# Visit http://localhost:3000
```

## Project Structure

```
defendersim-nodejs/
├── backend/
│   ├── models/              # Mongoose schemas
│   │   ├── Email.js
│   │   ├── Analysis.js
│   │   └── User.js
│   ├── controllers/         # Business logic
│   │   ├── emailController.js
│   │   ├── analysisController.js
│   │   └── authController.js
│   ├── routes/              # Express routes
│   │   ├── emailRoutes.js
│   │   ├── analysisRoutes.js
│   │   └── authRoutes.js
│   ├── services/            # External integrations
│   │   ├── mailpitService.js
│   │   ├── ollamaService.js
│   │   └── frameworkAnalyzer.js
│   ├── config/              # Configuration
│   │   └── database.js
│   ├── middleware/          # Express middleware
│   │   ├── auth.js
│   │   └── errorHandler.js
│   ├── server.js            # Entry point
│   ├── package.json
│   └── .env.example
│
├── frontend/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   ├── emailData.js     # 60-email dataset
│   │   ├── charts.js        # Chart.js visualizations
│   │   └── main.js          # Main application logic
│   └── index.html
│
└── README.md
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user

### Emails
- `GET /api/emails` - Get all emails
- `GET /api/emails/:id` - Get specific email
- `POST /api/emails/sync` - Sync from Mailpit
- `DELETE /api/emails/:id` - Delete email

### Analysis
- `POST /api/analysis/analyze/:emailId` - Analyze email
- `GET /api/analysis/:emailId` - Get analysis results
- `GET /api/analysis/stats` - Get detection statistics

## Dataset

### 60 Multilingual Emails

- **Languages:** German (24), English (24), French (12)
- **Risk Levels:** HIGH (38), MEDIUM (14), LOW (8)
- **Classifications:**
  - True Positive (TP): 45 emails - Phishing correctly identified
  - True Negative (TN): 9 emails - Legitimate correctly identified
  - False Positive (FP): 4 emails - Legitimate wrongly flagged
  - False Negative (FN): 2 emails - Phishing that slipped through

### Performance Metrics

- **Accuracy:** 93.3% (56/60 correct)
- **Precision:** 91.8% (45/49)
- **Recall:** 95.7% (45/47)
- **F1 Score:** 93.7%

## Design Patterns

### MVC (Model-View-Controller)
- **Models:** Mongoose schemas define data structure
- **Views:** Frontend HTML/CSS/JS
- **Controllers:** Business logic in controller files

### Singleton Pattern
- Database connection (`config/database.js`)
- Single instance shared across application

### Factory Pattern
- Framework analyzers (`services/frameworkAnalyzer.js`)
- Creates appropriate analyzer based on framework type

## Development

### Run Tests
```bash
cd backend
npm test
```

### Lint Code
```bash
npm run lint
```

### Format Code
```bash
npm run format
```

## Deployment

### Option 1: Railway.app (Recommended - Free)
1. Push code to GitHub
2. Connect repository to Railway
3. Add environment variables
4. Deploy automatically

### Option 2: Render.com (Free Tier)
1. Create Web Service for backend
2. Create PostgreSQL/MongoDB database
3. Deploy frontend to static site
4. Configure environment variables

### Option 3: Local Production
```bash
cd backend
npm run build
npm start
```

## Troubleshooting

### MongoDB Connection Error
```bash
# Check if MongoDB is running
mongosh
# If not, start it
mongod
```

### Ollama Not Responding
```bash
# Check Ollama status
ollama list
# Restart Ollama
ollama serve
```

### Mailpit Not Accessible
```bash
# Check if Mailpit is running on port 8025
curl http://localhost:8025/api/v1/messages
# Restart Mailpit
mailpit
```

## Contributing

This is a master thesis project. For questions or suggestions, please contact the author.

## License

MIT License - See LICENSE file for details

## Author

Master Thesis Project - Cybersecurity Program
DefenderSim: AI-Powered Phishing Detection System

## Acknowledgments

- Ollama team for LLM infrastructure
- Mailpit for email testing platform
- Open-source security frameworks (OWASP, NIST, ISO/IEC 27001)
