# DefenderSim Deployment Guide

This guide provides step-by-step instructions for deploying DefenderSim in various environments.

## Table of Contents

1. [Local Development Setup](#local-development-setup)
2. [Free Cloud Deployment (Railway.app)](#free-cloud-deployment-railwayapp)
3. [Alternative Deployment (Render.com)](#alternative-deployment-rendercom)
4. [Netlify Frontend Deployment](#netlify-frontend-deployment)
5. [Environment Variables](#environment-variables)
6. [Troubleshooting](#troubleshooting)

---

## 1. Local Development Setup

### Prerequisites

Before starting, ensure you have:

- **Node.js 18+** - [Download](https://nodejs.org/)
- **MongoDB 6.0+** - [Download](https://www.mongodb.com/try/download/community)
- **Ollama** - [Download](https://ollama.ai/)
- **Mailpit** - [Download](https://github.com/axllent/mailpit)
- **Git** - [Download](https://git-scm.com/)

### Step 1: Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/defendersim-nodejs.git
cd defendersim-nodejs
```

### Step 2: Install Backend Dependencies

```bash
cd backend
npm install
```

### Step 3: Configure Environment Variables

Create `.env` file in `backend/` directory:

```env
# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/defendersim

# Server Configuration
PORT=8000
NODE_ENV=development

# JWT Secret (generate with: openssl rand -base64 32)
JWT_SECRET=your_secure_random_secret_here_replace_this

# Ollama Configuration
OLLAMA_API_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b

# Mailpit Configuration
MAILPIT_API_URL=http://localhost:8025
```

### Step 4: Start MongoDB

**macOS (Homebrew):**
```bash
brew services start mongodb-community
```

**Linux:**
```bash
sudo systemctl start mongod
```

**Windows:**
```bash
net start MongoDB
```

**Verify MongoDB is running:**
```bash
mongosh
# Should connect successfully
```

### Step 5: Start Ollama

**Terminal 1:**
```bash
ollama serve
```

**Terminal 2 (pull model):**
```bash
ollama pull llama3.2:3b
```

**Verify Ollama:**
```bash
curl http://localhost:11434/api/tags
```

### Step 6: Start Mailpit

**Terminal 3:**
```bash
mailpit
```

**Access Mailpit UI:**
- Open browser: http://localhost:8025

### Step 7: Start Backend Server

**Terminal 4:**
```bash
cd backend
npm run dev
```

**Expected output:**
```
Server running on port 8000
MongoDB connected successfully
Ollama connection verified
```

### Step 8: Serve Frontend

**Terminal 5:**
```bash
cd frontend
python3 -m http.server 3000
# Or use: npx serve -p 3000
```

**Access Application:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- Mailpit UI: http://localhost:8025

---

## 2. Free Cloud Deployment (Railway.app)

Railway.app offers $5/month free credit, perfect for small projects.

### Step 1: Prepare Code for Deployment

**Update `backend/package.json`:**
```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

**Create `backend/Procfile`:**
```
web: node server.js
```

### Step 2: Push to GitHub

```bash
git add .
git commit -m "Prepare for Railway deployment"
git push origin main
```

### Step 3: Deploy to Railway

1. **Sign Up:**
   - Go to https://railway.app
   - Click "Login with GitHub"
   - Authorize Railway

2. **Create New Project:**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose `defendersim-nodejs`
   - Railway auto-detects Node.js

3. **Add MongoDB:**
   - Click "New" → "Database" → "Add MongoDB"
   - Railway provides connection string automatically
   - Copy `MONGODB_URI` from variables tab

4. **Configure Environment Variables:**
   - Go to project → Variables
   - Add:
     ```
     MONGODB_URI=<from_railway_mongodb>
     JWT_SECRET=<generate_secure_random>
     PORT=8000
     NODE_ENV=production
     ```

5. **Deploy:**
   - Railway automatically deploys
   - Get public URL from "Settings" → "Domains"
   - Example: `https://defendersim-production.up.railway.app`

### Step 4: Deploy Frontend to Netlify

See [Netlify Frontend Deployment](#netlify-frontend-deployment) section below.

---

## 3. Alternative Deployment (Render.com)

Render.com offers free tier with automatic SSL.

### Step 1: Create Web Service

1. **Sign Up:**
   - Go to https://render.com
   - Sign in with GitHub

2. **New Web Service:**
   - Click "New +" → "Web Service"
   - Connect GitHub repository
   - Select `defendersim-nodejs`

3. **Configure Service:**
   ```
   Name: defendersim-backend
   Environment: Node
   Build Command: cd backend && npm install
   Start Command: cd backend && npm start
   ```

4. **Select Plan:**
   - Choose "Free" tier
   - Note: Service sleeps after 15 min inactivity

### Step 2: Add Database

1. **Create MongoDB:**
   - Click "New +" → "PostgreSQL" (or use MongoDB Atlas free tier)
   - For MongoDB Atlas:
     - Go to https://www.mongodb.com/cloud/atlas
     - Create free M0 cluster
     - Get connection string

2. **Add Environment Variables:**
   ```
   MONGODB_URI=<mongodb_atlas_connection_string>
   JWT_SECRET=<secure_random_string>
   OLLAMA_API_URL=<external_ollama_url>
   PORT=8000
   NODE_ENV=production
   ```

### Step 3: Deploy

- Render automatically builds and deploys
- Get URL: `https://defendersim-backend.onrender.com`

**Note:** Free tier limitations:
- Service sleeps after 15 minutes
- Cold start takes ~30 seconds
- 750 hours/month free

---

## 4. Netlify Frontend Deployment

Deploy static frontend to Netlify for free hosting.

### Step 1: Prepare Frontend

**Update API URL in `frontend/js/main.js`:**
```javascript
const API_URL = 'https://your-backend-url.railway.app';
// Or use environment variable
const API_URL = process.env.API_URL || 'http://localhost:8000';
```

### Step 2: Deploy to Netlify

**Option A: Drag and Drop**

1. Go to https://app.netlify.com
2. Sign up with GitHub
3. Drag `frontend/` folder to Netlify
4. Get URL: `https://defendersim.netlify.app`

**Option B: GitHub Integration**

1. Push frontend to GitHub
2. Click "New site from Git"
3. Select repository
4. Configure:
   ```
   Build command: (leave empty for static)
   Publish directory: frontend
   ```
5. Deploy

### Step 3: Configure Custom Domain (Optional)

1. Go to Site settings → Domain management
2. Click "Add custom domain"
3. Follow DNS configuration instructions

---

## 5. Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/defendersim` |
| `JWT_SECRET` | Secret for JWT signing | `your_secure_random_secret` |
| `PORT` | Server port | `8000` |
| `NODE_ENV` | Environment mode | `development` or `production` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_API_URL` | Ollama API endpoint | `http://localhost:11434` |
| `OLLAMA_MODEL` | LLM model name | `llama3.2:3b` |
| `MAILPIT_API_URL` | Mailpit API endpoint | `http://localhost:8025` |

### Generating Secure Secrets

**JWT Secret:**
```bash
# macOS/Linux
openssl rand -base64 32

# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

---

## 6. Troubleshooting

### MongoDB Connection Issues

**Error:** `MongoNetworkError: failed to connect to server`

**Solutions:**
1. Check MongoDB is running:
   ```bash
   mongosh
   ```

2. Verify connection string:
   ```bash
   echo $MONGODB_URI
   ```

3. Check firewall settings (allow port 27017)

### Ollama Not Responding

**Error:** `ECONNREFUSED localhost:11434`

**Solutions:**
1. Start Ollama:
   ```bash
   ollama serve
   ```

2. Verify model is installed:
   ```bash
   ollama list
   ```

3. Pull model if missing:
   ```bash
   ollama pull llama3.2:3b
   ```

### Mailpit Not Accessible

**Error:** `Cannot GET /api/v1/messages`

**Solutions:**
1. Start Mailpit:
   ```bash
   mailpit
   ```

2. Check port 8025 is available:
   ```bash
   lsof -i :8025
   ```

3. Access web UI: http://localhost:8025

### Port Already in Use

**Error:** `EADDRINUSE: address already in use :::8000`

**Solutions:**
1. Find process using port:
   ```bash
   # macOS/Linux
   lsof -i :8000
   
   # Windows
   netstat -ano | findstr :8000
   ```

2. Kill process:
   ```bash
   # macOS/Linux
   kill -9 <PID>
   
   # Windows
   taskkill /PID <PID> /F
   ```

3. Or change PORT in `.env`

### Frontend Cannot Connect to Backend

**Error:** `Network Error` or `CORS Error`

**Solutions:**
1. Check backend is running:
   ```bash
   curl http://localhost:8000/api/health
   ```

2. Verify API URL in frontend:
   ```javascript
   console.log(API_URL);
   ```

3. Enable CORS in backend (already configured in `server.js`):
   ```javascript
   app.use(cors());
   ```

### Railway Deployment Fails

**Error:** `Build failed`

**Solutions:**
1. Check build logs in Railway dashboard

2. Verify `package.json` has correct scripts:
   ```json
   {
     "scripts": {
       "start": "node server.js"
     }
   }
   ```

3. Ensure all dependencies are in `dependencies`, not `devDependencies`

### Render Service Sleeping

**Issue:** Service takes 30 seconds to respond

**Solutions:**
1. Upgrade to paid plan ($7/month) for always-on

2. Use cron job to ping service every 14 minutes:
   ```bash
   # Add to crontab
   */14 * * * * curl https://your-service.onrender.com/api/health
   ```

3. Use UptimeRobot for free monitoring/pinging

---

## Production Checklist

Before deploying to production:

- [ ] Change `JWT_SECRET` to secure random value
- [ ] Set `NODE_ENV=production`
- [ ] Enable MongoDB authentication
- [ ] Configure HTTPS/SSL
- [ ] Set up error logging (e.g., Sentry)
- [ ] Configure rate limiting
- [ ] Set up backup strategy for database
- [ ] Test all API endpoints
- [ ] Verify frontend connects to production backend
- [ ] Set up monitoring (e.g., UptimeRobot)
- [ ] Document deployment process
- [ ] Create rollback plan

---

## Monitoring and Maintenance

### Health Check Endpoint

Backend includes health check at `/api/health`:

```bash
curl https://your-backend-url.com/api/health
```

**Expected response:**
```json
{
  "status": "ok",
  "timestamp": "2026-02-10T15:30:00.000Z",
  "services": {
    "mongodb": "connected",
    "ollama": "available"
  }
}
```

### Logging

**Development:**
```bash
npm run dev
# Logs to console
```

**Production:**
```bash
npm start > logs/app.log 2>&1
```

### Database Backups

**MongoDB Backup:**
```bash
mongodump --uri="mongodb://localhost:27017/defendersim" --out=./backup
```

**MongoDB Restore:**
```bash
mongorestore --uri="mongodb://localhost:27017/defendersim" ./backup/defendersim
```

---

## Support

For deployment issues:

1. Check this guide's troubleshooting section
2. Review Railway/Render documentation
3. Check GitHub Issues
4. Contact project author

---

## Next Steps

After successful deployment:

1. Test all features in production
2. Set up monitoring and alerts
3. Configure custom domain (optional)
4. Enable analytics (optional)
5. Document any deployment-specific configurations

---

**Deployment Guide Version:** 1.0
**Last Updated:** February 10, 2026
