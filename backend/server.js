require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');

const dbConnection = require('./config/database');
const errorHandler = require('./middleware/errorHandler');

// Import routes
const emailRoutes = require('./routes/emailRoutes');
const analysisRoutes = require('./routes/analysisRoutes');
const authRoutes = require('./routes/authRoutes');

/**
 * DefenderSim Backend Server
 * Node.js + Express + MongoDB
 * 
 * Architecture: MVC Pattern with Singleton (DB) and Factory (Analyzers)
 */

// Initialize Express app
const app = express();

// Connect to MongoDB
dbConnection.connect()
  .then(() => {
    console.log('[Server] Database connection established');
  })
  .catch((error) => {
    console.error('[Server] Database connection failed:', error.message);
    process.exit(1);
  });

// Middleware
app.use(helmet()); // Security headers
app.use(cors({
  origin: process.env.CORS_ORIGIN?.split(',') || '*',
  credentials: true
}));
app.use(compression()); // Compress responses
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// API Routes
app.use('/api/emails', emailRoutes);
app.use('/api/analysis', analysisRoutes);
app.use('/api/auth', authRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'DefenderSim API is running',
    timestamp: new Date().toISOString(),
    database: dbConnection.getStatus() ? 'connected' : 'disconnected',
    version: '1.0.0'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Welcome to DefenderSim API',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      emails: '/api/emails',
      analysis: '/api/analysis',
      auth: '/api/auth'
    },
    documentation: 'See README.md for API documentation'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
});

// Error handler (must be last)
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 8000;
const server = app.listen(PORT, () => {
  console.log(`[Server] DefenderSim backend running on port ${PORT}`);
  console.log(`[Server] Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`[Server] API available at http://localhost:${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('[Server] Unhandled Promise Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

// Handle SIGTERM
process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received. Closing server gracefully...');
  server.close(async () => {
    await dbConnection.disconnect();
    console.log('[Server] Server closed');
    process.exit(0);
  });
});

module.exports = app;
