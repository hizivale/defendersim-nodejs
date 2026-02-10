const express = require('express');
const router = express.Router();
const analysisController = require('../controllers/analysisController');
const { protect, authorize } = require('../middleware/auth');

/**
 * Analysis Routes
 * Defines API endpoints for phishing analysis operations
 * 
 * Design Pattern: MVC (Routes)
 * Purpose: Map HTTP requests to controller methods
 */

// Public routes (no authentication required for demo)
router.get('/', analysisController.getAnalyses);
router.get('/stats', analysisController.getStatistics);
router.get('/recent', analysisController.getRecentAnalyses);
router.get('/:id', analysisController.getAnalysisById);

// Analysis operations
router.post('/:emailId', analysisController.analyzeEmail);

// Protected routes (require authentication)
router.delete('/:id', protect, authorize('admin'), analysisController.deleteAnalysis);

module.exports = router;
