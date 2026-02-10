const express = require('express');
const router = express.Router();
const emailController = require('../controllers/emailController');
const { protect, authorize } = require('../middleware/auth');

/**
 * Email Routes
 * Defines API endpoints for email operations
 * 
 * Design Pattern: MVC (Routes)
 * Purpose: Map HTTP requests to controller methods
 */

// Public routes (no authentication required for demo)
router.get('/', emailController.getEmails);
router.get('/stats', emailController.getEmailStats);
router.get('/unanalyzed', emailController.getUnanalyzed Emails);

// Sync emails from Mailpit
router.get('/sync', emailController.syncEmails);

// Single email operations
router.get('/:id', emailController.getEmailById);

// Protected routes (require authentication)
router.delete('/:id', protect, authorize('admin', 'analyst'), emailController.deleteEmail);

module.exports = router;
