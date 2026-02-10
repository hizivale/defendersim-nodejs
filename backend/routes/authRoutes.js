const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect } = require('../middleware/auth');

/**
 * Authentication Routes
 * Defines API endpoints for user authentication
 * 
 * Design Pattern: MVC (Routes)
 * Purpose: Map HTTP requests to controller methods
 */

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);

// Protected routes (require authentication)
router.get('/me', protect, authController.getMe);
router.put('/profile', protect, authController.updateProfile);
router.put('/password', protect, authController.changePassword);

module.exports = router;
