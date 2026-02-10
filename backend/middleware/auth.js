const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Authentication Middleware
 * Protects routes and verifies user permissions
 * 
 * Purpose: JWT token verification and role-based access control
 */

/**
 * Protect routes - Verify JWT token
 * @middleware
 */
exports.protect = async (req, res, next) => {
  try {
    let token;

    // Check for token in Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route. Please login.'
      });
    }

    try {
      // Verify token
      const secret = process.env.JWT_SECRET || 'your-secret-key';
      const decoded = jwt.verify(token, secret);

      // Get user from token
      const user = await User.findById(decoded.id);

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found. Token may be invalid.'
        });
      }

      // Check if user is active
      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: 'Account is deactivated.'
        });
      }

      // Attach user to request
      req.user = {
        id: user._id,
        email: user.email,
        role: user.role,
        username: user.username
      };

      next();
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: 'Token is invalid or has expired'
      });
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Authorize roles - Check user permissions
 * @param {...string} roles - Allowed roles
 * @middleware
 */
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized. Please login first.'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `User role '${req.user.role}' is not authorized to access this route`
      });
    }

    next();
  };
};

/**
 * Optional authentication - Attach user if token exists, but don't require it
 * @middleware
 */
exports.optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (token) {
      try {
        const secret = process.env.JWT_SECRET || 'your-secret-key';
        const decoded = jwt.verify(token, secret);
        const user = await User.findById(decoded.id);

        if (user && user.isActive) {
          req.user = {
            id: user._id,
            email: user.email,
            role: user.role,
            username: user.username
          };
        }
      } catch (error) {
        // Token invalid, but that's okay for optional auth
      }
    }

    next();
  } catch (error) {
    next(error);
  }
};
