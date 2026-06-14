/**
 * auth.js – JWT Authentication Middleware
 *
 * Usage: add authMiddleware to any route that requires authentication.
 *   router.get('/profile', authMiddleware, (req, res) => { ... })
 *
 * The verified payload is attached to req.user so route handlers
 * can access req.user.id, req.user.email, etc.
 */

const jwt    = require('jsonwebtoken');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PRODUCTION';

/**
 * Extracts Bearer token from Authorization header,
 * verifies it, and attaches the decoded payload to req.user.
 */
function authMiddleware(req, res, next) {
  // Expected header format: "Authorization: Bearer <token>"
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn(`Unauthorized access attempt – no token | IP: ${req.ip} | Path: ${req.path}`);
    return res.status(401).json({ error: 'Access denied: authentication token required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, role, iat, exp }
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      logger.warn(`Expired token used | IP: ${req.ip} | Path: ${req.path}`);
      return res.status(401).json({ error: 'Token expired, please log in again' });
    }
    logger.warn(`Invalid token | IP: ${req.ip} | Path: ${req.path} | Error: ${err.message}`);
    return res.status(403).json({ error: 'Invalid authentication token' });
  }
}

/**
 * Optional role-based access control middleware.
 * Usage: router.delete('/user/:id', authMiddleware, requireRole('admin'), handler)
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      logger.warn(`Forbidden: user ${req.user?.id} lacks role [${roles}] | Path: ${req.path}`);
      return res.status(403).json({ error: 'Forbidden: insufficient permissions' });
    }
    next();
  };
}

module.exports = { authMiddleware, requireRole };
