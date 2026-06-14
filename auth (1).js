/**
 * auth.js – Authentication Routes
 *
 * POST /auth/signup  – Register a new user
 * POST /auth/login   – Login and receive JWT
 * POST /auth/logout  – Logout (client-side token invalidation)
 *
 * Security layers applied per route:
 *  - authLimiter    – Strict rate limit for auth endpoints
 *  - validateSignup / validateLogin – Input validation & sanitization
 *  - bcrypt         – Password hashing (via User model pre-save hook)
 *  - JWT            – Signed token issued on successful login
 *  - Generic errors – Login returns same message for wrong email OR password
 *                     (prevents user enumeration)
 */

const express   = require('express');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const User      = require('../models/User');
const logger    = require('../utils/logger');
const { validateSignup, validateLogin } = require('../middleware/validate');

const router = express.Router();

const JWT_SECRET     = process.env.JWT_SECRET     || 'CHANGE_THIS_IN_PRODUCTION';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// ─── Strict rate limiter for auth endpoints ───────────────────────
// Max 10 attempts per IP per 15 minutes – blocks brute-force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many attempts. Please try again in 15 minutes.' },
  handler: (req, res, next, options) => {
    logger.warn(`Auth rate limit hit | IP: ${req.ip} | Path: ${req.path}`);
    res.status(options.statusCode).json(options.message);
  },
});

// ─── POST /auth/signup ────────────────────────────────────────────
router.post('/signup', authLimiter, validateSignup, async (req, res) => {
  try {
    const { name, email, password } = req.sanitized;

    // Check if email already registered
    const existing = await User.findOne({ email });
    if (existing) {
      logger.warn(`Signup attempt with existing email: ${email} | IP: ${req.ip}`);
      // Generic message – do not confirm whether email exists (prevents enumeration)
      return res.status(409).json({ error: 'Registration failed. Please try again.' });
    }

    // Create user – password is hashed by the pre-save hook in User model
    const user = new User({ name, email, password });
    await user.save();

    logger.info(`New user registered: ${email}`);

    // Issue token immediately so user is logged in after signup
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    logger.error(`Signup error: ${err.message}`);
    return res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

// ─── POST /auth/login ─────────────────────────────────────────────
router.post('/login', authLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.sanitized;

    // Fetch user WITH password field (excluded by default)
    const user = await User.findOne({ email }).select('+password');

    // SECURITY: Use a single generic error for both "wrong email" and
    // "wrong password" to prevent user enumeration attacks
    const INVALID_CREDS = 'Invalid email or password';

    if (!user) {
      logger.warn(`Login attempt with unknown email: ${email} | IP: ${req.ip}`);
      return res.status(401).json({ error: INVALID_CREDS });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      logger.warn(`Failed login – wrong password for: ${email} | IP: ${req.ip}`);
      return res.status(401).json({ error: INVALID_CREDS });
    }

    // Update last login timestamp
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });

    // Sign and return JWT
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    logger.info(`Successful login: ${email} | IP: ${req.ip}`);

    return res.status(200).json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    return res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});

// ─── POST /auth/logout ────────────────────────────────────────────
// JWT is stateless – logout is handled client-side by deleting the token.
// This endpoint exists for logging purposes.
router.post('/logout', (req, res) => {
  logger.info(`Logout called | IP: ${req.ip}`);
  return res.status(200).json({ message: 'Logged out successfully. Please delete your token.' });
});

module.exports = router;
