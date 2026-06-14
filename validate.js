/**
 * validate.js – Input Validation & Sanitization Middleware
 *
 * Uses the 'validator' library to check and sanitize all user inputs
 * before they reach route handlers or the database.
 *
 * Each exported function is an Express middleware that:
 *  1. Validates the incoming fields
 *  2. Returns 400 with a clear error if invalid
 *  3. Sanitizes (escapes HTML entities) and attaches clean values
 *     to req.sanitized so route handlers never touch raw input
 */

const validator = require('validator');
const logger    = require('../utils/logger');

/**
 * Validate signup body: { name, email, password }
 */
function validateSignup(req, res, next) {
  const { name, email, password } = req.body;
  const errors = [];

  // ── Name ──────────────────────────────────────────────────────
  if (!name || validator.isEmpty(name.trim())) {
    errors.push('Name is required');
  } else if (!validator.isLength(name.trim(), { min: 2, max: 100 })) {
    errors.push('Name must be between 2 and 100 characters');
  }

  // ── Email ─────────────────────────────────────────────────────
  if (!email || validator.isEmpty(email.trim())) {
    errors.push('Email is required');
  } else if (!validator.isEmail(email.trim())) {
    errors.push('Invalid email address');
  }

  // ── Password ──────────────────────────────────────────────────
  if (!password || validator.isEmpty(password)) {
    errors.push('Password is required');
  } else if (!validator.isLength(password, { min: 8, max: 128 })) {
    errors.push('Password must be between 8 and 128 characters');
  } else if (!validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 0,
  })) {
    errors.push('Password must include uppercase, lowercase, and a number');
  }

  if (errors.length > 0) {
    logger.warn(`Signup validation failed | IP: ${req.ip} | Errors: ${errors.join('; ')}`);
    return res.status(400).json({ errors });
  }

  // Attach sanitized values – NEVER use raw req.body after this point
  req.sanitized = {
    name:     validator.escape(name.trim()),
    email:    validator.normalizeEmail(email.trim()),
    password, // raw – will be hashed by the model's pre-save hook
  };

  next();
}

/**
 * Validate login body: { email, password }
 */
function validateLogin(req, res, next) {
  const { email, password } = req.body;
  const errors = [];

  if (!email || !validator.isEmail(email.trim())) {
    errors.push('Valid email is required');
  }
  if (!password || validator.isEmpty(password)) {
    errors.push('Password is required');
  }

  if (errors.length > 0) {
    logger.warn(`Login validation failed | IP: ${req.ip}`);
    return res.status(400).json({ errors });
  }

  req.sanitized = {
    email:    validator.normalizeEmail(email.trim()),
    password, // compared with bcrypt, not stored
  };

  next();
}

/**
 * Validate profile update body: { name, bio }
 */
function validateProfileUpdate(req, res, next) {
  const { name, bio } = req.body;
  const errors = [];

  if (name !== undefined) {
    if (validator.isEmpty(name.trim())) {
      errors.push('Name cannot be empty');
    } else if (!validator.isLength(name.trim(), { min: 2, max: 100 })) {
      errors.push('Name must be between 2 and 100 characters');
    }
  }

  if (bio !== undefined && !validator.isLength(bio, { max: 500 })) {
    errors.push('Bio cannot exceed 500 characters');
  }

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  req.sanitized = {
    ...(name !== undefined && { name: validator.escape(name.trim()) }),
    ...(bio  !== undefined && { bio:  validator.escape(bio.trim())  }),
  };

  next();
}

module.exports = { validateSignup, validateLogin, validateProfileUpdate };
