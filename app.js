/**
 * app.js – Main application entry point
 * DevelopersHub Cybersecurity Internship – Secured User Management System
 *
 * Security measures applied:
 *  1. Helmet.js         – HTTP security headers
 *  2. express-rate-limit – Brute-force protection
 *  3. express-mongo-sanitize – NoSQL injection prevention
 *  4. Input validation  – validator.js in all route handlers
 *  5. bcrypt            – Password hashing (saltRounds=10)
 *  6. jsonwebtoken      – Stateless auth on protected routes
 *  7. winston           – Security event logging
 */

require('dotenv').config();

const express     = require('express');
const mongoose    = require('mongoose');
const helmet      = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit   = require('express-rate-limit');
const path        = require('path');

const logger      = require('./utils/logger');
const authRoutes  = require('./routes/auth');
const userRoutes  = require('./routes/user');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── View Engine ──────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Static Files ────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public')));

// ─── Body Parsers ────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── SECURITY MIDDLEWARE 1: HTTP Headers via Helmet ──────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'"],
        styleSrc:   ["'self'", "'unsafe-inline'"],
        imgSrc:     ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc:    ["'self'"],
        objectSrc:  ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);

// ─── SECURITY MIDDLEWARE 2: NoSQL Injection Sanitization ─────────
// Strips keys containing '$' or '.' from req.body, req.query, req.params
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitizeError: (req, res) => {
    logger.warn(`NoSQL injection attempt blocked from IP: ${req.ip} | Path: ${req.path}`);
  },
}));

// ─── SECURITY MIDDLEWARE 3: Global Rate Limiter ──────────────────
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 min
  max:      parseInt(process.env.RATE_LIMIT_MAX)        || 100,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many requests, please try again later.' },
  handler: (req, res, next, options) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip} | Path: ${req.path}`);
    res.status(options.statusCode).json(options.message);
  },
});
app.use(globalLimiter);

// ─── Request Logger ───────────────────────────────────────────────
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} – IP: ${req.ip}`);
  next();
});

// ─── Routes ───────────────────────────────────────────────────────
app.use('/auth', authRoutes);
app.use('/api',  userRoutes);

// ─── Page Routes (EJS views) ──────────────────────────────────────
app.get('/',        (req, res) => res.render('index'));
app.get('/signup',  (req, res) => res.render('signup'));
app.get('/login',   (req, res) => res.render('login'));
app.get('/profile', (req, res) => res.render('profile'));
app.get('/dashboard',(req, res) => res.render('dashboard'));

// ─── 404 Handler ─────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ─── Global Error Handler ────────────────────────────────────────
// NOTE: Does NOT expose stack traces in production
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message} | Path: ${req.path}`);
  const statusCode = err.statusCode || 500;
  const message    = process.env.NODE_ENV === 'production'
    ? 'An internal error occurred'
    : err.message;
  res.status(statusCode).json({ error: message });
});

// ─── Database Connection ─────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/user_management_db';

mongoose
  .connect(MONGO_URI)
  .then(() => {
    logger.info('MongoDB connected successfully');
    app.listen(PORT, () => {
      logger.info(`Application started – listening on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    logger.error(`MongoDB connection failed: ${err.message}`);
    process.exit(1);
  });

module.exports = app;
