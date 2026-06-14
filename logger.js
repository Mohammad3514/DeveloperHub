/**
 * logger.js – Winston security logger
 *
 * Outputs to:
 *  - Console (colorized for development)
 *  - logs/security.log (all levels)
 *  - logs/error.log    (error level only)
 */

const winston = require('winston');
const path    = require('path');
const fs      = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '..', '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const { combine, timestamp, printf, colorize, errors } = winston.format;

// Custom log format
const logFormat = printf(({ timestamp, level, message, stack }) => {
  return stack
    ? `[${timestamp}] [${level.toUpperCase()}] ${message}\n${stack}`
    : `[${timestamp}] [${level.toUpperCase()}] ${message}`;
});

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'warn' : 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    logFormat
  ),
  transports: [
    // Console – colorized
    new winston.transports.Console({
      format: combine(
        colorize({ all: true }),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        errors({ stack: true }),
        logFormat
      ),
    }),
    // All logs → security.log
    new winston.transports.File({
      filename: path.join(logsDir, 'security.log'),
      maxsize:  5 * 1024 * 1024, // 5 MB
      maxFiles: 5,
      tailable: true,
    }),
    // Error logs → error.log
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level:    'error',
      maxsize:  5 * 1024 * 1024,
      maxFiles: 3,
      tailable: true,
    }),
  ],
});

module.exports = logger;
