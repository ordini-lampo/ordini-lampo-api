// ============================================================
// src/lib/logger.js
// Pino logger (CommonJS)
// ============================================================

const pino = require('pino');

const NODE_ENV = process.env.NODE_ENV || 'development';

const logger = pino({
  level: process.env.LOG_LEVEL || (NODE_ENV === 'production' ? 'info' : 'debug'),
  transport: NODE_ENV !== 'production' ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'HH:MM:ss',
      ignore: 'pid,hostname',
    },
  } : undefined,
  base: {
    env: NODE_ENV,
  },
});

module.exports = { logger };
