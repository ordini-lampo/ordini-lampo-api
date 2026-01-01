if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

// ============================================================
// src/index.js
// Express Server - Ordini-Lampo API v2.2
// Stack: Railway + Session Auth + CSRF PLATINUM++
// ============================================================

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

const { logger } = require('./lib/logger');
const { requestIdMiddleware } = require('./middleware/request-id');
const { authMiddleware } = require('./middleware/auth');
const { csrfProtect } = require('./middleware/csrf');
const { govGuard } = require('./middleware/gov-guard');
const { rateLimiter } = require('./middleware/rate-limit');

const authRoutes = require('./routes/auth');
const govRoutes = require('./routes/gov');

// ============================================================
// CONFIG
// ============================================================

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';

// CORS allowed origins
const ALLOWED_ORIGINS = new Set(
  (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);

// ============================================================
// EXPRESS APP
// ============================================================

const app = express();

// Trust proxy (Railway)
app.set('trust proxy', 1);

// ============================================================
// GLOBAL MIDDLEWARE (ORDER MATTERS!)
// ============================================================

// 1. Request ID (first - needed for all logging)
app.use(requestIdMiddleware);

// 2. Security headers
app.use(helmet({
  contentSecurityPolicy: false, // API only
  crossOriginEmbedderPolicy: false,
}));

// 3. Cookie parser (before CORS and auth)
app.use(cookieParser());

// 4. CORS (cross-site cookie support)
// ✅ FIX P0-1: Definisci UNA SOLA VOLTA corsOptions
const corsOptions = {
  origin: function(origin, callback) {
    // Allow requests with no origin (curl, Postman) in dev only
    if (!origin) {
      return callback(null, NODE_ENV !== 'production');
    }
    if (ALLOWED_ORIGINS.has(origin)) {
      return callback(null, true);
    }
    logger.warn({ origin }, 'CORS blocked origin');
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Request-Id', 'X-OL-CSRF', 'Authorization'],
  exposedHeaders: ['X-Request-Id'],
  maxAge: 86400,
};

app.use(cors(corsOptions));

// ✅ FIX P0-1: Preflight coerente (stesse options)
app.options('*', cors(corsOptions));

// 5. Body parser
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 6. Rate limiting globale
app.use(rateLimiter.global);

// ============================================================
// HEALTH CHECK (bypasses all guards)
// ============================================================

app.get('/api/v1/health', async (req, res) => {
  try {
    // Quick DB check
    const { query } = require('./lib/db');
    await query('SELECT 1');

    res.json({
      status: 'ok',
      module: 'GOV',
      version: '2.2',
      stack: 'railway',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error({ err: error }, 'Health check failed');
    res.status(503).json({
      status: 'error',
      message: 'Database connection failed',
    });
  }
});

// Railway health check alias
app.get('/health', (req, res) => {
  res.redirect('/api/v1/health');
});

// ============================================================
// AUTH ROUTES (before auth middleware - public)
// ============================================================

app.use('/api/v1/auth', authRoutes);

// ============================================================
// PROTECTED ROUTES
// ============================================================

// 6. GOV Guard (kill-switch / maintenance) - fail-closed
app.use(govGuard);

// 7. Auth middleware (session validation)
app.use(authMiddleware);

// 8. CSRF protection (on non-safe methods)
app.use(csrfProtect);

// ============================================================
// API ROUTES
// ============================================================

app.use('/api/v1/gov', govRoutes);

// Future routes:
// app.use('/api/v1/orders', orderRoutes);
// app.use('/api/v1/menu', menuRoutes);
// app.use('/api/v1/tenants', tenantRoutes);

// ============================================================
// 404 HANDLER
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    error: 'NOT_FOUND',
    message: `Route ${req.method} ${req.path} not found`,
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
  logger.error({
    err,
    requestId: req.requestId,
    method: req.method,
    path: req.path,
  }, 'Unhandled error');

  // Don't leak error details in production
  const message = NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;

  res.status(500).json({
    error: 'INTERNAL_ERROR',
    message,
    requestId: req.requestId,
  });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  logger.info({
    port: PORT,
    env: NODE_ENV,
    origins: Array.from(ALLOWED_ORIGINS),
  }, `🚀 Ordini-Lampo API v2.2 running on port ${PORT}`);
});

module.exports = app;
