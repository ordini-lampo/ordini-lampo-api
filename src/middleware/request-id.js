// ============================================================
// src/middleware/request-id.js
// Correlation ID middleware
// ============================================================

const crypto = require('crypto');

function requestIdMiddleware(req, res, next) {
  // Use existing header or generate new
  const existing = req.headers['x-request-id'];
  const requestId = (existing && typeof existing === 'string' && existing.length >= 16)
    ? existing
    : crypto.randomUUID();
  
  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  
  next();
}

module.exports = { requestIdMiddleware };
