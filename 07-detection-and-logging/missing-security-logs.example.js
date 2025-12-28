/**
 * Example: Missing Security Logs
 * 
 * This file demonstrates the security issue of not logging security-relevant events
 * and shows how to implement comprehensive security logging.
 */

const express = require('express');
const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: No security logging
// ============================================================================

function insecureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    // BAD: No logging of authentication failure
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    // BAD: No logging of token validation failure
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function insecureAuthorizationCheck(req, res, next) {
  if (req.user.role !== 'admin') {
    // BAD: No logging of authorization denial
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ============================================================================
// ✅ SECURE: Comprehensive security logging
// ============================================================================

// Security logger utility
class SecurityLogger {
  static logAuthFailure(req, reason) {
    console.log(JSON.stringify({
      type: 'AUTH_FAILURE',
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      reason: reason,
      path: req.path
    }));
  }
  
  static logAuthSuccess(req, userId) {
    console.log(JSON.stringify({
      type: 'AUTH_SUCCESS',
      timestamp: new Date().toISOString(),
      userId: userId,
      ip: req.ip,
      path: req.path
    }));
  }
  
  static logAuthorizationDenial(req, userId, requiredPermission) {
    console.log(JSON.stringify({
      type: 'AUTHORIZATION_DENIAL',
      timestamp: new Date().toISOString(),
      userId: userId,
      ip: req.ip,
      requiredPermission: requiredPermission,
      path: req.path
    }));
  }
  
  static logTokenValidationFailure(req, reason) {
    console.log(JSON.stringify({
      type: 'TOKEN_VALIDATION_FAILURE',
      timestamp: new Date().toISOString(),
      ip: req.ip,
      reason: reason,
      path: req.path
    }));
  }
  
  static logSuspiciousActivity(req, activity, details) {
    console.log(JSON.stringify({
      type: 'SUSPICIOUS_ACTIVITY',
      timestamp: new Date().toISOString(),
      userId: req.user?.userId,
      ip: req.ip,
      activity: activity,
      details: details,
      path: req.path
    }));
  }
}

function secureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    // GOOD: Log authentication failure
    SecurityLogger.logAuthFailure(req, 'NO_TOKEN_PROVIDED');
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    
    // GOOD: Log successful authentication
    SecurityLogger.logAuthSuccess(req, decoded.userId);
    
    next();
  } catch (error) {
    // GOOD: Log token validation failure with reason
    SecurityLogger.logTokenValidationFailure(req, error.name);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function secureAuthorizationCheck(requiredPermission) {
  return (req, res, next) => {
    if (!req.user) {
      SecurityLogger.logAuthFailure(req, 'NOT_AUTHENTICATED');
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const userPermissions = req.user.permissions || [];
    if (!userPermissions.includes(requiredPermission)) {
      // GOOD: Log authorization denial
      SecurityLogger.logAuthorizationDenial(req, req.user.userId, requiredPermission);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// ============================================================================
// Express Route Examples
// ============================================================================

function insecureRoutes() {
  const app = express();
  
  // BAD: No logging
  app.get('/api/admin/data', insecureAuthMiddleware, (req, res) => {
    return res.json({ data: 'admin data' });
  });
  
  return app;
}

function secureRoutes() {
  const app = express();
  
  // GOOD: With security logging
  app.get('/api/admin/data',
    secureAuthMiddleware,
    secureAuthorizationCheck('admin:access'),
    (req, res) => {
      return res.json({ data: 'admin data' });
    }
  );
  
  return app;
}

// ============================================================================
// Advanced: Rate limiting detection
// ============================================================================

class RateLimitTracker {
  constructor() {
    this.attempts = new Map(); // ip -> { count, firstAttempt }
  }
  
  recordAttempt(ip) {
    const now = Date.now();
    const record = this.attempts.get(ip) || { count: 0, firstAttempt: now };
    
    record.count++;
    
    // Reset if more than 5 minutes passed
    if (now - record.firstAttempt > 5 * 60 * 1000) {
      record.count = 1;
      record.firstAttempt = now;
    }
    
    this.attempts.set(ip, record);
    
    // GOOD: Log suspicious activity
    if (record.count > 5) {
      SecurityLogger.logSuspiciousActivity(
        { ip },
        'RATE_LIMIT_EXCEEDED',
        { attempts: record.count, window: '5 minutes' }
      );
    }
    
    return record.count;
  }
}

const rateLimitTracker = new RateLimitTracker();

function secureAuthMiddlewareWithRateLimit(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    const attempts = rateLimitTracker.recordAttempt(req.ip);
    SecurityLogger.logAuthFailure(req, 'NO_TOKEN_PROVIDED');
    
    if (attempts > 5) {
      return res.status(429).json({ error: 'Too many requests' });
    }
    
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    SecurityLogger.logAuthSuccess(req, decoded.userId);
    next();
  } catch (error) {
    const attempts = rateLimitTracker.recordAttempt(req.ip);
    SecurityLogger.logTokenValidationFailure(req, error.name);
    
    if (attempts > 5) {
      return res.status(429).json({ error: 'Too many requests' });
    }
    
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================================================
// Logging sensitive operations
// ============================================================================

function secureUpdateUser(req, res) {
  const userId = parseInt(req.params.id);
  const updates = req.body;
  const requesterId = req.user.userId;
  
  // GOOD: Log sensitive operation
  console.log(JSON.stringify({
    type: 'USER_UPDATE_ATTEMPT',
    timestamp: new Date().toISOString(),
    requesterId: requesterId,
    targetUserId: userId,
    updates: Object.keys(updates),
    ip: req.ip
  }));
  
  // ... update logic ...
  
  // GOOD: Log successful update
  console.log(JSON.stringify({
    type: 'USER_UPDATE_SUCCESS',
    timestamp: new Date().toISOString(),
    requesterId: requesterId,
    targetUserId: userId
  }));
  
  return res.json({ message: 'User updated' });
}

// ============================================================================
// Structured logging with context
// ============================================================================

function createSecurityLog(type, req, details = {}) {
  return {
    type: type,
    timestamp: new Date().toISOString(),
    userId: req.user?.userId,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    path: req.path,
    method: req.method,
    ...details
  };
}

function secureMiddlewareWithStructuredLogging(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    const log = createSecurityLog('AUTH_FAILURE', req, { reason: 'NO_TOKEN' });
    console.log(JSON.stringify(log));
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    
    const log = createSecurityLog('AUTH_SUCCESS', req, { userId: decoded.userId });
    console.log(JSON.stringify(log));
    
    next();
  } catch (error) {
    const log = createSecurityLog('TOKEN_VALIDATION_FAILURE', req, { 
      reason: error.name 
    });
    console.log(JSON.stringify(log));
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================================================
// Best Practice: Centralized logging middleware
// ============================================================================

function securityLoggingMiddleware(req, res, next) {
  // Log all requests for audit trail
  const originalSend = res.send;
  
  res.send = function(data) {
    // Log response
    if (res.statusCode >= 400) {
      const log = createSecurityLog('REQUEST_ERROR', req, {
        statusCode: res.statusCode,
        response: data
      });
      console.log(JSON.stringify(log));
    }
    
    originalSend.call(this, data);
  };
  
  next();
}

module.exports = {
  insecureAuthMiddleware,
  insecureAuthorizationCheck,
  SecurityLogger,
  secureAuthMiddleware,
  secureAuthorizationCheck,
  insecureRoutes,
  secureRoutes,
  RateLimitTracker,
  secureAuthMiddlewareWithRateLimit,
  secureUpdateUser,
  createSecurityLog,
  secureMiddlewareWithStructuredLogging,
  securityLoggingMiddleware
};
