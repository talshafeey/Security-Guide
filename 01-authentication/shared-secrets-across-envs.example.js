/**
 * Example: Shared Secrets Across Environments
 * 
 * This file demonstrates the security issue of using the same JWT secret
 * across different environments (DEV, QA, PROD) and shows the correct approach.
 */

const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: Same secret for all environments
// ============================================================================

// BAD: Same secret used everywhere
const SHARED_SECRET = 'my-secret-key-12345'; // Same in DEV, QA, and PROD

function insecureGenerateToken(userId, environment) {
  // BAD: Uses same secret regardless of environment
  const token = jwt.sign(
    { userId: userId, env: environment },
    SHARED_SECRET, // Same secret everywhere!
    { expiresIn: '24h' }
  );
  return token;
}

function insecureVerifyToken(token) {
  // BAD: Accepts tokens from any environment
  try {
    const decoded = jwt.verify(token, SHARED_SECRET);
    return decoded; // Token from DEV works in PROD!
  } catch (error) {
    return null;
  }
}

// ============================================================================
// ✅ SECURE: Unique secrets per environment
// ============================================================================

// GOOD: Different secrets for each environment
const ENV_SECRETS = {
  development: process.env.JWT_SECRET_DEV,
  qa: process.env.JWT_SECRET_QA,
  production: process.env.JWT_SECRET_PROD
};

// GOOD: Current environment
const CURRENT_ENV = process.env.NODE_ENV || 'development';

function secureGenerateToken(userId) {
  // GOOD: Uses environment-specific secret
  const secret = ENV_SECRETS[CURRENT_ENV];
  
  if (!secret) {
    throw new Error(`JWT_SECRET not configured for environment: ${CURRENT_ENV}`);
  }
  
  const token = jwt.sign(
    { 
      userId: userId,
      env: CURRENT_ENV // Include environment in token
    },
    secret, // Environment-specific secret
    { expiresIn: '24h' }
  );
  return token;
}

function secureVerifyToken(token) {
  // GOOD: Only accepts tokens signed with current environment's secret
  const secret = ENV_SECRETS[CURRENT_ENV];
  
  if (!secret) {
    throw new Error(`JWT_SECRET not configured for environment: ${CURRENT_ENV}`);
  }
  
  try {
    const decoded = jwt.verify(token, secret);
    
    // GOOD: Also verify token was issued for this environment
    if (decoded.env !== CURRENT_ENV) {
      return null; // Reject tokens from other environments
    }
    
    return decoded;
  } catch (error) {
    return null;
  }
}

// ============================================================================
// Environment Configuration Example
// ============================================================================

// .env.development
// JWT_SECRET_DEV=dev-secret-abc123xyz789...

// .env.qa
// JWT_SECRET_QA=qa-secret-def456uvw012...

// .env.production
// JWT_SECRET_PROD=prod-secret-ghi789rst345...

// ============================================================================
// Express Middleware Example
// ============================================================================

// ❌ INSECURE Middleware
function insecureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const decoded = insecureVerifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  req.user = decoded;
  next(); // Accepts tokens from any environment!
}

// ✅ SECURE Middleware
function secureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const decoded = secureVerifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token or wrong environment' });
  }
  
  req.user = decoded;
  next();
}

// ============================================================================
// Validation on Startup
// ============================================================================

function validateEnvironmentConfig() {
  const requiredSecrets = ['JWT_SECRET_DEV', 'JWT_SECRET_QA', 'JWT_SECRET_PROD'];
  
  for (const secretName of requiredSecrets) {
    if (!process.env[secretName]) {
      throw new Error(`Missing required environment variable: ${secretName}`);
    }
    
    if (process.env[secretName].length < 32) {
      throw new Error(`${secretName} must be at least 32 characters long`);
    }
  }
  
  // GOOD: Ensure secrets are different
  if (process.env.JWT_SECRET_DEV === process.env.JWT_SECRET_PROD) {
    throw new Error('DEV and PROD secrets must be different!');
  }
  
  console.log('Environment configuration validated');
}

module.exports = {
  insecureGenerateToken,
  insecureVerifyToken,
  secureGenerateToken,
  secureVerifyToken,
  insecureAuthMiddleware,
  secureAuthMiddleware,
  validateEnvironmentConfig
};
