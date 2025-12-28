/**
 * Example: Environment Isolation
 * 
 * This file demonstrates the security issue of sharing secrets across environments
 * and shows how to enforce proper environment isolation.
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

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
// ✅ SECURE: Environment-specific secrets
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
// Environment Configuration Validation
// ============================================================================

function validateEnvironmentConfig() {
  const requiredSecrets = ['JWT_SECRET_DEV', 'JWT_SECRET_QA', 'JWT_SECRET_PROD'];
  
  // GOOD: Check all required secrets exist
  for (const secretName of requiredSecrets) {
    if (!process.env[secretName]) {
      throw new Error(`Missing required environment variable: ${secretName}`);
    }
    
    // GOOD: Validate secret strength
    if (process.env[secretName].length < 32) {
      throw new Error(`${secretName} must be at least 32 characters long`);
    }
  }
  
  // GOOD: Ensure secrets are different
  if (process.env.JWT_SECRET_DEV === process.env.JWT_SECRET_PROD) {
    throw new Error('DEV and PROD secrets must be different!');
  }
  
  if (process.env.JWT_SECRET_QA === process.env.JWT_SECRET_PROD) {
    throw new Error('QA and PROD secrets must be different!');
  }
  
  console.log('Environment configuration validated');
  return true;
}

// ============================================================================
// Express Middleware with Environment Check
// ============================================================================

const express = require('express');

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

function createSecureApp() {
  const app = express();
  
  // GOOD: Validate environment config on startup
  try {
    validateEnvironmentConfig();
  } catch (error) {
    console.error('Environment configuration error:', error.message);
    process.exit(1); // Fail fast if config is invalid
  }
  
  app.use('/api', secureAuthMiddleware);
  
  app.get('/api/data', (req, res) => {
    // Token is already validated for current environment
    return res.json({ data: 'sensitive data', env: CURRENT_ENV });
  });
  
  return app;
}

// ============================================================================
// Environment Isolation Helper
// ============================================================================

class EnvironmentManager {
  constructor() {
    this.currentEnv = process.env.NODE_ENV || 'development';
    this.secrets = {
      development: process.env.JWT_SECRET_DEV,
      qa: process.env.JWT_SECRET_QA,
      production: process.env.JWT_SECRET_PROD
    };
  }
  
  validate() {
    // Check all secrets exist
    for (const [env, secret] of Object.entries(this.secrets)) {
      if (!secret) {
        throw new Error(`Secret missing for environment: ${env}`);
      }
      if (secret.length < 32) {
        throw new Error(`Secret too short for environment: ${env}`);
      }
    }
    
    // Ensure secrets are unique
    const secretValues = Object.values(this.secrets);
    const uniqueSecrets = new Set(secretValues);
    if (uniqueSecrets.size !== secretValues.length) {
      throw new Error('All environment secrets must be unique');
    }
    
    return true;
  }
  
  getSecret() {
    const secret = this.secrets[this.currentEnv];
    if (!secret) {
      throw new Error(`Secret not configured for environment: ${this.currentEnv}`);
    }
    return secret;
  }
  
  getCurrentEnv() {
    return this.currentEnv;
  }
  
  isProduction() {
    return this.currentEnv === 'production';
  }
}

// ============================================================================
// Example: Environment-specific configuration
// ============================================================================

// .env.development
// NODE_ENV=development
// JWT_SECRET_DEV=dev-secret-abc123xyz789...
// JWT_SECRET_QA=qa-secret-def456uvw012...
// JWT_SECRET_PROD=prod-secret-ghi789rst345...

// .env.qa
// NODE_ENV=qa
// JWT_SECRET_DEV=dev-secret-abc123xyz789...
// JWT_SECRET_QA=qa-secret-def456uvw012...
// JWT_SECRET_PROD=prod-secret-ghi789rst345...

// .env.production
// NODE_ENV=production
// JWT_SECRET_DEV=dev-secret-abc123xyz789...
// JWT_SECRET_QA=qa-secret-def456uvw012...
// JWT_SECRET_PROD=prod-secret-ghi789rst345...

// ============================================================================
// Block Cross-Environment Access
// ============================================================================

function blockCrossEnvironmentAccess(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    // Decode without verification to check environment
    const decoded = jwt.decode(token);
    
    if (!decoded || !decoded.env) {
      return res.status(401).json({ error: 'Invalid token format' });
    }
    
    // GOOD: Block if token is from different environment
    if (decoded.env !== CURRENT_ENV) {
      return res.status(403).json({ 
        error: `Token from ${decoded.env} environment not allowed in ${CURRENT_ENV}` 
      });
    }
    
    // Now verify with correct secret
    const secret = ENV_SECRETS[CURRENT_ENV];
    jwt.verify(token, secret);
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================================================
// Startup Validation
// ============================================================================

function startupValidation() {
  console.log('Validating environment isolation...');
  
  try {
    validateEnvironmentConfig();
    console.log('✓ Environment isolation validated');
  } catch (error) {
    console.error('✗ Environment isolation failed:', error.message);
    console.error('Please ensure:');
    console.error('1. All environment secrets are set (JWT_SECRET_DEV, JWT_SECRET_QA, JWT_SECRET_PROD)');
    console.error('2. All secrets are at least 32 characters long');
    console.error('3. All secrets are unique');
    process.exit(1);
  }
}

// Run validation on module load (if this is the main module)
if (require.main === module) {
  startupValidation();
}

module.exports = {
  insecureGenerateToken,
  insecureVerifyToken,
  secureGenerateToken,
  secureVerifyToken,
  validateEnvironmentConfig,
  secureAuthMiddleware,
  createSecureApp,
  EnvironmentManager,
  blockCrossEnvironmentAccess,
  startupValidation
};
