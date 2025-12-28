/**
 * Example: Secret Strength Policy
 * 
 * This file demonstrates the security issue of using weak secrets
 * and shows how to generate and validate strong secrets.
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: Weak secrets
// ============================================================================

// BAD: Short, guessable secrets
const WEAK_SECRET_1 = 'secret';
const WEAK_SECRET_2 = 'myapp123';
const WEAK_SECRET_3 = 'jwt-secret-key';
const WEAK_SECRET_4 = '1234567890'; // Only 10 characters
const WEAK_SECRET_5 = 'password'; // Common word

function insecureGenerateToken(userId) {
  // BAD: Using weak secret
  const token = jwt.sign(
    { userId: userId },
    WEAK_SECRET_1, // Easy to brute-force!
    { expiresIn: '1h' }
  );
  return token;
}

// ============================================================================
// ✅ SECURE: Strong secret generation
// ============================================================================

// GOOD: Generate strong secret using crypto.randomBytes
function generateStrongSecret(length = 32) {
  // GOOD: High-entropy random bytes
  return crypto.randomBytes(length).toString('hex');
  // Returns 64-character hex string for length=32
}

// GOOD: Generate secret by hashing a random value
function generateStrongSecretByHash() {
  const randomValue = crypto.randomBytes(16);
  // GOOD: Hash the random value for additional security
  return crypto.createHash('sha256').update(randomValue).digest('hex');
  // Returns 64-character hex string
}

// GOOD: Validate secret strength
function validateSecretStrength(secret) {
  if (!secret) {
    throw new Error('Secret is required');
  }
  
  // GOOD: Minimum length requirement (32 characters = 64 hex chars)
  if (secret.length < 32) {
    throw new Error('Secret must be at least 32 characters long');
  }
  
  // GOOD: Check for common weak patterns
  const weakPatterns = [
    /^secret/i,
    /^password/i,
    /^12345/,
    /^admin/,
    /^test/,
    /^dev/,
    /^prod/,
    /^myapp/,
    /^jwt/
  ];
  
  for (const pattern of weakPatterns) {
    if (pattern.test(secret)) {
      throw new Error('Secret contains weak patterns');
    }
  }
  
  // GOOD: Check entropy (simple check for repeated characters)
  const uniqueChars = new Set(secret).size;
  if (uniqueChars < secret.length * 0.5) {
    throw new Error('Secret has low entropy (too many repeated characters)');
  }
  
  return true;
}

// ============================================================================
// Application Setup
// ============================================================================

function initializeApp() {
  // ❌ BAD: Using weak secret
  // const secret = 'secret';
  
  // ✅ GOOD: Load from environment and validate
  const secret = process.env.JWT_SECRET;
  
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is required');
  }
  
  // GOOD: Validate on startup
  validateSecretStrength(secret);
  
  return {
    jwtSecret: secret
  };
}

// ============================================================================
// Secret Generation Script
// ============================================================================

// Run this to generate a strong secret:
// node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

function generateAndDisplaySecret() {
  const secret = generateStrongSecret(32);
  console.log('Generated secret:', secret);
  console.log('Length:', secret.length);
  console.log('Add this to your .env file as JWT_SECRET=' + secret);
  return secret;
}

// ============================================================================
// Express App with Secret Validation
// ============================================================================

const express = require('express');

function createSecureApp() {
  const app = express();
  
  // GOOD: Validate secret on startup
  try {
    const config = initializeApp();
    
    app.use((req, res, next) => {
      // Use validated secret
      req.jwtSecret = config.jwtSecret;
      next();
    });
    
    app.post('/api/login', (req, res) => {
      const { userId } = req.body;
      
      // GOOD: Use strong secret
      const token = jwt.sign(
        { userId: userId },
        config.jwtSecret, // Strong, validated secret
        { expiresIn: '1h' }
      );
      
      return res.json({ token });
    });
    
  } catch (error) {
    console.error('Failed to initialize app:', error.message);
    process.exit(1); // GOOD: Fail fast if secret is weak
  }
  
  return app;
}

// ============================================================================
// Secret Rotation Example
// ============================================================================

function rotateSecret(oldSecret, newSecret) {
  // GOOD: Validate new secret before rotation
  validateSecretStrength(newSecret);
  
  // GOOD: Ensure new secret is different
  if (oldSecret === newSecret) {
    throw new Error('New secret must be different from old secret');
  }
  
  // In production, you would:
  // 1. Update environment variable
  // 2. Restart services
  // 3. Invalidate old tokens (or support both during transition)
  
  return {
    oldSecret: oldSecret.substring(0, 8) + '...', // Don't log full secret
    newSecret: newSecret.substring(0, 8) + '...',
    rotated: true
  };
}

// ============================================================================
// Best Practice: Secret Management
// ============================================================================

class SecretManager {
  constructor() {
    this.secret = null;
  }
  
  loadSecret() {
    const secret = process.env.JWT_SECRET;
    
    if (!secret) {
      throw new Error('JWT_SECRET not found in environment');
    }
    
    // GOOD: Validate on load
    validateSecretStrength(secret);
    
    this.secret = secret;
    return this.secret;
  }
  
  getSecret() {
    if (!this.secret) {
      this.loadSecret();
    }
    return this.secret;
  }
  
  generateNewSecret() {
    return generateStrongSecret(32);
  }
}

// ============================================================================
// Example: Using hashed value as secret
// ============================================================================

function generateSecretFromHash(input) {
  // GOOD: Hash a random input to create secret
  // This is useful when you need to derive a secret from something
  const salt = crypto.randomBytes(16);
  const hash = crypto.createHash('sha256')
    .update(input)
    .update(salt)
    .digest('hex');
  
  return hash; // 64-character hex string
}

// Example usage:
// const secret = generateSecretFromHash('my-app-name-' + Date.now());

module.exports = {
  WEAK_SECRET_1,
  insecureGenerateToken,
  generateStrongSecret,
  generateStrongSecretByHash,
  validateSecretStrength,
  initializeApp,
  generateAndDisplaySecret,
  createSecureApp,
  rotateSecret,
  SecretManager,
  generateSecretFromHash
};
