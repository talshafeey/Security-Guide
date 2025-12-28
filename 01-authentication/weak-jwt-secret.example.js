/**
 * Example: Weak JWT Secret
 * 
 * This file demonstrates the security issue of using weak or guessable JWT secrets
 * and shows how to generate and use strong secrets.
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ============================================================================
// ❌ INSECURE: Weak secrets
// ============================================================================

// BAD: Short, guessable secret
const WEAK_SECRET_1 = 'secret';
const WEAK_SECRET_2 = 'myapp123';
const WEAK_SECRET_3 = 'jwt-secret-key';
const WEAK_SECRET_4 = '1234567890'; // Only 10 characters

function insecureGenerateToken(userId) {
  // BAD: Using weak secret
  const token = jwt.sign(
    { userId: userId },
    WEAK_SECRET_1, // Easy to guess!
    { expiresIn: '1h' }
  );
  return token;
}

// ============================================================================
// ✅ SECURE: Strong secrets
// ============================================================================

// GOOD: Generate strong secret (32+ characters, high entropy)
function generateStrongSecret() {
  // Option 1: Use crypto.randomBytes (recommended)
  return crypto.randomBytes(32).toString('hex'); // 64 character hex string
  
  // Option 2: Hash a random value
  // return crypto.createHash('sha256').update(crypto.randomBytes(16)).digest('hex');
}

// GOOD: Strong secret stored in environment variable
// In .env file: JWT_SECRET=<64-character-random-hex-string>
const STRONG_SECRET = process.env.JWT_SECRET; // Load from environment

function secureGenerateToken(userId) {
  if (!STRONG_SECRET || STRONG_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }
  
  // GOOD: Using strong secret
  const token = jwt.sign(
    { userId: userId },
    STRONG_SECRET, // Strong, random, unguessable
    { expiresIn: '1h' }
  );
  return token;
}

// ============================================================================
// Secret Validation Function
// ============================================================================

function validateSecretStrength(secret) {
  if (!secret) {
    throw new Error('Secret is required');
  }
  
  if (secret.length < 32) {
    throw new Error('Secret must be at least 32 characters long');
  }
  
  // Check for common weak patterns
  const weakPatterns = [
    /^secret/i,
    /^password/i,
    /^12345/,
    /^admin/,
    /^test/,
    /^dev/,
    /^prod/
  ];
  
  for (const pattern of weakPatterns) {
    if (pattern.test(secret)) {
      throw new Error('Secret contains weak patterns');
    }
  }
  
  return true;
}

// ============================================================================
// Example: Secret Generation Script
// ============================================================================

// Run this once to generate a strong secret:
// node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

// ============================================================================
// Express App Initialization
// ============================================================================

function initializeApp() {
  // ❌ BAD: Using weak secret
  // const secret = 'secret';
  
  // ✅ GOOD: Validate secret on startup
  const secret = process.env.JWT_SECRET;
  validateSecretStrength(secret);
  
  return {
    jwtSecret: secret
  };
}

module.exports = {
  insecureGenerateToken,
  secureGenerateToken,
  generateStrongSecret,
  validateSecretStrength,
  initializeApp
};
