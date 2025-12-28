/**
 * Example: Redis Session Validation
 * 
 * This file demonstrates the security issue of validating tokens only by signature
 * without checking server-side state, and shows the correct implementation using Redis.
 */

const jwt = require('jsonwebtoken');
const redis = require('redis');

// Initialize Redis client
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379
});

// ============================================================================
// ❌ INSECURE: Token validation without Redis check
// ============================================================================

function insecureLogin(userId) {
  // BAD: Token is issued but not registered in Redis
  const token = jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  // Token is not stored - can't verify if it was actually issued
  return token;
}

function insecureVerifyToken(token) {
  try {
    // BAD: Only checks JWT signature and expiry
    // Doesn't check if token exists in Redis
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded; // Returns even if token was never issued!
  } catch (error) {
    return null;
  }
}

function insecureLogout(token) {
  // BAD: Logout doesn't invalidate token in Redis
  // Token remains valid until JWT expires
  return { message: 'Logged out' }; // But token still works!
}

// ============================================================================
// ✅ SECURE: Token registered and validated via Redis
// ============================================================================

async function secureLogin(userId) {
  // GOOD: Generate token
  const token = jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  
  // GOOD: Register token in Redis with same expiry as JWT
  const tokenKey = `token:${token}`;
  await redisClient.setex(tokenKey, 86400, 'valid'); // 24 hours in seconds
  
  return token;
}

async function secureVerifyToken(token) {
  try {
    // GOOD: First verify JWT signature and expiry
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // GOOD: Then check if token exists in Redis (was actually issued)
    const tokenKey = `token:${token}`;
    const tokenStatus = await redisClient.get(tokenKey);
    
    if (!tokenStatus) {
      // Token was never issued, was logged out, or expired in Redis
      return null;
    }
    
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      // Also clean up expired tokens from Redis
      const tokenKey = `token:${token}`;
      await redisClient.del(tokenKey);
    }
    return null;
  }
}

async function secureLogout(token) {
  // GOOD: Remove token from Redis to invalidate it
  const tokenKey = `token:${token}`;
  await redisClient.del(tokenKey);
  
  return { message: 'Logged out successfully' };
}

// ============================================================================
// Express Middleware Examples
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
  next(); // Allows forged or logged-out tokens!
}

// ✅ SECURE Middleware
async function secureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const decoded = await secureVerifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid, expired, or unknown token' });
  }
  
  req.user = decoded;
  next();
}

// ============================================================================
// Enhanced: Track logged-out tokens that haven't expired yet
// ============================================================================

async function secureLogoutWithExpiredTracking(token) {
  try {
    // Decode token to get expiry
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) {
      await redisClient.del(`token:${token}`);
      return { message: 'Logged out' };
    }
    
    // Calculate remaining TTL
    const now = Math.floor(Date.now() / 1000);
    const remainingTTL = decoded.exp - now;
    
    if (remainingTTL > 0) {
      // GOOD: Mark token as logged out, keep until JWT expires
      // This prevents reuse even if JWT hasn't expired yet
      const tokenKey = `token:${token}`;
      await redisClient.setex(tokenKey, remainingTTL, 'logged-out');
    } else {
      // Token already expired, just remove it
      await redisClient.del(`token:${token}`);
    }
    
    return { message: 'Logged out successfully' };
  } catch (error) {
    return { message: 'Error during logout' };
  }
}

async function secureVerifyTokenWithLogoutCheck(token) {
  try {
    // Verify JWT signature and expiry
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check Redis for token status
    const tokenKey = `token:${token}`;
    const tokenStatus = await redisClient.get(tokenKey);
    
    if (!tokenStatus) {
      // Token was never issued or already expired
      return null;
    }
    
    if (tokenStatus === 'logged-out') {
      // GOOD: Token was logged out but JWT hasn't expired yet
      // Reject it anyway
      return null;
    }
    
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      // Clean up expired tokens
      const tokenKey = `token:${token}`;
      await redisClient.del(tokenKey);
    }
    return null;
  }
}

// ============================================================================
// Token Refresh Example
// ============================================================================

async function secureRefreshToken(oldToken) {
  // Verify old token is valid
  const decoded = await secureVerifyToken(oldToken);
  if (!decoded) {
    throw new Error('Invalid token');
  }
  
  // Generate new token
  const newToken = jwt.sign(
    { userId: decoded.userId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  
  // Register new token
  await redisClient.setex(`token:${newToken}`, 86400, 'valid');
  
  // Invalidate old token
  await redisClient.del(`token:${oldToken}`);
  
  return newToken;
}

module.exports = {
  insecureLogin,
  insecureVerifyToken,
  insecureLogout,
  secureLogin,
  secureVerifyToken,
  secureLogout,
  insecureAuthMiddleware,
  secureAuthMiddleware,
  secureLogoutWithExpiredTracking,
  secureVerifyTokenWithLogoutCheck,
  secureRefreshToken
};
