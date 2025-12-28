/**
 * Example: Token Invalidation on Logout
 * 
 * This file demonstrates the security issue of tokens remaining valid after logout
 * and shows the correct implementation using Redis.
 */

const jwt = require('jsonwebtoken');
const redis = require('redis');

// ============================================================================
// ❌ INSECURE: Logout doesn't invalidate tokens
// ============================================================================

function insecureLogin(userId) {
  // BAD: Token is issued but not tracked
  const token = jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  // Token is not stored anywhere - can't be invalidated
  return token;
}

function insecureLogout(token) {
  // BAD: Logout does nothing server-side
  // Token remains valid until it expires naturally
  return { message: 'Logged out' }; // But token still works!
}

function insecureVerifyToken(token) {
  try {
    // BAD: Only checks signature and expiry
    // Doesn't check if token was logged out
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded; // Returns even if user logged out
  } catch (error) {
    return null;
  }
}

// ============================================================================
// ✅ SECURE: Token tracked and invalidated on logout
// ============================================================================

// Initialize Redis client
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});

async function secureLogin(userId) {
  // GOOD: Token is issued AND stored in Redis
  const token = jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  
  // Store token in Redis with same expiry as JWT
  await redisClient.setex(`token:${token}`, 86400, 'valid'); // 24 hours
  
  return token;
}

async function secureLogout(token) {
  // GOOD: Token is marked as invalid in Redis
  await redisClient.del(`token:${token}`);
  return { message: 'Logged out successfully' };
}

async function secureVerifyToken(token) {
  try {
    // GOOD: First verify JWT signature and expiry
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // GOOD: Then check if token is still valid in Redis
    const tokenStatus = await redisClient.get(`token:${token}`);
    if (!tokenStatus) {
      // Token was logged out or doesn't exist
      return null;
    }
    
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      // Also remove expired tokens from Redis
      await redisClient.del(`token:${token}`);
    }
    return null;
  }
}

// ============================================================================
// Express Middleware Example
// ============================================================================

// ❌ INSECURE Middleware
async function insecureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const decoded = insecureVerifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  req.user = decoded;
  next(); // Allows logged-out tokens!
}

// ✅ SECURE Middleware
async function secureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const decoded = await secureVerifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid, expired, or logged-out token' });
  }
  
  req.user = decoded;
  next();
}

module.exports = {
  insecureLogin,
  insecureLogout,
  insecureVerifyToken,
  secureLogin,
  secureLogout,
  secureVerifyToken,
  insecureAuthMiddleware,
  secureAuthMiddleware
};
