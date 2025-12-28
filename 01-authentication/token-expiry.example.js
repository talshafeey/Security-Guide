/**
 * Example: Token Expiry
 * 
 * This file demonstrates the security issue of tokens without expiry
 * and shows the correct implementation.
 */

const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: Token without expiry
// ============================================================================

function insecureGenerateToken(userId) {
  // BAD: Token never expires - can be used indefinitely
  const token = jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET,
    // Missing expiresIn - token is valid forever!
  );
  return token;
}

function insecureVerifyToken(token) {
  try {
    // BAD: Only checks signature, ignores expiry
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded; // Returns even if token is years old
  } catch (error) {
    return null;
  }
}

// ============================================================================
// ✅ SECURE: Token with proper expiry
// ============================================================================

function secureGenerateToken(userId) {
  // GOOD: Token expires after 1 hour
  const token = jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET,
    { expiresIn: '1h' } // Token expires in 1 hour
  );
  return token;
}

function secureVerifyToken(token) {
  try {
    // GOOD: jwt.verify automatically checks expiry
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // If token is expired, jwt.verify throws an error
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      console.log('Token has expired');
      return null;
    }
    return null;
  }
}

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
  next(); // Allows expired tokens!
}

// ✅ SECURE Middleware
function secureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const decoded = secureVerifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  req.user = decoded;
  next();
}

module.exports = {
  insecureGenerateToken,
  insecureVerifyToken,
  secureGenerateToken,
  secureVerifyToken,
  insecureAuthMiddleware,
  secureAuthMiddleware
};
