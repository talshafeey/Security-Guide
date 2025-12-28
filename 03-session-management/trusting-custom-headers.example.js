/**
 * Example: Trusting Custom Headers
 * 
 * This file demonstrates the security issue of trusting client-provided headers
 * for system identity and shows the correct approach using authenticated tokens.
 */

const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: Trusting custom headers for system identity
// ============================================================================

function insecureGetAdminData(req, res) {
  // BAD: Trusts client-provided header
  const systemName = req.headers['x-system-name'];
  
  if (systemName === 'admin-portal') {
    // BAD: Anyone can set this header!
    return res.json({ adminData: 'sensitive information' });
  }
  
  return res.status(403).json({ error: 'Access denied' });
}

function insecureGetInternalData(req, res) {
  // BAD: Trusts multiple headers
  const systemName = req.headers['x-system-name'];
  const isInternal = req.headers['x-internal-request'] === 'true';
  
  if (systemName === 'internal' || isInternal) {
    // BAD: Headers can be faked!
    return res.json({ internalData: 'sensitive' });
  }
  
  return res.status(403).json({ error: 'Access denied' });
}

function insecureRouteWithHeaderCheck() {
  const express = require('express');
  const app = express();
  
  // BAD: Authorization based on header
  app.get('/api/admin/data', (req, res) => {
    const system = req.headers['x-system-name'];
    if (system === 'admin-portal') {
      return res.json({ data: 'admin data' });
    }
    return res.status(403).json({ error: 'Forbidden' });
  });
  
  return app;
}

// ============================================================================
// ✅ SECURE: System identity in authenticated token
// ============================================================================

function secureLogin(userId, systemName) {
  // GOOD: Include system identity in JWT token (authenticated)
  const token = jwt.sign(
    { 
      userId: userId,
      system: systemName // System identity in token, not header
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  return token;
}

function requireSystem(allowedSystems) {
  const systems = Array.isArray(allowedSystems) ? allowedSystems : [allowedSystems];
  
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // GOOD: Get system from authenticated token, not header
    const userSystem = req.user.system;
    if (!userSystem || !systems.includes(userSystem)) {
      return res.status(403).json({ 
        error: 'System not authorized for this endpoint' 
      });
    }
    
    next();
  };
}

function secureGetAdminData(req, res) {
  // Authorization handled by requireSystem middleware
  // System identity comes from token, not header
  return res.json({ adminData: 'sensitive information' });
}

function secureGetInternalData(req, res) {
  // Authorization handled by requireSystem middleware
  return res.json({ internalData: 'sensitive' });
}

// ============================================================================
// Express Route Examples
// ============================================================================

// ❌ INSECURE Routes
function insecureRoutes() {
  const express = require('express');
  const app = express();
  
  // BAD: Checks header directly
  app.get('/api/admin/data', (req, res) => {
    if (req.headers['x-system-name'] === 'admin-portal') {
      return res.json({ data: 'admin data' });
    }
    return res.status(403).json({ error: 'Forbidden' });
  });
  
  return app;
}

// ✅ SECURE Routes
function secureRoutes() {
  const express = require('express');
  const app = express();
  
  // GOOD: Auth middleware extracts system from token
  app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
      } catch (error) {
        // Invalid token
      }
    }
    next();
  });
  
  // GOOD: System check uses token, not header
  app.get('/api/admin/data',
    requireSystem('admin-portal'),
    secureGetAdminData
  );
  
  app.get('/api/internal/data',
    requireSystem('internal'),
    secureGetInternalData
  );
  
  return app;
}

// ============================================================================
// Common Mistakes to Avoid
// ============================================================================

function badPattern1(req, res) {
  // BAD: Trusting any header
  const isAdmin = req.headers['x-is-admin'] === 'true';
  if (isAdmin) {
    return res.json({ adminData: 'data' });
  }
  return res.status(403).json({ error: 'Forbidden' });
}

function badPattern2(req, res) {
  // BAD: Trusting IP or User-Agent
  const userAgent = req.headers['user-agent'];
  if (userAgent.includes('InternalService')) {
    return res.json({ internalData: 'data' });
  }
  return res.status(403).json({ error: 'Forbidden' });
}

function badPattern3(req, res) {
  // BAD: Trusting custom API key in header
  const apiKey = req.headers['x-api-key'];
  if (apiKey === process.env.INTERNAL_API_KEY) {
    // This is better, but still not ideal - API key can be leaked
    // Better to use proper authentication with system identity in token
    return res.json({ internalData: 'data' });
  }
  return res.status(403).json({ error: 'Forbidden' });
}

// ============================================================================
// Best Practice: System Identity in Token
// ============================================================================

function secureLoginWithSystem(userId, systemName, permissions) {
  // GOOD: All identity information in authenticated token
  const token = jwt.sign(
    { 
      userId: userId,
      system: systemName, // System identity
      permissions: permissions // Permissions
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  return token;
}

function secureMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    // GOOD: Extract all identity from token
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    // System identity is now in req.user.system (authenticated, not from header)
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = {
  insecureGetAdminData,
  insecureGetInternalData,
  insecureRouteWithHeaderCheck,
  secureLogin,
  requireSystem,
  secureGetAdminData,
  secureGetInternalData,
  insecureRoutes,
  secureRoutes,
  badPattern1,
  badPattern2,
  badPattern3,
  secureLoginWithSystem,
  secureMiddleware
};
