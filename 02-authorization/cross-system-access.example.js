/**
 * Example: Cross-System Access
 * 
 * This file demonstrates the security issue of systems accessing each other's APIs
 * without proper isolation and shows how to enforce system-level authorization.
 */

const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: No system identity check
// ============================================================================

function insecureLogin(userId, systemName) {
  // BAD: System name not included in token
  const token = jwt.sign(
    { userId: userId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  return token;
}

// BAD: API doesn't check which system is calling
function insecureGetAdminData(req, res) {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  // BAD: No system check - any system can access admin data
  return res.json({ adminData: 'sensitive information' });
}

// BAD: Trusts custom header for system identity
function insecureGetInternalData(req, res) {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  // BAD: Trusts client-provided header
  const systemName = req.headers['x-system-name'];
  if (systemName === 'internal') {
    return res.json({ internalData: 'sensitive' });
  }
  
  return res.status(403).json({ error: 'Access denied' });
}

// ============================================================================
// ✅ SECURE: System identity in token, verified per API
// ============================================================================

function secureLogin(userId, systemName) {
  // GOOD: Include system identity in token (authenticated)
  const token = jwt.sign(
    { 
      userId: userId,
      system: systemName // System identity in token
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  return token;
}

// GOOD: System authorization guard
function requireSystem(allowedSystems) {
  const systems = Array.isArray(allowedSystems) ? allowedSystems : [allowedSystems];
  
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // GOOD: Verify system identity from token (not header)
    const userSystem = req.user.system;
    if (!userSystem || !systems.includes(userSystem)) {
      return res.status(403).json({ 
        error: 'System not authorized for this endpoint' 
      });
    }
    
    next();
  };
}

// GOOD: API with system-level authorization
function secureGetAdminData(req, res) {
  // Authorization handled by requireSystem middleware
  // Only 'admin-portal' system can access
  return res.json({ adminData: 'sensitive information' });
}

function secureGetInternalData(req, res) {
  // Authorization handled by requireSystem middleware
  // Only 'internal' system can access
  return res.json({ internalData: 'sensitive' });
}

// GOOD: API accessible by multiple systems
function secureGetSharedData(req, res) {
  // Authorization handled by requireSystem middleware
  // Both 'customer-portal' and 'admin-portal' can access
  return res.json({ sharedData: 'accessible by multiple systems' });
}

// ============================================================================
// Express Route Examples
// ============================================================================

// ❌ INSECURE Routes
function insecureRoutes() {
  const express = require('express');
  const app = express();
  
  // BAD: No system check
  app.get('/api/admin/data', insecureGetAdminData);
  
  // BAD: Trusts header
  app.get('/api/internal/data', insecureGetInternalData);
  
  return app;
}

// ✅ SECURE Routes
function secureRoutes() {
  const express = require('express');
  const app = express();
  
  // GOOD: Admin endpoint only for admin-portal system
  app.get('/api/admin/data',
    requireSystem('admin-portal'),
    secureGetAdminData
  );
  
  // GOOD: Internal endpoint only for internal system
  app.get('/api/internal/data',
    requireSystem('internal'),
    secureGetInternalData
  );
  
  // GOOD: Shared endpoint for multiple systems
  app.get('/api/shared/data',
    requireSystem(['customer-portal', 'admin-portal']),
    secureGetSharedData
  );
  
  return app;
}

// ============================================================================
// Combined: System + User Permissions
// ============================================================================

function requireSystemAndPermission(system, permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // GOOD: Check system identity
    if (req.user.system !== system) {
      return res.status(403).json({ error: 'System not authorized' });
    }
    
    // GOOD: Check user permission
    const permissions = req.user.permissions || [];
    if (!permissions.includes(permission)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// ============================================================================
// System Definitions
// ============================================================================

const SYSTEMS = {
  CUSTOMER_PORTAL: 'customer-portal',
  ADMIN_PORTAL: 'admin-portal',
  INTERNAL: 'internal',
  MOBILE_APP: 'mobile-app'
};

// Define which systems can access which endpoints
const SYSTEM_ACCESS_RULES = {
  '/api/admin/data': [SYSTEMS.ADMIN_PORTAL],
  '/api/internal/data': [SYSTEMS.INTERNAL],
  '/api/customer/data': [SYSTEMS.CUSTOMER_PORTAL, SYSTEMS.MOBILE_APP],
  '/api/shared/data': [SYSTEMS.CUSTOMER_PORTAL, SYSTEMS.ADMIN_PORTAL]
};

module.exports = {
  SYSTEMS,
  SYSTEM_ACCESS_RULES,
  insecureLogin,
  secureLogin,
  requireSystem,
  requireSystemAndPermission,
  insecureGetAdminData,
  secureGetAdminData,
  insecureGetInternalData,
  secureGetInternalData,
  secureGetSharedData,
  insecureRoutes,
  secureRoutes
};
