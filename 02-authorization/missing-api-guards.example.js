/**
 * Example: Missing API Guards
 * 
 * This file demonstrates the security issue of APIs without per-route authorization guards
 * and shows how to implement explicit route-level protection.
 */

const express = require('express');
const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: Global auth only, no per-route guards
// ============================================================================

function insecureAuthMiddleware(req, res, next) {
  // BAD: Only checks authentication globally
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// BAD: Routes rely only on global middleware
function insecureRoutes() {
  const app = express();
  
  // BAD: Global auth applied, but no per-route authorization
  app.use('/api', insecureAuthMiddleware);
  
  // BAD: Any authenticated user can access admin endpoint
  app.get('/api/admin/users', (req, res) => {
    res.json({ users: ['admin1', 'admin2'] });
  });
  
  // BAD: Any authenticated user can delete
  app.delete('/api/users/:id', (req, res) => {
    res.json({ message: 'User deleted' });
  });
  
  // BAD: Internal API exposed without proper guard
  app.get('/api/internal/config', (req, res) => {
    res.json({ config: process.env });
  });
  
  return app;
}

// ============================================================================
// ✅ SECURE: Per-route authorization guards
// ============================================================================

function secureAuthMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// GOOD: Authorization guard factory
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// GOOD: Permission-based guard
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const permissions = req.user.permissions || [];
    if (!permissions.includes(permission)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// GOOD: System identity guard
function requireSystem(systemName) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (req.user.system !== systemName) {
      return res.status(403).json({ error: 'System not authorized' });
    }
    
    next();
  };
}

// GOOD: Routes with explicit per-route guards
function secureRoutes() {
  const app = express();
  
  // GOOD: Apply auth middleware globally
  app.use('/api', secureAuthMiddleware);
  
  // GOOD: Admin endpoint requires admin role
  app.get('/api/admin/users',
    requireRole('admin'), // Explicit guard
    (req, res) => {
      res.json({ users: ['admin1', 'admin2'] });
    }
  );
  
  // GOOD: Delete requires specific permission
  app.delete('/api/users/:id',
    requirePermission('users:delete'), // Explicit guard
    (req, res) => {
      res.json({ message: 'User deleted' });
    }
  );
  
  // GOOD: Internal API requires internal system
  app.get('/api/internal/config',
    requireSystem('internal'), // Explicit guard
    (req, res) => {
      res.json({ config: process.env });
    }
  );
  
  // GOOD: Public endpoint (no guard needed)
  app.get('/api/public/info', (req, res) => {
    res.json({ info: 'Public information' });
  });
  
  return app;
}

// ============================================================================
// NestJS Example (conceptual)
// ============================================================================

/*
// GOOD: NestJS Guard example
@Controller('users')
export class UsersController {
  @Get('admin')
  @UseGuards(AuthGuard, RolesGuard) // Explicit guards
  @Roles('admin') // Metadata for guard
  getAdminUsers() {
    return { users: ['admin1', 'admin2'] };
  }
  
  @Delete(':id')
  @UseGuards(AuthGuard, PermissionsGuard)
  @RequirePermissions('users:delete')
  deleteUser(@Param('id') id: string) {
    return { message: 'User deleted' };
  }
}
*/

// ============================================================================
// Best Practice: Default Deny
// ============================================================================

function secureRoutesWithDefaultDeny() {
  const app = express();
  
  // GOOD: Apply auth to all /api routes
  app.use('/api', secureAuthMiddleware);
  
  // GOOD: By default, deny access unless explicitly allowed
  app.use('/api', (req, res, next) => {
    // Default: deny unless route has explicit guard
    return res.status(403).json({ error: 'Access denied' });
  });
  
  // GOOD: Explicitly allow with guard
  app.get('/api/public/info',
    // No guard = public access
    (req, res) => {
      res.json({ info: 'Public information' });
    }
  );
  
  return app;
}

module.exports = {
  insecureAuthMiddleware,
  insecureRoutes,
  secureAuthMiddleware,
  requireRole,
  requirePermission,
  requireSystem,
  secureRoutes,
  secureRoutesWithDefaultDeny
};
