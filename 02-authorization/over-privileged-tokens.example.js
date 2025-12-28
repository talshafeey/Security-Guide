/**
 * Example: Over-Privileged Tokens
 * 
 * This file demonstrates the security issue of tokens granting excessive permissions
 * and shows how to implement proper per-API authorization checks.
 */

const jwt = require('jsonwebtoken');

// ============================================================================
// ❌ INSECURE: Token grants full access
// ============================================================================

function insecureLogin(userId, role) {
  // BAD: Token only contains user ID, no permissions
  const token = jwt.sign(
    { userId: userId, role: role },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  return token;
}

// BAD: API only checks if token is valid, not permissions
function insecureGetAllUsers(req, res) {
  // BAD: Any authenticated user can access this admin endpoint
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  // No permission check - any user can get all users!
  return res.json({ users: ['user1', 'user2', 'user3'] });
}

function insecureDeleteUser(req, res) {
  // BAD: Any authenticated user can delete users
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  // No permission check!
  const userId = req.params.id;
  // Delete user without checking if requester has permission
  return res.json({ message: `User ${userId} deleted` });
}

// ============================================================================
// ✅ SECURE: Token with permissions, per-API authorization
// ============================================================================

// Define permissions
const PERMISSIONS = {
  USERS_READ: 'users:read',
  USERS_WRITE: 'users:write',
  USERS_DELETE: 'users:delete',
  ADMIN_ACCESS: 'admin:access'
};

// User roles and their permissions
const ROLE_PERMISSIONS = {
  admin: [PERMISSIONS.USERS_READ, PERMISSIONS.USERS_WRITE, PERMISSIONS.USERS_DELETE, PERMISSIONS.ADMIN_ACCESS],
  user: [PERMISSIONS.USERS_READ], // Regular users can only read
  moderator: [PERMISSIONS.USERS_READ, PERMISSIONS.USERS_WRITE] // Can read and write, but not delete
};

function secureLogin(userId, role) {
  // GOOD: Include permissions in token
  const permissions = ROLE_PERMISSIONS[role] || [];
  
  const token = jwt.sign(
    { 
      userId: userId, 
      role: role,
      permissions: permissions // Include permissions in token
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  return token;
}

// GOOD: Authorization middleware that checks permissions
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // GOOD: Check if user has required permission
    const userPermissions = req.user.permissions || [];
    if (!userPermissions.includes(permission)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// GOOD: API with explicit permission check
function secureGetAllUsers(req, res) {
  // Authorization is handled by requirePermission middleware
  // Only users with USERS_READ permission can access
  return res.json({ users: ['user1', 'user2', 'user3'] });
}

function secureDeleteUser(req, res) {
  // Authorization is handled by requirePermission middleware
  // Only users with USERS_DELETE permission can access
  const userId = req.params.id;
  return res.json({ message: `User ${userId} deleted` });
}

// ============================================================================
// Express Route Examples
// ============================================================================

// ❌ INSECURE Routes
function insecureRoutes(app) {
  // BAD: No authorization check
  app.get('/api/users', insecureGetAllUsers);
  
  // BAD: Only authentication, no permission check
  app.delete('/api/users/:id', insecureDeleteUser);
}

// ✅ SECURE Routes
function secureRoutes(app) {
  // GOOD: Explicit permission requirement per route
  app.get('/api/users', 
    requirePermission(PERMISSIONS.USERS_READ),
    secureGetAllUsers
  );
  
  // GOOD: Different permission required
  app.delete('/api/users/:id',
    requirePermission(PERMISSIONS.USERS_DELETE),
    secureDeleteUser
  );
}

// ============================================================================
// Alternative: Check permissions in route handler
// ============================================================================

function secureGetAllUsersAlt(req, res) {
  // GOOD: Check permission inside handler
  const userPermissions = req.user.permissions || [];
  if (!userPermissions.includes(PERMISSIONS.USERS_READ)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  
  return res.json({ users: ['user1', 'user2', 'user3'] });
}

module.exports = {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  insecureLogin,
  secureLogin,
  requirePermission,
  insecureGetAllUsers,
  secureGetAllUsers,
  insecureDeleteUser,
  secureDeleteUser,
  secureGetAllUsersAlt,
  insecureRoutes,
  secureRoutes
};
