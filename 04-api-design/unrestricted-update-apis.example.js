/**
 * Example: Unrestricted Update APIs
 * 
 * This file demonstrates the security issue of update APIs that don't verify
 * resource ownership and shows how to implement proper authorization checks.
 */

const express = require('express');

// Mock database
const users = [
  { id: 1, email: 'user1@example.com', name: 'User 1', ownerId: 1 },
  { id: 2, email: 'user2@example.com', name: 'User 2', ownerId: 2 },
  { id: 3, email: 'admin@example.com', name: 'Admin', ownerId: 3, role: 'admin' }
];

// ============================================================================
// ❌ INSECURE: Update API without ownership check
// ============================================================================

function insecureUpdateUser(req, res) {
  const userId = parseInt(req.params.id); // BAD: Trusts client-provided ID
  const updates = req.body;
  
  // BAD: No check if requester owns this user
  // BAD: No check if requester has permission to update this resource
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // BAD: Updates without authorization
  Object.assign(user, updates);
  
  return res.json({ message: 'User updated', user });
}

function insecureUpdateUserEmail(req, res) {
  const userId = parseInt(req.params.id);
  const { email } = req.body;
  
  // BAD: User can update ANY user's email, including other users
  // This allows privilege escalation - update another user's email and login as them
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  user.email = email; // BAD: No ownership check!
  
  return res.json({ message: 'Email updated', user });
}

// ============================================================================
// ✅ SECURE: Update API with ownership verification
// ============================================================================

function secureUpdateUser(req, res) {
  const userId = parseInt(req.params.id);
  const updates = req.body;
  const requesterId = req.user.userId; // From authenticated token
  
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // GOOD: Verify ownership
  if (user.ownerId !== requesterId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized to update this user' });
  }
  
  // GOOD: Protect sensitive fields
  const allowedFields = ['name', 'phone']; // Only allow certain fields
  const filteredUpdates = {};
  for (const field of allowedFields) {
    if (updates[field] !== undefined) {
      filteredUpdates[field] = updates[field];
    }
  }
  
  Object.assign(user, filteredUpdates);
  
  return res.json({ message: 'User updated', user });
}

function secureUpdateUserEmail(req, res) {
  const userId = parseInt(req.params.id);
  const { email } = req.body;
  const requesterId = req.user.userId;
  
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // GOOD: Only allow updating own email (or admin)
  if (user.ownerId !== requesterId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized to update this email' });
  }
  
  // GOOD: Additional validation
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  
  user.email = email;
  
  return res.json({ message: 'Email updated', user });
}

// ============================================================================
// Express Route Examples
// ============================================================================

// ❌ INSECURE Routes
function insecureRoutes() {
  const app = express();
  app.use(express.json());
  
  // BAD: No ownership check
  app.put('/api/users/:id', insecureUpdateUser);
  app.patch('/api/users/:id/email', insecureUpdateUserEmail);
  
  return app;
}

// ✅ SECURE Routes
function secureRoutes() {
  const app = express();
  app.use(express.json());
  
  // GOOD: With ownership verification
  app.put('/api/users/:id', secureUpdateUser);
  app.patch('/api/users/:id/email', secureUpdateUserEmail);
  
  return app;
}

// ============================================================================
// Helper: Ownership verification middleware
// ============================================================================

function verifyOwnership(resourceType) {
  return async (req, res, next) => {
    const resourceId = parseInt(req.params.id);
    const requesterId = req.user.userId;
    
    // GOOD: Fetch resource and verify ownership
    let resource;
    if (resourceType === 'user') {
      resource = users.find(u => u.id === resourceId);
    }
    // Add other resource types as needed
    
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    
    // GOOD: Check ownership or admin role
    if (resource.ownerId !== requesterId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // GOOD: Attach resource to request for use in handler
    req.resource = resource;
    next();
  };
}

function secureUpdateUserWithMiddleware(req, res) {
  // Resource ownership already verified by middleware
  const updates = req.body;
  const user = req.resource;
  
  // GOOD: Filter allowed fields
  const allowedFields = ['name', 'phone'];
  const filteredUpdates = {};
  for (const field of allowedFields) {
    if (updates[field] !== undefined) {
      filteredUpdates[field] = updates[field];
    }
  }
  
  Object.assign(user, filteredUpdates);
  
  return res.json({ message: 'User updated', user });
}

// ============================================================================
// Advanced: Field-level authorization
// ============================================================================

function secureUpdateWithFieldChecks(req, res) {
  const userId = parseInt(req.params.id);
  const updates = req.body;
  const requesterId = req.user.userId;
  const requesterRole = req.user.role;
  
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // GOOD: Verify ownership
  const isOwner = user.ownerId === requesterId;
  const isAdmin = requesterRole === 'admin';
  
  if (!isOwner && !isAdmin) {
    return res.status(403).json({ error: 'Not authorized' });
  }
  
  // GOOD: Field-level authorization
  const allowedUpdates = {};
  
  // Everyone can update these
  if (updates.name !== undefined) {
    allowedUpdates.name = updates.name;
  }
  
  // Only owner or admin can update email
  if (updates.email !== undefined && (isOwner || isAdmin)) {
    allowedUpdates.email = updates.email;
  }
  
  // Only admin can update role
  if (updates.role !== undefined && isAdmin) {
    allowedUpdates.role = updates.role;
  }
  
  // GOOD: System-controlled fields cannot be updated
  // (e.g., createdAt, id, etc.)
  
  Object.assign(user, allowedUpdates);
  
  return res.json({ message: 'User updated', user });
}

// ============================================================================
// Best Practice: Resource-level authorization helper
// ============================================================================

async function checkResourceAccess(resourceId, requesterId, requesterRole, resourceType) {
  let resource;
  
  if (resourceType === 'user') {
    resource = users.find(u => u.id === resourceId);
  }
  
  if (!resource) {
    return { allowed: false, error: 'Resource not found' };
  }
  
  const isOwner = resource.ownerId === requesterId;
  const isAdmin = requesterRole === 'admin';
  
  if (!isOwner && !isAdmin) {
    return { allowed: false, error: 'Not authorized' };
  }
  
  return { allowed: true, resource, isOwner, isAdmin };
}

module.exports = {
  insecureUpdateUser,
  insecureUpdateUserEmail,
  secureUpdateUser,
  secureUpdateUserEmail,
  insecureRoutes,
  secureRoutes,
  verifyOwnership,
  secureUpdateUserWithMiddleware,
  secureUpdateWithFieldChecks,
  checkResourceAccess
};
