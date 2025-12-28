/**
 * Example: Unsafe Update Patterns (Mass Assignment)
 * 
 * This file demonstrates the security issue of mass assignment vulnerabilities
 * and shows how to explicitly control which fields can be updated.
 */

const express = require('express');

// Mock database
const users = [
  { id: 1, email: 'user1@example.com', name: 'User 1', role: 'user', isAdmin: false, is2FAEnabled: true }
];

// ============================================================================
// ❌ INSECURE: Mass assignment - accepting all fields
// ============================================================================

function insecureUpdateUser(userId, updateData) {
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  // BAD: Updates all fields from request without filtering
  // Attacker can send: { role: 'admin', isAdmin: true, is2FAEnabled: false }
  Object.assign(user, updateData); // VULNERABLE!
  
  return user;
}

// BAD: Using ORM spread operator
async function insecureORMUpdate(userId, updateData) {
  const User = require('./models/User'); // Example ORM model
  
  // BAD: Spreads entire request body into update
  await User.update(
    { ...updateData }, // VULNERABLE! Accepts any field
    { where: { id: userId } }
  );
}

// ============================================================================
// ✅ SECURE: Explicit field whitelist
// ============================================================================

function secureUpdateUser(userId, updateData) {
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  // GOOD: Define allowed fields explicitly
  const allowedFields = ['name', 'phone', 'avatar'];
  
  // GOOD: Only update allowed fields
  const safeUpdates = {};
  for (const field of allowedFields) {
    if (updateData[field] !== undefined) {
      safeUpdates[field] = updateData[field];
    }
  }
  
  // GOOD: Apply only safe updates
  Object.assign(user, safeUpdates);
  
  return user;
}

// GOOD: Using ORM with explicit fields
async function secureORMUpdate(userId, updateData) {
  const User = require('./models/User');
  
  // GOOD: Explicitly list allowed fields
  const allowedFields = ['name', 'phone', 'avatar'];
  const safeUpdates = {};
  
  for (const field of allowedFields) {
    if (updateData[field] !== undefined) {
      safeUpdates[field] = updateData[field];
    }
  }
  
  // GOOD: Update only with safe fields
  await User.update(
    safeUpdates, // GOOD: Only allowed fields
    { where: { id: userId } }
  );
}

// ============================================================================
// Express Route Examples
// ============================================================================

// ❌ INSECURE Route
function insecureRoute() {
  const app = express();
  app.use(express.json());
  
  app.put('/api/users/:id', (req, res) => {
    const userId = parseInt(req.params.id);
    const updateData = req.body; // BAD: Accepts entire body
    
    try {
      const user = insecureUpdateUser(userId, updateData);
      return res.json({ user });
    } catch (error) {
      return res.status(404).json({ error: error.message });
    }
  });
  
  return app;
}

// ✅ SECURE Route
function secureRoute() {
  const app = express();
  app.use(express.json());
  
  app.put('/api/users/:id', (req, res) => {
    const userId = parseInt(req.params.id);
    const updateData = req.body;
    
    try {
      const user = secureUpdateUser(userId, updateData);
      return res.json({ user });
    } catch (error) {
      return res.status(404).json({ error: error.message });
    }
  });
  
  return app;
}

// ============================================================================
// Field-level authorization
// ============================================================================

function secureUpdateWithRoleCheck(userId, updateData, requesterRole) {
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  const safeUpdates = {};
  
  // GOOD: Different fields allowed based on role
  if (requesterRole === 'admin') {
    // Admin can update more fields
    const adminAllowedFields = ['name', 'phone', 'avatar', 'role', 'is2FAEnabled'];
    for (const field of adminAllowedFields) {
      if (updateData[field] !== undefined) {
        safeUpdates[field] = updateData[field];
      }
    }
  } else {
    // Regular users can only update limited fields
    const userAllowedFields = ['name', 'phone', 'avatar'];
    for (const field of userAllowedFields) {
      if (updateData[field] !== undefined) {
        safeUpdates[field] = updateData[field];
      }
    }
  }
  
  Object.assign(user, safeUpdates);
  return user;
}

// ============================================================================
// TypeORM Example
// ============================================================================

/*
// ❌ BAD: TypeORM mass assignment
import { getRepository } from 'typeorm';

async function insecureTypeORMUpdate(userId: number, updateData: any) {
  const userRepository = getRepository(User);
  const user = await userRepository.findOne(userId);
  
  // BAD: Spreads all fields
  Object.assign(user, updateData);
  await userRepository.save(user);
}
*/

/*
// ✅ GOOD: TypeORM with field whitelist
import { getRepository } from 'typeorm';

async function secureTypeORMUpdate(userId: number, updateData: any) {
  const userRepository = getRepository(User);
  const user = await userRepository.findOne(userId);
  
  // GOOD: Explicit field updates
  const allowedFields = ['name', 'phone', 'avatar'];
  for (const field of allowedFields) {
    if (updateData[field] !== undefined) {
      user[field] = updateData[field];
    }
  }
  
  await userRepository.save(user);
}

// ✅ GOOD: TypeORM column protection
// In entity definition:
@Entity()
export class User {
  @Column({ update: false }) // GOOD: Prevents updates to this field
  email: string;
  
  @Column()
  name: string;
  
  @Column({ update: false })
  role: string; // GOOD: Cannot be updated via ORM
}
*/

// ============================================================================
// Prisma Example
// ============================================================================

/*
// ❌ BAD: Prisma mass assignment
async function insecurePrismaUpdate(userId: number, updateData: any) {
  const prisma = new PrismaClient();
  
  // BAD: Updates all fields from request
  await prisma.user.update({
    where: { id: userId },
    data: updateData // VULNERABLE!
  });
}
*/

/*
// ✅ GOOD: Prisma with explicit fields
async function securePrismaUpdate(userId: number, updateData: any) {
  const prisma = new PrismaClient();
  
  // GOOD: Explicitly specify allowed fields
  const allowedFields = ['name', 'phone', 'avatar'];
  const safeData = {};
  
  for (const field of allowedFields) {
    if (updateData[field] !== undefined) {
      safeData[field] = updateData[field];
    }
  }
  
  await prisma.user.update({
    where: { id: userId },
    data: safeData // GOOD: Only allowed fields
  });
}
*/

// ============================================================================
// Helper: Field whitelist utility
// ============================================================================

function whitelistFields(data, allowedFields) {
  const safeData = {};
  
  for (const field of allowedFields) {
    if (data[field] !== undefined) {
      safeData[field] = data[field];
    }
  }
  
  return safeData;
}

function secureUpdateWithHelper(userId, updateData) {
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  // GOOD: Use helper to filter fields
  const allowedFields = ['name', 'phone', 'avatar'];
  const safeUpdates = whitelistFields(updateData, allowedFields);
  
  Object.assign(user, safeUpdates);
  return user;
}

// ============================================================================
// Best Practice: Separate DTOs
// ============================================================================

// GOOD: Define update DTO with only allowed fields
class UpdateUserDTO {
  name?: string;
  phone?: string;
  avatar?: string;
  // Note: role, isAdmin, etc. are NOT here - they cannot be updated
}

function secureUpdateWithDTO(userId, dto) {
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  // GOOD: DTO only contains allowed fields
  if (dto.name !== undefined) user.name = dto.name;
  if (dto.phone !== undefined) user.phone = dto.phone;
  if (dto.avatar !== undefined) user.avatar = dto.avatar;
  
  return user;
}

module.exports = {
  insecureUpdateUser,
  insecureORMUpdate,
  secureUpdateUser,
  secureORMUpdate,
  insecureRoute,
  secureRoute,
  secureUpdateWithRoleCheck,
  whitelistFields,
  secureUpdateWithHelper,
  UpdateUserDTO,
  secureUpdateWithDTO
};
