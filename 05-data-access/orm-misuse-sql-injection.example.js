/**
 * Example: ORM Misuse and SQL Injection
 * 
 * This file demonstrates the security issue of SQL injection through incorrect ORM usage
 * and shows how to use parameterized queries correctly.
 */

// Using Sequelize as example ORM (similar patterns apply to TypeORM, Prisma, etc.)

// ============================================================================
// ❌ INSECURE: Direct string concatenation in queries
// ============================================================================

const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize(process.env.DATABASE_URL);

// BAD: String concatenation - vulnerable to SQL injection
async function insecureFindUser(userName) {
  // BAD: User input directly in query string
  const query = `SELECT * FROM users WHERE email = '${userName}'`;
  const [results] = await sequelize.query(query);
  return results;
}

// BAD: Using ORM but with raw string interpolation
async function insecureFindUserWithORM(userName) {
  const User = sequelize.define('User', {
    email: DataTypes.STRING
  });
  
  // BAD: Using raw SQL with string interpolation
  return await User.findAll({
    where: sequelize.literal(`email = '${userName}'`) // VULNERABLE!
  });
}

// BAD: Dynamic query building with user input
async function insecureDynamicQuery(filters) {
  let query = 'SELECT * FROM users WHERE 1=1';
  
  // BAD: Building query string from user input
  if (filters.email) {
    query += ` AND email = '${filters.email}'`;
  }
  if (filters.role) {
    query += ` AND role = '${filters.role}'`;
  }
  
  const [results] = await sequelize.query(query);
  return results;
}

// ============================================================================
// ✅ SECURE: Parameterized queries
// ============================================================================

// GOOD: Using parameterized queries
async function secureFindUser(userName) {
  // GOOD: Parameterized query - user input is bound, not concatenated
  const query = `SELECT * FROM users WHERE email = :userName`;
  const [results] = await sequelize.query(query, {
    replacements: { userName: userName } // GOOD: Parameter binding
  });
  return results;
}

// GOOD: Using ORM methods correctly
async function secureFindUserWithORM(userName) {
  const User = sequelize.define('User', {
    email: DataTypes.STRING
  });
  
  // GOOD: ORM handles parameterization automatically
  return await User.findAll({
    where: {
      email: userName // GOOD: ORM parameterizes this
    }
  });
}

// GOOD: Dynamic query with proper parameterization
async function secureDynamicQuery(filters) {
  const User = sequelize.define('User', {
    email: DataTypes.STRING,
    role: DataTypes.STRING
  });
  
  // GOOD: Build where clause object, not string
  const whereClause = {};
  
  if (filters.email) {
    whereClause.email = filters.email; // GOOD: Parameterized
  }
  if (filters.role) {
    whereClause.role = filters.role; // GOOD: Parameterized
  }
  
  return await User.findAll({
    where: whereClause // GOOD: ORM handles parameterization
  });
}

// ============================================================================
// Express Route Examples
// ============================================================================

const express = require('express');

// ❌ INSECURE Route
function insecureRoute() {
  const app = express();
  
  app.get('/api/users/generateOTP', async (req, res) => {
    const userName = req.query.email;
    
    // BAD: Vulnerable to SQL injection
    const user = await insecureFindUser(userName);
    
    if (user.length > 0) {
      // Generate OTP...
      return res.json({ message: 'OTP generated' });
    }
    
    return res.status(404).json({ error: 'User not found' });
  });
  
  return app;
}

// ✅ SECURE Route
function secureRoute() {
  const app = express();
  
  app.get('/api/users/generateOTP', async (req, res) => {
    const userName = req.query.email;
    
    // GOOD: Uses parameterized query
    const user = await secureFindUser(userName);
    
    if (user.length > 0) {
      // Generate OTP...
      return res.json({ message: 'OTP generated' });
    }
    
    return res.status(404).json({ error: 'User not found' });
  });
  
  return app;
}

// ============================================================================
// TypeORM Example
// ============================================================================

/*
// ❌ BAD: TypeORM with raw SQL and string interpolation
import { getRepository } from 'typeorm';

async function insecureTypeORM(userName: string) {
  const userRepository = getRepository(User);
  
  // BAD: Raw SQL with string interpolation
  const users = await userRepository.query(
    `SELECT * FROM users WHERE email = '${userName}'`
  );
  return users;
}
*/

/*
// ✅ GOOD: TypeORM with parameterized query
import { getRepository } from 'typeorm';

async function secureTypeORM(userName: string) {
  const userRepository = getRepository(User);
  
  // GOOD: Parameterized query
  const users = await userRepository.query(
    `SELECT * FROM users WHERE email = $1`,
    [userName] // GOOD: Parameter binding
  );
  
  // OR use ORM methods (even better)
  const users2 = await userRepository.find({
    where: { email: userName } // GOOD: ORM handles parameterization
  });
  
  return users2;
}
*/

// ============================================================================
// Prisma Example
// ============================================================================

/*
// ✅ GOOD: Prisma automatically parameterizes queries
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function securePrisma(userName: string) {
  // GOOD: Prisma automatically uses parameterized queries
  const user = await prisma.user.findMany({
    where: {
      email: userName // GOOD: Automatically parameterized
    }
  });
  
  return user;
}

// ❌ BAD: Prisma with raw query and string interpolation
async function insecurePrisma(userName: string) {
  // BAD: Raw query with string interpolation
  const users = await prisma.$queryRaw(
    `SELECT * FROM users WHERE email = '${userName}'`
  );
  return users;
}

// ✅ GOOD: Prisma raw query with parameterization
async function securePrismaRaw(userName: string) {
  // GOOD: Parameterized raw query
  const users = await prisma.$queryRaw`
    SELECT * FROM users WHERE email = ${userName}
  `;
  return users;
}
*/

// ============================================================================
// Best Practice: Input Validation + Parameterization
// ============================================================================

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

async function secureFindUserWithValidation(userName) {
  // GOOD: Validate input first
  if (!validateEmail(userName)) {
    throw new Error('Invalid email format');
  }
  
  // GOOD: Then use parameterized query
  const query = `SELECT * FROM users WHERE email = :userName`;
  const [results] = await sequelize.query(query, {
    replacements: { userName: userName }
  });
  
  return results;
}

// ============================================================================
// Complex Query: Use Database Views
// ============================================================================

/*
// GOOD: For complex queries, use database views instead of raw SQL
// Create view in database:
// CREATE VIEW user_profile_view AS
//   SELECT u.id, u.email, p.name, p.phone
//   FROM users u
//   JOIN profiles p ON u.id = p.user_id;

async function secureComplexQuery(userId) {
  // GOOD: Query view instead of constructing complex SQL
  const query = `SELECT * FROM user_profile_view WHERE id = :userId`;
  const [results] = await sequelize.query(query, {
    replacements: { userId: userId }
  });
  return results;
}
*/

module.exports = {
  insecureFindUser,
  insecureFindUserWithORM,
  insecureDynamicQuery,
  secureFindUser,
  secureFindUserWithORM,
  secureDynamicQuery,
  insecureRoute,
  secureRoute,
  secureFindUserWithValidation
};
