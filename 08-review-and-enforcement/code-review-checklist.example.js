/**
 * Example: Code Review Checklist Implementation
 * 
 * This file demonstrates how to implement automated checks for the code review checklist
 * and provides examples of what to look for during manual reviews.
 */

// ============================================================================
// Automated Checks (can be integrated into CI/CD)
// ============================================================================

class CodeReviewChecker {
  // Check 1: Authentication & Authorization
  static checkAuthGuards(code) {
    const issues = [];
    
    // Check for routes without auth middleware
    const routePattern = /app\.(get|post|put|delete|patch)\(['"]([^'"]+)['"]/g;
    const authPattern = /(auth|requireAuth|authenticate)/;
    
    let match;
    while ((match = routePattern.exec(code)) !== null) {
      const route = match[0];
      const routePath = match[2];
      
      // Skip public routes
      if (routePath.includes('/public') || routePath.includes('/health')) {
        continue;
      }
      
      // Check if auth middleware is present
      if (!authPattern.test(code.substring(0, match.index + match[0].length))) {
        issues.push({
          type: 'MISSING_AUTH',
          route: routePath,
          severity: 'HIGH'
        });
      }
    }
    
    return issues;
  }
  
  // Check 2: SQL Injection - Parameterized Queries
  static checkSQLInjection(code) {
    const issues = [];
    
    // Check for string interpolation in SQL
    const dangerousPatterns = [
      /query\([^)]*`[^`]*\$\{/g,  // Template literals in queries
      /query\([^)]*['"][^'"]*\+/g,  // String concatenation
      /sequelize\.literal\([^)]*['"][^'"]*\$\{/g  // Raw SQL with interpolation
    ];
    
    dangerousPatterns.forEach((pattern, index) => {
      if (pattern.test(code)) {
        issues.push({
          type: 'SQL_INJECTION_RISK',
          pattern: `Pattern ${index + 1}`,
          severity: 'CRITICAL'
        });
      }
    });
    
    return issues;
  }
  
  // Check 3: Token Management
  static checkTokenManagement(code) {
    const issues = [];
    
    // Check for tokens without expiry
    if (code.includes('jwt.sign') && !code.includes('expiresIn')) {
      issues.push({
        type: 'TOKEN_WITHOUT_EXPIRY',
        severity: 'HIGH'
      });
    }
  
    // Check for logout without token invalidation
    if (code.includes('logout') && !code.includes('redis') && !code.includes('del') && !code.includes('invalidate')) {
      issues.push({
        type: 'LOGOUT_WITHOUT_INVALIDATION',
        severity: 'HIGH'
      });
    }
    
    return issues;
  }
  
  // Check 4: Secrets & Environment Config
  static checkSecrets(code) {
    const issues = [];
    
    // Check for hardcoded secrets
    const secretPatterns = [
      /secret\s*[:=]\s*['"](secret|password|12345|admin)/i,
      /JWT_SECRET\s*[:=]\s*['"][^'"]{0,20}['"]/  // Short secrets
    ];
    
    secretPatterns.forEach(pattern => {
      if (pattern.test(code)) {
        issues.push({
          type: 'HARDCODED_WEAK_SECRET',
          severity: 'CRITICAL'
        });
      }
    });
    
    // Check for secrets in code (should use env vars)
    if (code.includes('process.env.JWT_SECRET') === false && code.includes('jwt.sign')) {
      issues.push({
        type: 'SECRET_NOT_FROM_ENV',
        severity: 'HIGH'
      });
    }
    
    return issues;
  }
  
  // Check 5: Mass Assignment
  static checkMassAssignment(code) {
    const issues = [];
    
    // Check for spread operator in update calls
    const massAssignmentPatterns = [
      /\.update\([^)]*\.\.\.[^)]*\)/g,  // Spread in update
      /Object\.assign\([^,]+,\s*req\.body\)/g,  // Direct assign from body
      /\.save\(\)/g  // Combined with spread above
    ];
    
    if (massAssignmentPatterns.some(pattern => pattern.test(code))) {
      issues.push({
        type: 'MASS_ASSIGNMENT_RISK',
        severity: 'HIGH'
      });
    }
    
    return issues;
  }
  
  // Check 6: Security Logging
  static checkSecurityLogging(code) {
    const issues = [];
    
    // Check for auth failures without logging
    if (code.includes('status(401)') && !code.includes('log') && !code.includes('SecurityLogger')) {
      issues.push({
        type: 'MISSING_SECURITY_LOG',
        severity: 'MEDIUM'
      });
    }
    
    return issues;
  }
  
  // Run all checks
  static runAllChecks(code) {
    const allIssues = {
      auth: this.checkAuthGuards(code),
      sql: this.checkSQLInjection(code),
      tokens: this.checkTokenManagement(code),
      secrets: this.checkSecrets(code),
      massAssignment: this.checkMassAssignment(code),
      logging: this.checkSecurityLogging(code)
    };
    
    return allIssues;
  }
}

// ============================================================================
// Example: Manual Review Checklist
// ============================================================================

const CODE_REVIEW_CHECKLIST = {
  authentication: {
    items: [
      'All endpoints are protected with authentication middleware',
      'No public endpoints expose sensitive data',
      'Token validation happens on every request'
    ],
    examples: {
      good: `
        // GOOD: Route with auth middleware
        app.get('/api/users',
          requireAuth,
          getUserHandler
        );
      `,
      bad: `
        // BAD: Route without auth
        app.get('/api/users', getUserHandler);
      `
    }
  },
  
  authorization: {
    items: [
      'Per-route authorization checks are in place',
      'Permissions are checked at request time',
      'Resource ownership is verified'
    ],
    examples: {
      good: `
        // GOOD: Explicit permission check
        app.delete('/api/users/:id',
          requireAuth,
          requirePermission('users:delete'),
          verifyOwnership,
          deleteUserHandler
        );
      `,
      bad: `
        // BAD: No authorization check
        app.delete('/api/users/:id',
          requireAuth,
          deleteUserHandler
        );
      `
    }
  },
  
  sqlQueries: {
    items: [
      'All queries use parameterized inputs',
      'No string concatenation in SQL',
      'ORM methods are used correctly'
    ],
    examples: {
      good: `
        // GOOD: Parameterized query
        await User.findAll({
          where: { email: userEmail }
        });
      `,
      bad: `
        // BAD: String interpolation
        await sequelize.query(
          \`SELECT * FROM users WHERE email = '\${userEmail}'\`
        );
      `
    }
  },
  
  tokenManagement: {
    items: [
      'Tokens have expiry set',
      'Logout invalidates tokens in Redis',
      'Tokens don't grant excessive permissions'
    ],
    examples: {
      good: `
        // GOOD: Token with expiry
        jwt.sign(payload, secret, { expiresIn: '1h' });
      `,
      bad: `
        // BAD: Token without expiry
        jwt.sign(payload, secret);
      `
    }
  },
  
  secrets: {
    items: [
      'Secrets are loaded from environment variables',
      'Secrets are at least 32 characters',
      'No secrets are hardcoded'
    ],
    examples: {
      good: `
        // GOOD: From environment
        const secret = process.env.JWT_SECRET;
      `,
      bad: `
        // BAD: Hardcoded
        const secret = 'my-secret-key';
      `
    }
  },
  
  massAssignment: {
    items: [
      'Update operations use field whitelist',
      'Sensitive fields cannot be updated by clients',
      'No spread operator in update calls'
    ],
    examples: {
      good: `
        // GOOD: Explicit fields
        const allowedFields = ['name', 'phone'];
        const safeUpdates = {};
        for (const field of allowedFields) {
          if (updateData[field]) {
            safeUpdates[field] = updateData[field];
          }
        }
        await User.update(safeUpdates, { where: { id } });
      `,
      bad: `
        // BAD: Mass assignment
        await User.update({ ...req.body }, { where: { id } });
      `
    }
  },
  
  logging: {
    items: [
      'Authentication failures are logged',
      'Authorization denials are logged',
      'Security events include context (who, what, when)'
    ],
    examples: {
      good: `
        // GOOD: Log security event
        if (!token) {
          SecurityLogger.logAuthFailure(req, 'NO_TOKEN');
          return res.status(401).json({ error: 'Unauthorized' });
        }
      `,
      bad: `
        // BAD: No logging
        if (!token) {
          return res.status(401).json({ error: 'Unauthorized' });
        }
      `
    }
  }
};

// ============================================================================
// Review Helper Functions
// ============================================================================

function reviewCode(code, checklist = CODE_REVIEW_CHECKLIST) {
  const automatedIssues = CodeReviewChecker.runAllChecks(code);
  
  const review = {
    automatedChecks: automatedIssues,
    manualChecks: checklist,
    passed: Object.values(automatedIssues).every(issues => issues.length === 0)
  };
  
  return review;
}

// ============================================================================
// Example Usage
// ============================================================================

function exampleReview() {
  const insecureCode = `
    app.get('/api/users', (req, res) => {
      const email = req.query.email;
      sequelize.query(\`SELECT * FROM users WHERE email = '\${email}'\`);
    });
    
    app.put('/api/users/:id', (req, res) => {
      User.update({ ...req.body }, { where: { id: req.params.id } });
    });
  `;
  
  const review = reviewCode(insecureCode);
  console.log('Review Results:', JSON.stringify(review, null, 2));
  
  return review;
}

module.exports = {
  CodeReviewChecker,
  CODE_REVIEW_CHECKLIST,
  reviewCode,
  exampleReview
};
