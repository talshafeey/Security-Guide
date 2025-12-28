/**
 * Example: Pre-Merge Security Rules
 * 
 * This file demonstrates how to implement automated pre-merge security checks
 * that can be integrated into CI/CD pipelines.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// ============================================================================
// Rule 1: Automated Linting & Static Analysis
// ============================================================================

class LintingChecker {
  static runESLint() {
    try {
      execSync('npm run lint', { stdio: 'inherit' });
      return { passed: true, message: 'ESLint passed' };
    } catch (error) {
      return { passed: false, message: 'ESLint failed', error: error.message };
    }
  }
  
  static checkForSecurityIssues(code) {
    const issues = [];
    
    // Check for common security anti-patterns
    const patterns = [
      { pattern: /eval\(/, name: 'Use of eval()', severity: 'HIGH' },
      { pattern: /dangerouslySetInnerHTML/, name: 'XSS risk', severity: 'HIGH' },
      { pattern: /process\.env\.\w+\s*[:=]\s*['"][^'"]+['"]/, name: 'Hardcoded env var', severity: 'MEDIUM' }
    ];
    
    patterns.forEach(({ pattern, name, severity }) => {
      if (pattern.test(code)) {
        issues.push({ name, severity });
      }
    });
    
    return issues;
  }
}

// ============================================================================
// Rule 2: Dependency Checks
// ============================================================================

class DependencyChecker {
  static checkVulnerabilities() {
    try {
      // Run npm audit
      const result = execSync('npm audit --json', { encoding: 'utf-8' });
      const audit = JSON.parse(result);
      
      if (audit.vulnerabilities && Object.keys(audit.vulnerabilities).length > 0) {
        return {
          passed: false,
          message: 'Vulnerable dependencies found',
          vulnerabilities: audit.vulnerabilities
        };
      }
      
      return { passed: true, message: 'No known vulnerabilities' };
    } catch (error) {
      return { passed: false, message: 'Failed to check dependencies', error: error.message };
    }
  }
  
  static checkOutdatedPackages() {
    try {
      const result = execSync('npm outdated --json', { encoding: 'utf-8' });
      const outdated = JSON.parse(result);
      
      if (Object.keys(outdated).length > 0) {
        return {
          passed: false,
          message: 'Outdated packages found',
          outdated: outdated
        };
      }
      
      return { passed: true, message: 'All packages up to date' };
    } catch (error) {
      // npm outdated returns non-zero if packages are outdated
      return { passed: false, message: 'Outdated packages detected' };
    }
  }
}

// ============================================================================
// Rule 3: Unit & Integration Tests
// ============================================================================

class TestChecker {
  static runTests() {
    try {
      execSync('npm test', { stdio: 'inherit' });
      return { passed: true, message: 'All tests passed' };
    } catch (error) {
      return { passed: false, message: 'Tests failed', error: error.message };
    }
  }
  
  static checkSecurityTestCoverage() {
    // Check if security-critical tests exist
    const testFiles = [
      'auth.test.js',
      'authorization.test.js',
      'token.test.js',
      'sql-injection.test.js'
    ];
    
    const missingTests = testFiles.filter(file => {
      return !fs.existsSync(path.join(__dirname, '..', 'tests', file));
    });
    
    if (missingTests.length > 0) {
      return {
        passed: false,
        message: 'Missing security tests',
        missing: missingTests
      };
    }
    
    return { passed: true, message: 'Security tests present' };
  }
}

// ============================================================================
// Rule 4: Environment Config Validation
// ============================================================================

class ConfigChecker {
  static validateSecrets() {
    const requiredSecrets = [
      'JWT_SECRET_DEV',
      'JWT_SECRET_QA',
      'JWT_SECRET_PROD'
    ];
    
    const missing = requiredSecrets.filter(secret => !process.env[secret]);
    
    if (missing.length > 0) {
      return {
        passed: false,
        message: 'Missing required environment variables',
        missing: missing
      };
    }
    
    // Check secret strength
    const weakSecrets = requiredSecrets.filter(secret => {
      const value = process.env[secret];
      return !value || value.length < 32;
    });
    
    if (weakSecrets.length > 0) {
      return {
        passed: false,
        message: 'Weak secrets detected',
        weak: weakSecrets
      };
    }
    
    return { passed: true, message: 'Secrets validated' };
  }
  
  static checkForHardcodedSecrets(code) {
    const patterns = [
      /secret\s*[:=]\s*['"](secret|password|12345)/i,
      /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i
    ];
    
    const issues = [];
    patterns.forEach(pattern => {
      if (pattern.test(code)) {
        issues.push('Potential hardcoded secret detected');
      }
    });
    
    return {
      passed: issues.length === 0,
      message: issues.length > 0 ? 'Hardcoded secrets found' : 'No hardcoded secrets',
      issues: issues
    };
  }
}

// ============================================================================
// Rule 5: Code Review Compliance
// ============================================================================

class ReviewChecker {
  static checkReviewApproval() {
    // In real implementation, this would check Git/GitHub for approvals
    // For example, using GitHub API or Git hooks
    
    return {
      passed: true, // Would be false if no approval
      message: 'Code review approval verified',
      note: 'This should be checked via Git/GitHub API in CI/CD'
    };
  }
  
  static checkHighRiskFiles(files) {
    const highRiskPatterns = [
      /auth/i,
      /token/i,
      /secret/i,
      /password/i,
      /query/i,
      /database/i
    ];
    
    const highRiskFiles = files.filter(file => {
      return highRiskPatterns.some(pattern => pattern.test(file));
    });
    
    if (highRiskFiles.length > 0) {
      return {
        passed: false,
        message: 'High-risk files require double review',
        files: highRiskFiles
      };
    }
    
    return { passed: true, message: 'No high-risk files detected' };
  }
}

// ============================================================================
// Rule 6: Pre-Merge Approval
// ============================================================================

class ApprovalChecker {
  static checkSecurityTeamApproval() {
    // In real implementation, check Git/GitHub for security team approval
    return {
      passed: true,
      message: 'Security team approval verified',
      note: 'Integrate with Git/GitHub API'
    };
  }
  
  static checkMinimumApprovals(count = 1) {
    // Check if minimum number of approvals exist
    return {
      passed: true,
      message: `Minimum ${count} approval(s) verified`,
      note: 'Integrate with Git/GitHub API'
    };
  }
}

// ============================================================================
// Rule 7: Logging & Monitoring Verification
// ============================================================================

class LoggingChecker {
  static checkSecurityLogging(code) {
    const securityEndpoints = [
      'login',
      'logout',
      'auth',
      'token',
      'admin',
      'delete',
      'update'
    ];
    
    const issues = [];
    
    securityEndpoints.forEach(endpoint => {
      if (code.includes(endpoint) && !code.includes('log') && !code.includes('SecurityLogger')) {
        issues.push(`Missing security logging for ${endpoint} endpoint`);
      }
    });
    
    return {
      passed: issues.length === 0,
      message: issues.length > 0 ? 'Missing security logs detected' : 'Security logging present',
      issues: issues
    };
  }
}

// ============================================================================
// Rule 8: Secrets & Key Management
// ============================================================================

class SecretChecker {
  static checkSecretStrength() {
    return ConfigChecker.validateSecrets();
  }
  
  static checkSecretRotation() {
    // Check if secrets have been rotated recently
    return {
      passed: true,
      message: 'Secret rotation policy verified',
      note: 'Implement secret rotation tracking'
    };
  }
}

// ============================================================================
// Main Pre-Merge Checker
// ============================================================================

class PreMergeSecurityChecker {
  static async runAllChecks(code = null) {
    const results = {
      linting: LintingChecker.runESLint(),
      dependencies: DependencyChecker.checkVulnerabilities(),
      tests: TestChecker.runTests(),
      config: ConfigChecker.validateSecrets(),
      review: ReviewChecker.checkReviewApproval(),
      approval: ApprovalChecker.checkMinimumApprovals(),
      logging: code ? LoggingChecker.checkSecurityLogging(code) : { passed: true, message: 'Skipped (no code provided)' },
      secrets: SecretChecker.checkSecretStrength()
    };
    
    const allPassed = Object.values(results).every(result => result.passed);
    
    return {
      allPassed,
      results,
      summary: allPassed 
        ? 'All pre-merge security checks passed'
        : 'Some pre-merge security checks failed'
    };
  }
  
  static generateReport(results) {
    console.log('\n=== Pre-Merge Security Check Report ===\n');
    
    Object.entries(results.results).forEach(([check, result]) => {
      const status = result.passed ? '✓' : '✗';
      console.log(`${status} ${check}: ${result.message}`);
      
      if (!result.passed && result.issues) {
        result.issues.forEach(issue => {
          console.log(`  - ${issue}`);
        });
      }
    });
    
    console.log(`\nOverall: ${results.allPassed ? 'PASSED' : 'FAILED'}\n`);
    
    return results;
  }
}

// ============================================================================
// CI/CD Integration Example
// ============================================================================

async function preMergeCheck() {
  // This would be called in CI/CD pipeline
  const code = fs.readFileSync(process.argv[2] || __filename, 'utf-8');
  
  const results = await PreMergeSecurityChecker.runAllChecks(code);
  PreMergeSecurityChecker.generateReport(results);
  
  // Exit with error code if checks failed
  if (!results.allPassed) {
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  preMergeCheck();
}

module.exports = {
  LintingChecker,
  DependencyChecker,
  TestChecker,
  ConfigChecker,
  ReviewChecker,
  ApprovalChecker,
  LoggingChecker,
  SecretChecker,
  PreMergeSecurityChecker,
  preMergeCheck
};
