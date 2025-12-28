### Pre-Merge Security Rules

**Issue Name:** Pre-Merge Security Rules

**Description:**
Before any code is merged into main branches, certain automated and manual checks should be enforced to prevent introducing security vulnerabilities. Skipping pre-merge checks can lead to critical issues reaching production.

**In-Plain-English:**
Before merging new code, make sure it doesn’t break security rules. Think of it as a final security gate.

**Rules / Checks:**

1. **Automated Linting & Static Analysis:**

   * Ensure code passes linters and static security analysis tools.
   * Detect potential SQL injections, insecure JWT handling, or unsafe update patterns.

2. **Dependency Checks:**

   * Run automated tools to detect vulnerable or outdated packages.
   * Confirm no insecure versions of libraries are being introduced.

3. **Unit & Integration Tests:**

   * Critical security flows (authentication, authorization, token handling) must have tests.
   * Ensure tests fail if unsafe code is introduced.

4. **Environment Config Validation:**

   * Ensure secrets, API keys, and configuration values are correct per environment.
   * Validate no production secrets are included in commits or code.

5. **Code Review Compliance:**

   * Confirm the reviewer has checked the **Code Review Checklist**.
   * High-risk changes (auth, DB queries, admin APIs) must be double-reviewed.

6. **Pre-Merge Approval:**

   * No code merges without approvals from at least one developer familiar with backend security.
   * Critical changes require security team sign-off.

7. **Logging & Monitoring Verification:**

   * Ensure any new endpoints or flows have proper logging for security events.

8. **Secrets & Key Management:**

   * Verify that no secrets are hardcoded or weak.
   * Ensure tokens, passwords, and API keys follow the team’s security policy.

**How to Use:**

* Integrate these rules into CI/CD pipelines.
* Make it mandatory that all pre-merge checks pass before merging.
* Update the rules whenever a new type of security risk is discovered.

---