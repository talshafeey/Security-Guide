### Code Review Checklist

**Issue Name:** Code Review Checklist

**Description:**
A consistent code review process is critical to maintain security hygiene and catch potential vulnerabilities early. Lack of standardized checks can allow SQL injections, improper authentication/authorization, weak secrets, and other issues to slip into production.

**In-Plain-English:**
We need a repeatable, checklist-driven process so that everyone knows what to look for when reviewing code. This helps catch security problems before they reach production.

**Checklist Items:**

1. **Authentication & Authorization:**

   * Ensure all endpoints are protected with proper authentication.
   * Verify per-route authorization checks are in place according to business roles.

2. **SQL Queries & ORM Usage:**

   * Check for parameterized queries or safe ORM usage.
   * Avoid dynamic queries that concatenate user input.

3. **Token Management:**

   * Validate that JWT tokens have proper expiry.
   * Ensure logout invalidates tokens.
   * Tokens shouldn’t grant more privileges than required.

4. **Secrets & Environment Configurations:**

   * Confirm secret keys are strong, unique per environment, and not hardcoded.
   * Check API keys, tokens, and other sensitive data are stored securely.

5. **Input Validation & Sanitization:**

   * Verify all external input is validated and sanitized.
   * Ensure endpoints cannot be abused to escalate privileges.

6. **Logging & Monitoring:**

   * Confirm security-relevant events are logged.
   * Logs should include failed authentication attempts, unauthorized access, and system errors.

7. **Error Handling:**

   * Ensure sensitive information is not leaked in error messages.

8. **Dependencies & Libraries:**

   * Check for outdated or vulnerable dependencies.
   * Confirm that any third-party library usage follows security best practices.

9. **Environment Isolation:**

   * Ensure production, staging, and development environments are separated.
   * Sensitive operations or test data should never leak between environments.

**How to Use:**

* Include this checklist in all code reviews.
* Reviewers should tick off each item and raise comments for anything missing.
* The checklist should evolve as new security issues are discovered.

---