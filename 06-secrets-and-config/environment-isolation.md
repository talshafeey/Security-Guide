### environment-isolation.md

**Issue Name**
Missing or Weak Environment Isolation

---

**Risk / Impact**

This issue allows:

* Actions in lower environments to affect production
* Tokens, secrets, or access paths to cross environments
* Testing systems to become attack paths into production

This is a **critical** issue.

---

**In Plain English**

Development and testing environments are not as protected as production.
If they are connected, production inherits their risk.

---

**How It Exists in Current Code**

The issue appears when:

* Environments share secrets or credentials
* Tokens are accepted across environments
* Environment checks are missing or inconsistent
* Configuration is copied without isolation controls
* Token Secrets are the same between the QA + Production envs

This often happens when environments are created by duplication.

---

**Exploitation Scenario**

An attacker:

* Gains access to a DEV or QA environment
* Uses credentials, tokens, or access paths
* Interacts successfully with production services

Production is compromised indirectly.

---

**Correct Approach / Rule**

Mandatory rules:

* Each environment must be isolated by design
* Secrets, tokens, and credentials must be environment-specific
* Cross-environment access must be explicitly blocked
* Production must never trust non-production artifacts

Isolation must be enforced, not assumed.

---

**What to Do If This Appears Again**

If you see:

* Shared credentials
* Tokens working across environments
* Missing environment checks

You must:

* Treat it as a boundary violation
* Rotate affected secrets
* Re-establish strict separation

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Isolation is an architectural responsibility

---

**Key Rule**

> Environments are trust boundaries.

---