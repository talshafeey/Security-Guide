### shared-secrets-across-environments.md

**Issue Name**
Shared Authentication Secrets Across Environments

---

**Risk / Impact**

This issue allows:

* Non-production access to become production access
* Tokens generated in DEV or QA to work in PROD
* Lower-security environments to compromise higher-security ones

This is a **critical** issue.

---

**In Plain English**

If the same secret is used everywhere,
anything that works in testing can also work in production.

That removes the safety boundary between environments.

---

**How It Exists in Current Code**

The issue appears when:

* The same JWT secret is reused across DEV, QA, and PROD
* Environment configuration is copied without changes
* Secrets are stored in shared files or pipelines

This often happens during fast setup or environment replication.

---

**Exploitation Scenario**

An attacker:

* Gains access to a lower environment
* Generates a valid token there
* Uses the same token against production APIs

Production accepts it as legitimate.

---

**Correct Approach / Rule**

Mandatory rules:

* Every environment must have unique secrets
* Production secrets must never exist in lower environments
* Tokens must only be valid in the environment that issued them
* Secret management must be environment-aware

Environment isolation is a security boundary, not a convenience.

---

**What to Do If This Appears Again**

If you see:

* Identical secrets across environments
* Tokens working outside their origin environment
* Configuration copied without secret changes

You must:

* Treat it as an isolation failure
* Rotate affected secrets
* Re-issue tokens per environment

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Environment separation is external to framework logic

---

**Key Rule**

> Lower environments like (QA, Dev) must never be able to unlock production.

---