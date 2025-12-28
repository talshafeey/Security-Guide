### cross-system-access.md

**Issue Name**
Cross-System Access Without Proper Isolation

---

**Risk / Impact**

This issue allows:

* One system to access APIs intended for another system
* Customer-facing portals to reach admin or internal APIs
* Privilege escalation across system boundaries
* Blurring of trust zones

This is a **critical** issue.

---

**In Plain English**

Different systems exist for a reason.
If one system can act like another, boundaries disappear.

A backend must know **which system** is calling it, not just **which user**.

---

**How It Exists in Current Code**

The issue appears when:

* Multiple systems share the same backend APIs
* System identity is inferred, not verified
* Authorization rules do not distinguish between systems
* Access decisions are based only on user tokens

This commonly happens when systems evolve and start sharing infrastructure.

---

**Exploitation Scenario**

An attacker:

* Logs in through a lower-privilege system
* Reuses the same token against higher-privilege APIs
* Backend accepts the request because user authentication succeeds

The backend does not enforce system-level separation.

---

**Correct Approach / Rule**

Mandatory rules:

* System identity must be explicitly authenticated an example of implmenetation is to do it inside the jwt payload
* Authorization must consider both user and system
* APIs must declare which systems are allowed to call them
* System boundaries must be enforced server-side

System access is a security rule, not a routing detail.

---

**What to Do If This Appears Again**

If you see:

* Shared APIs without system checks
* Authorization based only on user identity
* Assumptions about “where the request comes from”

You must:

* Treat it as a trust boundary violation
* Define allowed systems per API
* Enforce system-aware authorization

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* This is an authorization design concern, not framework-specific

---

**Key Rule**

> User identity is not enough.
> The calling system matters.

---