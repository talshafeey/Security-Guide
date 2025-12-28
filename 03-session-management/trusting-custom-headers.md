### trusting-custom-headers-for-system-identity.md

**Issue Name**
Trusting Custom Headers for System Identity

---

**Risk / Impact**

This issue allows:

* Bypassing authorization boundaries
* Accessing privileged or internal APIs
* One system impersonating another
* Customer-facing systems reaching admin-only endpoints

This is a **critical** issue.

---

**In Plain English**

If the backend trusts a header that says
“I am the admin system”,
anyone who can send requests can say the same thing.

Headers are not proof of identity.

---

**How It Exists in Current Code**

The issue appears when:

* Custom headers are used to identify calling systems
* Authorization logic relies on header values
* Backend behavior changes based on client-provided metadata

This pattern is often introduced to distinguish internal systems quickly.

---

**Exploitation Scenario**

An attacker:

* Uses a valid token from a customer-facing portal
* Adds or modifies a custom header
* Sends the request to an admin API
* Backend treats the request as coming from a trusted system

No special access is required beyond the ability to send HTTP requests.

---

**Correct Approach / Rule**

Mandatory rules:

* Never trust client-provided headers for identity
* System identity must be authenticated, not declared
* Authorization must not rely on request metadata alone
* Internal APIs must have independent protection

Trust must be proven cryptographically, not asserted.

---

**What to Do If This Appears Again**

If you see:

* Headers used to decide access level
* Logic like “if system = X then allow”
* No authentication tied to system identity

You must:

* Treat it as an authorization bypass
* Redesign the trust model
* Enforce explicit authentication and authorization

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* This is a design issue, not a framework limitation

---

**Key Rule**

> Anything the client can send, an attacker can fake.

---