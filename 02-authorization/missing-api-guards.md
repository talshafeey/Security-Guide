### api-access-without-per-route-guards.md

**Issue Name**
API Access Without Per-Route Authorization Guards

---

**Risk / Impact**

This issue allows:

* Unauthorized access to sensitive APIs
* Accidental exposure of internal functionality
* Reliance on global or implicit protection
* Easy bypass of intended access controls

This is a **critical** issue.

---

**In Plain English**

If an API does not actively check who can call it,
any authenticated user may be able to reach it.

Protection must exist **at the API itself**, not assumed elsewhere.

---

**How It Exists in Current Code**

The issue appears when:

* APIs rely only on global authentication middleware
* No route-level authorization is enforced
* Authorization logic is missing or inconsistent

This often happens when APIs grow quickly or are refactored.

---

**Exploitation Scenario**

An attacker:

* Uses a valid token with limited permissions
* Calls an API that lacks route-level checks
* Backend processes the request successfully

The API is exposed simply because it was not explicitly protected.

---

**Correct Approach / Rule**

Mandatory rules:

* Every protected API must enforce authorization explicitly
* Route-level guards must exist for sensitive operations
* Internal APIs must still be protected
* Default behavior must be “deny unless allowed”

Protection must be deliberate, not implied.

---

**What to Do If This Appears Again**

If you see:

* Routes without authorization checks
* Security handled only globally

You must:

* Treat it as a security gap
* Add route-level authorization
* Review similar APIs for the same pattern

---

**Framework Notes**

* **Express**: apply authorization middleware per route
* **NestJS**: apply Guards at controller or route level

---

**Key Rule**

> If an API exists, it must defend itself.

---