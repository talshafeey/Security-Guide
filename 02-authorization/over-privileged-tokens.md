### authenticated-but-over-privileged-tokens.md

**Issue Name**
Authenticated Tokens Grant Excessive Authorization

---

**Risk / Impact**

This issue allows:

* Access to APIs beyond business role permissions
* Privilege escalation without exploiting authentication
* Use of valid tokens to perform restricted actions
* Business logic abuse

This is a **critical** issue.

---

**In Plain English**

Logging in should not give you access to everything.

A token can be valid and still not be allowed to perform certain actions.

---

**How It Exists in Current Code**

The issue appears when:

* Authorization is checked only at login and at Frontend screens/routes
* Tokens imply full system access once authenticated
* APIs do not enforce permission checks
* Role or permission information is ignored during requests

This often happens when authentication is implemented first and authorization is added later.

---

**Exploitation Scenario**

An attacker:

* Logs in as a normal user
* Uses the same token to call admin or internal APIs
* Backend allows the request because the token is valid

No technical exploit is required—only missing authorization checks.

---

**Correct Approach / Rule**

Mandatory rules:

* Authorization must be enforced per API
* Permissions must be checked at request time
* Tokens must not imply full access
* Business rules must be enforced server-side

Authorization is a continuous check, not a one-time decision.

---

**What to Do If This Appears Again**

If you see:

* APIs protected only by authentication
* No permission checks inside routes or handlers
* Statements like “this token is already authenticated”

You must:

* Treat it as an authorization gap
* Add explicit permission checks
* Block access by default

---

**Framework Notes**

* **Express**: enforce via middleware per route
* **NestJS**: enforce via Guards and metadata

In both cases:

> Authorization must be explicit and local to the API.

---

**Key Rule**

> Valid identity does not equal allowed action.

---