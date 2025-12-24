### authorization-model.md

**What Authorization Means**

Authorization answers a different question than authentication:

> *Is this authenticated identity allowed to do this specific action?*

A request can be:

* Authenticated **and still forbidden**
* Authenticated **and still dangerous**

Authorization must always be **explicit**.

---

**Authentication ≠ Authorization**

This distinction is mandatory:

* **Authentication** → who you are
* **Authorization** → what you are allowed to do

A valid token:

* Does not grant access to all APIs
* Does not bypass business rules
* Does not imply system-level trust

If authorization is missing, the backend is effectively open.

---

**Authorization Must Be API-Level**

Authorization rules must exist:

* Per API
* Per action
* Per resource (when applicable)

It is not acceptable to:

* Authorize only at login time
* Authorize only on the frontend
* Authorize based on assumptions about the caller

Every protected API must enforce its own authorization.

---

**Roles, Permissions, and Actions**

Rules:

* Roles are **containers**, not permissions
* Permissions must map to **explicit actions**
* APIs must check permissions, not roles

Example conceptually:

* “Admin” is meaningless unless translated into allowed actions
* A user with a valid token but no permission must be rejected

---

**System-to-System Access**

Backend services must not trust:

* Custom headers
* Client-provided flags
* Claimed system names

System identity must be:

* Authenticated
* Authorized
* Verified independently of user identity

If a system can “pretend” to be another system, authorization is broken.

---

**In Plain English**

Authorization is the rule that says:

> “Even if I know who you are, you still might not be allowed to do this.”

Without it, logging in once gives you the keys to everything.

---

**Framework Notes**

* **Express**: authorization usually lives in middleware or per-route checks
* **NestJS**: authorization usually lives in Guards

In both cases:

> Authorization must be close to the API it protects.

---

**Key Rule**

> Never assume a request is allowed.
> Always prove that it is.

---
