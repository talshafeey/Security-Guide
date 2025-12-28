### unrestricted-update-apis.md

**Issue Name**
Unrestricted Update APIs

---

**Risk / Impact**

This issue allows:

* Modifying resources without proper ownership checks
* Updating other users’ data
* Changing system-controlled fields
* Violating core business rules

This is a **critical** issue.

---

**In Plain English**

Just because someone can call an update API
does not mean they should be able to update *anything*.

The backend must decide **who can update what**.

---

**How It Exists in Current Code**

The issue appears when:

* Update APIs accept resource identifiers from the client
* No ownership or scope checks are performed
* Authorization is not tied to the target resource
* APIs assume “if you reached here, you are allowed”

This often happens when focus is placed on authentication only.

---

**Exploitation Scenario**

An attacker:

* Uses a valid token
* Supplies a different resource ID
* Updates data they do not own or control
* Backend accepts the change
* A user can update other user's email and try to login with it

The API works as designed, but the design is incomplete.

---

**Correct Approach / Rule**

Mandatory rules:

* Every update must verify ownership or scope
* Authorization must be evaluated against the target resource
* Sensitive fields must be protected server-side
* Access must be denied by default

Authorization must include **who**, **what**, and **which resource**.

---

**What to Do If This Appears Again**

If you see:

* Update APIs that trust client-provided IDs
* No checks against the authenticated identity
* Broad update logic reused across resources

You must:

* Treat it as a broken authorization issue
* Add resource-level checks
* Re-evaluate similar endpoints

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Resource checks belong close to the business logic

---

**Key Rule**

> Authorization without resource context is incomplete.

---