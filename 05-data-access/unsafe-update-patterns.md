### unsafe-update-patterns.md

**Issue Name**
Unsafe Update Patterns (Mass Assignment)

---

**Risk / Impact**

This issue allows:

* Updating data that the caller should not control
* Modifying sensitive fields (roles, status, ownership)
* Privilege escalation
* Corruption of business data

This is a **critical** issue.

---

**In Plain English**

If an API accepts an object and updates the database with it “as-is”,
a user can update **more than what was intended**, including sensitive fields.

---

**How It Exists in Current Code**

The issue appears when:

* Update APIs accept a full object from the request
* That object is passed directly to the ORM update method
* No explicit field-level control exists

This pattern is often introduced for speed and convenience,
but it removes an important security boundary.

---

**Exploitation Scenario**

An attacker:

* Uses a valid token
* Sends extra fields in the update request like (is_admin: true, is_2fa_enabled: false, email: attackr@email.com to attack)
* The backend applies all provided fields without restriction

This can allow:

* Changing another user’s role
* Activating or deactivating accounts
* Modifying internal or protected properties

---

**Correct Approach / Rule**

Mandatory rules:

* Update operations must explicitly define **allowed fields**
* Sensitive fields must never be client-controlled
* Request payloads must be mapped, not forwarded

Updates should reflect **business intent**, not raw input.

---

**What to Do If This Appears Again**

If you see:

* Spreading request bodies into update calls
    * don't use {...} update/insert APIs like that the frontend or the api will accept anything and tries to update it
* Generic “update everything” logic
* No clear list of allowed fields

You must:

* Stop and redesign the update flow
* Reduce the payload to intended properties only
* Treat this as a security issue, not a refactor task

---

**Framework Notes**

* Applies to both **Express** and **NestJS**
* The risk exists at the API boundary, not in the framework
* ORMs have a flag usually ```{updated: false}``` that can be put on the column to make that field unable to update
---

**Key Rule**

> You can never Trust Frontend.
> APIs must decide what can change.
> Clients must never decide what gets updated.

---