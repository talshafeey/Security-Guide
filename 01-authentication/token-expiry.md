### token-expiry-and-reuse.md

**Issue Name**
Tokens Without Expiry and Unrestricted Reuse

---

**Risk / Impact**

This issue allows:

* Long-term unauthorized access
* Reuse of leaked or stolen tokens
* Access long after logout or role change
* Silent compromise that is hard to detect

This is a **critical** issue.

---

**In Plain English**

If a token never expires,
anyone who gets a copy of it can keep using it indefinitely.

Logging out or changing a password does not help if the token still works.

---

**How It Exists in Current Code**

The issue appears when:

* Tokens are generated without an expiration
* Token expiration is not checked on every request
* Token validity relies only on signature verification

This approach makes tokens effectively permanent credentials.

---

**Exploitation Scenario**

An attacker:

* Obtains a token (log leak, browser storage, network capture, shared device)
* Reuses it days or weeks later
* Continues accessing APIs as a valid user

The system has no way to distinguish old, stolen tokens from active sessions.

---

**Correct Approach / Rule**

Mandatory rules:

* Every token must have a defined expiration
* Expired tokens must always be rejected
* Token lifetime must be intentionally short
* Long-lived access must require renewal

Token validity must be time-bound.

---

**What to Do If This Appears Again**

If you see:

* Tokens without expiry fields
* “Never expires” logic
* Authentication checks that only verify signatures

You must:

* Treat it as a security defect
* Require expiration as a hard rule
* Reject designs that rely on permanent tokens

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Token expiry is framework-independent

---

**Key Rule**

> A token without expiry is not a session.
> It is a permanent key.

---