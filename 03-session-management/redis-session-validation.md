### token-validation-via-redis.md

**Issue Name**
Missing Token Availability Validation (Redis)

---

**Risk / Impact**

This issue allows:

* Use of forged tokens
* Use of revoked or unknown tokens
* Bypassing logout and session controls
* Authentication logic to rely solely on token structure

This is a **critical** issue.

---

**In Plain English**

Just because a token *looks valid* does not mean
the system has ever approved it.

If the backend does not check whether it knows the token,
it cannot control who is actually logged in.

---

**How It Exists in Current Code**

The issue appears when:

* Tokens are validated only by signature
* Redis (or another store) is not checked on each request
* Tokens are not registered when issued
* Token presence is not verified during authentication
* Tokens that have been logged out (but have not yet expired) must be tracked server-side and explicitly blocked from reuse, even if their JWT signature and expiry appear valid.

This makes authentication stateless in a way that removes control.

---

**Exploitation Scenario**

An attacker:

* Generates a token using a valid secret
* Sends it directly to the backend
* Backend accepts it without checking if it was issued

The system cannot distinguish attacker-issued tokens from real ones.

---

**Correct Approach / Rule**

Mandatory rules:

* Issued tokens must be registered server-side
* Every authenticated request must verify token availability
* Token state must be authoritative
* Redis (or equivalent) must be treated as part of authentication

Authentication must be both **cryptographically valid** and **server-approved**.

---

**What to Do If This Appears Again**

If you see:

* Authentication logic that skips availability checks
* Tokens accepted without server-side state
* Redis used only on logout

You must:

* Flag it as incomplete authentication
* Require token registration and lookup
* Ensure token revocation is enforceable

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Token lookup usually lives in middleware or guards

---

**Key Rule**

> If the backend did not issue it,
> it should not accept it.

---