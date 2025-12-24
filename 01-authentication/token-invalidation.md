### token-invalidation-on-logout.md

**Issue Name**
Tokens Not Invalidated on Logout

---

**Risk / Impact**

This issue allows:

* Continued access after logout
* Reuse of previously issued tokens
* False sense of security for users and operators
* Inability to stop compromised sessions

This is a **critical** issue.

---

**In Plain English**

Logging out should mean *“this access is over”*.
If the token still works after logout, the user is not really logged out.

---

**How It Exists in Current Code**

The issue appears when:

* Logout only removes client-side state
* Tokens remain valid until they expire
* The backend does not track token validity
* Token checks rely only on cryptographic verification

This behavior is common when logout is treated as a UI action rather than a backend security event.

---

**Exploitation Scenario**

An attacker:

* Steals a token before or after logout
* Reuses the same token manually
* Continues accessing protected APIs

From the backend’s perspective, the request still looks legitimate.

---

**Correct Approach / Rule**

Mandatory rules:

* Logout must invalidate the token server-side
* Invalidated tokens must always be rejected
* Token validity must be checked on every request
* Signature validity alone is not sufficient
* Implement server-side token state—track whether a token is valid or revoked, rather than relying only on cryptographic checks. See [03-session-management/redis-session-validation.md](../03-session-management/redis-session-validation.md) for practical patterns to manage token invalidation using Redis or similar backends.

Logout must be enforced by the backend, not implied.

---

**What to Do If This Appears Again**

If you see:

* Logout endpoints that do not affect backend state
* Token checks that ignore revocation status
* Statements like “the token will expire eventually”

You must:

* Treat it as incomplete authentication logic
* Require explicit invalidation
* Ensure the backend remains the source of truth

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Invalidation logic usually lives outside controllers (middleware / guards)

---

**Key Rule**

> Every Token must be tracked.
> If the backend cannot revoke access,
> it does not control access.

---