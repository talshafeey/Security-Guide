### authentication-model.md

**What Authentication Means in Our Systems**

Authentication answers **one question only**:

>*Who is making this request?*

If a request is authenticated, it means:

* The backend was able to verify the identity claim
* Nothing more

Authentication does **not**:

* Grant permissions
* Allow access to all APIs
* Imply trust in intent
* Replace authorization checks

---

**What a Token Represents**

A token represents:

* A logged-in identity
* For a limited amount of time
* Under strict conditions

A token must **never** be treated as:

* A session that lives forever
* Proof of permission
* Proof of system origin
* Proof that the user is still logged in

---

**Token Lifecycle (Required)**

Every token must follow this lifecycle:

1. **Creation**

   * Issued only after successful login
   * Linked to a specific user identity

2. **Validity Window**

   * Must have a clear expiration
   * Expired tokens must always fail

3. **Active Validation**

   * Backend must check that the token is still allowed
   * Signature alone is not sufficient

4. **Invalidation**

   * Logout must make the token unusable
   * Reusing an invalidated token must always fail

If any of these steps are missing, authentication is incomplete.

---

**In Plain English**

Authentication is just showing an ID card.
It does **not** mean:

* You are allowed inside every room
* Your ID never expires
* You can keep using it after leaving the building

---

**Environment Boundaries**

Authentication must respect environment boundaries:

* DEV, QA, and PROD are separate trust zones
* A token or secret from one environment must never work in another

If it does, environments are not isolated.

---

**Framework Notes**

* In **Express**: authentication is usually middleware-based
* In **NestJS**: authentication is usually Guard-based

Regardless of framework:

> Authentication logic must be centralized and consistently enforced.

---

**Key Rule**

> If authentication is implemented incorrectly,
> every authorization rule built on top of it becomes meaningless.

---
