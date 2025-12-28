### secret-strength-policy.md

**Issue Name**
Insufficient Secret Strength Policy

---

**Risk / Impact**

This issue allows:

* Brute-force or guessing of secrets
* Forged tokens and signatures
* Undetected authentication bypass
* Compromise of multiple services at once

This is a **critical** issue.

---

**In Plain English**

A secret is like a lock.
If it’s simple, it can be opened quickly.

Strong secrets make attacks impractical.

---

**How It Exists in Current Code**

The issue appears when:

* Secrets are short or human-readable
* Secrets are reused across services
* Secrets are manually chosen
* No minimum strength requirements exist

This often happens when secrets are created for convenience.

---

**Exploitation Scenario**

An attacker:

* Obtains a signed token or signature
* Attempts offline guessing
* Successfully discovers the secret
* Generates valid authentication artifacts

The system cannot distinguish them from legitimate ones.

---

**Correct Approach / Rule**

Mandatory rules:

* Secrets must meet minimum length requirements
* Secrets must be high-entropy and non-guessable even if it's random recomnded to have 32-length string, try hashing a value and use the hashed value as the secert
* Secrets must never be reused casually
* Secret generation must be deliberate and controlled

Secret strength is a security requirement, not a preference.

---

**What to Do If This Appears Again**

If you see:

* Short or readable secrets
* Example values used in real environments
* Secrets shared informally

You must:

* Treat it as a security risk
* Replace the secret
* Rotate affected tokens or credentials

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Secret handling is independent of framework

---

**Key Rule**

> Weak secrets break strong systems.

---