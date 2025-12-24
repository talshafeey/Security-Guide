Continuing.

---

### weak-jwt-secret.md

**Issue Name**
Weak or Guessable JWT Signing Secret

---

**Risk / Impact**

This issue allows:

* Forging valid tokens
* Impersonating any user
* Full authentication bypass
* Undetectable access using attacker-generated tokens

This is a **critical** issue.

---

**In Plain English**

If the secret used to sign tokens is weak,
an attacker can guess it and create their own “valid” tokens.

The system cannot tell the difference.

---

**How It Exists in Current Code**

The issue appears when:

* JWT secrets are short or simple
* Secrets are human-readable words or patterns
* Secrets are reused across services
* Secrets are committed or shared insecurely

These choices are often made for convenience or ease of setup.

---

**Exploitation Scenario**

An attacker:

* Obtains a token
* Attempts to guess the signing secret offline
* Successfully generates new tokens with any identity
* Uses them directly against the backend APIs

No database access or user interaction is required.

---

**Correct Approach / Rule**

Mandatory rules:

* JWT secrets must be long and high-entropy
* Secrets must not be human-guessable
* Secrets must be treated as credentials
* Rotating secrets must be possible without downtime

Token integrity depends entirely on secret strength.

---

**What to Do If This Appears Again**

If you see:

* Short secrets
* Default or example secrets
* Secrets shared casually between services

You must:

* Replace them even if it means to slam on the keyboard for some hard guessed secret to make them longer and semi-impossible to guess
* Treat the situation as a compromise risk
* Rotate existing tokens if necessary

---

**Framework Notes**

* Applies equally to **Express** and **NestJS**
* Secret strength is independent of framework

---

**Key Rule**
> Slamming the keyboard 16 times makes one of the most secure secrets in the world.

> Anyone who knows the secret can mint access and generate tokens. 

> Protect it accordingly.
