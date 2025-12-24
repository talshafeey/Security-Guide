### overview.md

**Purpose**

This guide documents security rules, pitfalls, and required practices for our backend systems.
It exists because real security incidents already happened, and we want to prevent them from happening again.

This is not a theoretical security guide.
Everything here is based on:

* Issues found in our own code
* Real attack scenarios
* Practical fixes that developers are expected to apply

---

**Audience**

* Backend developers (primary)
* Tech leads / reviewers
* Anyone approving backend changes

No prior security expertise is assumed.

---

**Scope**

This guide applies to:

* Backend services written in **NodeJS + Express**
* Backend services written in **NestJS**
* Authentication, authorization, sessions, APIs, data access, and secrets

Frontend security, infrastructure hardening, and network-level security are **out of scope** unless explicitly mentioned.

---

**How to Use This Guide**

* Start from `index.md` to navigate topics
* Each issue is documented in a **single file**
* Every issue follows the same structure:

  * What the issue is
  * Why it is dangerous
  * How it appears in our code
  * How to fix it
  * How to avoid reintroducing it

Each issue also includes an **“In Plain English”** section to explain the risk without technical jargon.

---

**Non-Goals**

This guide does **not**:

* Replace code reviews
* Automatically secure the system
* Act as a compliance or audit document

Security still depends on:

* Developer discipline
* Proper reviews
* Following the rules documented here

---

**Key Principle**

> Authentication does not mean authorization.
> A working token does not mean trusted behavior.
> If the backend does not explicitly block something, assume it can be abused.

---