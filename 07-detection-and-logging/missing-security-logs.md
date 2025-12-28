### missing-security-logs.md

**Issue Name**
Missing or Insufficient Security Logging

---

**Risk / Impact**

This issue allows:

* Attacks to go unnoticed
* Delayed incident response
* Inability to investigate security events
* Lack of accountability and traceability

This is an **important** issue that amplifies the impact of others.

---

**In Plain English**

If something bad happens and there are no logs,
you won’t know **what happened**, **when**, or **how**.

Security without logs is invisible.

---

**How It Exists in Current Code**

The issue appears when:

* Authentication failures are not logged
* Authorization denials are silent
* Token misuse is not recorded
* Logs focus only on technical errors, not security events

This often happens when logging is treated as a debugging tool only.

---

**Exploitation Scenario**

An attacker:

* Repeatedly attempts unauthorized actions
* Uses stolen or forged tokens
* Probes APIs for weaknesses

Without logs, these actions leave no meaningful trace.

---

**Correct Approach / Rule**

Mandatory rules:

* Authentication failures must be logged
* Authorization denials must be logged
* Token validation failures must be logged
* Logs must include context (who, what, when)

Logs must support investigation, not just debugging.

---

**What to Do If This Appears Again**

If you see:

* Silent failures
* Missing audit trails
* No distinction between errors and security events

You must:

* Treat it as an observability gap
* Add explicit security logging
* Review similar flows for the same issue

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Logging strategy must be consistent across services

---

**Key Rule**

> If you can’t see it, you can’t secure it.

---