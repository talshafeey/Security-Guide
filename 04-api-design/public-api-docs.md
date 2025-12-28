### public-api-documentation-exposure.md

**Issue Name**
Public Exposure of API Documentation

---

**Risk / Impact**

This issue allows:

* Easy discovery of internal APIs
* Faster reconnaissance for attackers
* Clear visibility into parameters, payloads, and flows
* Reduced effort to exploit other vulnerabilities

This is an **important** issue that often enables critical ones.

---

**In Plain English**

API documentation is a map of your backend.
If everyone can see it, attackers don’t have to guess.

---

**How It Exists in Current Code**

The issue appears when:

* API documentation endpoints are publicly accessible
* Exposure is controlled only by an environment variable
* Documentation is enabled in production by default
* No authentication is required to view API specs

This commonly happens to simplify development and testing.

---

**Exploitation Scenario**

An attacker:

* Accesses the API documentation endpoint
* Learns all available routes and payloads
* Targets sensitive APIs directly
* Chains this knowledge with other weaknesses

The documentation becomes a reconnaissance tool.

---

**Correct Approach / Rule**

Mandatory rules:

* API documentation must not be publicly accessible in production it could be configured with a current_env flag to display it only at QA/Dev Envs
* Access must require authentication and authorization
* Documentation exposure must be intentional and controlled
* Production defaults must be restrictive

Visibility must be treated as a security decision.

---

**What to Do If This Appears Again**

If you see:

* Docs accessible without authentication
* Docs enabled via simple flags
* Production environments exposing full API specs
* For NestJS projects using SwaggerUI in `main.ts`, only set up and import the Swagger module in non-production environments. Never expose Swagger or API docs in production by default.

You must:

* Treat it as an information disclosure issue
* Restrict or disable access
* Review other environments for similar exposure

---

**Framework Notes**

* Applies to **Express** and **NestJS**
* Documentation tooling does not change the risk

---

**Key Rule**

> If attackers can see the map,
> they will find the shortest path.

---