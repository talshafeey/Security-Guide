### orm-misuse-sql-injection.md

**Issue Name**
SQL Injection via Incorrect ORM Usage

---

**Risk / Impact**

This issue allows an attacker to:

* Execute arbitrary SQL queries
* Read or modify sensitive data
* Bypass authentication and authorization
* Potentially take full control of the database

This is a **critical** issue.

---

**In Plain English**

If user input is mixed directly into database queries,
an attacker can trick the database into running commands you never intended.

Using an ORM does **not** automatically make you safe.

---

**How It Exists in Current Code**

The vulnerability was introduced by:

* Using the ORM to construct SQL queries dynamically based on user input
* Allowing user-supplied data to flow directly into query conditions (such as `where` clauses or custom query builders)
* Failing to enforce proper parameter binding or escaping of all values

This resulted in situations where the SQL query text contained unsanitized input provided by external callers.

---

**Exploitation Scenario**

Example from a real incident:

* The `/users/generateOTPforLogin` API accepted user input (userName="test@test.com'") and inserted it directly into a SQL fragment using the ORM’s query builder or raw query feature.
* An attacker supplied input like a single quote character (`'`) to intentionally break the query syntax.
* The backend did not use parameterized statements, so the raw input was injected directly into the SQL.
* As a result, the attacker was able to receive database error messages revealing details such as column names.
* The attacker then automated exploitation using tools such as `sqlmap` to issue arbitrary SQL statements, escalating the attack and potentially gaining full database access.

Note: This attack did not require authentication bypass—the vulnerable API was publicly exposed.

---

**Correct Approach / Rule**

Mandatory rules:

* All database queries must use **parameterized input**
* User input must never alter query structure
* Dynamic query construction must be treated as unsafe by default
* For complex queries involving multiple joins, consider implementing a database view rather than constructing the query as a raw SQL statement.
* ORM features that bypass parameter binding are forbidden unless reviewed

ORM convenience must never override safety.

---

**What to Do If This Appears Again**

If you see:

* String-based query construction
* Dynamic conditions using raw input
* ORM methods that accept raw expressions

You must:

* Stop the change
* Flag it during review
* Treat it as a security bug, not a style issue

---

**Framework Notes**

* This applies equally to **Express** and **NestJS**
* The vulnerability is in **data access**, not the framework

Framework choice does not reduce responsibility.

---

**Key Rule**

> An ORM is a tool, not a security boundary.
> If input reaches SQL without strict binding, it is a vulnerability.

---
