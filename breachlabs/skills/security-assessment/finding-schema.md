# BreachLabs Security Assessment - Finding Schema Reference

Detailed reference for the BreachLabs finding data model.

## Overview

Every security finding in BreachLabs is represented by a structured `Finding` object defined in `breachlabs/core/types.py`. This document describes each field in detail with examples.

## Complete Schema

```json
{
  "id": "BL-0001",
  "title": "Short descriptive title",
  "category": "injection",
  "severity": "high",
  "confidence": "confirmed",
  "status": "verified",
  "location": {
    "file": "app.py",
    "line": 72,
    "route": "/search"
  },
  "description": "Human-readable description of the finding.",
  "evidence": [
    {
      "id": "EVD-0001",
      "source": "sast",
      "description": "Source code shows vulnerable pattern",
      "data": {"snippet": "query = f'SELECT ...'"},
      "file": "app.py",
      "line": 72,
      "captured_at": "2026-09-18T10:00:00Z"
    }
  ],
  "sources": ["sast", "dast"],
  "verification": {
    "attempted": true,
    "result": "confirmed",
    "details": "Verification details here."
  },
  "impact": "What an attacker can do.",
  "remediation": "What to change to fix it.",
  "limitations": ["Limitation 1", "Limitation 2"]
}
```

## Field Reference

### id: string (required)
Unique finding identifier. Format: `BL-` followed by a zero-padded sequence number (e.g., `BL-0001`, `BL-0012`). Assigned automatically by the assessment pipeline. IDs are unique within a single assessment.

### title: string (required)
Short, specific title. Should identify the finding without requiring the reader to read the description.

Good titles:
- `SQL injection in /search endpoint`
- `Hardcoded admin credentials in config.py`
- `Missing Content-Security-Policy header`
- `IDOR allows viewing other users' profiles`

Bad titles: `Potential security issue`, `Vulnerability found`

### category: string (required)
Category classifying the type of security issue. Standard categories: `injection` (SQL, command, template injection), `xss` (cross-site scripting), `authorization` (broken access control), `idor` (insecure direct object references), `headers` (missing security headers), `secrets` (hardcoded credentials), `configuration` (insecure configuration), `cryptography` (weak crypto), `session` (session management), `input-validation`, `information-disclosure`, `authentication`, `dependency` (vulnerable dependencies), `file-upload`, `ssrf`, `csrf`, `other` (catch-all).

### severity: enum (required)
Impact severity. One of: `critical`, `high`, `medium`, `low`, `informational`.

| Level | Meaning |
|---|---|
| critical | Immediate severe impact; trivial or likely exploitation |
| high | Significant impact; feasible exploitation |
| medium | Moderate impact; possible exploitation with limitations |
| low | Minor impact; difficult exploitation or limited effect |
| informational | Worth noting; not an actionable vulnerability |

Do not inflate severity to make the report look more serious.

### confidence: enum (required)
How certain the assessment is. One of: `confirmed`, `high`, `suspected`, `informational`, `false_positive`.

| Level | Meaning |
|---|---|
| confirmed | Reproduced and verified through active testing |
| high | Multiple sources corroborate, or source context confirms |
| suspected | Signal detected, not yet fully investigated |
| informational | Not clearly a vulnerability |
| false_positive | Not a real vulnerability |

### status: enum (required)
Workflow status. One of: `unverified`, `investigating`, `verified`, `dismissed`, `false_positive`.

| Status | Meaning |
|---|---|
| unverified | Created, not yet investigated |
| investigating | Agent is investigating |
| verified | Confirmed through verification |
| dismissed | Under investigation, being evaluated |
| false_positive | Confirmed not to be a real vulnerability |

A finding cannot transition to `verified` without a verification attempt.

### location: object (optional)
Where the finding is located. Contains:
- `file` (string): Source file name (for static findings)
- `line` (int): Line number in the source file
- `route` (string): URL path for runtime/dynamic findings

A finding can have both `file` and `route` (e.g., a SQL injection in a specific handler function).

### description: string (required)
Human-readable explanation of the finding. Should cover what was detected, why it matters, and any relevant context.

### evidence: list (optional)
List of `Evidence` objects supporting the finding. Each evidence item:
- `id`: Unique evidence identifier
- `source`: Where it came from (`sast`, `dast`, `browser`, `runtime`, `manual`, `investigation`, `verification`)
- `description`: What this evidence shows
- `data`: Structured data (snippets, request/response pairs, etc.)
- `file`/`line`: Optional file reference
- `captured_at`: Timestamp

### sources: list (optional)
List of source names that contributed to this finding. Used for correlation. Examples: `["sast"]`, `["sast", "dast"]`. Findings with 2+ distinct sources get HIGH confidence automatically during correlation.

### verification: object (optional)
Verification result. Contains:
- `attempted` (bool): Whether verification was attempted
- `result` (string): `confirmed`, `inconclusive`, or `rejected`
- `details` (string): Human-readable explanation

### impact: string (optional)
Description of likely impact if exploited. Should be specific.

### remediation: string (optional)
Description of how to fix the finding. Should be actionable and specific.

### limitations: list (optional)
List of strings describing limitations or uncertainties about the finding.

## Severity Mapping

Scanners may use different severity labels. The `Severity.from_scanner()` method maps them:

| Scanner label | BreachLabs severity |
|---|---|
| critical | critical |
| high | high |
| medium, moderate | medium |
| low | low |
| info, informational, none | informational |

Unknown labels default to `medium`.

## Confidence Assignment

| Condition | Confidence |
|---|---|
| Reproduced via active testing | confirmed |
| 2+ independent sources corroborate | high |
| Source context confirms exploitability | high |
| Scanner signal, not yet investigated | suspected |
| Not clearly a vulnerability | informational |
| Confirmed not a real vulnerability | false_positive |

## Default Values

When a `Finding` is created without explicit values:
- `status` defaults to `unverified`
- `confidence` defaults to `suspected`
- `evidence` defaults to empty list
- `sources` defaults to empty list
- `verification` defaults to `attempted=False`

These defaults ensure that unverified findings are not accidentally presented as confirmed.

## Example Finding: SQL Injection (confirmed)

```json
{
  "id": "BL-0001",
  "title": "SQL injection in /search endpoint",
  "category": "injection",
  "severity": "high",
  "confidence": "confirmed",
  "status": "verified",
  "location": {"file": "app.py", "line": 72, "route": "/search"},
  "description": "The /search endpoint constructs a SQL query using string formatting with user-supplied input from the q parameter. An attacker can inject arbitrary SQL by supplying crafted values for q.",
  "sources": ["sast", "dast"],
  "verification": {
    "attempted": true,
    "result": "confirmed",
    "details": "Confirmed via SQL tautology probe and source code review."
  },
  "impact": "An attacker can extract, modify, or delete data from the database by injecting SQL via the q parameter.",
  "remediation": "Use parameterized queries. Never interpolate user input into SQL strings.",
  "limitations": ["Only GET parameters were tested; POST body injection was not assessed"]
}
```

## Example Finding: Hardcoded Credentials (static, source-verified)

```json
{
  "id": "BL-0003",
  "title": "Hardcoded admin password in source code",
  "category": "secrets",
  "severity": "critical",
  "confidence": "confirmed",
  "status": "verified",
  "location": {"file": "vulnerable_app.py", "line": 29},
  "description": "The application contains a hardcoded admin password in source code, stored in plaintext.",
  "sources": ["secrets"],
  "verification": {
    "attempted": true,
    "result": "confirmed",
    "details": "Hardcoded credential confirmed via static analysis. Secrets findings are verified through source review, not runtime probing."
  },
  "impact": "Anyone with access to the source code knows the admin password. If committed to a repository, the password is in version control history.",
  "remediation": "Remove hardcoded credentials from source code. Use environment variables or a secrets manager. Rotate the compromised password immediately.",
  "limitations": ["Static analysis only - runtime behavior not tested"]
}
```
