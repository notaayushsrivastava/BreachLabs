# BreachLabs Security Assessment - Report Guidelines

Guidance for generating security assessment reports from BreachLabs findings.

## Report Purpose

The BreachLabs report is the primary output of the assessment. It is the document that developers, security reviewers, and stakeholders will read. It must be clear, actionable, and honest.

The report serves three audiences:
1. **Developers** - need to understand what to fix and how
2. **Security reviewers** - need to assess the quality and completeness of the assessment
3. **Stakeholders** - need an executive summary of the security posture

## Report Format

The report is generated in two formats:
- **Markdown** - human-readable, suitable for reading and sharing
- **JSON** - machine-readable, suitable for programmatic processing and integration

Both formats are generated from the same assessment data. The Markdown report is for people; the JSON report is for systems.

## Report Structure

### 1. Title and metadata
```
# BreachLabs Security Assessment
```
Followed by a metadata block: assessment ID, repository name, commit or branch, assessment mode (deep/quick), start/completion time, environment ID, assessment status.

### 2. Executive Summary
A concise summary of the assessment results. Should answer:
- What was assessed?
- What did BreachLabs find?
- How many findings of each severity?
- How many were verified?
- What is the overall security posture?

The executive summary should be readable by a non-specialist. Avoid jargon. Focus on the results and their meaning.

Example:
```
BreachLabs assessed the vulnerable demo application in an isolated environment.
12 findings were produced, of which 6 were high severity, 4 medium, and 2 low.
3 findings were verified through active testing. 1 finding was dismissed as a false positive.
The application has significant security weaknesses in input validation, authentication,
and configuration that should be addressed before deployment.
```

### 3. Assessment Scope
Describe what was assessed and under what constraints: repository path or identifier, commit or branch assessed, assessment mode, scope restrictions (isolated environment, allowed hosts, active checks enabled/disabled), tools and checks that were run.

### 4. Application Profile
Describe the application that was assessed: framework and language, entry points identified, routes and endpoints discovered, technologies detected, dependencies identified.

### 5. Attack Surface
Summarize the attack surface: number of routes, API endpoints, forms, authentication flows identified, technologies in use, dependencies.

### 6. Findings
The core of the report. Each finding is presented as a section:

```
### BL-0001 - SQL Injection in /search Endpoint

**Severity:** High
**Confidence:** Confirmed
**Status:** Verified
**Category:** Injection
**Location:** app.py:72, route /search
**Sources:** SAST, DAST

Description...

**Evidence**
- [SAST] Source code at app.py:72 shows string-formatted SQL query
- [DAST] SQL error probe returned database error message
- [DAST] SQL tautology probe confirmed row count manipulation

**Impact:** ...

**Remediation:** ...

**Verification:** Confirmed via SQL tautology probe.

**Limitations:** ...
```

Group findings by severity (critical first, then high, medium, low, informational).

### 7. Security Hygiene
Summarize security hygiene findings: missing security headers, configuration issues, dependency issues, secret detection results (with redaction).

### 8. Coverage
Describe what was and was not covered: phases completed, tools run, areas not assessed, limitations of the assessment.

### 9. Limitations
Be honest about what the assessment cannot tell you: coverage limitations, tool limitations, scope limitations, and the fundamental limitation - a clean assessment is not proof that the application is secure.

### 10. Disclaimer
Include the standard BreachLabs disclaimer:
```
BreachLabs performs an automated, evidence-backed application security assessment
within the declared scope. A clean assessment is not proof that an application is
secure.
```

## Writing Guidance

### Descriptions
Descriptions should be:
- **Specific** - name the exact file, line, route, and parameter
- **Actionable** - explain what the finding means in practice
- **Evidence-backed** - reference the evidence that supports the finding
- **Honest** - acknowledge uncertainty when it exists

Avoid vague language, technical jargon without explanation, and speculation presented as fact.

### Impact statements
Impact statements should answer: "What can an attacker do if this is exploited?"

Be specific:
- Good: "An attacker can extract all records from the notes table by injecting UNION SELECT statements via the q parameter."
- Bad: "This could lead to data exposure."

### Remediation guidance
Remediation should be:
- **Actionable** - tell the developer what to change
- **Specific** - include code-level guidance where possible
- **Practical** - suggest changes that are reasonable to implement
- **Prioritized** - note which findings should be fixed first

Include code examples where helpful:
```
Use parameterized queries. Replace:
    query = f"SELECT * FROM notes WHERE body LIKE '%{q}%'"
With:
    query = "SELECT * FROM notes WHERE body LIKE ?"
    result = conn.execute(query, (f"%{q}%",))
```

### Evidence presentation
Present evidence clearly:
- Source evidence: show the code snippet with file and line
- Runtime evidence: show the request and response (redacting sensitive values)
- Scanner evidence: summarize the scanner output

Redact secrets and sensitive values from all evidence. Never include actual passwords, API keys, tokens, or PII in the report.

## Severity Distribution
Include a severity summary:
```
## Severity Summary
- Critical: 0
- High: 6
- Medium: 4
- Low: 2
- Informational: 0
- Total: 12
```

## Verification Summary
Include a verification summary:
```
## Verification Summary
- Verified: 3
- Inconclusive: 2
- Dismissed (false positive): 1
- Not verified: 6
```

## What to avoid in reports
- Do not claim that a clean report means the application is secure
- Do not overstate confidence without evidence
- Do not include raw secrets or sensitive data
- Do not speculate about attacker intent beyond what the evidence supports
- Do not present scanner output verbatim without analysis and context
- Do not omit limitations

## Report quality checklist
- [ ] Every finding has a severity, confidence, and status
- [ ] Every finding has a description, impact, and remediation
- [ ] Every finding has at least one piece of evidence
- [ ] Secrets are redacted from all evidence and snippets
- [ ] The executive summary is readable by a non-specialist
- [ ] The report acknowledges its limitations
- [ ] The disclaimer is present
- [ ] Findings are grouped by severity
- [ ] Remediation guidance is actionable and specific
