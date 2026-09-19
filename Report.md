=== BreachLabs demo assessment ===
Target: C:\Users\Aayush\Desktop\python_projects_shared\BreachLabs\breachlabs\demo (isolated sandbox, port 5005)
[*] Creating isolated environment...
[*] Starting target application (auto-detected app.py)...
[+] Target healthy at http://127.0.0.1:5005
[         INTAKE] Intake validated for demo/vulnerable_app@demo
[          BUILD] Creating isolated environment
[          BUILD] [check_health] Application healthy at http://127.0.0.1:5005
[          RECON] [list_routes] 4 routes discovered
[STATIC_ANALYSIS] [run_static_scan] Static analysis produced 6 signals
[STATIC_ANALYSIS] [scan_secrets] Secret scan produced 8 total signals so far
[DYNAMIC_ANALYSIS] [run_dast] Dynamic analysis produced 5 alerts
[        BROWSER] [open_page] Browser explored 3 workflows
[  INVESTIGATION] [ai_triage] 15 scanner signals correlated into 15 investigations
[  INVESTIGATION] [ai_triage] Investigating 15 findings: reading source context, correlating with attack surface, generating remediation
[  INVESTIGATION] [ai_triage] Investigation completed: 15 findings enriched with context, 8 elevated to high confidence
[   VERIFICATION] [verify_finding] Verifying 5 high-value findings
[   VERIFICATION] [verify_finding] Verification completed
[         REPORT] Browser driver torn down (budget: {'elapsed_seconds': 2.9, 'tool_calls': '0/30', 'browser_actions': '4/40', 'investigation_loops': '0/5'})
[         REPORT] Budget consumed: {'elapsed_seconds': 2.9, 'tool_calls': '0/30', 'browser_actions': '4/40', 'investigation_loops': '0/5'}
[         REPORT] Assessment pipeline completed
[*] Destroying isolated environment...

Assessment status: completed
Findings: 15
Investigated: 15 | Verified: 1 | Inconclusive: 0

  - BL-0002 [high/high] Hardcoded credential assignment (sources: sast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Review the flagged code location and apply secure patterns.
  - BL-0003 [high/high] Hardcoded credential assignment (sources: sast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Review the flagged code location and apply secure patterns.
  - BL-0007 [high/high] Generic API token assignment (sources: secrets, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Rotate the credential and remove it from source history.
  - BL-0008 [high/high] Generic API token assignment (sources: secrets, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Rotate the credential and remove it from source history.
  - BL-0012 [high/confirmed] Reflected cross-site scripting (sources: dast, investigation, verification)
      status=verified evidence=3 verification=confirmed
      probe: Probe 'xss_reflection': XSS payload reflected unencoded in response body (script tag present): http://127.0.0.1:5005/search?q=<script>alert(b1x9zx)</script>
      fix: Harden the affected endpoint; see remediation guidance.
  - BL-0013 [high/suspected] Possible SQL injection (error-based) (sources: dast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Harden the affected endpoint; see remediation guidance.
  - BL-0001 [medium/high] Debug mode enabled (sources: sast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Review the flagged code location and apply secure patterns.
  - BL-0004 [medium/high] Weak hash algorithm (sources: sast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Review the flagged code location and apply secure patterns.
  - BL-0005 [medium/high] Weak hash algorithm (sources: sast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Review the flagged code location and apply secure patterns.
  - BL-0006 [medium/high] Debug mode enabled (sources: sast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Review the flagged code location and apply secure patterns.
  - BL-0009 [medium/suspected] Missing security header: content-security-policy (sources: dast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Harden the affected endpoint; see remediation guidance.
  - BL-0015 [medium/suspected] Browser: login workflow reaches authenticated page (sources: browser, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Enforce strong, unique credentials; add rate limiting and lockout; never ship defaults.
  - BL-0010 [low/suspected] Missing security header: x-content-type-options (sources: dast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Harden the affected endpoint; see remediation guidance.
  - BL-0011 [low/suspected] Missing security header: strict-transport-security (sources: dast, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Harden the affected endpoint; see remediation guidance.
  - BL-0014 [low/suspected] Browser: form on /login (sources: browser, investigation)
      status=investigating evidence=2 verification=not attempted
      fix: Validate every field server-side; encode output for its context.

========================================================================
FULL REPORT
========================================================================
# BreachLabs Security Assessment

## Executive Summary

Assessment ASM-0001 evaluated demo/vulnerable_app in an isolated environment. 15 findings were produced, of which 1 were verified and 0 dismissed as false positives. Findings are prioritized by severity and confidence; remediation guidance is provided for each.

## Assessment Scope

- **Repository:** demo/vulnerable_app
- **Commit:** demo
- **Mode:** deep
- **Assessment ID:** ASM-0001
- **Environment:** sbx-680-1789778317

## Findings

### BL-0002 — Hardcoded credential assignment

- **Severity:** high
- **Confidence:** high
- **Status:** investigating
- **Location:** vulnerable_app.py:29
- **Sources:** sast, investigation

Possible hardcoded credential in source.

**Evidence**

- [sast] BL-SAST-007: Possible hardcoded credential in source.
- [investigation] Source context from vulnerable_app.py:14-44 (finding at line 29)

**Impact:** Potential exploitable behavior in application code.

**Remediation:** Review the flagged code location and apply secure patterns.

### BL-0003 — Hardcoded credential assignment

- **Severity:** high
- **Confidence:** high
- **Status:** investigating
- **Location:** vulnerable_app.py:30
- **Sources:** sast, investigation

Possible hardcoded credential in source.

**Evidence**

- [sast] BL-SAST-007: Possible hardcoded credential in source.
- [investigation] Source context from vulnerable_app.py:15-45 (finding at line 30)

**Impact:** Potential exploitable behavior in application code.

**Remediation:** Review the flagged code location and apply secure patterns.

### BL-0007 — Generic API token assignment

- **Severity:** high
- **Confidence:** high
- **Status:** investigating
- **Location:** vulnerable_app.py:29
- **Sources:** secrets, investigation

Long credential-looking literal assigned in source.

**Evidence**

- [secrets] Long credential-looking literal assigned in source.
- [investigation] Source context from vulnerable_app.py:14-44 (finding at line 29)

**Impact:** Committed credentials may allow unauthorized access.

**Remediation:** Rotate the credential and remove it from source history.

### BL-0008 — Generic API token assignment

- **Severity:** high
- **Confidence:** high
- **Status:** investigating
- **Location:** vulnerable_app.py:30
- **Sources:** secrets, investigation

Long credential-looking literal assigned in source.

**Evidence**

- [secrets] Long credential-looking literal assigned in source.
- [investigation] Source context from vulnerable_app.py:15-45 (finding at line 30)

**Impact:** Committed credentials may allow unauthorized access.

**Remediation:** Rotate the credential and remove it from source history.

### BL-0012 — Reflected cross-site scripting

- **Severity:** high
- **Confidence:** confirmed
- **Status:** verified
- **Location:** http://127.0.0.1:5005/search?q=<script>breachlabs-probe</script>
- **Sources:** dast, investigation, verification

Probe payload reflected unencoded in response body.

**Evidence**

- [dast] Probe payload reflected unencoded in response body.
- [investigation] Route http://127.0.0.1:5005/search?q=<script>breachlabs-probe</script> was not found in the recon attack surface; the finding may reference an undiscovered or dynamic route.
- [verification] Probe 'xss_reflection': XSS payload reflected unencoded in response body (script tag present): http://127.0.0.1:5005/search?q=<script>alert(b1x9zx)</script>

**Impact:** Runtime-observed weakness reachable from HTTP interface.

**Remediation:** Harden the affected endpoint; see remediation guidance.

### BL-0013 — Possible SQL injection (error-based)

- **Severity:** high
- **Confidence:** suspected
- **Status:** investigating
- **Location:** http://127.0.0.1:5005/search?q=%27BREACHLABS
- **Sources:** dast, investigation

Database error signature in response: 'syntax error'.

**Evidence**

- [dast] Database error signature in response: 'syntax error'.
- [investigation] Route http://127.0.0.1:5005/search?q=%27BREACHLABS was not found in the recon attack surface; the finding may reference an undiscovered or dynamic route.

**Impact:** Runtime-observed weakness reachable from HTTP interface.

**Remediation:** Harden the affected endpoint; see remediation guidance.

### BL-0001 — Debug mode enabled

- **Severity:** medium
- **Confidence:** high
- **Status:** investigating
- **Location:** app.py:22
- **Sources:** sast, investigation

Application runs with debug mode enabled.

**Evidence**

- [sast] BL-SAST-004: Application runs with debug mode enabled.
- [investigation] Source context from app.py:7-26 (finding at line 22)

**Impact:** Potential exploitable behavior in application code.

**Remediation:** Review the flagged code location and apply secure patterns.

### BL-0004 — Weak hash algorithm

- **Severity:** medium
- **Confidence:** high
- **Status:** investigating
- **Location:** vulnerable_app.py:56
- **Sources:** sast, investigation

Weak hash algorithm (MD5/SHA-1) used.

**Evidence**

- [sast] BL-SAST-006: Weak hash algorithm (MD5/SHA-1) used.
- [investigation] Source context from vulnerable_app.py:41-71 (finding at line 56)

**Impact:** Potential exploitable behavior in application code.

**Remediation:** Review the flagged code location and apply secure patterns.

### BL-0005 — Weak hash algorithm

- **Severity:** medium
- **Confidence:** high
- **Status:** investigating
- **Location:** vulnerable_app.py:121
- **Sources:** sast, investigation

Weak hash algorithm (MD5/SHA-1) used.

**Evidence**

- [sast] BL-SAST-006: Weak hash algorithm (MD5/SHA-1) used.
- [investigation] Source context from vulnerable_app.py:106-135 (finding at line 121)

**Impact:** Potential exploitable behavior in application code.

**Remediation:** Review the flagged code location and apply secure patterns.

### BL-0006 — Debug mode enabled

- **Severity:** medium
- **Confidence:** high
- **Status:** investigating
- **Location:** vulnerable_app.py:135
- **Sources:** sast, investigation

Application runs with debug mode enabled.

**Evidence**

- [sast] BL-SAST-004: Application runs with debug mode enabled.
- [investigation] Source context from vulnerable_app.py:120-135 (finding at line 135)

**Impact:** Potential exploitable behavior in application code.

**Remediation:** Review the flagged code location and apply secure patterns.

### BL-0009 — Missing security header: content-security-policy

- **Severity:** medium
- **Confidence:** suspected
- **Status:** investigating
- **Location:** http://127.0.0.1:5005
- **Sources:** dast, investigation

Response is missing the 'content-security-policy' header.

**Evidence**

- [dast] Response is missing the 'content-security-policy' header.
- [investigation] Route http://127.0.0.1:5005 was not found in the recon attack surface; the finding may reference an undiscovered or dynamic route.

**Impact:** Runtime-observed weakness reachable from HTTP interface.

**Remediation:** Harden the affected endpoint; see remediation guidance.

### BL-0015 — Browser: login workflow reaches authenticated page

- **Severity:** medium
- **Confidence:** suspected
- **Status:** investigating
- **Location:** /login
- **Sources:** browser, investigation

Browser-driven login with default credentials reached an authenticated page.

**Evidence**

- [browser] Browser login workflow record
- [investigation] Route /login confirmed in attack surface (4 routes discovered during recon).

**Impact:** Default credentials allow unauthorized access.

**Remediation:** Enforce strong, unique credentials; add rate limiting and lockout; never ship defaults.

### BL-0010 — Missing security header: x-content-type-options

- **Severity:** low
- **Confidence:** suspected
- **Status:** investigating
- **Location:** http://127.0.0.1:5005
- **Sources:** dast, investigation

Response is missing the 'x-content-type-options' header.

**Evidence**

- [dast] Response is missing the 'x-content-type-options' header.
- [investigation] Route http://127.0.0.1:5005 was not found in the recon attack surface; the finding may reference an undiscovered or dynamic route.

**Impact:** Runtime-observed weakness reachable from HTTP interface.

**Remediation:** Harden the affected endpoint; see remediation guidance.

### BL-0011 — Missing security header: strict-transport-security

- **Severity:** low
- **Confidence:** suspected
- **Status:** investigating
- **Location:** http://127.0.0.1:5005
- **Sources:** dast, investigation

Response is missing the 'strict-transport-security' header.

**Evidence**

- [dast] Response is missing the 'strict-transport-security' header.
- [investigation] Route http://127.0.0.1:5005 was not found in the recon attack surface; the finding may reference an undiscovered or dynamic route.

**Impact:** Runtime-observed weakness reachable from HTTP interface.

**Remediation:** Harden the affected endpoint; see remediation guidance.

### BL-0014 — Browser: form on /login

- **Severity:** low
- **Confidence:** suspected
- **Status:** investigating
- **Location:** /login
- **Sources:** browser, investigation

Browser found a form with 3 inputs; validate each server-side.

**Evidence**

- [browser] Browser form discovery
- [investigation] Route /login confirmed in attack surface (4 routes discovered during recon).

**Impact:** Unvalidated form inputs are injection vectors.

**Remediation:** Validate every field server-side; encode output for its context.

## Coverage

- 16 assessment events recorded
- {'critical': 0, 'high': 6, 'medium': 6, 'low': 3, 'informational': 0}

## Limitations

- Coverage is limited to checks enabled by the assessment policy.
- Dynamic checks were limited to scoped, isolated targets.
- Absence of findings does not establish that the application is secure.
- Automated triage cannot replace manual security review.

## Disclaimer

BreachLabs performs an automated, evidence-backed application security assessment within the declared scope. A clean assessment is not proof that an application is secure.

