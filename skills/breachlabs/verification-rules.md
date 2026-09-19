# BreachLabs Security Assessment - Verification Rules

Rules for verifying security findings in the BreachLabs assessment pipeline.

## Verification Principles

### Verify, don't assert
A finding becomes trustworthy through evidence, not assertion. Verification means actively testing whether the finding represents a real, exploitable vulnerability - not just re-reading the scanner output.

### Downgrade on doubt
If verification is inconclusive, downgrade confidence rather than overstate. An `inconclusive` result is honest and useful. A false `confirmed` finding damages credibility.

### Match the method to the category
Different vulnerability categories require different verification methods. SQL injection is verified through database probes; hardcoded credentials are verified through source review; missing headers are verified through HTTP response inspection.

### Scope verification to high-value findings
Not every finding needs active verification. Informational findings, low-severity configuration issues, and findings that are obvious from source review may not benefit from runtime probing. Focus verification effort on high-severity, high-impact findings where confirmation adds value.

## Verification by Category

### Injection (SQL, command, template, etc.)
**Method:** Active probing against the running application.
1. Identify the injection point from the finding's location (route + parameter, or file + line)
2. Send a probe payload designed to trigger the injection
3. Compare the probe response with a baseline response
4. Look for evidence of injection: error messages, changed behavior, unexpected data

**SQL injection specific:**
- Error-based: probe with a single quote and look for SQL error messages
- Tautology: probe with OR 1=1 -- and check for row count changes
- Time-based: probe with a delay payload if other probes are not conclusive

**Command injection specific:** probe with a benign command (id, whoami, echo) and check for output in the response. Use a unique marker to confirm the command was executed.

**Confirmation criterion:** The probe produces a response that differs from baseline in a way that demonstrates the injection is processed by the sensitive sink, not just reflected.

### Cross-site scripting (XSS)
**Method:** Payload reflection check.
1. Inject a test payload into the input parameter
2. Check if the payload appears in the response
3. Check if the payload is encoded, filtered, or stripped
4. Determine the context (HTML body, attribute, JavaScript, URL)

**Confirmation criterion:** The payload appears unencoded in a context where a browser would execute it.

### Missing security headers
**Method:** HTTP response header inspection.
1. Send a request to the route
2. Check for security headers: Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, X-Frame-Options, Referrer-Policy, Permissions-Policy
3. Record which headers are missing

**Confirmation criterion:** The header is absent from the HTTP response.

### Authorization / IDOR
**Method:** Access control testing.
1. Identify the protected resource from the finding's location
2. Attempt to access the resource without authentication
3. Attempt to access the resource with a different user's identity
4. Attempt to access resources belonging to other users by modifying object IDs

**Confirmation criterion:** The resource can be accessed without proper authentication or authorization.

**Note:** IDOR verification requires understanding the application's authentication model. If the target has no authentication, the finding may be a design issue rather than an exploitable vulnerability.

### Secrets / hardcoded credentials
**Method:** Source review. Secrets findings are static - they are verified through code inspection, not runtime probing.
1. Locate the credential in the source code
2. Confirm it is a real credential and not a placeholder or example value
3. Assess the exposure risk: is the file in version control? Is it deployed with the application?

**Confirmation criterion:** The credential exists in the source code and is used by the application.

### Configuration weaknesses
**Method:** Source review + runtime inspection.
1. Check the application configuration for insecure settings (debug mode, verbose errors)
2. Verify the configuration is active at runtime
3. Assess the exposure impact

**Confirmation criterion:** The insecure configuration is present in the source and active at runtime.

### Cryptography weaknesses
**Method:** Source review.
1. Identify the cryptographic operation in the source code
2. Check the algorithm and parameters used
3. Determine if a weaker algorithm or insecure configuration is used

**Confirmation criterion:** The code uses a weak or outdated cryptographic algorithm or insecure parameters.

## Verification Outcomes

### Confirmed
The finding represents a real, exploitable vulnerability. Verification produced positive evidence through active testing or source review.
**Action:** Mark status as `verified`, confidence as `confirmed`. Include verification evidence in the finding.

### Inconclusive
Verification did not produce a clear result. The finding may or may not be exploitable, but the available evidence is insufficient to confirm.
**Action:** Mark status as `investigating`, confidence as `suspected` or `high` depending on the strength of the initial signal. Note the inconclusive result in the verification details.

### Rejected
Verification shows the finding is not a real vulnerability. The scanner signal was a false positive, or the code is not actually vulnerable when examined in context.
**Action:** Mark status as `false_positive`, confidence as `false_positive`. Include the reason for rejection. Do not remove the finding from the report - a dismissed finding with an explanation is more useful than no finding at all.

## Verification Confidence Rules

### When to assign CONFIRMED
- Active probing reproduced the vulnerability
- Source review confirmed the vulnerable pattern exists and is reachable
- Multiple independent verification methods produced consistent results

### When to assign HIGH (without full confirmation)
- The finding is corroborated by 2+ independent sources (e.g., SAST + DAST)
- Source code review confirms the vulnerable pattern exists
- Runtime testing shows related behavior but full exploitation was not demonstrated

### When to assign SUSPECTED
- A scanner signal was detected but not yet verified
- The finding needs further investigation
- Initial evidence is weak or ambiguous

### When to dismiss (false_positive)
- The signal is a known scanner artifact
- The code is not vulnerable when examined in context
- The finding is in test/demo code that is not deployed
- The finding is a false alarm due to scanner misconfiguration

## Verification Budget

Verification takes time. Focus on:
1. **High-severity findings first** - critical and high severity findings should be verified before medium and low
2. **Findings with clear verification paths** - some findings are easy to verify (missing headers, SQL injection); others are harder (complex authorization bugs)
3. **Findings where verification adds value** - if a finding is obvious from source review, verification may not add much. If a finding is ambiguous, verification can clarify it.

## Verification Evidence

Every verification attempt must produce evidence:
- **For active probing:** record the request sent, the response received, and the comparison with baseline
- **For source review:** record the file, line, and relevant code snippet
- **For configuration review:** record the configuration setting and its value

Verification evidence is added to the finding's evidence list with source `verification` or `investigation`.

## What NOT to do during verification
- Do not test against targets outside the assessment scope
- Do not use destructive payloads (drop tables, delete data, etc.)
- Do not exploit the vulnerability beyond what is needed to confirm it
- Do not exfiltrate real data from the target
- Do not test credentials or secrets found during the assessment against other systems
- Do not modify the target application during verification (use the fix-and-retest loop for that)
