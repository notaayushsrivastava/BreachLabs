# BreachLabs Security Assessment - Methodology

Detailed methodology for each phase of the BreachLabs assessment pipeline.

## Reconnaissance Methodology

### Source inspection
1. **Inspect repository structure** - list top-level entries, identify language and framework from manifest files
2. **Read key source files** - read the application entrypoint, framework configuration, and key modules to understand architecture
3. **Identify entry points** - find all routes, API endpoints, form actions, and event handlers
4. **Map data flow** - trace how user input flows from entry points to sensitive operations (database queries, file operations, command execution)
5. **Identify authn/z** - locate authentication mechanisms, authorization checks, session management, and access control patterns

### Runtime inspection
1. **Start the application** - launch in the isolated sandbox environment
2. **Verify health** - confirm the application responds to requests
3. **Crawl discoverable routes** - visit each discovered route, note responses, parameters, and behavior
4. **Identify input vectors** - document all parameters, headers, body fields, cookies that accept user input
5. **Document the attack surface** - compile a structured map of routes, endpoints, forms, auth flows, technologies, and dependencies

### Dependency review
1. Identify dependency manifests (requirements.txt, package.json, go.mod, pom.xml, Cargo.toml, Gemfile, etc.)
2. List all declared dependencies with versions
3. Check for known vulnerable versions in the dependency tree
4. Flag outdated packages that have available security updates
5. Flag dependencies with known security issues or unmaintained status

## Source-Analysis Methodology

When investigating a finding from static analysis:

### Step 1: Read the source location
Read the file around the reported line, at minimum 15 lines on each side. Read more if the context requires it - function boundaries, imports, nearby callers, and data definitions may all be relevant.

### Step 2: Understand the context
Determine what function or module the finding is in, what data flows into this location, what other code trusts this location, and whether the code path is reachable from user input or external data.

### Step 3: Trace the data
Follow the data from its source to the finding location. Determine if the input is user-controlled, whether it passes through any sanitization or validation, and whether it reaches a sensitive sink (database query, file write, command execution, HTML output).

### Step 4: Check for compensating controls
Look for additional checks nearby - input validation upstream, output encoding, parameterized queries, access control checks, or other defenses that may mitigate the finding.

### Step 5: Assess the impact
Determine what an attacker could achieve if the finding is exploitable. Consider data confidentiality, integrity, and availability impacts, as well as whether the finding enables further attacks.

### Step 6: Determine exploitability
Decide whether this is a real vulnerability or a false positive. A finding that looks dangerous in isolation may be harmless in context - for example, a string-formatted query that only ever receives hardcoded values is not exploitable.

## Injection Analysis

For findings related to injection (SQL, XSS, command injection, template injection):
1. Identify the injection point - where does user input reach a sensitive sink?
2. Check for sanitization or parameterization - is the input escaped, parameterized, or validated?
3. Check for context-appropriate output encoding - is HTML output encoded, are JavaScript contexts handled, are URL parameters encoded?
4. Determine if the injection is exploitable in the runtime context - can an attacker control the input, and does the sink process it unsafely?
5. Classify by severity based on impact and exploitability.

## Authorization Analysis

For findings related to authorization (IDOR, privilege escalation, missing access control):
1. Identify the resource being accessed - which object, record, or action is involved?
2. Check whether the request authenticates the user - is there a session, token, or other credential?
3. Check whether the request authorizes the user for this specific resource - does the code verify that the authenticated user is allowed to access this particular object?
4. Determine if horizontal or vertical privilege escalation is possible
5. Check for direct object references that lack access control

## Runtime-Analysis Methodology

When investigating a finding from dynamic analysis:

### Step 1: Reproduce the finding
Send the same request that triggered the alert. Confirm that the alert is reproducible and not a one-time artifact.

### Step 2: Observe the response
Examine what the application returned. Note the response body, status code, headers, and any error messages.

### Step 3: Understand the trigger
Determine what input or condition caused the alert. Identify the specific parameter, header, or body field that triggered the finding.

### Step 4: Check for false positive
Determine whether this is actually a vulnerability or a scanner artifact. Common false positives: probes that match text in the response without being processed, error messages shown only in debug mode, alerts on responses containing the probe string in a benign context.

### Step 5: Assess exploitability
Determine whether the finding can be exploited in practice. Consider whether the required input can be controlled by an attacker, whether the effect is observable, and whether the finding represents a real security risk.

### Step 6: Document evidence
Capture the request, response, and explanation. Evidence must be specific enough that another reviewer could reproduce it without additional investigation.

## SQL Injection Verification
1. Test with a single quote to trigger SQL errors - append a single quote to a parameter and check for SQL error messages in the response
2. Test with a tautology - append OR 1=1 -- to a parameter and check if the response returns more records than the baseline
3. Compare baseline response with probe responses - count rows, check for error signatures, compare response sizes
4. Look for SQL error messages - database error text in the response is strong evidence of SQL injection
5. Confirm the injection point and payload - document the exact parameter and payload that demonstrates the vulnerability

## Cross-Site Scripting Verification
1. Inject a test payload into the input parameter - use a unique marker that is easy to search for in the response
2. Check if the payload is reflected in the response - search for the marker in the response body
3. Check if the payload is encoded or filtered - determine whether HTML entities are encoded, whether the payload is stripped, or whether it appears verbatim
4. Determine the context - is the payload in HTML body, an HTML attribute, a JavaScript context, or a URL? This affects exploitability and severity.
5. Confirm reflected XSS if the payload appears unencoded in a context where a browser would execute it

## Configuration Review Methodology
1. Check for debug mode enabled - debug mode exposes stack traces, interactive debuggers, and internal details
2. Check for verbose error messages - errors that expose SQL queries, file paths, internal logic, or stack traces aid attackers
3. Check for missing security headers - Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, X-Frame-Options
4. Check for weak or default credentials - hardcoded passwords, API keys, tokens, default admin accounts
5. Check for insecure configuration values - disabled security features, overly permissive settings
6. Check for exposed administrative interfaces - admin panels, debug endpoints, management interfaces without access control
