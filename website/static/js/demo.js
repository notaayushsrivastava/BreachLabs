/**
 * BreachLabs Interactive Deterministic Demo (/demo).
 * Features:
 * - Multi-scenario simulation engine (E-Commerce, API Gateway, Auth Service)
 * - Step-by-step & Auto-play Stage Pipeline Controller
 * - Real-time Streaming Telemetry Log
 * - Deep Finding Inspector Drawer with Code Context, Evidence Trace, AI Reasoning & Patch Diffs
 * - Report Preview Tabs (Findings Explorer, Markdown Report, Raw JSON)
 * - Interactive Severity Filters & Clipboard Copy Actions
 * - 100% deterministic, safe client-side simulation (no live scanning or network requests).
 */

const SCENARIOS = {
  ecommerce: {
    id: "DEMO-0001",
    target: "breachlabs-demo",
    duration_ms: 4820,
    routes_discovered: 14,
    status: "completed",
    stages: [
      { name: "Discovery & Recon", log: "[00:01.450] DISCOVER: Enumerated 14 HTTP routes, 3 forms, 9 JSON endpoints on 'breachlabs-demo'" },
      { name: "Deterministic Scans", log: "[00:02.810] SAST: Taint sink in search.py:38 -> direct string concatenation into SQL query" },
      { name: "AI Investigation", log: "[00:03.200] AGENT: Correlated route GET /search?q= with unvalidated query parameter" },
      { name: "Targeted Verification", log: "[00:04.110] VERIFY: Dispatched deterministic probe -> Syntax verification payload confirmed BL-DEMO-001" },
      { name: "Fix & Retest Proof", log: "[00:04.820] SUMMARY: Assessment complete · 3 findings recorded in append-only evidence store" }
    ],
    findings: [
      {
        id: "BL-DEMO-001",
        title: "SQL injection in search parameter",
        severity: "high",
        confidence: "verified",
        status: "verified",
        surface: "GET /search?q=",
        cwe: "CWE-89: SQL Injection",
        codeFile: "search.py:38",
        codeSnippet: [
          { num: 36, text: "def search_products(request):", cls: "cm" },
          { num: 37, text: "    term = request.args.get('q', '')", cls: "cm" },
          { num: 38, text: "    query = \"SELECT * FROM items WHERE name = '\" + term + \"'\"", cls: "hl" },
          { num: 39, text: "    return db.engine.execute(query).fetchall()", cls: "cm" }
        ],
        evidence: [
          { sev: "high", source: "search.py:38 — AST Taint analysis sink", kind: "SAST" },
          { sev: "high", source: "GET /search?q='%20OR%20'1'='1 → HTTP 200 with full DB dump", kind: "DAST PROBE" },
          { sev: "medium", source: "Unparameterized SQL executed in 2 surrounding helper calls", kind: "CORRELATION" }
        ],
        reasoning: "The `q` query parameter is read directly from untrusted user input and concatenated without sanitization or SQL parameter binding. The verification probe confirmed that arbitrary SQL syntax executes against the SQLite datastore.",
        patchDiff: [
          { num: 1, text: "- query = \"SELECT * FROM items WHERE name = '\" + term + \"'\"", cls: "del" },
          { num: 2, text: "- return db.engine.execute(query).fetchall()", cls: "del" },
          { num: 3, text: "+ query = \"SELECT * FROM items WHERE name = ?\"", cls: "add" },
          { num: 4, text: "+ return db.engine.execute(query, (term,)).fetchall()", cls: "add" }
        ],
        retestNotice: "Retest Verified: Replaying probe payload against patched code resulted in HTTP 200 with zero injected query syntax execution. Finding marked RESOLVED."
      },
      {
        id: "BL-DEMO-002",
        title: "Reflected XSS in comment field",
        severity: "high",
        confidence: "verified",
        status: "verified",
        surface: "POST /comments",
        cwe: "CWE-79: Cross-site Scripting",
        codeFile: "comments.py:24",
        codeSnippet: [
          { num: 22, text: "def post_comment(request):", cls: "cm" },
          { num: 23, text: "    content = request.form.get('comment')", cls: "cm" },
          { num: 24, text: "    return render_template_string(f\"<p>{content}</p>\")", cls: "hl" }
        ],
        evidence: [
          { sev: "high", source: "comments.py:24 — Raw string template rendering", kind: "SAST" },
          { sev: "high", source: "POST /comments payload `<svg/onload=alert(1)>` executed in headless DOM", kind: "BROWSER" }
        ],
        reasoning: "User comment submission is rendered directly into HTML without context-aware escaping. Automated browser probe confirmed arbitrary JavaScript execution in DOM context.",
        patchDiff: [
          { num: 1, text: "- return render_template_string(f\"<p>{content}</p>\")", cls: "del" },
          { num: 2, text: "+ return render_template(\"comment.html\", content=escape(content))", cls: "add" }
        ],
        retestNotice: "Retest Verified: Automated browser replay against patched template confirmed characters are properly entity-encoded (`&lt;svg...`). Script did not execute."
      },
      {
        id: "BL-DEMO-003",
        title: "Missing security response headers",
        severity: "medium",
        confidence: "investigating",
        status: "investigating",
        surface: "GET /",
        cwe: "CWE-693: Protection Mechanism Failure",
        codeFile: "app.py:12",
        codeSnippet: [
          { num: 10, text: "@app.route('/')", cls: "cm" },
          { num: 11, text: "def index():", cls: "cm" },
          { num: 12, text: "    return render_template('index.html')", cls: "hl" }
        ],
        evidence: [
          { sev: "medium", source: "HTTP/1.1 200 OK missing Content-Security-Policy and X-Frame-Options", kind: "DAST" }
        ],
        reasoning: "Root route does not emit strict CSP or frame isolation headers. Triage agent is correlating if reverse proxy applies headers downstream.",
        patchDiff: [
          { num: 1, text: "+ @app.after_request", cls: "add" },
          { num: 2, text: "+ def apply_security_headers(response):", cls: "add" },
          { num: 3, text: "+     response.headers['Content-Security-Policy'] = \"default-src 'self'\"", cls: "add" },
          { num: 4, text: "+     return response", cls: "add" }
        ],
        retestNotice: "Pending Verification: Awaiting upstream reverse-proxy configuration test."
      }
    ]
  },
  "api-gateway": {
    id: "DEMO-0002",
    target: "api-gateway-v2",
    duration_ms: 3640,
    routes_discovered: 28,
    status: "completed",
    stages: [
      { name: "Discovery & Recon", log: "[00:00.950] DISCOVER: Enumerated 28 REST endpoints & OpenAPI schema on 'api-gateway-v2'" },
      { name: "Deterministic Scans", log: "[00:01.880] SAST: Discovered missing session claim verification on /api/v2/accounts/{id}" },
      { name: "AI Investigation", log: "[00:02.420] AGENT: Traced user ID lookup in account_service.py against caller JWT payload" },
      { name: "Targeted Verification", log: "[00:03.100] VERIFY: Dual-session probe reproduced BOLA unauthorized balance inspection" },
      { name: "Fix & Retest Proof", log: "[00:03.640] SUMMARY: Assessment complete · 3 findings recorded in append-only evidence store" }
    ],
    findings: [
      {
        id: "BL-GATE-001",
        title: "Broken object level authorization (BOLA) in account endpoint",
        severity: "critical",
        confidence: "verified",
        status: "verified",
        surface: "GET /api/v2/accounts/{id}",
        cwe: "CWE-285: Improper Authorization",
        codeFile: "controllers/account.py:44",
        codeSnippet: [
          { num: 42, text: "@router.get('/accounts/{account_id}')", cls: "cm" },
          { num: 43, text: "def get_account(account_id: str, auth: Auth = Depends(get_auth)):", cls: "cm" },
          { num: 44, text: "    return account_service.fetch_by_id(account_id)", cls: "hl" }
        ],
        evidence: [
          { sev: "critical", source: "controllers/account.py:44 — Object fetched without tenant check", kind: "SAST" },
          { sev: "critical", source: "User B session token accessed Account A record -> HTTP 200 returned", kind: "DAST PROBE" }
        ],
        reasoning: "The account lookup endpoint takes an arbitrary account ID path parameter and fails to check whether the authenticated user has permission to view that account.",
        patchDiff: [
          { num: 1, text: "- return account_service.fetch_by_id(account_id)", cls: "del" },
          { num: 2, text: "+ return account_service.fetch_for_user(account_id, user_id=auth.user_id)", cls: "add" }
        ],
        retestNotice: "Retest Verified: User B probe received HTTP 403 Forbidden on cross-account ID. Finding marked RESOLVED."
      },
      {
        id: "BL-GATE-002",
        title: "JWT 'none' algorithm signature bypass",
        severity: "high",
        confidence: "verified",
        status: "verified",
        surface: "POST /api/v2/auth/validate",
        cwe: "CWE-347: Improper Verification of Cryptographic Signature",
        codeFile: "middleware/jwt.py:19",
        codeSnippet: [
          { num: 18, text: "def verify_token(token: str):", cls: "cm" },
          { num: 19, text: "    return jwt.decode(token, verify=False)", cls: "hl" }
        ],
        evidence: [
          { sev: "high", source: "middleware/jwt.py:19 — Signature verification bypassed in decoder", kind: "SAST" },
          { sev: "high", source: "Crafted header `{\"alg\":\"none\"}` granted admin access in DAST probe", kind: "VERIFY" }
        ],
        reasoning: "JWT token parser accepts tokens with algorithm set to None, allowing attackers to forge arbitrary claims without knowing the secret key.",
        patchDiff: [
          { num: 1, text: "- return jwt.decode(token, verify=False)", cls: "del" },
          { num: 2, text: "+ return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])", cls: "add" }
        ],
        retestNotice: "Retest Verified: Unsigned token probe rejected with HTTP 401 Unauthorized."
      },
      {
        id: "BL-GATE-003",
        title: "Missing rate limiting on authentication route",
        severity: "medium",
        confidence: "investigating",
        status: "investigating",
        surface: "POST /api/v2/auth/login",
        cwe: "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        codeFile: "controllers/auth.py:8",
        codeSnippet: [
          { num: 7, text: "@router.post('/auth/login')", cls: "cm" },
          { num: 8, text: "def login(creds: LoginRequest):", cls: "hl" }
        ],
        evidence: [
          { sev: "medium", source: "120 login requests within 2 seconds accepted without 429 response", kind: "DAST" }
        ],
        reasoning: "Burst test completed 120 consecutive login attempts with no throttling. Investigating if cloud WAF provides IP rate limits.",
        patchDiff: [
          { num: 1, text: "+ @limiter.limit('5/minute')", cls: "add" },
          { num: 2, text: "  def login(creds: LoginRequest):", cls: "ctx" }
        ],
        retestNotice: "Pending Verification: Retest scheduled with distributed probe."
      }
    ]
  },
  "auth-service": {
    id: "DEMO-0003",
    target: "auth-service-internal",
    duration_ms: 2980,
    routes_discovered: 8,
    status: "completed",
    stages: [
      { name: "Discovery & Recon", log: "[00:00.620] DISCOVER: Mapped 8 internal auth RPCs and environment configurations" },
      { name: "Deterministic Scans", log: "[00:01.310] SECRETS: Regex scanner matched AWS access key pattern in test fixture" },
      { name: "AI Investigation", log: "[00:01.900] AGENT: Verified file is committed in main branch history: tests/fixtures/aws.json" },
      { name: "Targeted Verification", log: "[00:02.440] VERIFY: Key format verified against synthetic credential scanner rules" },
      { name: "Fix & Retest Proof", log: "[00:02.980] SUMMARY: Assessment complete · 2 findings recorded in append-only evidence store" }
    ],
    findings: [
      {
        id: "BL-AUTH-001",
        title: "Committed AWS Access Key in Test Fixture",
        severity: "critical",
        confidence: "verified",
        status: "verified",
        surface: "tests/fixtures/aws.json:3",
        cwe: "CWE-798: Use of Hard-coded Credentials",
        codeFile: "tests/fixtures/aws.json:3",
        codeSnippet: [
          { num: 1, text: "{", cls: "cm" },
          { num: 2, text: "  \"environment\": \"staging\",", cls: "cm" },
          { num: 3, text: "  \"aws_access_key_id\": \"AKIAIOSFODNN7EXAMPLE\",", cls: "hl" },
          { num: 4, text: "  \"aws_secret_access_key\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"", cls: "hl" },
          { num: 5, text: "}", cls: "cm" }
        ],
        evidence: [
          { sev: "critical", source: "tests/fixtures/aws.json:3 — AWS Access Key ID match", kind: "SECRETS" },
          { sev: "critical", source: "Committed in Git history at commit 4f2a1e", kind: "REPO PROVENANCE" }
        ],
        reasoning: "High-entropy AWS credential strings found committed in test fixtures. Key has been redacted and marked for immediate rotation.",
        patchDiff: [
          { num: 1, text: "- \"aws_access_key_id\": \"AKIAIOSFODNN7EXAMPLE\",", cls: "del" },
          { num: 2, text: "+ \"aws_access_key_id\": os.environ.get('AWS_ACCESS_KEY_ID', ''),", cls: "add" }
        ],
        retestNotice: "Retest Verified: Secret detection probe verified zero credentials in working tree. Finding marked RESOLVED."
      },
      {
        id: "BL-AUTH-002",
        title: "Permissive CORS Wildcard Origin with Credentials",
        severity: "medium",
        confidence: "verified",
        status: "verified",
        surface: "OPTIONS /api/sso/session",
        cwe: "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        codeFile: "server.py:15",
        codeSnippet: [
          { num: 14, text: "app.add_middleware(CORSMiddleware,", cls: "cm" },
          { num: 15, text: "    allow_origins=['*'], allow_credentials=True)", cls: "hl" }
        ],
        evidence: [
          { sev: "medium", source: "Access-Control-Allow-Origin: * sent with Access-Control-Allow-Credentials: true", kind: "DAST" }
        ],
        reasoning: "Wildcard origin with credentials enabled allows malicious third-party websites to make authenticated cross-origin requests.",
        patchDiff: [
          { num: 1, text: "- allow_origins=['*'], allow_credentials=True", cls: "del" },
          { num: 2, text: "+ allow_origins=['https://app.breachlabs.io'], allow_credentials=True", cls: "add" }
        ],
        retestNotice: "Retest Verified: Unauthorized origin requests receive standard non-credentialed CORS response."
      }
    ]
  }
};

let currentScenarioKey = "ecommerce";
let currentFindingIndex = 0;
let currentStageIndex = 4; // Completed by default
let currentFilter = "all";
let isSimulating = false;

function getScenario() {
  return SCENARIOS[currentScenarioKey] || SCENARIOS.ecommerce;
}

function updateSummaryKPIs() {
  const scenario = getScenario();
  const findings = scenario.findings;
  const verifiedCount = findings.filter(f => f.confidence === "verified").length;
  const investigatingCount = findings.filter(f => f.confidence !== "verified").length;

  const targetEl = document.querySelector("[data-active-target]");
  const targetTerminalEl = document.querySelector("[data-active-target-terminal]");
  const durationEl = document.querySelector("[data-active-duration]");
  const routesEl = document.querySelector("[data-active-routes]");
  const metricFindings = document.querySelector("[data-metric-findings]");
  const metricVerified = document.querySelector("[data-metric-verified-count]");
  const metricInvestigating = document.querySelector("[data-metric-investigating-count]");
  const metricDuration = document.querySelector("[data-metric-duration]");
  const metricRoutes = document.querySelector("[data-metric-routes]");

  if (targetEl) targetEl.textContent = scenario.target;
  if (targetTerminalEl) targetTerminalEl.textContent = scenario.target;
  if (durationEl) durationEl.textContent = `${scenario.duration_ms}ms`;
  if (routesEl) routesEl.textContent = String(scenario.routes_discovered);
  if (metricFindings) metricFindings.textContent = String(findings.length);
  if (metricVerified) metricVerified.textContent = String(verifiedCount);
  if (metricInvestigating) metricInvestigating.textContent = String(investigatingCount);
  if (metricDuration) metricDuration.innerHTML = `${scenario.duration_ms}<em>ms</em>`;
  if (metricRoutes) metricRoutes.textContent = String(scenario.routes_discovered);

  // Update filter counts
  const countAll = document.querySelector("[data-count-all]");
  const countHigh = document.querySelector("[data-count-high]");
  const countMed = document.querySelector("[data-count-medium]");
  const countLow = document.querySelector("[data-count-low]");
  if (countAll) countAll.textContent = String(findings.length);
  if (countHigh) countHigh.textContent = String(findings.filter(f => f.severity === "high" || f.severity === "critical").length);
  if (countMed) countMed.textContent = String(findings.filter(f => f.severity === "medium").length);
  if (countLow) countLow.textContent = String(findings.filter(f => f.severity === "low").length);

  // Update Report and JSON tabs
  const reportTarget = document.querySelector("[data-report-target]");
  const reportId = document.querySelector("[data-report-id]");
  const jsonId = document.querySelector("[data-json-id]");
  const jsonTarget = document.querySelector("[data-json-target]");
  const jsonDuration = document.querySelector("[data-json-duration]");
  const jsonRoutes = document.querySelector("[data-json-routes]");
  if (reportTarget) reportTarget.textContent = scenario.target;
  if (reportId) reportId.textContent = scenario.id;
  if (jsonId) jsonId.textContent = scenario.id;
  if (jsonTarget) jsonTarget.textContent = scenario.target;
  if (jsonDuration) jsonDuration.textContent = String(scenario.duration_ms);
  if (jsonRoutes) jsonRoutes.textContent = String(scenario.routes_discovered);
}

function renderFindingsGrid() {
  const scenario = getScenario();
  const container = document.querySelector("[data-findings]");
  if (!container) return;

  container.replaceChildren();

  scenario.findings.forEach((f, idx) => {
    const isVisible = currentFilter === "all" || f.severity === currentFilter || (currentFilter === "high" && f.severity === "critical");
    const col = document.createElement("div");
    col.className = "b-4";
    col.dataset.finding = "";
    col.dataset.findingId = f.id;
    col.dataset.sev = f.severity;
    if (!isVisible) col.style.display = "none";

    const sevColor = f.severity === "critical" ? "var(--crit, #ff5c5c)" : f.severity === "high" ? "var(--bad)" : f.severity === "medium" ? "var(--warn)" : "var(--info)";
    const confColor = f.confidence === "verified" ? "var(--ok)" : "var(--warn)";

    col.innerHTML = `
      <div class="bezel" style="height:100%">
        <div class="bezel-core finding-card" data-card-finding="${f.id}" data-active="${idx === currentFindingIndex ? 'true' : 'false'}">
          <div class="artifact-top" style="border-bottom:0;padding-bottom:0">
            <span class="artifact-id mono">${f.id}</span>
            <span class="status status--${f.status}"><i aria-hidden="true"></i>${f.status.toUpperCase()}</span>
          </div>
          <p class="h-card mt-l" style="margin-top:14px">${f.title}</p>
          <div class="keyline mt-l" style="margin-top:16px">
            <div><span class="k">Severity</span><span class="v" style="font-weight:700;color:${sevColor}">${f.severity.toUpperCase()}</span></div>
            <div><span class="k">Confidence</span><span class="v" style="color:${confColor}">${f.confidence.toUpperCase()}</span></div>
            <div><span class="k">Surface</span><span class="v"><code>${f.surface}</code></span></div>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-top:16px;padding-top:12px;border-top:1px solid var(--hair)">
            <span class="eyebrow" style="font-size:10px">Click to inspect</span>
            <span class="link-arrow" style="font-size:12px">Evidence &amp; Fix →</span>
          </div>
        </div>
      </div>
    `;

    col.querySelector(".finding-card").addEventListener("click", () => {
      currentFindingIndex = idx;
      renderFindingsGrid();
      renderFindingDrawer();
    });

    container.appendChild(col);
  });

  const emptyEl = document.querySelector("[data-empty]");
  const visibleCards = Array.from(container.children).filter(c => c.style.display !== "none");
  if (emptyEl) emptyEl.hidden = visibleCards.length > 0;

  const countLabel = document.querySelector("[data-count-label]");
  if (countLabel) countLabel.textContent = String(visibleCards.length);
}

function renderFindingDrawer() {
  const scenario = getScenario();
  const finding = scenario.findings[currentFindingIndex] || scenario.findings[0];
  if (!finding) return;

  const drawer = document.querySelector("[data-finding-drawer]");
  if (!drawer) return;

  const idEl = drawer.querySelector("[data-drawer-id]");
  const titleEl = drawer.querySelector("[data-drawer-title]");
  const cweEl = drawer.querySelector("[data-drawer-cwe]");
  const statusEl = drawer.querySelector("[data-drawer-status]");
  const surfaceEl = drawer.querySelector("[data-drawer-surface]");
  const codeFileEl = drawer.querySelector("[data-drawer-code-file]");
  const codeBodyEl = drawer.querySelector("[data-drawer-code-body]");
  const evidenceEl = drawer.querySelector("[data-drawer-evidence]");
  const reasoningEl = drawer.querySelector("[data-drawer-reasoning]");
  const diffBodyEl = drawer.querySelector("[data-drawer-diff-body]");

  if (idEl) idEl.textContent = finding.id;
  if (titleEl) titleEl.textContent = finding.title;
  if (cweEl) cweEl.textContent = finding.cwe || "Security Vulnerability";
  if (statusEl) {
    statusEl.className = `status status--${finding.status}`;
    statusEl.innerHTML = `<i aria-hidden="true"></i>${finding.status.toUpperCase()}`;
  }
  if (surfaceEl) surfaceEl.textContent = finding.surface;
  if (codeFileEl) codeFileEl.textContent = finding.codeFile;
  if (reasoningEl) reasoningEl.textContent = finding.reasoning;

  if (codeBodyEl) {
    codeBodyEl.replaceChildren();
    finding.codeSnippet.forEach(line => {
      const row = document.createElement("div");
      row.className = `l ${line.cls === 'hl' ? 'hl' : ''}`;
      row.innerHTML = `<u>${line.num}</u><span>${escapeHtml(line.text)}</span>`;
      codeBodyEl.appendChild(row);
    });
  }

  if (evidenceEl) {
    evidenceEl.replaceChildren();
    finding.evidence.forEach(e => {
      const row = document.createElement("div");
      row.className = "evidence-row";
      row.dataset.sev = e.sev;
      row.innerHTML = `
        <span class="sev" aria-hidden="true"></span>
        <span class="src"><code>${escapeHtml(e.source)}</code></span>
        <span class="kind">${escapeHtml(e.kind)}</span>
      `;
      evidenceEl.appendChild(row);
    });
  }

  if (diffBodyEl) {
    diffBodyEl.replaceChildren();
    finding.patchDiff.forEach(line => {
      const row = document.createElement("div");
      row.className = `l`;
      row.innerHTML = `<u>${line.num}</u><span class="${line.cls}">${escapeHtml(line.text)}</span>`;
      diffBodyEl.appendChild(row);
    });
  }
}

function updateStagePipeline(stageIdx) {
  currentStageIndex = stageIdx;
  const pills = document.querySelectorAll("[data-stage-pipeline] .demo-step-pill");
  pills.forEach((pill, idx) => {
    pill.setAttribute("data-active", String(idx <= stageIdx));
  });

  const globalStatus = document.querySelector("[data-demo-global-status]");
  if (globalStatus) {
    if (stageIdx >= 4) {
      globalStatus.className = "status status--verified";
      globalStatus.innerHTML = "<i aria-hidden='true'></i>COMPLETED";
    } else if (stageIdx >= 0) {
      globalStatus.className = "status status--investigating";
      globalStatus.innerHTML = `<i aria-hidden='true'></i>STAGE 0${stageIdx + 1} RUNNING`;
    } else {
      globalStatus.className = "status status--detected";
      globalStatus.innerHTML = "<i aria-hidden='true'></i>READY";
    }
  }
}

function appendTelemetryLog(text, isHl = false) {
  const terminalBody = document.querySelector("[data-telemetry-body]");
  if (!terminalBody) return;
  const rowCount = terminalBody.children.length + 1;
  const numStr = rowCount < 10 ? `0${rowCount}` : String(rowCount);

  const row = document.createElement("div");
  row.className = `l ${isHl ? 'hl' : ''}`;
  row.innerHTML = `<u>${numStr}</u><span>${escapeHtml(text)}</span>`;
  terminalBody.appendChild(row);
  terminalBody.scrollTop = terminalBody.scrollHeight;
}

function runSimulation() {
  if (isSimulating) return;
  isSimulating = true;
  const scenario = getScenario();
  const terminalBody = document.querySelector("[data-telemetry-body]");
  if (terminalBody) terminalBody.replaceChildren();

  appendTelemetryLog(`[00:00.000] INITIALIZE: Replay target environment '${scenario.target}'`);

  let currentStep = 0;
  updateStagePipeline(-1);

  const interval = setInterval(() => {
    if (currentStep < scenario.stages.length) {
      const st = scenario.stages[currentStep];
      updateStagePipeline(currentStep);
      appendTelemetryLog(st.log, currentStep === 1 || currentStep === 3);
      currentStep += 1;
    } else {
      clearInterval(interval);
      isSimulating = false;
      updateStagePipeline(4);
      appendTelemetryLog(`[DONE] Assessment concluded with verified findings attached.`);
    }
  }, 750);
}

function stepNext() {
  const scenario = getScenario();
  if (currentStageIndex >= 4) {
    currentStageIndex = -1;
  }
  const nextIdx = currentStageIndex + 1;
  updateStagePipeline(nextIdx);
  if (scenario.stages[nextIdx]) {
    appendTelemetryLog(scenario.stages[nextIdx].log, nextIdx === 1 || nextIdx === 3);
  }
}

function resetSimulation() {
  const scenario = getScenario();
  updateStagePipeline(4);
  const terminalBody = document.querySelector("[data-telemetry-body]");
  if (terminalBody) {
    terminalBody.replaceChildren();
    scenario.stages.forEach((st, idx) => {
      appendTelemetryLog(st.log, idx === 1 || idx === 3);
    });
  }
}

function initTabs() {
  const tabBtns = document.querySelectorAll("[data-view-tab]");
  const panels = document.querySelectorAll("[data-view-panel]");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.viewTab;
      tabBtns.forEach(b => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-pressed", String(b === btn));
      });

      panels.forEach(panel => {
        panel.hidden = panel.dataset.viewPanel !== tab;
      });
    });
  });
}

function initFilters() {
  const filterBtns = document.querySelectorAll("[data-sev-filter]");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      currentFilter = btn.dataset.sevFilter;
      filterBtns.forEach(b => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-pressed", String(b === btn));
      });
      renderFindingsGrid();
    });
  });
}

function initScenarios() {
  const scenarioBtns = document.querySelectorAll("[data-scenario]");
  scenarioBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      currentScenarioKey = btn.dataset.scenario;
      currentFindingIndex = 0;
      scenarioBtns.forEach(b => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-pressed", String(b === btn));
      });
      updateSummaryKPIs();
      renderFindingsGrid();
      renderFindingDrawer();
      resetSimulation();
    });
  });
}

function initCopyButtons() {
  const copyPatchBtn = document.querySelector("[data-copy-patch]");
  if (copyPatchBtn) {
    copyPatchBtn.addEventListener("click", () => {
      const scenario = getScenario();
      const finding = scenario.findings[currentFindingIndex] || scenario.findings[0];
      const diffText = finding.patchDiff.map(l => l.text).join("\n");
      navigator.clipboard.writeText(diffText).then(() => {
        const textSpan = copyPatchBtn.querySelector("[data-copy-text]");
        if (textSpan) textSpan.textContent = "✓ Copied!";
        setTimeout(() => {
          if (textSpan) textSpan.textContent = "Copy Patch";
        }, 2000);
      });
    });
  }

  const copyReportBtn = document.querySelector("[data-copy-report]");
  if (copyReportBtn) {
    copyReportBtn.addEventListener("click", () => {
      const reportMarkdownEl = document.querySelector("[data-report-markdown-body]");
      if (reportMarkdownEl) {
        const text = reportMarkdownEl.innerText;
        navigator.clipboard.writeText(text).then(() => {
          const textSpan = copyReportBtn.querySelector("[data-copy-report-text]");
          if (textSpan) textSpan.textContent = "✓ Copied!";
          setTimeout(() => {
            if (textSpan) textSpan.textContent = "Copy Markdown";
          }, 2000);
        });
      }
    });
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function initDemo() {
  updateSummaryKPIs();
  renderFindingsGrid();
  renderFindingDrawer();
  initTabs();
  initFilters();
  initScenarios();
  initCopyButtons();

  const replayBtn = document.querySelector("[data-demo-replay]");
  const nextBtn = document.querySelector("[data-demo-next]");
  const resetBtn = document.querySelector("[data-demo-reset]");

  if (replayBtn) replayBtn.addEventListener("click", runSimulation);
  if (nextBtn) nextBtn.addEventListener("click", stepNext);
  if (resetBtn) resetBtn.addEventListener("click", resetSimulation);
}

if (typeof window !== "undefined") {
  window.document.addEventListener("DOMContentLoaded", () => {
    try {
      initDemo();
    } catch (e) {
      console.error(e);
    }
  });
}