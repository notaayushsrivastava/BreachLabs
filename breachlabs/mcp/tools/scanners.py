"""Concrete MCP tools for the MVP.

Each tool is narrowly scoped (PRD.md section 5.4). Scanners are implemented
deterministically with heuristics so the hackathon demo runs without external
binaries; external integrations (Semgrep, ZAP) can be swapped in behind the
same interface.
"""

from __future__ import annotations

import os
import re
from typing import Any

from pydantic import BaseModel, Field

from breachlabs.core.types import AttackSurface, Route, ToolRiskLevel
from breachlabs.mcp.tool import MCPTool, ToolContext, ToolError


class RepoPathParams(BaseModel):
    path: str = Field(default="", description="Relative path within the repo; empty = root")


class InspectRepositoryTool(MCPTool):
    """List repository structure (top-level) and detect manifests."""

    name = "inspect_repository"
    description = "Inspect the repository structure: top-level entries and dependency manifests."
    risk_level = ToolRiskLevel.READ_ONLY

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        if not context.repo_path:
            raise ToolError("No repository path configured in tool context.")
        root = os.path.abspath(context.repo_path)
        entries: list[str] = []
        manifests: list[str] = []
        known = {
            "requirements.txt", "pyproject.toml", "setup.py", "package.json",
            "go.mod", "Gemfile", "pom.xml", "Cargo.toml", "Pipfile",
        }
        for name in sorted(os.listdir(root)):
            entries.append(name)
            if name in known:
                manifests.append(name)
        return {"root": root, "entries": entries, "dependency_manifests": manifests}


class ReadSourceFileTool(MCPTool):
    """Read a single source file inside the sandbox repo."""

    name = "read_source_file"
    description = "Read one source file from the sandboxed repository copy."
    risk_level = ToolRiskLevel.READ_ONLY

    class Params(RepoPathParams):
        max_bytes: int = 200_000

    def execute(self, validated: ReadSourceFileTool.Params, context: ToolContext) -> dict[str, Any]:
        if not context.repo_path:
            raise ToolError("No repository path configured in tool context.")
        root = os.path.abspath(context.repo_path)
        target = os.path.abspath(os.path.join(root, validated.path))
        if not target.startswith(root + os.sep) and target != root:
            raise ToolError("Path escapes the sandboxed repository.")
        if not os.path.isfile(target):
            raise ToolError(f"File not found: {validated.path}")
        with open(target, encoding="utf-8", errors="replace") as fh:
            content = fh.read(validated.max_bytes)
        lines = content.splitlines()
        return {"path": validated.path, "line_count": len(lines), "content": lines}


ROUTE_FLASK = re.compile(r"@app\.route\(\s*[\"']([^\"']+)[\"']\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?")
ROUTE_FASTAPI = re.compile(r"@app\.(get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']")


class ListRoutesTool(MCPTool):
    """Discover routes and API endpoints from framework source files."""

    name = "list_routes"
    description = "Discover routes and API endpoints in the application source."
    risk_level = ToolRiskLevel.READ_ONLY

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        if not context.repo_path:
            raise ToolError("No repository path configured in tool context.")
        surface = AttackSurface()
        for dirpath, dirnames, filenames in os.walk(context.repo_path):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules", ".venv")]
            for filename in filenames:
                if not filename.endswith((".py", ".js", ".ts")):
                    continue
                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                for line in content.splitlines():
                    m = ROUTE_FLASK.search(line)
                    if m:
                        methods = [x.strip().strip("'\"") for x in (m.group(2) or "").split(",") if x.strip()]
                        for method in methods or ["GET"]:
                            surface.routes.append(Route(path=m.group(1), method=method, kind="page"))
                        continue
                    m = ROUTE_FASTAPI.search(line)
                    if m:
                        route = Route(path=m.group(2), method=m.group(1).upper(), kind="api")
                        surface.routes.append(route)
                        surface.api_endpoints.append(route)
        return {
            "routes": [r.model_dump() for r in surface.routes],
            "api_endpoints": [r.model_dump() for r in surface.api_endpoints],
            "route_count": surface.route_count(),
        }


# ---------------------------------------------------------------------------
# SAST / secrets / dependencies
# ---------------------------------------------------------------------------

SAST_RULES: list[dict[str, str]] = [
    {"id": "BL-SAST-001", "title": "SQL query built with string formatting",
     "pattern": r"(execute|executemany)\s*\(\s*f?[\"'].*%s.*[\"']|execute\(f[\"']",
     "severity": "high", "category": "injection",
     "message": "Possible SQL injection: SQL executed with formatted/f-string input."},
    {"id": "BL-SAST-002", "title": "eval() usage",
     "pattern": r"\beval\s*\(", "severity": "high", "category": "code_execution",
     "message": "Use of eval() can lead to arbitrary code execution."},
    {"id": "BL-SAST-003", "title": "Shell command with user input",
     "pattern": r"subprocess\.(call|run|Popen)\([^)]*\bshell\s*=\s*True",
     "severity": "high", "category": "command_injection",
     "message": "subprocess with shell=True can lead to command injection."},
    {"id": "BL-SAST-004", "title": "Debug mode enabled",
     "pattern": r"debug\s*=\s*True", "severity": "medium", "category": "configuration",
     "message": "Application runs with debug mode enabled."},
    {"id": "BL-SAST-005", "title": "Permissive CORS",
     "pattern": r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*", "severity": "medium",
     "category": "configuration",
     "message": "CORS policy allows any origin."},
    {"id": "BL-SAST-006", "title": "Weak hash algorithm",
     "pattern": r"hashlib\.(md5|sha1)\s*\(", "severity": "medium", "category": "cryptography",
     "message": "Weak hash algorithm (MD5/SHA-1) used."},
    {"id": "BL-SAST-007", "title": "Hardcoded credential assignment",
     "pattern": r"(password|passwd|secret|api_key|apikey|token)\s*=\s*[\"'][^\"']{6,}[\"']",
     "severity": "high", "category": "secrets",
     "message": "Possible hardcoded credential in source."},
]

SECRET_RULES: list[dict[str, str]] = [
    {"id": "BL-SEC-001", "title": "AWS access key",
     "pattern": r"(AKIA|ASIA)[0-9A-Z]{16}", "severity": "critical", "category": "secrets",
     "message": "AWS access key ID found in source."},
    {"id": "BL-SEC-002", "title": "Private key block",
     "pattern": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "severity": "critical",
     "category": "secrets",
     "message": "Embedded private key found."},
    {"id": "BL-SEC-003", "title": "Generic API token assignment",
     "pattern": r"(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
     "severity": "high", "category": "secrets",
     "message": "Long credential-looking literal assigned in source."},
]


def _scan_files(repo_path: str, rules: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Deterministic regex scan over text files; returns raw signals."""
    results: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules", ".venv")]
        for filename in filenames:
            if filename.endswith((".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".txt", ".cfg", ".ini", ".html")):
                filepath = os.path.join(dirpath, filename)
                relpath = os.path.relpath(filepath, repo_path).replace("\\", "/")
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                for lineno, line in enumerate(content.splitlines(), start=1):
                    for rule in rules:
                        if re.search(rule["pattern"], line, re.IGNORECASE):
                            results.append({
                                "rule_id": rule["id"],
                                "title": rule["title"],
                                "severity": rule["severity"],
                                "category": rule["category"],
                                "message": rule["message"],
                                "file": relpath,
                                "line": lineno,
                                "snippet": line.strip()[:200],
                            })
    return results


class SastScanTool(MCPTool):
    """Run static security analysis against the sandboxed source copy."""

    name = "run_static_scan"
    description = "Run deterministic SAST rules over the application source."
    risk_level = ToolRiskLevel.READ_ONLY

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        if not context.repo_path:
            raise ToolError("No repository path configured in tool context.")
        signals = _scan_files(context.repo_path, SAST_RULES)
        return {"scanner": "builtin-sast", "signals": signals, "signal_count": len(signals)}


class SecretScanTool(MCPTool):
    """Detect secrets committed to the repository."""

    name = "scan_secrets"
    description = "Scan the repository for committed secrets and credentials."
    risk_level = ToolRiskLevel.READ_ONLY

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        if not context.repo_path:
            raise ToolError("No repository path configured in tool context.")
        signals = _scan_files(context.repo_path, SECRET_RULES)
        # Redact matched secret literals from snippets before returning.
        for signal in signals:
            signal["snippet"] = re.sub(r"[A-Za-z0-9_\-]{16,}", "[REDACTED]", signal["snippet"])
        return {"scanner": "builtin-secrets", "signals": signals, "signal_count": len(signals)}


# ---------------------------------------------------------------------------
# DAST / health check
# ---------------------------------------------------------------------------


class DastParams(BaseModel):
    paths: list[str] = Field(default_factory=list, description="Paths to check on the target")
    follow_redirects: bool = True


class HealthCheckTool(MCPTool):
    """Validate that the isolated target application is running."""

    name = "check_health"
    description = "Perform an HTTP health check against the isolated target application."
    risk_level = ToolRiskLevel.READ_ONLY

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        import httpx

        if not context.target_base_url:
            raise ToolError("No target base URL configured in tool context.")
        host = context.base_url_host() or ""
        self.validate_scope(context.allowed_hosts, host)
        try:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                response = client.get(context.target_base_url)
            return {
                "healthy": 200 <= response.status_code < 500,
                "status_code": response.status_code,
                "url": str(response.url),
            }
        except httpx.HTTPError as exc:
            return {"healthy": False, "status_code": None, "error": str(exc)}


class DastTool(MCPTool):
    """Run lightweight, scoped dynamic checks against the isolated target.

    MVP checks (deterministic, active only when policy allows):
      - missing security headers
      - reflective XSS probe on GET parameters
      - SQL error signature detection via probe payloads
    """

    name = "run_dast"
    description = "Run scoped dynamic checks (headers, reflected XSS probe, SQL error probe)."
    risk_level = ToolRiskLevel.ACTIVE_SCAN
    Params = DastParams

    SQL_ERROR_SIGNATURES = [
        "you have an error in your sql syntax",
        "sql syntax",
        "syntax error",
        "warning: sqlite",
        "unterminated quoted string",
        "sqlite3.operationalerror",
        "psycopg2.errors",
        "mysql_fetch",
    ]

    XSS_PROBE = "<script>breachlabs-probe</script>"

    def execute(self, validated: DastParams, context: ToolContext) -> dict[str, Any]:
        import httpx

        if not context.target_base_url:
            raise ToolError("No target base URL configured in tool context.")
        host = context.base_url_host() or ""
        self.validate_scope(context.allowed_hosts, host)
        if validated.paths and not context.active_checks_enabled:
            # passive mode: headers only
            validated.paths = []
        alerts: list[dict[str, Any]] = []
        with httpx.Client(timeout=10.0, follow_redirects=validated.follow_redirects) as client:
            baseline = client.get(context.target_base_url)
            alerts.extend(self._check_headers(baseline, str(baseline.url)))
            for path in validated.paths:
                url = context.target_base_url.rstrip("/") + "/" + path.lstrip("/")
                # reflected XSS probe
                sep = "&" if "?" in url else "?"
                probe_url = f"{url}{sep}q={self.XSS_PROBE}"
                try:
                    resp = client.get(probe_url)
                except httpx.HTTPError:
                    continue
                if self.XSS_PROBE in resp.text:
                    alerts.append({
                        "alert": "Reflected cross-site scripting",
                        "severity": "high", "url": probe_url,
                        "evidence": "Probe payload reflected unencoded in response body.",
                    })
                # SQL error probe: unbalanced quote forces a database error
                sql_url = f"{url}{sep}q=%27BREACHLABS"
                try:
                    resp = client.get(sql_url)
                except httpx.HTTPError:
                    continue
                body_lower = resp.text.lower()
                for signature in self.SQL_ERROR_SIGNATURES:
                    if signature in body_lower:
                        alerts.append({
                            "alert": "Possible SQL injection (error-based)",
                            "severity": "high", "url": sql_url,
                            "evidence": f"Database error signature in response: '{signature}'.",
                        })
                        break
                # SQL tautology probe: ' OR 1=1 -- returns all rows
                try:
                    taut = client.get(f"{url}{sep}q=' OR 1=1 --")
                except httpx.HTTPError:
                    continue
                try:
                    base_rows = client.get(url).text.count("),")
                except httpx.HTTPError:
                    base_rows = 0
                if taut.status_code == 200 and taut.text.count("),") > base_rows:
                    alerts.append({
                        "alert": "Possible SQL injection (tautology)",
                        "severity": "high", "url": f"{url}?q=' OR 1=1 --",
                        "evidence": "Tautology payload returned more records than the baseline query.",
                    })
        return {"scanner": "builtin-dast", "alerts": alerts, "alert_count": len(alerts)}

    def _check_headers(self, response: Any, url: str) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        for header, severity in (
            ("content-security-policy", "medium"),
            ("x-content-type-options", "low"),
            ("strict-transport-security", "low"),
        ):
            if header not in {k.lower() for k in response.headers}:
                alerts.append({
                    "alert": f"Missing security header: {header}",
                    "severity": severity, "url": url,
                    "evidence": f"Response is missing the '{header}' header.",
                })
        return alerts


class VerifyInstallationTool(MCPTool):
    """Verify whether BreachLabs MCP server and AI Skill are properly installed."""

    name = "verify_installation"
    description = (
        "Verify whether the BreachLabs MCP server and BreachLabs Skill are installed in the environment. "
        "Returns installation status and actionable prompts if either component is missing."
    )
    risk_level = ToolRiskLevel.READ_ONLY

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        from breachlabs.mcp.skill_check import check_skill_installation

        repo_path = context.repo_path if context else None
        return check_skill_installation(repo_path)
