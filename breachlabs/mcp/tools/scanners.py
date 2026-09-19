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
    path: str = Field(default="", description="Relative path within repo, subfolder, or target directory to inspect; empty = root")
    repo_path: str = Field(default="", description="Target repository or workspace directory path (optional override)")


def _resolve_target_repo(repo_arg: str = "", path_arg: str = "", context: ToolContext | None = None) -> tuple[str, str]:
    """Resolve target repository root and subpath directory.

    Order of precedence:
    1. Explicit repo_arg passed in tool arguments or path_arg if absolute/alias.
    2. context.repo_path if set.
    3. Environment variable BREACHLABS_REPO_PATH.
    4. Bundled demo vulnerable app if available.
    5. Current working directory.
    """
    demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "demo"))

    raw_repo = (repo_arg or "").strip()
    sub_path = (path_arg or "").strip()

    # Check if path_arg is an absolute directory or alias
    if sub_path:
        if sub_path.lower() in ("demo", "breachlabs/demo", "breachlabs-demo", "vulnerable_app"):
            raw_repo = demo_dir
            sub_path = ""
        elif os.path.isabs(sub_path) and os.path.isdir(sub_path):
            raw_repo = sub_path
            sub_path = ""

    if not raw_repo and context and context.repo_path:
        raw_repo = context.repo_path.strip()

    if not raw_repo:
        raw_repo = os.environ.get("BREACHLABS_REPO_PATH", "").strip()

    if raw_repo.lower() in ("demo", "breachlabs/demo", "breachlabs-demo", "vulnerable_app"):
        root = demo_dir if os.path.isdir(demo_dir) else os.getcwd()
    elif raw_repo:
        root = os.path.abspath(raw_repo)
    else:
        # Default to the demo app rather than the BreachLabs engine internal code
        if os.path.isdir(demo_dir):
            root = demo_dir
        else:
            root = os.getcwd()

    if not os.path.isdir(root):
        raise ToolError(f"Target repository directory not found: {root}")

    if sub_path:
        if os.path.isabs(sub_path):
            target = os.path.abspath(sub_path)
        else:
            target = os.path.abspath(os.path.join(root, sub_path))
        if not target.startswith(root + os.sep) and target != root and not os.path.isdir(target):
            raise ToolError(f"Path escapes the repository: {sub_path}")
    else:
        target = root

    return root, target


def _detect_framework(root: str) -> str:
    """Detect the web or application framework used by the repository."""
    patterns = [
        (r"from flask import|import flask", "Flask (Python)"),
        (r"from fastapi import|import fastapi", "FastAPI (Python)"),
        (r"from django|import django", "Django (Python)"),
        (r"from tornado|import tornado", "Tornado (Python)"),
        (r"from starlette|import starlette", "Starlette (Python)"),
        (r"express\(\)|require\(['\"]express['\"]\)", "Express.js (Node.js)"),
        (r"from ['\"]next|next/server", "Next.js (Node.js)"),
        (r"github\.com/gin-gonic/gin", "Gin (Go)"),
        (r"actix_web::", "Actix Web (Rust)"),
    ]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules", ".venv")]
        for filename in filenames:
            if filename.endswith((".py", ".js", ".ts", ".go", ".rs")):
                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as fh:
                        snippet = fh.read(4096)
                    for regex, name in patterns:
                        if re.search(regex, snippet, re.IGNORECASE):
                            return name
                except OSError:
                    continue
    return ""


def _detect_entry_points(root: str) -> list[str]:
    """Find common application entry points."""
    common_entries = [
        "app.py", "main.py", "wsgi.py", "manage.py", "server.py", "run.py",
        "index.js", "server.js", "main.js", "app.js", "src/index.ts", "src/main.ts",
        "main.go", "src/main.rs",
    ]
    detected: list[str] = []
    for entry in common_entries:
        full_path = os.path.join(root, entry)
        if os.path.isfile(full_path):
            detected.append(entry)
    return detected


def _detect_tech_stack(root: str) -> list[str]:
    """Identify languages and ecosystem tools in the repository."""
    stack: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules", ".venv")]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext == ".py":
                stack.add("Python")
            elif ext in (".js", ".jsx"):
                stack.add("JavaScript")
            elif ext in (".ts", ".tsx"):
                stack.add("TypeScript")
            elif ext == ".go":
                stack.add("Go")
            elif ext == ".rs":
                stack.add("Rust")
            elif ext == ".html":
                stack.add("HTML/Templates")
            elif filename == "Dockerfile":
                stack.add("Docker")
            elif filename in ("sqlite3", "app.db", "database.db") or filename.endswith(".db"):
                stack.add("SQLite")
    return sorted(stack)


def _generate_tree_view(target: str, max_depth: int = 2) -> str:
    """Generate a clean ASCII directory tree view."""
    lines = [f"{os.path.basename(target) or target}/"]

    def _walk(curr_dir: str, prefix: str, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            items = sorted(os.listdir(curr_dir))
        except OSError:
            return
        items = [i for i in items if i not in (".git", "__pycache__", "node_modules", ".venv", ".pytest_cache")]
        for i, item in enumerate(items):
            is_last = i == len(items) - 1
            branch = "└── " if is_last else "├── "
            item_path = os.path.join(curr_dir, item)
            is_dir = os.path.isdir(item_path)
            lines.append(f"{prefix}{branch}{item}{'/' if is_dir else ''}")
            if is_dir:
                next_prefix = prefix + ("    " if is_last else "│   ")
                _walk(item_path, next_prefix, depth + 1)

    _walk(target, "", 1)
    return "\n".join(lines[:30])


class InspectRepositoryTool(MCPTool):
    """List repository structure, detect frameworks/manifests, and communicate repository profile to AI agent."""

    name = "inspect_repository"
    description = (
        "Inspect repository structure: enumerate directory hierarchy, detect dependency manifests, "
        "identify web framework and application entry points, and communicate an actionable AI security summary."
    )
    risk_level = ToolRiskLevel.READ_ONLY
    Params = RepoPathParams

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        root, target = _resolve_target_repo(validated.repo_path, validated.path, context)

        entries: list[dict[str, Any]] = []
        entry_names: list[str] = []
        manifests: list[str] = []
        known = {
            "requirements.txt", "pyproject.toml", "setup.py", "package.json",
            "go.mod", "Gemfile", "pom.xml", "Cargo.toml", "Pipfile", "composer.json",
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        }

        try:
            items = sorted(os.listdir(target))
        except OSError as err:
            raise ToolError(f"Cannot read directory '{target}': {err}")

        for name in items:
            entry_names.append(name)
            if name in known:
                manifests.append(name)
            full_item_path = os.path.join(target, name)
            is_dir = os.path.isdir(full_item_path)
            size = 0 if is_dir else (os.path.getsize(full_item_path) if os.path.exists(full_item_path) else 0)
            entries.append({
                "name": name,
                "type": "directory" if is_dir else "file",
                "size_bytes": size,
            })

        framework = _detect_framework(root)
        entry_points = _detect_entry_points(root)
        tech_stack = _detect_tech_stack(root)
        tree_view = _generate_tree_view(target, max_depth=2)

        rel_path = os.path.relpath(target, root).replace("\\", "/")
        if rel_path == ".":
            rel_path = ""

        summary_msg = (
            f"Repository inspection complete for '{os.path.basename(root) or root}'.\n"
            f"• Location: {target}\n"
            f"• Detected Framework: {framework or 'Generic Web Application'}\n"
            f"• Entry Points: {', '.join(entry_points) if entry_points else 'None detected'}\n"
            f"• Dependency Manifests: {', '.join(manifests) if manifests else 'None'}\n"
            f"• Technologies: {', '.join(tech_stack) if tech_stack else 'Standard codebase'}\n\n"
            f"Recommended Next Actions:\n"
            f"1. Discover routes and endpoints: `list_routes`\n"
            f"2. Run static security analysis: `run_static_scan`\n"
            f"3. Check for committed secrets: `scan_secrets`\n"
            f"4. Inspect specific source files: `read_source_file`\n"
            f"5. Run full automated assessment: `run_assessment`"
        )

        return {
            "root": root,
            "inspected_path": rel_path or "root",
            "entries": entry_names,
            "detailed_entries": entries,
            "dependency_manifests": manifests,
            "framework": framework,
            "entry_points": entry_points,
            "tech_stack": tech_stack,
            "directory_tree": tree_view,
            "communication_summary": summary_msg,
            "message": summary_msg,
        }


class ReadSourceFileTool(MCPTool):
    """Read a single source file inside the target repo."""

    name = "read_source_file"
    description = "Read one source file from the sandboxed or target repository."
    risk_level = ToolRiskLevel.READ_ONLY

    class Params(RepoPathParams):
        max_bytes: int = 200_000

    def execute(self, validated: ReadSourceFileTool.Params, context: ToolContext) -> dict[str, Any]:
        root, _ = _resolve_target_repo(validated.repo_path, "", context)
        target = os.path.abspath(os.path.join(root, validated.path))
        if not target.startswith(root + os.sep) and target != root:
            raise ToolError("Path escapes the repository.")
        if not os.path.isfile(target):
            raise ToolError(f"File not found: {validated.path}")
        with open(target, encoding="utf-8", errors="replace") as fh:
            content = fh.read(validated.max_bytes)
        lines = content.splitlines()
        return {"path": validated.path, "line_count": len(lines), "content": lines}


ROUTE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # Python (Flask)
    (re.compile(r"@app\.route\(\s*[\"']([^\"']+)[\"']\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?"), "page", "flask"),
    # Python (FastAPI / Starlette)
    (re.compile(r"@(?:app|router)\.(get|post|put|delete|patch|options|head)\(\s*[\"']([^\"']+)[\"']"), "api", "fastapi"),
    # Python (Django)
    (re.compile(r"(?:path|re_path)\(\s*[\"']([^\"']+)[\"']"), "page", "django"),
    # JavaScript / TypeScript (Express.js / Fastify)
    (re.compile(r"(?:app|router)\.(get|post|put|delete|patch|all)\(\s*[\"']([^\"']+)[\"']"), "api", "express"),
    # Go (Gin / Echo / Chi)
    (re.compile(r"(?:r|router|e|app)\.(GET|POST|PUT|DELETE|PATCH)\(\s*[\"']([^\"']+)[\"']"), "api", "gin"),
    # Go (net/http)
    (re.compile(r"http\.HandleFunc\(\s*[\"']([^\"']+)[\"']"), "api", "net/http"),
    # Rust (Actix Web / Axum)
    (re.compile(r"#\[(?:get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']\)\]|\.route\(\s*[\"']([^\"']+)[\"']"), "api", "rust"),
    # PHP (Laravel / Lumen)
    (re.compile(r"Route::(get|post|put|delete|patch|any)\(\s*[\"']([^\"']+)[\"']"), "api", "laravel"),
    # Ruby (Sinatra / Rails)
    (re.compile(r"(?:get|post|put|delete|patch)\s+[\"']([^\"']+)[\"']"), "page", "ruby"),
    # Java (Spring Boot)
    (re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']"), "api", "spring"),
]


class ListRoutesTool(MCPTool):
    """Discover routes and API endpoints from framework source files across Python, Node.js, Go, Rust, Java, and PHP."""

    name = "list_routes"
    description = "Discover routes and API endpoints across Python, Node.js, Go, Rust, Java, and PHP framework files."
    risk_level = ToolRiskLevel.READ_ONLY
    Params = RepoPathParams

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        root, _ = _resolve_target_repo(validated.repo_path, validated.path, context)
        surface = AttackSurface()
        valid_exts = (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".php", ".rb", ".java")

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules", ".venv", "target", "dist")]
            for filename in filenames:
                if not filename.endswith(valid_exts):
                    continue
                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                for line in content.splitlines():
                    for pattern, default_kind, framework in ROUTE_PATTERNS:
                        m = pattern.search(line)
                        if not m:
                            continue
                        # Determine path and method based on group structure
                        if framework == "flask":
                            path = m.group(1)
                            raw_methods = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                            methods = [x.strip().strip("'\"") for x in (raw_methods or "").split(",") if x.strip()]
                            for method in methods or ["GET"]:
                                surface.routes.append(Route(path=path, method=method, kind="page"))
                        elif framework in ("fastapi", "express", "gin", "laravel", "spring"):
                            method = (m.group(1) or "GET").upper()
                            path = m.group(2) if m.lastindex and m.lastindex >= 2 and m.group(2) else m.group(1)
                            route = Route(path=path, method=method, kind="api")
                            surface.routes.append(route)
                            surface.api_endpoints.append(route)
                        else:
                            path = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else "/")
                            route = Route(path=path, method="GET", kind=default_kind)
                            surface.routes.append(route)
                            if default_kind == "api":
                                surface.api_endpoints.append(route)
                        break

        return {
            "routes": [r.model_dump() for r in surface.routes],
            "api_endpoints": [r.model_dump() for r in surface.api_endpoints],
            "route_count": surface.route_count(),
        }


# ---------------------------------------------------------------------------
# SAST / secrets / dependencies
# ---------------------------------------------------------------------------

SAST_RULES: list[dict[str, str]] = [
    # Cross-Language & Python Injection
    {"id": "BL-SAST-001", "title": "SQL query built with string formatting",
     "pattern": r"(execute|executemany)\s*\(\s*f?[\"'].*%s.*[\"']|execute\(f[\"']",
     "severity": "high", "category": "injection",
     "message": "Possible SQL injection: SQL executed with formatted/f-string input."},
    {"id": "BL-SAST-002", "title": "eval() usage",
     "pattern": r"\beval\s*\(|vm\.runInContext\(|vm\.runInNewContext\(",
     "severity": "high", "category": "code_execution",
     "message": "Dynamic code evaluation (eval / vm) can lead to arbitrary code execution."},
    {"id": "BL-SAST-003", "title": "Shell command with user input",
     "pattern": r"subprocess\.(call|run|Popen)\([^)]*\bshell\s*=\s*True|child_process\.(exec|execSync)\(|exec\.Command\(",
     "severity": "high", "category": "command_injection",
     "message": "Command execution with shell invocation can lead to command injection."},
    {"id": "BL-SAST-004", "title": "Debug mode enabled in application",
     "pattern": r"debug\s*=\s*True|process\.env\.NODE_ENV\s*===?\s*['\"]development['\"]",
     "severity": "medium", "category": "configuration",
     "message": "Application runs with debug mode or development mode enabled in production code."},
    {"id": "BL-SAST-005", "title": "Permissive CORS policy",
     "pattern": r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|cors\(\s*\{\s*origin:\s*['\"]\*['\"]",
     "severity": "medium", "category": "configuration",
     "message": "CORS policy allows arbitrary origins (wildcard '*')."},
    {"id": "BL-SAST-006", "title": "Weak cryptographic hash algorithm",
     "pattern": r"hashlib\.(md5|sha1)\s*\(|crypto\.createHash\(['\"](md5|sha1)['\"]\)|md5\.Sum\(",
     "severity": "medium", "category": "cryptography",
     "message": "Weak hash algorithm (MD5/SHA-1) used; replace with SHA-256 or bcrypt/argon2 for passwords."},
    {"id": "BL-SAST-007", "title": "Hardcoded credential assignment",
     "pattern": r"(password|passwd|secret|api_key|apikey|token|auth_token)\s*[:=]\s*[\"'][^\"']{6,}[\"']",
     "severity": "high", "category": "secrets",
     "message": "Possible hardcoded credential or access key in source."},
    # JavaScript / TypeScript
    {"id": "BL-SAST-008", "title": "Prototype pollution vector",
     "pattern": r"(__proto__|prototype)\s*\[|Object\.assign\([^,]+,\s*req\.body",
     "severity": "high", "category": "injection",
     "message": "Unvalidated object assignment allows prototype pollution."},
    {"id": "BL-SAST-009", "title": "DOM XSS / Unsafe HTML insertion",
     "pattern": r"innerHTML\s*=|dangerouslySetInnerHTML\s*=|document\.write\(",
     "severity": "high", "category": "xss",
     "message": "Direct HTML insertion without contextual sanitization allows DOM-based XSS."},
    # Go
    {"id": "BL-SAST-010", "title": "Go SQL injection via fmt.Sprintf",
     "pattern": r"db\.(Query|QueryRow|Exec)\(fmt\.Sprintf\(",
     "severity": "high", "category": "injection",
     "message": "Go database query constructed with fmt.Sprintf allows SQL injection; use query placeholders."},
    # Java / Spring
    {"id": "BL-SAST-011", "title": "Java command injection via Runtime.exec",
     "pattern": r"Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder\(",
     "severity": "high", "category": "command_injection",
     "message": "Java process execution with user parameters can lead to command execution."},
    # PHP
    {"id": "BL-SAST-012", "title": "PHP shell execution with superglobal",
     "pattern": r"(system|exec|passthru|shell_exec)\s*\(\s*(\$|_GET|_POST|_REQUEST)",
     "severity": "critical", "category": "command_injection",
     "message": "PHP shell execution function receives unsanitized superglobal input."},
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
    valid_exts = (
        ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".php", ".rb", ".java",
        ".env", ".yaml", ".yml", ".json", ".txt", ".cfg", ".ini", ".html"
    )
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules", ".venv", "target", "dist")]
        for filename in filenames:
            if filename.endswith(valid_exts):
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
    """Run static security analysis against the target source copy."""

    name = "run_static_scan"
    description = "Run deterministic SAST rules over the application source."
    risk_level = ToolRiskLevel.READ_ONLY
    Params = RepoPathParams

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        root, _ = _resolve_target_repo(validated.repo_path, validated.path, context)
        signals = _scan_files(root, SAST_RULES)
        return {"scanner": "builtin-sast", "signals": signals, "signal_count": len(signals)}


class SecretScanTool(MCPTool):
    """Detect secrets committed to the repository."""

    name = "scan_secrets"
    description = "Scan the repository for committed secrets and credentials."
    risk_level = ToolRiskLevel.READ_ONLY
    Params = RepoPathParams

    def execute(self, validated: RepoPathParams, context: ToolContext) -> dict[str, Any]:
        root, _ = _resolve_target_repo(validated.repo_path, validated.path, context)
        signals = _scan_files(root, SECRET_RULES)
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


class RunAssessmentParams(BaseModel):
    repo_path: str = Field(
        default="",
        description="Path to target repository or code (or 'demo' for built-in vulnerable test app); empty = current workspace",
    )
    target_url: str = Field(
        default="",
        description="Optional URL of already-running application instance (e.g. http://127.0.0.1:5000)",
    )
    mode: str = Field(
        default="deep",
        description="Assessment mode: 'deep', 'fast', 'static_only', 'dynamic_only'",
    )
    port: int = Field(
        default=5005,
        description="Port for local sandbox application if auto-starting",
    )
    report_format: str = Field(
        default="markdown",
        description="Format of returned report: 'markdown', 'json', or 'both'",
    )


class RunAssessmentTool(MCPTool):
    """Run an end-to-end security assessment on an application and return the security report."""

    name = "run_assessment"
    description = (
        "Execute an autonomous application security assessment on the application in an isolated sandbox, "
        "correlate static & dynamic evidence, verify findings, and return a comprehensive security report back to the AI agent."
    )
    risk_level = ToolRiskLevel.ACTIVE_SCAN
    Params = RunAssessmentParams

    def execute(self, validated: RunAssessmentParams, context: ToolContext) -> dict[str, Any]:
        from breachlabs.core.agent import SecurityAgent
        from breachlabs.core.types import Assessment, AssessmentMode, Scope
        from breachlabs.report.generator import generate_markdown, generate_report
        from breachlabs.sandbox.manager import LocalSandbox

        repo = validated.repo_path or (context.repo_path if context else "") or os.getcwd()
        if repo.lower() in ("demo", "breachlabs/demo", "breachlabs-demo", "vulnerable_app"):
            demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "demo"))
            if os.path.isdir(demo_dir):
                repo = demo_dir

        repo = os.path.abspath(repo)
        if not os.path.isdir(repo):
            raise ToolError(f"Repository directory not found: {repo}")

        if validated.mode in ("static", "static_only"):
            assessment_mode = AssessmentMode.STATIC_ONLY
        elif validated.mode == "fast":
            assessment_mode = AssessmentMode.QUICK
        else:
            assessment_mode = AssessmentMode.DEEP

        assessment = Assessment(
            repository=os.path.basename(repo) or "application",
            commit="HEAD",
            mode=assessment_mode,
            scope=Scope(
                allowed_hosts=["127.0.0.1", "localhost", "0.0.0.0", "::1"],
                active_checks_enabled=validated.mode not in ("static", "static_only", "sast_only"),
            ),
        )

        sandbox = LocalSandbox(repo, port=validated.port)
        try:
            sandbox.create()
            if validated.mode != "static_only":
                sandbox.start()
            agent = SecurityAgent()
            agent.run(assessment, sandbox)
        finally:
            sandbox.destroy()

        report_dict = generate_report(assessment)
        report_md = generate_markdown(assessment)

        # Record assessment in global store if available
        try:
            from breachlabs.api.server import _assessments, _lock
            with _lock:
                _assessments[assessment.id] = assessment
                _assessments["latest"] = assessment
        except Exception:
            pass

        if validated.report_format == "json":
            return {
                "assessment_id": assessment.id,
                "status": assessment.status.value,
                "report": report_dict,
            }
        elif validated.report_format == "both":
            return {
                "assessment_id": assessment.id,
                "status": assessment.status.value,
                "markdown_report": report_md,
                "structured_report": report_dict,
            }
        else:
            return {
                "assessment_id": assessment.id,
                "status": assessment.status.value,
                "verified_findings": report_dict.get("verified_count", 0),
                "total_findings": len(assessment.findings),
                "executive_summary": report_dict.get("executive_summary", ""),
                "markdown_report": report_md,
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "status": f.status.value,
                        "location": f.location.file or f.location.route,
                        "remediation": f.remediation,
                    }
                    for f in assessment.findings
                ],
            }


class GetReportParams(BaseModel):
    assessment_id: str = Field(default="latest", description="ID of assessment or 'latest'")
    format: str = Field(default="markdown", description="'markdown' or 'json'")


class GetAssessmentReportTool(MCPTool):
    """Retrieve the security report for a completed assessment."""

    name = "get_assessment_report"
    description = "Retrieve the generated security assessment report (Markdown or JSON) for an assessment ID or latest run."
    risk_level = ToolRiskLevel.READ_ONLY
    Params = GetReportParams

    def execute(self, validated: GetReportParams, context: ToolContext) -> dict[str, Any]:
        from breachlabs.report.generator import generate_markdown, generate_report

        assessment = None
        try:
            from breachlabs.api.server import _assessments, _lock
            with _lock:
                assessment = _assessments.get(validated.assessment_id)
                if not assessment and validated.assessment_id == "latest" and _assessments:
                    assessment = list(_assessments.values())[-1]
        except Exception:
            pass

        if not assessment:
            raise ToolError(f"Assessment '{validated.assessment_id}' not found.")

        if validated.format == "json":
            return {"assessment_id": assessment.id, "report": generate_report(assessment)}
        return {
            "assessment_id": assessment.id,
            "format": "markdown",
            "report": generate_markdown(assessment),
        }


class CommunicateParams(BaseModel):
    message: str = Field(..., description="Message, question, finding details, or security query from the AI agent")
    topic: str = Field(default="general", description="Security topic: 'recon', 'sast', 'dast', 'triage', 'verification', 'remediation', or 'general'")
    context_data: dict[str, Any] = Field(default_factory=dict, description="Optional finding, snippet, or attack surface data to analyze")


class CommunicateTool(MCPTool):
    """Communicate directly with BreachLabs Security Engine for advisory, triage, and remediation guidance."""

    name = "communicate"
    description = (
        "Communicate with the BreachLabs Security Engine. Ask security questions, request triage advice on findings, "
        "get tailored remediation diffs, verify exploitability criteria, or coordinate multi-step security assessments."
    )
    risk_level = ToolRiskLevel.READ_ONLY
    Params = CommunicateParams

    def execute(self, validated: CommunicateParams, context: ToolContext) -> dict[str, Any]:
        msg_lower = validated.message.lower()
        topic = validated.topic.lower()
        finding = validated.context_data.get("finding", {})

        advisory: list[str] = []
        suggested_tools: list[str] = []

        if "sql" in msg_lower or "injection" in msg_lower:
            advisory.append(
                "SQL Injection Analysis: Verify whether user input reaches database cursor/execution methods via string concatenation or f-strings. "
                "Remediation requires parameterized queries with positional placeholders (`?` for SQLite, `%s` for PostgreSQL) rather than formatting string literals."
            )
            suggested_tools.extend(["run_static_scan", "read_source_file", "run_assessment"])
        elif "xss" in msg_lower or "cross-site" in msg_lower:
            advisory.append(
                "Cross-Site Scripting (XSS) Analysis: Reflected and DOM XSS occur when user-controlled request parameters or URL inputs are rendered into HTML contexts without contextual encoding. "
                "Use `markupsafe.escape()` in Python/Flask or ensure template auto-escaping is active."
            )
            suggested_tools.extend(["list_routes", "read_source_file", "run_dast"])
        elif "secret" in msg_lower or "credential" in msg_lower or "api_key" in msg_lower:
            advisory.append(
                "Secret Exposure Analysis: Hardcoded credentials should immediately be rotated and removed from source code history. "
                "Replace hardcoded secrets with `os.environ.get('KEY_NAME')` and inject credentials via environment variables or secret vaults."
            )
            suggested_tools.extend(["scan_secrets", "read_source_file"])
        elif "idor" in msg_lower or "authorization" in msg_lower:
            advisory.append(
                "IDOR / Broken Object-Level Authorization: Endpoints accessing tenant/user resources by ID must validate that the authenticated session owns or has explicit permission to access the requested resource ID."
            )
            suggested_tools.extend(["list_routes", "run_dast", "run_assessment"])
        elif "recon" in topic or "route" in msg_lower:
            advisory.append(
                "Attack Surface Reconnaissance: Start by invoking `inspect_repository` and `list_routes` to discover framework routes, entry points, and dependency manifests."
            )
            suggested_tools.extend(["inspect_repository", "list_routes"])
        else:
            advisory.append(
                "BreachLabs Security Advisor: Ready to assist with full-scope security assessments. "
                "You can execute static scans (`run_static_scan`, `scan_secrets`), map endpoints (`list_routes`), "
                "read source code (`read_source_file`), verify live endpoints (`check_health`, `run_dast`), or run an autonomous assessment (`run_assessment`)."
            )
            suggested_tools.extend(["run_assessment", "inspect_repository", "list_routes", "run_static_scan"])

        response_text = (
            f"BreachLabs Security Engine Response:\n"
            f"-----------------------------------------\n"
            f"{' '.join(advisory)}\n\n"
            f"Recommended Next MCP Tools: {', '.join(dict.fromkeys(suggested_tools))}"
        )

        return {
            "status": "success",
            "topic": topic,
            "response": response_text,
            "advisory": advisory,
            "recommended_tools": list(dict.fromkeys(suggested_tools)),
            "finding_evaluated": bool(finding),
        }


class DiagnoseErrorParams(BaseModel):
    error_log: str = Field(..., description="Error stack trace, crash log, compiler output, or exception message")
    source_file: str = Field(default="", description="Optional related source file path")
    repo_path: str = Field(default="", description="Target repository path")
    language: str = Field(default="auto", description="Programming language ('python', 'javascript', 'typescript', 'go', 'rust', 'java', 'php', 'auto')")


class DiagnoseErrorTool(MCPTool):
    """Diagnose application errors, stack traces, compiler output, port conflicts, database errors, and sandbox failures."""

    name = "diagnose_error"
    description = (
        "Diagnose application errors, stack traces, compiler output, port conflicts, database errors, and sandbox startup failures. "
        "Returns root cause analysis, affected lines, and actionable step-by-step remediation instructions across multiple languages."
    )
    risk_level = ToolRiskLevel.READ_ONLY
    Params = DiagnoseErrorParams

    def execute(self, validated: DiagnoseErrorParams, context: ToolContext) -> dict[str, Any]:
        log = validated.error_log
        log_lower = log.lower()

        diagnosis: dict[str, Any] = {
            "error_type": "Unknown",
            "category": "runtime_error",
            "detected_language": validated.language,
            "root_cause": "",
            "affected_file": validated.source_file,
            "affected_line": None,
            "resolution_steps": [],
            "suggested_fix": "",
            "diagnostic_summary": "",
        }

        # Language detection if auto
        if validated.language == "auto":
            if "traceback (most recent call last)" in log_lower or ".py" in log_lower or "filenotfounderror" in log_lower or "modulenotfounderror" in log_lower:
                diagnosis["detected_language"] = "Python"
            elif "node_modules" in log_lower or "typeerror:" in log_lower or "syntaxerror:" in log_lower or "cannot find module" in log_lower or "at async " in log_lower:
                diagnosis["detected_language"] = "JavaScript/Node.js"
            elif "goroutine" in log_lower or "panic:" in log_lower or ".go:" in log_lower:
                diagnosis["detected_language"] = "Go"
            elif "thread 'main' panicked" in log_lower or ".rs:" in log_lower or "cargo" in log_lower:
                diagnosis["detected_language"] = "Rust"
            elif "exception in thread" in log_lower or "java.lang." in log_lower or ".java:" in log_lower:
                diagnosis["detected_language"] = "Java"
            elif "fatal error:" in log_lower or "php stack trace:" in log_lower or ".php" in log_lower:
                diagnosis["detected_language"] = "PHP"
            else:
                diagnosis["detected_language"] = "Generic / Multi-runtime"

        # Pattern Matchers for Common Failure Modes
        if "modulenotfounderror" in log_lower or "no module named" in log_lower:
            m = re.search(r"No module named ['\"]([^'\"]+)['\"]", log, re.IGNORECASE)
            pkg = m.group(1) if m else "missing_package"
            diagnosis["error_type"] = "ModuleNotFoundError"
            diagnosis["category"] = "dependency_missing"
            diagnosis["root_cause"] = f"Required Python package '{pkg}' is not installed in the environment."
            diagnosis["resolution_steps"] = [
                f"Install the missing dependency: `pip install {pkg}`",
                f"Add `{pkg}` to requirements.txt",
                "Restart the application sandbox or server process.",
            ]
            diagnosis["suggested_fix"] = f"pip install {pkg}"

        elif "cannot find module" in log_lower:
            m = re.search(r"Cannot find module ['\"]([^'\"]+)['\"]", log, re.IGNORECASE)
            pkg = m.group(1) if m else "missing_module"
            diagnosis["error_type"] = "NodeMissingModule"
            diagnosis["category"] = "dependency_missing"
            diagnosis["root_cause"] = f"Required Node.js module '{pkg}' is missing."
            diagnosis["resolution_steps"] = [
                f"Run `npm install {pkg}` or `yarn add {pkg}`",
                "Ensure `node_modules` is populated and package.json is up to date.",
            ]
            diagnosis["suggested_fix"] = f"npm install {pkg}"

        elif "eaddrinuse" in log_lower or "10048" in log_lower or "address already in use" in log_lower or "port is already allocated" in log_lower:
            diagnosis["error_type"] = "PortConflictError"
            diagnosis["category"] = "network_port_binding"
            diagnosis["root_cause"] = "The target port is already bound by another process or application instance."
            diagnosis["resolution_steps"] = [
                "Find and terminate the process occupying the port (`netstat -ano | findstr <port>` on Windows or `lsof -i :<port>` on Linux/macOS).",
                "Or configure a different port using environment variable `PORT=5001` or passing `port` to `run_assessment`.",
            ]
            diagnosis["suggested_fix"] = "Select an alternate port (e.g. 5005, 8080) or kill existing process."

        elif "sqlite3.operationalerror" in log_lower or "no such table" in log_lower:
            m = re.search(r"no such table:\s*(\w+)", log, re.IGNORECASE)
            tbl = m.group(1) if m else "table"
            diagnosis["error_type"] = "DatabaseTableMissing"
            diagnosis["category"] = "database_schema"
            diagnosis["root_cause"] = f"Database schema table '{tbl}' does not exist or migrations were not run."
            diagnosis["resolution_steps"] = [
                "Run database initialization script or migrations.",
                "Verify database file path and SQLite permissions.",
            ]
            diagnosis["suggested_fix"] = "Initialize database tables before starting the application."

        elif "cors" in log_lower and ("blocked by cors" in log_lower or "preflight" in log_lower):
            diagnosis["error_type"] = "CORSError"
            diagnosis["category"] = "http_security_policy"
            diagnosis["root_cause"] = "Cross-Origin Resource Sharing (CORS) header missing or mismatched origin."
            diagnosis["resolution_steps"] = [
                "Add `Access-Control-Allow-Origin` and `Access-Control-Allow-Headers` to API responses.",
                "Ensure preflight OPTIONS requests return HTTP 200/204.",
            ]
            diagnosis["suggested_fix"] = "Configure CORS middleware in framework settings."

        elif "health check timed out" in log_lower or "application process exited early" in log_lower:
            diagnosis["error_type"] = "SandboxHealthCheckTimeout"
            diagnosis["category"] = "sandbox_lifecycle"
            diagnosis["root_cause"] = "Target application failed to boot or did not respond to HTTP polling within the timeout window."
            diagnosis["resolution_steps"] = [
                "Inspect application stdout/stderr logs for unhandled startup crashes.",
                "Verify host binding is `0.0.0.0` or `127.0.0.1` and port matches configured sandbox port.",
            ]
            diagnosis["suggested_fix"] = "Check entry point syntax and ensure web server listens on the assigned port."

        else:
            diagnosis["error_type"] = "GenericException"
            diagnosis["category"] = "general_error"
            diagnosis["root_cause"] = f"Exception encountered during execution: {log[:150]}"
            diagnosis["resolution_steps"] = [
                "Inspect source file at the indicated line number.",
                "Validate input types and error handling blocks.",
            ]
            diagnosis["suggested_fix"] = "Wrap fragile block with try/catch exception handling."

        line_match = re.search(r'File ["\']([^"\']+)["\'], line (\d+)', log)
        if line_match:
            diagnosis["affected_file"] = diagnosis["affected_file"] or line_match.group(1)
            diagnosis["affected_line"] = int(line_match.group(2))
        else:
            js_line_match = re.search(r'at\s+.*?\((.*?):(\d+):(\d+)\)', log)
            if js_line_match:
                diagnosis["affected_file"] = diagnosis["affected_file"] or js_line_match.group(1)
                diagnosis["affected_line"] = int(js_line_match.group(2))

        summary_text = (
            f"BreachLabs Error Diagnosis ({diagnosis['detected_language']}):\n"
            f"--------------------------------------------------\n"
            f"• Error Type: {diagnosis['error_type']} ({diagnosis['category']})\n"
            f"• Root Cause: {diagnosis['root_cause']}\n"
            f"• Location: {diagnosis['affected_file'] or 'N/A'}"
            + (f":{diagnosis['affected_line']}" if diagnosis["affected_line"] else "") + "\n"
            f"• Resolution Steps:\n"
            + "\n".join(f"  {i+1}. {step}" for i, step in enumerate(diagnosis["resolution_steps"])) + "\n"
            f"• Suggested Fix: {diagnosis['suggested_fix']}"
        )
        diagnosis["diagnostic_summary"] = summary_text
        diagnosis["response"] = summary_text
        return diagnosis


class GenerateRemediationParams(BaseModel):
    vulnerability_type: str = Field(..., description="Vulnerability type ('sqli', 'xss', 'idor', 'secrets', 'command_injection', 'cors', 'weak_crypto', 'debug_mode', 'prototype_pollution')")
    file_path: str = Field(default="app.py", description="Target file path")
    vulnerable_snippet: str = Field(default="", description="Original vulnerable code snippet or line")
    line_number: int = Field(default=1, description="Line number of vulnerable code")
    language: str = Field(default="python", description="Language ('python', 'javascript', 'typescript', 'go', 'rust', 'java', 'php')")
    framework: str = Field(default="", description="Optional framework name ('flask', 'fastapi', 'express', 'django', 'gin', 'spring')")


class GenerateRemediationTool(MCPTool):
    """Generate precise, contextual, language-native security remediation patches and diffs."""

    name = "generate_remediation"
    description = (
        "Generate production-grade security patches across Python, JavaScript/TypeScript, Go, Rust, Java, and PHP. "
        "Provides git diffs, corrected code snippets, and defense-in-depth architectural rationale."
    )
    risk_level = ToolRiskLevel.READ_ONLY
    Params = GenerateRemediationParams

    def execute(self, validated: GenerateRemediationParams, context: ToolContext) -> dict[str, Any]:
        v_type = validated.vulnerability_type.lower()
        lang = validated.language.lower()
        file_path = validated.file_path
        snippet = validated.vulnerable_snippet.strip()
        line = validated.line_number

        is_js = any(k in lang for k in ("javascript", "typescript", "node", "js", "ts")) or file_path.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))
        is_go = "go" in lang or file_path.endswith(".go")

        patch_code = ""
        diff = ""
        rationale = ""

        if "sql" in v_type:
            if is_js:
                patch_code = 'const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);'
                rationale = "Replaces raw template string interpolation with parameterized SQL query placeholders ($1, $2)."
            elif is_go:
                patch_code = 'rows, err := db.Query("SELECT * FROM users WHERE username = ?", username)'
                rationale = "Replaces fmt.Sprintf string interpolation with parameterized database query arguments."
            else:
                patch_code = 'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))'
                rationale = "Replaces string formatting with DB-API compliant tuple parameter binding."
        elif "xss" in v_type:
            if is_js:
                patch_code = 'const safeOutput = validator.escape(userInput);'
                rationale = "Applies contextual HTML entity encoding before rendering user input into the DOM."
            else:
                patch_code = 'from markupsafe import escape\nreturn f"<h1>Hello, {escape(user_input)}</h1>"'
                rationale = "Uses MarkupSafe contextual escaping to neutralize HTML and script tags."
        elif "secret" in v_type or "credential" in v_type:
            if is_js:
                patch_code = 'const API_KEY = process.env.API_KEY || "";'
            elif is_go:
                patch_code = 'apiKey := os.Getenv("API_KEY")'
            else:
                patch_code = 'API_KEY = os.environ.get("API_KEY", "")'
            rationale = "Removes hardcoded secret literal from source repository and injects credential from environment variables."
        elif "command" in v_type or "exec" in v_type:
            if is_js:
                patch_code = 'const { execFile } = require("child_process");\nexecFile("ping", ["-c", "4", targetHost], callback);'
            elif is_go:
                patch_code = 'cmd := exec.Command("ping", "-c", "4", targetHost)'
            else:
                patch_code = 'subprocess.run(["ping", "-c", "4", target_host], check=True, shell=False)'
            rationale = "Eliminates shell=True and passes arguments as discrete array parameters to bypass shell interpolation."
        elif "crypto" in v_type or "hash" in v_type:
            if is_js:
                patch_code = 'const hash = await bcrypt.hash(password, 12);'
            else:
                patch_code = 'import bcrypt\nhashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))'
            rationale = "Upgrades broken cryptographic hash (MD5/SHA-1) to salted, adaptive bcrypt key derivation."
        elif "debug" in v_type:
            if is_js:
                patch_code = 'const isDebug = process.env.NODE_ENV === "development";'
            else:
                patch_code = 'is_debug = os.environ.get("FLASK_DEBUG", "0") == "1"\napp.run(debug=is_debug)'
            rationale = "Disables hardcoded debug mode in production to prevent stack trace leaks and interactive debugger exposure."
        else:
            patch_code = f"// Secured implementation for {v_type}\n" + (snippet or "// Add input validation and access controls")
            rationale = f"Applies standard defensive coding patterns for {v_type}."

        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -{line},1 +{line},1 @@\n"
            f"- {snippet or '# Vulnerable code'}\n"
            f"+ {patch_code}"
        )

        return {
            "vulnerability_type": v_type,
            "language": lang,
            "file_path": file_path,
            "line_number": line,
            "remediation_patch": patch_code,
            "git_diff": diff,
            "rationale": rationale,
            "response": f"### Remediation Plan for {v_type.upper()}\n\n**File:** `{file_path}:{line}`\n**Rationale:** {rationale}\n\n```diff\n{diff}\n```\n",
        }


class GenerateSecurityTestParams(BaseModel):
    vulnerability_type: str = Field(..., description="Vulnerability type ('sqli', 'xss', 'idor', 'cors', 'secrets')")
    target_route: str = Field(default="/api/search", description="Target route or endpoint")
    language: str = Field(default="python", description="Test language ('python', 'javascript', 'go', 'curl')")
    parameter_name: str = Field(default="q", description="Vulnerable parameter name")


class GenerateSecurityTestTool(MCPTool):
    """Generate automated security regression tests and exploit verification probes."""

    name = "generate_security_test"
    description = (
        "Generate automated security test cases and CI/CD verification assertions for Python (pytest), "
        "JavaScript (Jest/Supertest), Go (testing), and Curl to verify vulnerability resolution."
    )
    risk_level = ToolRiskLevel.READ_ONLY
    Params = GenerateSecurityTestParams

    def execute(self, validated: GenerateSecurityTestParams, context: ToolContext) -> dict[str, Any]:
        v_type = validated.vulnerability_type.lower()
        route = validated.target_route
        param = validated.parameter_name
        lang = validated.language.lower()

        is_js = any(k in lang for k in ("javascript", "typescript", "node", "js", "ts"))
        is_go = "go" in lang

        test_code = ""
        if "sql" in v_type:
            if is_js:
                test_code = (
                    f"test('security: {route} rejects SQL injection tautology', async () => {{\n"
                    f"  const res = await request(app).get('{route}?{param}=%27%20OR%201=1--');\n"
                    f"  expect(res.status).not.toBe(500);\n"
                    f"  expect(res.text).not.toContain('syntax error');\n"
                    f"}});"
                )
            elif is_go:
                test_code = (
                    f"func TestSQLInjection_{param}(t *testing.T) {{\n"
                    f"  req := httptest.NewRequest(\"GET\", \"{route}?{param}=' OR 1=1--\", nil)\n"
                    f"  w := httptest.NewRecorder()\n"
                    f"  handler(w, req)\n"
                    f"  if strings.Contains(w.Body.String(), \"syntax error\") {{\n"
                    f"    t.Fatalf(\"Potential SQL injection detected\")\n"
                    f"  }}\n"
                    f"}}"
                )
            else:
                test_code = (
                    f"def test_security_{param}_sql_injection(client):\n"
                    f"    response = client.get(f'{route}?{param}=%27%20OR%201=1--')\n"
                    f"    assert response.status_code != 500\n"
                    f"    assert 'syntax error' not in response.text.lower()\n"
                )
        elif "xss" in v_type:
            marker = "xss_probe_test_987"
            if is_js:
                test_code = (
                    f"test('security: {route} contextually encodes XSS payloads', async () => {{\n"
                    f"  const res = await request(app).get('{route}?{param}=<script>{marker}</script>');\n"
                    f"  expect(res.text).not.toContain('<script>{marker}</script>');\n"
                    f"}});"
                )
            else:
                test_code = (
                    f"def test_security_{param}_xss_reflection(client):\n"
                    f"    probe = '<script>{marker}</script>'\n"
                    f"    response = client.get(f'{route}?{param}={{probe}}')\n"
                    f"    assert '<script>' not in response.text\n"
                )
        else:
            test_code = (
                f"def test_security_{v_type}_verification(client):\n"
                f"    response = client.get('{route}')\n"
                f"    assert response.status_code < 400\n"
            )

        return {
            "vulnerability_type": v_type,
            "target_route": route,
            "language": lang,
            "test_code": test_code,
            "response": f"```javascript\n{test_code}\n```" if is_js else f"```python\n{test_code}\n```",
        }


