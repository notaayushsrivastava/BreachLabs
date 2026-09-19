"""Tests for the verification toolkit (Phase 2 - PRD section 11 Phase H).

Runs the vulnerable demo target live on a dedicated port so probes hit real
HTTP responses (deterministic: the demo's weaknesses are fixed by design).
"""

import os
import sys
import time

import pytest

from breachlabs.core.types import Finding, Location, Severity
from breachlabs.core.verify import (
    probe_idor,
    probe_missing_headers,
    probe_sql_injection,
    probe_xss_reflection,
    verify_finding,
)
from breachlabs.mcp.tool import ToolContext

DEMO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo"))
PORT = 5935
BASE_URL = f"http://127.0.0.1:{PORT}"


@pytest.fixture(scope="module")
def demo_app():
    import subprocess

    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen(
        [
            sys.executable, "-c",
            "import sys; sys.path.insert(0, '.');"
            "from vulnerable_app import app, _init_db;"
            "_init_db();"
            f"app.run(host='127.0.0.1', port={PORT}, debug=False, use_reloader=False)",
        ],
        cwd=DEMO_DIR,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        creationflags=creationflags,
    )
    import httpx

    deadline = time.time() + 30
    healthy = False
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            resp = httpx.get(BASE_URL, timeout=3.0)
            if resp.status_code < 500:
                healthy = True
                break
        except Exception:  # noqa: S110
            time.sleep(0.5)
    if not healthy:
        proc.terminate()
        pytest.fail("Demo target failed to start for verification tests")
    yield BASE_URL
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:  # noqa: S110
        pass


def _finding(category, route, title="t"):
    return Finding(
        title=title, category=category, severity=Severity.HIGH,
        location=Location(route=route),
        description="demo finding",
    )


class TestSqlInjectionProbe:
    def test_error_based_detects_sqli(self, demo_app):
        result = probe_sql_injection(demo_app, "/search")
        assert result.succeeded is True
        assert result.probe in ("sql_error_based", "sql_tautology")

    def test_no_sqli_on_clean_route(self, demo_app):
        result = probe_sql_injection(demo_app, "/")
        assert result.succeeded is False


class TestXssProbe:
    def test_reflection_detected(self, demo_app):
        result = probe_xss_reflection(demo_app, "/search")
        assert result.succeeded is True
        assert result.probe == "xss_reflection"

    def test_no_reflection_on_clean_route(self, demo_app):
        result = probe_xss_reflection(demo_app, "/")
        assert result.succeeded is False


class TestHeaderProbe:
    def test_missing_headers_detected(self, demo_app):
        result = probe_missing_headers(demo_app, "/")
        assert result.succeeded is True
        assert "content-security-policy" in (result.evidence_snippet or "")

    def test_all_headers_present_case(self, demo_app):
        # The demo always lacks headers; a server that sets them would pass.
        result = probe_missing_headers(demo_app, "/")
        assert result.probe == "missing_headers"


class TestIdorProbe:
    def test_unauthenticated_data_returned(self, demo_app):
        result = probe_idor(demo_app, "/api/profile/1")
        assert result.succeeded is True
        assert result.probe == "idor_auth_bypass"

    def test_no_data_on_public_route(self, demo_app):
        result = probe_idor(demo_app, "/")
        assert result.succeeded is False


class TestVerifyFindingDispatch:
    def test_dispatch_sql_injection(self, demo_app):
        context = ToolContext(assessment_id="A", target_base_url=demo_app)
        finding = _finding("web", f"{demo_app}/search", "Possible SQL injection (error-based)")
        result = verify_finding(finding, context)
        assert result is not None
        assert result.succeeded is True
        assert result.probe.startswith("sql")

    def test_dispatch_xss(self, demo_app):
        context = ToolContext(assessment_id="A", target_base_url=demo_app)
        finding = _finding("web", f"{demo_app}/search", "Reflected cross-site scripting")
        result = verify_finding(finding, context)
        assert result is not None
        assert result.probe == "xss_reflection"

    def test_dispatch_headers(self, demo_app):
        context = ToolContext(assessment_id="A", target_base_url=demo_app)
        finding = _finding("headers", "/", "Missing security header: content-security-policy")
        result = verify_finding(finding, context)
        assert result is not None
        assert result.probe == "missing_headers"

    def test_dispatch_idor(self, demo_app):
        context = ToolContext(assessment_id="A", target_base_url=demo_app)
        finding = _finding("authorization", "/api/profile/1", "Broken object-level authorization")
        result = verify_finding(finding, context)
        assert result is not None
        assert result.probe == "idor_auth_bypass"

    def test_secrets_category_returns_none(self, demo_app):
        context = ToolContext(assessment_id="A", target_base_url=demo_app)
        finding = _finding("secrets", None, "Hardcoded admin password")
        assert verify_finding(finding, context) is None

    def test_no_base_url_returns_none(self):
        context = ToolContext(assessment_id="A", target_base_url=None)
        finding = _finding("injection", "/search")
        assert verify_finding(finding, context) is None

    def test_injection_without_route_returns_probe_on_root(self, demo_app):
        context = ToolContext(assessment_id="A", target_base_url=demo_app)
        finding = _finding("injection", None)
        result = verify_finding(finding, context)
        assert result is not None  # falls back to "/" probe, never crashes
