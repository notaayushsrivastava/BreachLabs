"""End-to-end pipeline integration test (PRD.md section 24).

repository → sandbox → application → scanner → finding → agent → report
Runs against the controlled vulnerable demo application.
"""

import os
import time

import pytest

from breachlabs.core.agent import SecurityAgent
from breachlabs.core.types import Assessment
from breachlabs.sandbox.manager import LocalSandbox

DEMO_DIR = os.path.join(os.path.dirname(__file__), "..", "demo")
DEMO_REPO = os.path.abspath(DEMO_DIR)


def _wait_health(base_url: str, timeout: float = 30.0) -> bool:
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.get(base_url, timeout=5.0)
            if resp.status_code < 500:
                return True
        except Exception:  # noqa: S110
            pass
        time.sleep(0.5)
    return False


@pytest.fixture(scope="module")
def demo_sandbox():
    sandbox = LocalSandbox(DEMO_REPO, port=5911)
    sandbox.create()
    sandbox.start(launch_command=[
        __import__("sys").executable, "-c",
        "import sys; sys.path.insert(0, '.');"
        "from vulnerable_app import app, _init_db;"
        "_init_db();"
        "app.run(host='127.0.0.1', port=5911, debug=True, use_reloader=False)",
    ])
    assert _wait_health("http://127.0.0.1:5911", timeout=20.0), "demo app failed to start"
    yield sandbox
    sandbox.destroy()


class TestEndToEndPipeline:
    def test_sandbox_autodetects_demo_wrapper(self):
        """The demo wrapper (app.py) must boot via auto-detected launch.

        Regression test: _detect_launch looks for app.py/main.py, so the demo
        directory must contain a runnable wrapper — otherwise assessments
        complete with zero findings.
        """
        sandbox = LocalSandbox(DEMO_REPO, port=5912)
        sandbox.create()
        try:
            base_url = sandbox.start()  # no explicit launch command
            assert base_url == "http://127.0.0.1:5912"
            assert _wait_health(base_url, timeout=20.0), "auto-launched app unhealthy"
        finally:
            sandbox.destroy()

    def test_full_pipeline_produces_verified_findings(self, demo_sandbox):
        assessment = Assessment(repository="demo/vulnerable_app", commit="deadbee")
        agent = SecurityAgent()
        result = agent.run(assessment, demo_sandbox)

        assert result.status.value == "completed"
        assert result.findings, "expected at least one finding"
        # deterministic demo: SQLi + reflected XSS expected from DAST
        titles = [f.title for f in result.findings]
        assert any("SQL" in t for t in titles)
        assert any("XSS" in t or "cross-site" in t.lower() for t in titles)
        # demo must produce security signals from static analysis too
        assert any(f.category == "secrets" for f in result.findings)
        # events recorded for the dashboard timeline
        phases = {e.phase.value for e in result.events}
        assert {"intake", "build", "recon", "static_analysis",
                "dynamic_analysis", "investigation"} <= phases

    def test_report_generated_from_pipeline(self, demo_sandbox):
        assessment = Assessment(repository="demo/vulnerable_app", commit="deadbee")
        SecurityAgent().run(assessment, demo_sandbox)
        from breachlabs.report.generator import generate_markdown, generate_report

        report = generate_report(assessment)
        assert report["status"] == "completed"
        assert report["severity_counts"]["high"] >= 1
        md = generate_markdown(assessment)
        assert "BL-" in md
