"""Unit tests for the agent: correlation, triage, verification."""

import pytest

from breachlabs.core.agent import SecurityAgent, correlate_signals, dedupe_key
from breachlabs.core.types import (
    Assessment,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Location,
    Severity,
)


def _finding(title="SQLi", file="app.py", line=10, source="sast",
             severity=Severity.HIGH, route=None):
    f = Finding(
        title=title, category="injection", severity=severity,
        location=Location(file=file, line=line, route=route),
        description="Possible SQL injection: SQL executed with formatted input.",
    )
    f.add_evidence(Evidence(source=source, description="signal"))
    return f


class TestCorrelation:
    def test_multi_source_finding_gets_high_confidence(self):
        a = _finding(source="sast", file=None, route="/search")
        b = _finding(source="dast", file=None, route="/search")
        merged = correlate_signals([a, b])
        assert len(merged) == 1
        assert merged[0].confidence is Confidence.HIGH
        assert set(merged[0].sources) == {"sast", "dast"}

    def test_single_source_keeps_default_confidence(self):
        merged = correlate_signals([_finding(source="sast")])
        assert len(merged) == 1
        assert merged[0].confidence is Confidence.SUSPECTED

    def test_dedupe_key_stable(self):
        assert dedupe_key(_finding()) == dedupe_key(_finding())
        assert dedupe_key(_finding(file="x.py")) != dedupe_key(_finding(file="y.py"))


class TestPrioritize:
    def test_critical_before_low(self):
        from breachlabs.core.agent import prioritize

        low = _finding(severity=Severity.LOW)
        crit = _finding(severity=Severity.CRITICAL)
        ordered = prioritize([low, crit])
        assert ordered[0].severity is Severity.CRITICAL


class TestVerificationPolicy:
    def test_unverified_never_confirmed(self):
        agent = SecurityAgent()
        assessment = Assessment(repository="r", commit="c")
        findings = agent.investigate(assessment, [_finding(source="sast")], None)
        for f in findings:
            assert f.confidence is not Confidence.CONFIRMED
            assert f.status is not FindingStatus.VERIFIED

    def test_investigation_marks_status(self):
        agent = SecurityAgent()
        assessment = Assessment(repository="r", commit="c")
        findings = agent.investigate(assessment, [_finding()], None)
        assert findings[0].status is FindingStatus.INVESTIGATING


class TestInvestigationEnrichment:
    def test_investigation_enriches_finding_with_source(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n" * 40)
        from breachlabs.mcp.tool import ToolContext

        agent = SecurityAgent()
        assessment = Assessment(repository="r", commit="c")
        finding = _finding(file="app.py", line=20)
        enriched = agent.investigate(
            assessment, [finding], ToolContext(assessment_id="A", repo_path=str(tmp_path))
        )
        assert any(e.source == "investigation" for e in enriched[0].evidence)
        assert enriched[0].remediation

    def test_investigation_enriches_finding_with_route(self):
        from breachlabs.core.types import AttackSurface, Route
        from breachlabs.mcp.tool import ToolContext

        agent = SecurityAgent()
        agent._attack_surface = AttackSurface(
            routes=[Route(path="/search", method="GET")]
        )
        assessment = Assessment(repository="r", commit="c")
        finding = _finding(file=None, route="/search")
        enriched = agent.investigate(
            assessment, [finding], ToolContext(assessment_id="A", repo_path=None)
        )
        route_evidence = [
            e for e in enriched[0].evidence if e.source == "investigation"
        ]
        assert route_evidence
        assert route_evidence[0].data["confirmed"] is True

    def test_agent_verify_confirms_sql_injection_against_live_target(self):
        """Full agent verify() path: SQLi finding confirmed via runtime probe."""
        import os
        import subprocess
        import sys
        import time

        import httpx

        demo_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "demo")
        )
        port = 5936
        base_url = f"http://127.0.0.1:{port}"
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        proc = subprocess.Popen(
            [
                sys.executable, "-c",
                "import sys; sys.path.insert(0, '.');"
                "from vulnerable_app import app, _init_db;"
                "_init_db();"
                f"app.run(host='127.0.0.1', port={port}, debug=False, use_reloader=False)",
            ],
            cwd=demo_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, creationflags=creationflags,
        )
        try:
            deadline = time.time() + 30
            healthy = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                try:
                    if httpx.get(base_url, timeout=3.0).status_code < 500:
                        healthy = True
                        break
                except Exception:  # noqa: S110
                    time.sleep(0.5)
            if not healthy:
                pytest.fail("demo target failed to start")
            from breachlabs.mcp.tool import ToolContext

            agent = SecurityAgent()
            assessment = Assessment(repository="demo", commit="c")
            finding = _finding(
                file=None, route=f"{base_url}/search",
                title="Possible SQL injection (error-based)",
            )
            findings = agent.investigate(
                assessment, [finding],
                ToolContext(assessment_id="A", target_base_url=base_url),
            )
            agent.verify(assessment, findings, ToolContext(
                assessment_id="A", target_base_url=base_url,
            ))
            verified = findings[0]
            assert verified.verification.attempted is True
            assert verified.verification.result.value == "confirmed"
            assert verified.status is FindingStatus.VERIFIED
            assert any(e.source == "verification" for e in verified.evidence)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: S110
                pass
