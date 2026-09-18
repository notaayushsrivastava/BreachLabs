"""Tests for the investigation engine (Phase 2 - PRD section 11 Phase G)."""

from breachlabs.core.investigate import (
    correlate_route,
    investigate_finding,
    read_source_context,
    run_investigation,
)
from breachlabs.core.types import (
    Assessment,
    AttackSurface,
    Confidence,
    Evidence,
    Finding,
    Location,
    Route,
    Severity,
)
from breachlabs.mcp.tool import ToolContext


def _finding(file=None, line=None, route=None, category="injection",
             severity=Severity.HIGH, remediation=None, impact=None):
    finding = Finding(
        title="SQL injection in search",
        category=category,
        severity=severity,
        location=Location(file=file, line=line, route=route),
        description="SQL executed with formatted input.",
        remediation=remediation or "",
        impact=impact or "",
    )
    finding.add_evidence(Evidence(source="sast", description="signal"))
    return finding


class TestReadSourceContext:
    def test_reads_context_around_line(self, tmp_path):
        (tmp_path / "app.py").write_text("\n".join(f"line {i}" for i in range(1, 51)))
        finding = _finding(file="app.py", line=25)
        ev = read_source_context(finding, str(tmp_path))
        assert ev is not None
        assert ev.source == "investigation"
        assert ev.data["start_line"] <= 15
        assert ev.data["end_line"] >= 35
        assert "line 25" in ev.data["snippet"]

    def test_missing_file_returns_none(self, tmp_path):
        finding = _finding(file="nope.py", line=5)
        assert read_source_context(finding, str(tmp_path)) is None

    def test_no_repo_path_returns_none(self):
        finding = _finding(file="app.py", line=5)
        assert read_source_context(finding, None) is None

    def test_path_escape_returns_none(self, tmp_path):
        finding = _finding(file="../../etc/passwd", line=1)
        assert read_source_context(finding, str(tmp_path)) is None


class TestCorrelateRoute:
    def test_route_confirmed(self):
        surface = AttackSurface(routes=[Route(path="/search", method="GET")])
        finding = _finding(route="/search")
        ev = correlate_route(finding, surface)
        assert ev is not None
        assert ev.data["confirmed"] is True

    def test_route_unknown(self):
        surface = AttackSurface(routes=[Route(path="/other", method="GET")])
        finding = _finding(route="/search")
        ev = correlate_route(finding, surface)
        assert ev is not None
        assert ev.data["confirmed"] is False

    def test_no_route_returns_none(self):
        finding = _finding(file="app.py", line=3)
        assert correlate_route(finding, AttackSurface()) is None

    def test_no_surface_returns_none(self):
        finding = _finding(route="/search")
        assert correlate_route(finding, None) is None


class TestInvestigateFinding:
    def test_source_context_added(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n" * 40)
        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        finding = _finding(file="app.py", line=20)
        investigate_finding(finding, context)
        assert any(e.source == "investigation" for e in finding.evidence)

    def test_remediation_generated_when_empty(self):
        context = ToolContext(assessment_id="A", repo_path=None)
        finding = _finding(remediation=None)
        investigate_finding(finding, context)
        assert finding.remediation
        assert "parameterized" in finding.remediation.lower()

    def test_existing_remediation_preserved(self):
        context = ToolContext(assessment_id="A", repo_path=None)
        finding = _finding(remediation="Custom guidance.")
        investigate_finding(finding, context)
        assert finding.remediation == "Custom guidance."

    def test_impact_generated_when_empty(self):
        context = ToolContext(assessment_id="A", repo_path=None)
        finding = _finding(impact=None)
        investigate_finding(finding, context)
        assert finding.impact

    def test_confidence_bumped_with_source_and_route(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n" * 40)
        surface = AttackSurface(routes=[Route(path="/search", method="GET")])
        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        finding = _finding(file="app.py", line=20, route="/search")
        investigate_finding(finding, context, surface)
        assert finding.confidence is Confidence.HIGH

    def test_confidence_stays_suspected_without_source(self):
        surface = AttackSurface(routes=[Route(path="/search", method="GET")])
        context = ToolContext(assessment_id="A", repo_path=None)
        finding = _finding(route="/search")
        investigate_finding(finding, context, surface)
        assert finding.confidence is Confidence.SUSPECTED

    def test_never_confirmed_by_investigation(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n" * 40)
        surface = AttackSurface(routes=[Route(path="/search", method="GET")])
        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        finding = _finding(file="app.py", line=20, route="/search")
        investigate_finding(finding, context, surface)
        assert finding.confidence is not Confidence.CONFIRMED


class TestRunInvestigation:
    def test_logs_events(self):
        assessment = Assessment(repository="r", commit="c")
        context = ToolContext(assessment_id="A", repo_path=None)
        run_investigation(assessment, [_finding()], context)
        phases = [e.phase.value for e in assessment.events]
        assert "investigation" in phases

    def test_returns_all_findings(self):
        assessment = Assessment(repository="r", commit="c")
        context = ToolContext(assessment_id="A", repo_path=None)
        findings = [_finding(), _finding(route="/x")]
        result = run_investigation(assessment, findings, context)
        assert len(result) == 2
