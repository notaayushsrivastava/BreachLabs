"""Unit tests for the agent: correlation, triage, verification."""

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
