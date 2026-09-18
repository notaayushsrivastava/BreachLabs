"""Unit tests for the type system (PRD.md section 24)."""

from breachlabs.core.types import (
    Assessment,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Location,
    Phase,
    Scope,
    Severity,
    VerificationResult,
)


class TestSeverityMapping:
    def test_scanner_aliases(self):
        assert Severity.from_scanner("HIGH") is Severity.HIGH
        assert Severity.from_scanner("moderate") is Severity.MEDIUM
        assert Severity.from_scanner("info") is Severity.INFORMATIONAL
        assert Severity.from_scanner("") is Severity.MEDIUM  # default
        assert Severity.from_scanner("garbage", Severity.LOW) is Severity.LOW


class TestFinding:
    def test_defaults_are_unverified(self):
        finding = Finding(title="t", category="c", severity=Severity.HIGH)
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confidence is Confidence.SUSPECTED

    def test_never_confirmed_without_verification(self):
        finding = Finding(title="t", category="c", severity=Severity.HIGH)
        finding.mark_verified(VerificationResult.INCONCLUSIVE)
        assert finding.confidence is not Confidence.CONFIRMED
        assert finding.status is not FindingStatus.VERIFIED

    def test_verification_state_transitions(self):
        finding = Finding(title="t", category="c", severity=Severity.HIGH)
        finding.mark_verified(VerificationResult.CONFIRMED, "done")
        assert finding.status is FindingStatus.VERIFIED
        assert finding.confidence is Confidence.CONFIRMED
        finding.mark_verified(VerificationResult.REJECTED, "no")
        assert finding.status is FindingStatus.FALSE_POSITIVE

    def test_evidence_tracks_sources(self):
        finding = Finding(title="t", category="c", severity=Severity.LOW)
        finding.add_evidence(Evidence(source="sast", description="d1"))
        finding.add_evidence(Evidence(source="sast", description="d2"))
        finding.add_evidence(Evidence(source="dast", description="d3"))
        assert finding.sources == ["sast", "dast"]
        assert len(finding.evidence) == 3

    def test_secret_redaction(self):
        ev = Evidence(
            source="secrets",
            description="leak",
            data={"snippet": "password = hunter2secretvalue"},
        )
        red = ev.redacted(["hunter2secretvalue"])
        assert "hunter2secretvalue" not in str(red.data)


class TestScope:
    def test_rejects_non_isolated_target(self):
        scope = Scope(target="production")
        assert scope.target != "isolated"
        assessment = Assessment(repository="x", commit="abc", scope=scope)
        assert not assessment.validate_scope("anything")

    def test_allows_localhost_by_default(self):
        assessment = Assessment(repository="x", commit="abc")
        assert assessment.validate_scope("127.0.0.1")

    def test_allowlist_enforcement(self):
        assessment = Assessment(
            repository="x",
            commit="abc",
            scope=Scope(allowed_hosts=["example.com"]),
        )
        assert assessment.validate_scope("example.com")
        assert not assessment.validate_scope("evil.com")


class TestAssessment:
    def test_events_are_recorded(self):
        assessment = Assessment(repository="x", commit="abc")
        assessment.add_event("hello", phase=Phase.RECON, tool="t")
        assert assessment.events[0].phase is Phase.RECON
        assert assessment.events[0].assessment_id == assessment.id

    def test_finding_schema_roundtrip(self):
        finding = Finding(
            title="Example",
            category="authorization",
            severity=Severity.HIGH,
            location=Location(file="app.py", line=10, route="/api/x"),
        )
        data = finding.model_dump()
        restored = Finding(**data)
        assert restored.location.file == "app.py"
        assert restored.location.line == 10
