"""Tests for report generation (PRD.md sections 14 and 24)."""

from breachlabs.core.types import Assessment, Finding, Location, Severity
from breachlabs.report.generator import generate_json, generate_markdown, generate_report


def _assessment_with_findings() -> Assessment:
    assessment = Assessment(repository="demo/app", commit="abc123def")
    finding = Finding(
        title="SQL injection in search",
        category="injection",
        severity=Severity.HIGH,
        location=Location(file="app.py", line=42, route="/search"),
        description="SQL query built with user input.",
    )
    assessment.findings.append(finding)
    return assessment


class TestReport:
    def test_json_report_is_valid_structure(self):
        assessment = _assessment_with_findings()
        report = generate_report(assessment)
        assert report["assessment_id"] == assessment.id
        assert report["verified_count"] == 0
        assert report["findings"][0]["title"] == "SQL injection in search"

    def test_markdown_contains_required_sections(self):
        assessment = _assessment_with_findings()
        md = generate_markdown(assessment)
        for section in (
            "# BreachLabs Security Assessment",
            "## Executive Summary",
            "## Assessment Scope",
            "## Findings",
            "## Limitations",
            "BL-",
        ):
            assert section in md

    def test_json_string_parses(self):
        import json

        data = json.loads(generate_json(_assessment_with_findings()))
        assert data["repository"] == "demo/app"

    def test_empty_report_states_no_findings(self):
        md = generate_markdown(Assessment(repository="r", commit="c"))
        assert "No findings were produced" in md
        assert "not proof that an application is secure" in md
