"""Security report generation (PRD.md section 14).

Generates Markdown and JSON reports with executive summary, scope, attack
surface, findings with evidence, remediation, coverage, and limitations.
"""

from __future__ import annotations

import json
from typing import Any

from breachlabs.core.types import Assessment, FindingStatus, Severity


def generate_report(assessment: Assessment) -> dict[str, Any]:
    """Build the structured report dictionary."""
    verified = [f for f in assessment.findings if f.status is FindingStatus.VERIFIED]
    dismissed = [f for f in assessment.findings if f.status is FindingStatus.FALSE_POSITIVE]
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for finding in assessment.findings:
        counts[finding.severity.value] += 1
    return {
        "assessment_id": assessment.id,
        "repository": assessment.repository,
        "commit": assessment.commit,
        "mode": assessment.mode.value,
        "status": assessment.status.value,
        "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
        "environment_id": assessment.environment_id,
        "executive_summary": _executive_summary(assessment, verified, dismissed),
        "attack_surface": {
            "event_count": len(assessment.events),
            "recon_events": [
                e.message for e in assessment.events if e.phase.value == "recon"
            ],
        },
        "severity_counts": counts,
        "findings": [f.model_dump(mode="json") for f in assessment.findings],
        "verified_count": len(verified),
        "dismissed_count": len(dismissed),
        "limitations": _limitations(),
        "disclaimer": (
            "BreachLabs performs an automated, evidence-backed application "
            "security assessment within the declared scope. A clean assessment "
            "is not proof that an application is secure."
        ),
    }


def _executive_summary(
    assessment: Assessment, verified: list, dismissed: list
) -> str:
    total = len(assessment.findings)
    return (
        f"Assessment {assessment.id} evaluated {assessment.repository} "
        f"in an isolated environment. {total} findings were produced, of which "
        f"{len(verified)} were verified and {len(dismissed)} dismissed as "
        f"false positives. Findings are prioritized by severity and confidence; "
        f"remediation guidance is provided for each."
    )


def _limitations() -> list[str]:
    return [
        "Coverage is limited to checks enabled by the assessment policy.",
        "Dynamic checks were limited to scoped, isolated targets.",
        "Absence of findings does not establish that the application is secure.",
        "Automated triage cannot replace manual security review.",
    ]


def generate_markdown(assessment: Assessment) -> str:
    """Render the PRD-suggested Markdown report structure."""
    report = generate_report(assessment)
    lines: list[str] = [
        "# BreachLabs Security Assessment",
        "",
        "## Executive Summary",
        "",
        report["executive_summary"],
        "",
        "## Assessment Scope",
        "",
        f"- **Repository:** {report['repository']}",
        f"- **Commit:** {report['commit'] or 'HEAD'}",
        f"- **Mode:** {report['mode']}",
        f"- **Assessment ID:** {report['assessment_id']}",
        f"- **Environment:** {report['environment_id'] or 'n/a'}",
        "",
        "## Findings",
        "",
    ]
    if not assessment.findings:
        lines.append("No findings were produced by the enabled checks.")
        lines.append("")
    for finding in assessment.findings:
        lines.append(f"### {finding.id} — {finding.title}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.severity.value}")
        lines.append(f"- **Confidence:** {finding.confidence.value}")
        lines.append(f"- **Status:** {finding.status.value}")
        loc = finding.location
        location = loc.file or loc.route or "n/a"
        if loc.line:
            location += f":{loc.line}"
        lines.append(f"- **Location:** {location}")
        lines.append(f"- **Sources:** {', '.join(finding.sources) or 'n/a'}")
        lines.append("")
        lines.append(finding.description)
        lines.append("")
        if finding.evidence:
            lines.append("**Evidence**")
            lines.append("")
            for ev in finding.evidence:
                lines.append(f"- [{ev.source}] {ev.description}")
            lines.append("")
        lines.append(f"**Impact:** {finding.impact or 'n/a'}")
        lines.append("")
        lines.append(f"**Remediation:** {finding.remediation or 'n/a'}")
        lines.append("")
    lines += [
        "## Coverage",
        "",
        f"- {len(assessment.events)} assessment events recorded",
        f"- {report['severity_counts']}",
        "",
        "## Limitations",
        "",
    ]
    lines += [f"- {item}" for item in report["limitations"]]
    lines += ["", "## Disclaimer", "", report["disclaimer"], ""]
    return "\n".join(lines)


def generate_json(assessment: Assessment) -> str:
    return json.dumps(generate_report(assessment), indent=2, default=str)
