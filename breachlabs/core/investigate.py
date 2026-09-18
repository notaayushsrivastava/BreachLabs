"""Investigation engine (PRD.md section 11 Phase G / section 7.1).

Enriches scanner findings with source context, attack-surface correlation, and
remediation guidance. Investigation upgrades a raw signal into an
evidence-backed candidate for verification; it never claims confirmation on
its own (verification is a separate phase).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from breachlabs.core.types import (
    Assessment,
    Confidence,
    Evidence,
    Finding,
    Phase,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from breachlabs.mcp.tool import ToolContext
else:  # runtime duck-typing keeps the module import-light
    ToolContext = Any

CONTEXT_RADIUS = 15  # lines of source context to capture around a finding


def read_source_context(finding: Finding, repo_path: str | None) -> Evidence | None:
    """Read source around finding.location and return evidence, or None."""
    loc = finding.location
    if not repo_path or not loc.file:
        return None
    target = os.path.abspath(os.path.join(repo_path, loc.file))
    root = os.path.abspath(repo_path)
    if not target.startswith(root + os.sep) and target != root:
        return None  # path escape - never read outside the sandbox
    if not os.path.isfile(target):
        return None
    try:
        with open(target, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    line_no = loc.line or 1
    start = max(1, line_no - CONTEXT_RADIUS)
    end = min(len(lines), line_no + CONTEXT_RADIUS)
    snippet = "".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
    return Evidence(
        source="investigation",
        description=(
            f"Source context from {loc.file}:{start}-{end} "
            f"(finding at line {line_no})"
        ),
        data={"snippet": snippet, "file": loc.file, "start_line": start, "end_line": end},
        file=loc.file,
        line=line_no,
    )


def correlate_route(finding: Finding, attack_surface: Any | None) -> Evidence | None:
    """Check finding.location.route against the discovered attack surface."""
    loc = finding.location
    if not loc.route or attack_surface is None:
        return None
    routes = list(getattr(attack_surface, "routes", []) or [])
    routes += list(getattr(attack_surface, "api_endpoints", []) or [])
    route_paths = {r.path for r in routes}
    known = loc.route in route_paths
    detail = (
        f"Route {loc.route} confirmed in attack surface "
        f"({len(route_paths)} routes discovered during recon)."
        if known
        else (
            f"Route {loc.route} was not found in the recon attack surface; "
            "the finding may reference an undiscovered or dynamic route."
        )
    )
    return Evidence(
        source="investigation",
        description=detail,
        data={
            "route": loc.route,
            "confirmed": known,
            "attack_surface_routes": len(route_paths),
        },
    )


def investigate_finding(
    finding: Finding,
    context: ToolContext,
    attack_surface: Any | None = None,
) -> Finding:
    """Enrich one finding with source context, route correlation, remediation.

    Confidence policy: investigation alone elevates a finding from SUSPECTED
    to HIGH only when both source context was read AND its route is confirmed
    in the attack surface (or the finding has no route to confirm).
    CONFIRMED is reserved for the verification phase.
    """
    had_source = False
    had_route = False

    if finding.location.file and finding.location.line and context is not None:
        repo = getattr(context, "repo_path", None)
        evidence = read_source_context(finding, repo)
        if evidence is not None:
            finding.add_evidence(evidence)
            had_source = True

    if finding.location.route and attack_surface is not None:
        evidence = correlate_route(finding, attack_surface)
        if evidence is not None:
            finding.add_evidence(evidence)
            had_route = bool(evidence.data.get("confirmed"))

    if not finding.remediation:
        finding.remediation = Finding.remediation_guide(
            finding.category, finding.sources, finding.description
        )

    if not finding.impact:
        finding.impact = (
            "Exploitation could compromise the confidentiality, integrity, or "
            "availability of the application or its data, depending on the "
            "affected component and deployment context."
        )

    if (
        finding.confidence is Confidence.SUSPECTED
        and had_source
        and (had_route or not finding.location.route)
    ):
        finding.confidence = Confidence.HIGH

    return finding


def run_investigation(
    assessment: Assessment,
    findings: list[Finding],
    context: ToolContext,
    attack_surface: Any | None = None,
) -> list[Finding]:
    """Entry point used by SecurityAgent.investigate(). Logs phase events."""
    assessment.add_event(
        f"Investigating {len(findings)} findings: reading source context, "
        "correlating with attack surface, generating remediation",
        phase=Phase.INVESTIGATION,
        tool="ai_triage",
    )
    enriched = 0
    elevated = 0
    for finding in findings:
        before_evidence = len(finding.evidence)
        investigate_finding(finding, context, attack_surface)
        if len(finding.evidence) > before_evidence:
            enriched += 1
        if finding.confidence is Confidence.HIGH:
            elevated += 1
    assessment.add_event(
        f"Investigation completed: {enriched} findings enriched with context, "
        f"{elevated} elevated to high confidence",
        phase=Phase.INVESTIGATION,
        tool="ai_triage",
    )
    return findings

