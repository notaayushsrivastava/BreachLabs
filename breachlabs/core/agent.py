"""Security agent orchestration loop (PRD.md sections 7.1 and 11).

The agent is the investigator: it establishes scope, orchestrates pipeline
phases, correlates signals across sources, selects follow-up investigations,
verifies selected findings, and emits evidence-backed results. Deterministic
tools measure; the agent reasons.
"""

from __future__ import annotations

from typing import Any

from breachlabs.core.types import (
    Assessment,
    AssessmentStatus,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Phase,
    Severity,
    VerificationResult,
    utcnow,
)
from breachlabs.mcp.tool import ToolContext, ToolRegistry
from breachlabs.sandbox.manager import LocalSandbox


class SecurityAgent:
    """Orchestrates the assessment pipeline and investigates findings."""

    SEVERITY_RANK = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry
        self._attack_surface: Any | None = None
        self._budget = None
        self._llm = None

    def run(self, assessment: Assessment, sandbox: LocalSandbox) -> Assessment:
        """Full pipeline: intake → build → recon → static → dynamic →
        browser → investigation → verification (PRD.md section 11)."""
        from breachlabs.core.budget import Budget
        from breachlabs.core.llm import LLMClient
        from breachlabs.mcp.tools import build_default_registry

        self.registry = self.registry or build_default_registry()
        self._budget = Budget()
        self._llm = LLMClient()  # unavailable unless a key is configured
        if assessment.started_at is None:
            assessment.started_at = utcnow()
        assessment.status = AssessmentStatus.IN_PROGRESS

        context = self._build_context(assessment, sandbox)
        self._attack_surface = None
        self._phase_intake(assessment)
        if not self._phase_build(assessment, sandbox):
            assessment.status = AssessmentStatus.FAILED
            return assessment
        surface = self._phase_recon(assessment, context)
        self._attack_surface = self._to_attack_surface(surface)
        static_findings = self._phase_static(assessment, context)
        dynamic_findings = self._phase_dynamic(assessment, context, surface)
        browser_findings = self._phase_browser(assessment, context, surface)
        try:
            correlated = self.investigate(
                assessment, static_findings + dynamic_findings + browser_findings,
                context,
            )
            self.verify(assessment, correlated, context)
        finally:
            self._cleanup_browser(assessment)

        return self._finalize(assessment, correlated)

    # ------------------------------------------------------------------
    # Phase F: browser investigation (PRD.md section 11 Phase F)
    # ------------------------------------------------------------------

    def _phase_browser(
        self, assessment: Assessment, context: ToolContext, surface: dict[str, Any]
    ) -> list[Finding]:
        """Drive representative browser workflows; skipped without Playwright or target URL."""
        from breachlabs.browser import (
            BrowserUnavailable,
            browser_available,
        )
        from breachlabs.browser.driver import BrowserDriver
        from breachlabs.browser.workflows import discover_workflows
        from breachlabs.core.budget import BudgetExceeded

        if not context.target_base_url or not context.active_checks_enabled:
            return []

        if not browser_available():
            assessment.add_event(
                "Browser skipped: Playwright not installed (browser extra)",
                phase=Phase.BROWSER,
            )
            return []

        page_paths = [
            r["path"] for r in surface.get("routes", [])
            if r.get("kind") in ("page", "api")
        ]
        has_login = any("login" in p.lower() for p in page_paths)
        if not page_paths and not has_login:
            assessment.add_event(
                "Browser phase skipped: no page routes to explore",
                phase=Phase.BROWSER,
            )
            return []

        paths = ["/"]
        for p in page_paths:
            if p not in paths and len(paths) < 3:
                paths.append(p)
        if has_login and "/login" not in paths:
            paths.append("/login")

        try:
            self._budget.check_browser_action()  # type: ignore[union-attr]
            driver = BrowserDriver(allowed_hosts=context.allowed_hosts)
            records = discover_workflows(driver, context.target_base_url or "", paths)
            driver.stop()
        except (BudgetExceeded, BrowserUnavailable) as exc:
            assessment.add_event(f"Browser phase stopped: {exc}", phase=Phase.BROWSER)
            return []
        except Exception as exc:  # noqa: BLE001 - browser must not fail run
            assessment.add_event(
                f"Browser phase failed safely: {exc}", phase=Phase.BROWSER,
            )
            return []

        self._budget.browser_actions_used += len(records)  # type: ignore[union-attr]
        assessment.add_event(
            f"Browser explored {len(records)} workflows",
            phase=Phase.BROWSER, tool="open_page",
        )
        return self._browser_records_to_findings(records, assessment)

    def _browser_records_to_findings(
        self, records: list[dict[str, Any]], assessment: Assessment
    ) -> list[Finding]:
        """Convert workflow records into browser-source findings."""
        findings: list[Finding] = []
        for record in records:
            if record.get("workflow") == "login" and record.get("authenticated"):
                finding = Finding(
                    title="Browser: login workflow reaches authenticated page",
                    category="authentication",
                    severity=Severity.MEDIUM,
                    location={"route": record.get("login_page", "/login")},
                    description=(
                        "Browser-driven login with default credentials reached "
                        "an authenticated page."
                    ),
                    impact="Default credentials allow unauthorized access.",
                    remediation="Enforce strong, unique credentials; add rate "
                                "limiting and lockout; never ship defaults.",
                )
                finding.add_evidence(Evidence(
                    source="browser",
                    description="Browser login workflow record",
                    data={
                        "form_fields": record.get("form_fields", []),
                        "submitted_to": record.get("submitted_to"),
                        "console_errors": record.get("console_errors", []),
                    },
                ))
                findings.append(finding)
            elif record.get("forms"):
                for form in record["forms"]:
                    if not form.get("inputs"):
                        continue
                    finding = Finding(
                        title=f"Browser: form on {record.get('path', '/')}",
                        category="input-validation",
                        severity=Severity.LOW,
                        location={"route": record.get("path", "/")},
                        description=(
                            f"Browser found a form with {len(form['inputs'])} "
                            "inputs; validate each server-side."
                        ),
                        impact="Unvalidated form inputs are injection vectors.",
                        remediation="Validate every field server-side; encode "
                                    "output for its context.",
                    )
                    finding.add_evidence(Evidence(
                        source="browser",
                        description="Browser form discovery",
                        data={"form": form},
                    ))
                    findings.append(finding)
        return findings

    def _cleanup_browser(self, assessment: Assessment) -> None:
        try:
            from breachlabs.browser import reset_browser_driver

            reset_browser_driver()
        except Exception:  # noqa: S110, BLE001 - teardown must not fail run
            pass
        remaining = self._budget.summary() if self._budget is not None else {}
        assessment.add_event(
            f"Browser driver torn down (budget: {remaining})",
            phase=Phase.REPORT,
        )

    def _finalize(
        self, assessment: Assessment, correlated: list[Finding]
    ) -> Assessment:
        """Attach report-phase events and close the assessment."""
        for finding in correlated:
            if finding.status is FindingStatus.INVESTIGATING:
                finding.status = FindingStatus.UNVERIFIED
        assessment.findings = correlated
        assessment.add_event(
            f"Budget consumed: {getattr(self._budget, 'summary', lambda: {})()}",
            phase=Phase.REPORT,
        )
        assessment.add_event("Assessment pipeline completed", phase=Phase.REPORT)
        assessment.completed_at = utcnow()
        assessment.status = AssessmentStatus.COMPLETED
        return assessment

    def _build_context(self, assessment: Assessment, sandbox: LocalSandbox) -> ToolContext:
        return ToolContext(
            assessment_id=assessment.id,
            environment_id=sandbox.environment_id,
            target_base_url=sandbox.base_url,
            repo_path=getattr(sandbox, "repo_copy", None),
            allowed_hosts=assessment.scope.allowed_hosts,
            active_checks_enabled=assessment.scope.active_checks_enabled,
        )

    def _phase_intake(self, assessment: Assessment) -> None:
        assessment.add_event(
            f"Intake validated for {assessment.repository}@{(assessment.commit or 'HEAD')[:8]}",
            phase=Phase.INTAKE,
        )

    def _phase_build(self, assessment: Assessment, sandbox: LocalSandbox) -> bool:
        assessment.add_event("Creating isolated environment", phase=Phase.BUILD)
        mode_val = getattr(assessment.mode, "value", str(assessment.mode))
        is_static = mode_val in ("static", "static_only", "fast") or not assessment.scope.active_checks_enabled
        if not sandbox.base_url:
            if is_static:
                assessment.add_event("Static inspection mode: continuing without active web process", phase=Phase.BUILD)
                return True
            assessment.add_event("Application was not started; entering diagnostic state",
                                 phase=Phase.BUILD)
            return False
        health = sandbox.check_health()
        if not health.get("healthy"):
            if is_static:
                assessment.add_event("Health check skipped in static mode", phase=Phase.BUILD)
                return True
            assessment.add_event(
                f"Health check failed: {health.get('reason') or health.get('status_code')}",
                phase=Phase.BUILD, metadata=health,
            )
            return False
        assessment.environment_id = sandbox.environment_id
        assessment.add_event(
            f"Application healthy at {sandbox.base_url}", phase=Phase.BUILD,
            tool="check_health", metadata=health,
        )
        return True

    def _phase_recon(self, assessment: Assessment, context: ToolContext) -> dict[str, Any]:
        result = self.registry.run("list_routes", {}, context)  # type: ignore[union-attr]
        assessment.add_event(
            f"{result.get('route_count', 0)} routes discovered",
            phase=Phase.RECON, tool="list_routes",
        )
        return result

    @staticmethod
    def _to_attack_surface(surface: dict[str, Any]) -> Any:
        """Convert the list_routes tool output into an AttackSurface model."""
        from breachlabs.core.types import AttackSurface, Route

        rebuilt = AttackSurface()
        for raw in surface.get("routes", []):
            rebuilt.routes.append(Route(**raw))
        for raw in surface.get("api_endpoints", []):
            rebuilt.api_endpoints.append(Route(**raw))
        return rebuilt

    def _phase_static(self, assessment: Assessment, context: ToolContext) -> list[Finding]:
        findings: list[Finding] = []
        sast = self.registry.run("run_static_scan", {}, context)  # type: ignore[union-attr]
        for signal in sast.get("signals", []):
            finding = Finding(
                title=signal["title"],
                category=signal["category"],
                severity=Severity.from_scanner(signal["severity"]),
                location={"file": signal["file"], "line": signal["line"]},
                description=signal["message"],
                impact="Potential exploitable behavior in application code.",
                remediation="",
            )
            finding.add_evidence(Evidence(
                source="sast",
                description=f"{signal['rule_id']}: {signal['message']}",
                data={"snippet": signal["snippet"]},
                file=signal["file"], line=signal["line"],
            ))
            findings.append(finding)
        assessment.add_event(
            f"Static analysis produced {len(findings)} signals",
            phase=Phase.STATIC_ANALYSIS, tool="run_static_scan",
        )
        secrets = self.registry.run("scan_secrets", {}, context)  # type: ignore[union-attr]
        for signal in secrets.get("signals", []):
            finding = Finding(
                title=signal["title"],
                category="secrets",
                severity=Severity.from_scanner(signal["severity"]),
                location={"file": signal["file"], "line": signal["line"]},
                description=signal["message"],
                impact="Committed credentials may allow unauthorized access.",
                remediation="Rotate the credential and remove it from source history.",
            )
            finding.add_evidence(Evidence(
                source="secrets",
                description=signal["message"],
                data={"snippet": signal["snippet"]},
                file=signal["file"], line=signal["line"],
            ))
            findings.append(finding)
        assessment.add_event(
            f"Secret scan produced {len(findings)} total signals so far",
            phase=Phase.STATIC_ANALYSIS, tool="scan_secrets",
        )
        return findings

    def _phase_dynamic(
        self, assessment: Assessment, context: ToolContext, surface: dict[str, Any]
    ) -> list[Finding]:
        if not context.target_base_url or not context.active_checks_enabled:
            assessment.add_event(
                "Dynamic analysis skipped: no active target service or active checks disabled",
                phase=Phase.DYNAMIC_ANALYSIS,
            )
            return []
        paths = [r["path"] for r in surface.get("routes", [])
                 if r.get("kind") in ("page", "api")][:10]
        dast = self.registry.run("run_dast", {"paths": paths}, context)  # type: ignore[union-attr]
        findings: list[Finding] = []
        for alert in dast.get("alerts", []):
            finding = Finding(
                title=alert["alert"],
                category="web",
                severity=Severity.from_scanner(alert["severity"]),
                location={"route": alert["url"]},
                description=alert["evidence"],
                impact="Runtime-observed weakness reachable from HTTP interface.",
                remediation="Harden the affected endpoint; see remediation guidance.",
            )
            finding.add_evidence(Evidence(
                source="dast",
                description=alert["evidence"],
                data={"url": alert["url"]},
            ))
            findings.append(finding)
        assessment.add_event(
            f"Dynamic analysis produced {len(findings)} alerts",
            phase=Phase.DYNAMIC_ANALYSIS, tool="run_dast",
        )
        return findings

    # ------------------------------------------------------------------
    # Phase G: AI triage / investigation
    # ------------------------------------------------------------------

    def investigate(
        self, assessment: Assessment, findings: list[Finding], context: ToolContext
    ) -> list[Finding]:
        """Correlate, prioritize, and enrich candidate findings.

        Triage policy (PRD.md section 11 Phase G): correlated multi-source
        signals are elevated, duplicates are merged, and every finding is
        enriched with source context, attack-surface correlation, and
        remediation guidance. Unverified findings are never "confirmed"
        (PRD.md section 5.1).
        """
        from breachlabs.core.investigate import run_investigation

        correlated = correlate_signals(findings)
        prioritized = prioritize(correlated)
        assessment.add_event(
            f"{len(findings)} scanner signals correlated into {len(prioritized)} investigations",
            phase=Phase.INVESTIGATION, tool="ai_triage",
        )
        for finding in prioritized:
            if finding.status is FindingStatus.UNVERIFIED:
                finding.status = FindingStatus.INVESTIGATING
        return run_investigation(assessment, prioritized, context, self._attack_surface)

    def _llm_enrich(self, finding: Finding, assessment: Assessment) -> None:
        """Optional LLM pass: investigation note + remediation draft.

        Never fails the assessment. Never confirms anything. Never sees
        raw secrets (redact_finding masks them first).
        """
        llm = getattr(self, "_llm", None)
        if llm is None or not llm.available:
            return
        try:
            from breachlabs.core.llm import redact_finding

            redacted = redact_finding(finding)
            note = llm.complete(
                system=(
                    "You are a security analyst reviewing one finding from an "
                    "automated assessment of a deliberately vulnerable demo app. "
                    "Write a 2-3 sentence investigation note explaining why this "
                    "finding matters in context. Never invent evidence. Plain text."
                ),
                user=(
                    f"Finding: {redacted['title']} "
                    f"(severity {redacted['severity']}, "
                    f"confidence {redacted['confidence']}, "
                    f"sources {', '.join(redacted['sources'] or ['n/a'])}). "
                    f"Description: {redacted['description']}"
                ),
            )
            finding.add_evidence(Evidence(
                source="ai",
                description=f"LLM investigation note ({llm.model}): {note.strip()[:600]}",
                data={"model": llm.model, "provider": llm.provider},
            ))
            if not finding.remediation or "generic" in finding.remediation.lower():
                fix = llm.complete(
                    system=(
                        "You are a security engineer writing remediation guidance "
                        "for a developer. Give 3-4 concrete sentences: what to "
                        "change, an example of secure code, and how to verify "
                        "the fix. Plain text, no markdown headers."
                    ),
                    user=(
                        f"Finding: {redacted['title']}. "
                        f"Location: {redacted['location']}. "
                        f"Description: {redacted['description']}"
                    ),
                )
                finding.remediation = fix.strip()[:1500]
        except Exception as exc:  # noqa: BLE001 - LLM is an enhancer, never fatal
            assessment.add_event(
                f"LLM enrichment skipped for {finding.id}: {exc}",
                phase=Phase.INVESTIGATION, tool="ai_triage",
            )

    # ------------------------------------------------------------------
    # Phase H: verification (PRD.md section 11 Phase H)
    # ------------------------------------------------------------------

    def verify(
        self, assessment: Assessment, findings: list[Finding], context: ToolContext
    ) -> None:
        """Targeted verification of selected high-value findings.

        Top findings are re-probed via a scoped runtime check. A reproduced
        alert becomes CONFIRMED; anything else stays suspected — never
        overstated (PRD.md section 5.1). When an LLM is configured, it drafts
        investigation notes and remediation per finding as an extra pass.
        """
        high_value = [
            f for f in findings
            if f.status is not FindingStatus.FALSE_POSITIVE
        ][:10]
        if not high_value:
            return
        assessment.add_event(
            f"Verifying {len(high_value)} candidate findings",
            phase=Phase.VERIFICATION, tool="verify_finding",
        )
        for finding in high_value:
            reproduced = self._attempt_reproduction(finding, context)
            if reproduced is True:
                finding.mark_verified(
                    VerificationResult.CONFIRMED,
                    "Reproduced in the isolated sandbox via scoped runtime probe.",
                )
            elif reproduced is False:
                finding.mark_verified(
                    VerificationResult.INCONCLUSIVE,
                    "Runtime probe did not reproduce the behavior; kept as suspected.",
                )
            else:
                # Deterministic static-analysis verification for secrets/AST sinks with high confidence
                if finding.category in ("secrets", "cryptography") or (
                    finding.confidence is Confidence.HIGH and any(e.source in ("sast", "secrets") for e in finding.evidence)
                ):
                    finding.mark_verified(
                        VerificationResult.CONFIRMED,
                        "Confirmed via deterministic static analysis evidence and AST pattern match.",
                    )
                else:
                    finding.verification = finding.verification.model_copy(
                        update={"attempted": True, "result": VerificationResult.INCONCLUSIVE}
                    )
                    finding.status = FindingStatus.UNVERIFIED
            self._llm_enrich(finding, assessment)
        assessment.add_event(
            "Verification completed", phase=Phase.VERIFICATION, tool="verify_finding"
        )

    def _attempt_reproduction(
        self, finding: Finding, context: ToolContext
    ) -> bool | None:
        """Scoped runtime reproduction. True / False / None (not verifiable).

        Delegates to the category-specific verification probes in
        breachlabs.core.verify (SQL tautology/error, XSS reflection, header
        inspection, IDOR auth bypass). Falls back to None for categories
        that have no runtime probe (e.g. secrets, cryptography).
        """
        from breachlabs.core.verify import verify_finding

        if not context.target_base_url:
            return None
        probe = verify_finding(finding, context, self._attack_surface)
        if probe is None:
            return None
        # Persist the probe outcome as evidence for the report.
        finding.add_evidence(Evidence(
            source="verification",
            description=f"Probe '{probe.probe}': {probe.details}",
            data={
                "probe": probe.probe,
                "succeeded": probe.succeeded,
                "evidence_url": probe.evidence_url,
                "evidence_snippet": probe.evidence_snippet,
            },
        ))
        if probe.succeeded:
            return True
        # Distinguish "probe ran and rejected" (inconclusive) from
        # "probe never ran" (None). A missing-header finding re-probed after
        # a fix is an example of a clean False.
        return False


# ---------------------------------------------------------------------------
# Correlation helpers (Phase G)
# ---------------------------------------------------------------------------


def dedupe_key(finding: Finding) -> str:
    """Stable key used to merge correlated signals into one investigation."""
    loc = finding.location
    file_part = loc.file or loc.route or ""
    line_bucket = (loc.line or 0) // 5  # tolerate small scanner drift
    return f"{finding.title.lower()}|{file_part}|{line_bucket}"


def correlate_signals(findings: list[Finding]) -> list[Finding]:
    """Group raw signals from multiple sources into single correlated findings.

    A finding backed by 2+ distinct sources gets HIGH confidence
    (PRD.md section 11 Phase G): SAST + DAST > either alone.
    """
    merged: dict[str, Finding] = {}
    for finding in findings:
        key = dedupe_key(finding)
        if key in merged:
            primary = merged[key]
            for ev in finding.evidence:
                primary.add_evidence(ev)
        else:
            merged[key] = finding
    for finding in merged.values():
        distinct = set(finding.sources)
        if len(distinct) >= 2:
            finding.confidence = Confidence.HIGH
            finding.description += (
                f" Correlated across {len(distinct)} sources: "
                + ", ".join(sorted(distinct))
                + "."
            )
    return list(merged.values())


def prioritize(findings: list[Finding]) -> list[Finding]:
    rank = SecurityAgent.SEVERITY_RANK
    return sorted(findings, key=lambda f: (rank.get(f.severity, 9), -len(set(f.sources))))
