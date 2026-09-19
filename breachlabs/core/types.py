"""BreachLabs core type system.

Defines the data models for assessments, findings, evidence, and events
following the Finding Schema specified in PRD.md section 12.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

_counters: dict[str, itertools.count] = {}


def _next_id(prefix: str) -> str:
    counter = _counters.setdefault(prefix, itertools.count(1))
    return f"{prefix}-{next(counter):04d}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def from_scanner(
        cls, raw: str, default: Severity | None = None
    ) -> Severity:
        """Map a scanner-provided severity string to a canonical Severity."""
        aliases = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
            "none": cls.INFORMATIONAL,
        }
        if default is None:
            default = cls.MEDIUM
        return aliases.get((raw or "").strip().lower(), default)


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    SUSPECTED = "suspected"
    INFORMATIONAL = "informational"
    FALSE_POSITIVE = "false_positive"


class FindingStatus(str, Enum):
    UNVERIFIED = "unverified"
    INVESTIGATING = "investigating"
    VERIFIED = "verified"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false_positive"


class VerificationResult(str, Enum):
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


class AssessmentStatus(str, Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class AssessmentMode(str, Enum):
    DEEP = "deep"
    QUICK = "quick"


class Phase(str, Enum):
    """Assessment pipeline phases (PRD.md section 11)."""

    INTAKE = "intake"
    BUILD = "build"
    RECON = "recon"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    BROWSER = "browser"
    INVESTIGATION = "investigation"
    VERIFICATION = "verification"
    REPORT = "report"


class ToolRiskLevel(str, Enum):
    """Risk classification for MCP tools (least-privilege enforcement)."""

    READ_ONLY = "read_only"
    ACTIVE_SCAN = "active_scan"
    WRITE = "write"


class Evidence(BaseModel):
    """A single piece of evidence supporting a finding."""

    id: str = Field(default_factory=lambda: _next_id("EVD"))
    source: str  # e.g. "sast", "dast", "browser", "runtime", "manual"
    description: str
    data: dict[str, Any] = Field(default_factory=dict)
    file: str | None = None
    line: int | None = None
    captured_at: datetime = Field(default_factory=utcnow)

    def redacted(self, secret_values: list[str] | None = None) -> Evidence:
        """Return a copy with known secret values redacted from data."""
        import copy

        clone = copy.deepcopy(self)
        if secret_values:
            for value in secret_values:
                clone.data = _redact_recursive(clone.data, value)
        return clone


def _redact_recursive(obj: Any, secret: str) -> Any:
    if isinstance(obj, dict):
        return {
            k: _redact_recursive(v, secret)
            for k, v in obj.items()
            if not (isinstance(v, str) and secret and secret in v)
        }
    if isinstance(obj, list):
        return [_redact_recursive(v, secret) for v in obj]
    if isinstance(obj, str) and secret and secret in obj:
        return "[REDACTED]"
    return obj


class Location(BaseModel):
    file: str | None = None
    line: int | None = None
    route: str | None = None
    column: int | None = None
    parameter: str | None = None


class Verification(BaseModel):
    attempted: bool = False
    result: VerificationResult | None = None
    details: str = ""


class Finding(BaseModel):
    """Canonical finding representation (PRD.md section 12)."""

    id: str = Field(default_factory=lambda: _next_id("BL"))
    title: str
    category: str  # e.g. "authorization", "injection", "secrets", "dependencies"
    severity: Severity
    confidence: Confidence = Confidence.SUSPECTED
    status: FindingStatus = FindingStatus.UNVERIFIED
    location: Location = Field(default_factory=Location)
    description: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)  # e.g. ["sast", "runtime"]
    verification: Verification = Field(default_factory=Verification)
    impact: str = ""
    remediation: str = ""
    limitations: list[str] = Field(default_factory=list)

    def add_evidence(self, evidence: Evidence) -> None:
        if evidence.source not in self.sources:
            self.sources.append(evidence.source)
        self.evidence.append(evidence)

    def mark_verified(self, result: VerificationResult, details: str = "") -> None:
        self.verification = Verification(attempted=True, result=result, details=details)
        if result is VerificationResult.CONFIRMED:
            self.status = FindingStatus.VERIFIED
            self.confidence = Confidence.CONFIRMED
        elif result is VerificationResult.REJECTED:
            self.status = FindingStatus.FALSE_POSITIVE
            self.confidence = Confidence.FALSE_POSITIVE
        else:
            self.status = FindingStatus.UNVERIFIED
            self.confidence = Confidence.SUSPECTED

    def dismiss(self, reason: str) -> None:
        self.status = FindingStatus.FALSE_POSITIVE
        self.confidence = Confidence.FALSE_POSITIVE
        self.verification = Verification(
            attempted=True, result=VerificationResult.REJECTED, details=reason
        )

    @classmethod
    def remediation_guide(cls, category: str, sources: list[str], description: str = "") -> str:
        """Generate category-specific remediation guidance (PRD 7.1 resp. 14)."""
        guides = {
            "injection": (
                "Use parameterized queries or prepared statements instead of string "
                "formatting. Never interpolate user input into SQL, command, or template "
                "strings. Validate and escape input at the boundary; apply least-privilege "
                "permissions on the database user."
            ),
            "xss": (
                "Encode output for the correct context (HTML body, attribute, JavaScript, "
                "URL) using a vetted escaping library. Add a Content-Security-Policy "
                "header as defense-in-depth. Prefer frameworks that auto-escape by "
                "default and avoid raw HTML injection of user data."
            ),
            "authorization": (
                "Enforce authorization checks server-side on every request that accesses "
                "a protected resource. Deny by default; verify the authenticated user is "
                "permitted to perform the action on the specific object. Add tests for "
                "cross-user access attempts."
            ),
            "idor": (
                "Replace sequential or guessable object references with access-controlled "
                "lookups: verify object ownership on every request, avoid exposing "
                "internal IDs in URLs where possible, and add authorization tests that "
                "attempt cross-tenant access."
            ),
            "headers": (
                "Set security headers on every response: Content-Security-Policy, "
                "X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and "
                "Strict-Transport-Security (for HTTPS deployments). Centralize header "
                "configuration in middleware or the framework's response pipeline."
            ),
            "secrets": (
                "Remove hardcoded credentials from source code. Load secrets from "
                "environment variables or a secrets manager, rotate the exposed values "
                "immediately, and purge them from version-control history. Add "
                "secret-scanning to CI to prevent regressions."
            ),
            "configuration": (
                "Disable debug mode and verbose errors in production configurations. "
                "Return generic error pages and log details server-side only. Review "
                "deployment settings so insecure defaults cannot reach production."
            ),
            "cryptography": (
                "Replace weak algorithms with modern standards: use bcrypt/argon2/scrypt "
                "for password hashing (never MD5/SHA1), use TLS 1.2+ for transport, and "
                "use vetted library APIs instead of custom cryptography."
            ),
        }
        default = (
            "Review the finding location, apply input validation and output encoding "
            "where appropriate, and follow secure defaults for the affected component. "
            "Verify the fix resolves the issue before deploying."
        )
        return guides.get((category or "").strip().lower(), default)



class Scope(BaseModel):
    """Explicit authorization scope for an assessment (PRD.md section 5.3)."""

    target: str = "isolated"  # only "isolated" is supported in the MVP
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_phases: list[Phase] = Field(default_factory=list)
    active_checks_enabled: bool = True


class AssessmentEvent(BaseModel):
    id: str = Field(default_factory=lambda: _next_id("EVT"))
    assessment_id: str
    timestamp: datetime = Field(default_factory=utcnow)
    phase: Phase = Phase.INTAKE
    tool: str | None = None
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Assessment(BaseModel):
    id: str = Field(default_factory=lambda: _next_id("ASM"))
    repository: str
    commit: str
    mode: AssessmentMode = AssessmentMode.DEEP
    status: AssessmentStatus = AssessmentStatus.QUEUED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    scope: Scope = Field(default_factory=Scope)
    environment_id: str | None = None
    framework: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    events: list[AssessmentEvent] = Field(default_factory=list)

    def add_event(
        self,
        message: str,
        phase: Phase = Phase.INTAKE,
        tool: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AssessmentEvent:
        event = AssessmentEvent(
            assessment_id=self.id,
            phase=phase,
            tool=tool,
            message=message,
            metadata=metadata or {},
        )
        self.events.append(event)
        return event

    def validate_scope(self, target_host: str) -> bool:
        """Reject any target outside the declared scope (PRD.md section 11 Phase A)."""
        if self.scope.target != "isolated":
            return False
        if not self.scope.allowed_hosts:
            return True  # empty allowlist permits only sandbox-local targets
        return target_host in self.scope.allowed_hosts


class Route(BaseModel):
    path: str
    method: str = "GET"
    kind: str = "page"  # "page" | "api" | "static"
    auth_required: bool = False
    parameters: list[str] = Field(default_factory=list)


class FormSpec(BaseModel):
    action: str
    method: str = "POST"
    fields: list[str] = Field(default_factory=list)


class AttackSurface(BaseModel):
    """Output of Phase C: Reconnaissance (PRD.md section 11)."""

    routes: list[Route] = Field(default_factory=list)
    forms: list[FormSpec] = Field(default_factory=list)
    api_endpoints: list[Route] = Field(default_factory=list)
    auth_flows: list[str] = Field(default_factory=list)
    framework: str | None = None
    entry_points: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    dependency_manifests: list[str] = Field(default_factory=list)

    def route_count(self) -> int:
        return len({r.path for r in self.routes})
