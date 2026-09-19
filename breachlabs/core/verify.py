"""Verification toolkit (PRD.md section 11 Phase H).

Actively probes findings against the running isolated target to confirm or
reject them. Each category has a dedicated probe; unverifiable categories
(e.g. secrets) return None. Downgrade on doubt: a probe that cannot decide
yields INCONCLUSIVE, never CONFIRMED.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from breachlabs.core.types import Finding


class VerificationProbeResult(BaseModel):
    """Outcome of a single verification probe."""

    probe: str  # e.g. "sql_tautology", "xss_reflection", "idor_auth_bypass"
    succeeded: bool  # True = vulnerability confirmed by probe
    details: str
    evidence_url: str | None = None
    evidence_snippet: str | None = None


SQL_ERROR_SIGNATURES = (
    "sqlite3.",
    "sqlite error",
    "operationalerror",
    "programmingerror",
    "syntax error",
    "sql syntax",
    "warning: sqlite",
    "unrecognized token",
)


def _row_count(text: str) -> int:
    """Heuristic row counter: demo apps render rows as dict reprs."""
    return text.count("),") + text.count("}]")


def _get(url: str, timeout: float = 10.0) -> Any:
    import httpx

    return httpx.get(url, timeout=timeout, follow_redirects=True)


def probe_sql_injection(base_url: str, route: str) -> VerificationProbeResult:
    """Probe a route for SQL injection via error-based and tautology payloads."""
    base = base_url.rstrip("/")
    path = route if route.startswith("/") else "/" + route
    url = f"{base}{path}"
    sep = "&" if "?" in url else "?"
    baseline_rows = -1
    try:
        baseline_rows = _row_count(_get(url).text)
    except Exception:
        pass

    # Error-based probe
    error_url = f"{url}{sep}q=%27BREACHLABS"
    try:
        resp = _get(error_url)
        body_lower = resp.text.lower()
        for signature in SQL_ERROR_SIGNATURES:
            if signature in body_lower:
                return VerificationProbeResult(
                    probe="sql_error_based",
                    succeeded=True,
                    details=(
                        f"SQL error signature '{signature}' in response to "
                        f"single-quote probe: {error_url}"
                    ),
                    evidence_url=error_url,
                    evidence_snippet=signature,
                )
    except Exception:
        pass

    # Tautology probe
    taut_url = f"{url}{sep}q=%27+OR+1%3D1+--"
    try:
        taut = _get(taut_url)
        taut_rows = _row_count(taut.text)
        if taut.status_code == 200 and taut_rows > baseline_rows:
            return VerificationProbeResult(
                probe="sql_tautology",
                succeeded=True,
                details=(
                    f"Tautology probe returned {taut_rows} row markers vs "
                    f"baseline {baseline_rows}: {taut_url}"
                ),
                evidence_url=taut_url,
                evidence_snippet=taut.text[:400],
            )
        if taut.status_code == 500 and baseline_rows == 0:
            # Error page on tautology when baseline 200s is suspicious
            return VerificationProbeResult(
                probe="sql_tautology",
                succeeded=False,
                details="Tautology probe returned an error; inconclusive.",
                evidence_url=taut_url,
            )
    except Exception:
        pass
    return VerificationProbeResult(
        probe="sql_tautology",
        succeeded=False,
        details="No SQL error signature and no row-count change observed.",
        evidence_url=url,
    )


XSS_MARKER = "b1x9zx"


def probe_xss_reflection(base_url: str, route: str) -> VerificationProbeResult:
    """Probe a route for reflected XSS using an HTML marker payload.

    The payload deliberately contains no single quotes: reflected probes hit
    the same parameter that feeds a SQL sink in the demo target, and quotes
    would trip the SQL layer before the reflection point is reached.
    """
    base = base_url.rstrip("/")
    path = route if route.startswith("/") else "/" + route
    url = f"{base}{path}"
    sep = "&" if "?" in url else "?"
    payload = f"<script>alert({XSS_MARKER})</script>"
    probe_url = f"{url}{sep}q={payload}"
    try:
        resp = _get(probe_url)
        if payload in resp.text:
            return VerificationProbeResult(
                probe="xss_reflection",
                succeeded=True,
                details=(
                    "XSS payload reflected unencoded in response body "
                    f"(script tag present): {probe_url}"
                ),
                evidence_url=probe_url,
                evidence_snippet=payload,
            )
    except Exception:
        pass
    return VerificationProbeResult(
        probe="xss_reflection",
        succeeded=False,
        details="Marker payload was not reflected unencoded.",
        evidence_url=probe_url,
    )


SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
)


def probe_missing_headers(base_url: str, route: str = "") -> VerificationProbeResult:
    """Check a route for missing standard security headers."""
    base = base_url.rstrip("/")
    path = route if route.startswith("/") else "/" + route
    url = f"{base}{path}"
    try:
        resp = _get(url)
        present = {k.lower() for k in resp.headers}
        missing = [h for h in SECURITY_HEADERS if h not in present]
        if missing:
            return VerificationProbeResult(
                probe="missing_headers",
                succeeded=True,
                details=f"Missing security headers: {', '.join(missing)}",
                evidence_url=url,
                evidence_snippet=", ".join(missing),
            )
        return VerificationProbeResult(
            probe="missing_headers",
            succeeded=False,
            details="All standard security headers are present.",
            evidence_url=url,
        )
    except Exception as exc:
        return VerificationProbeResult(
            probe="missing_headers",
            succeeded=False,
            details=f"Could not reach target for header inspection: {exc}",
            evidence_url=url,
        )


def probe_idor(base_url: str, route: str) -> VerificationProbeResult:
    """Verify IDOR by checking unauthenticated access to a protected route.

    Heuristic: request the route with no credentials. If the route returns
    user-controlled data (JSON with id/username/role, or different content
    than the control route), access is uncontrolled.
    """
    base = base_url.rstrip("/")
    path = route if route.startswith("/") else "/" + route
    url = f"{base}{path}"
    try:
        resp = _get(url)
        body = resp.text
        suspicious_markers = ('"id"', '"username"', '"role"', '"email"')
        data_exposed = any(m in body for m in suspicious_markers)
        if data_exposed and resp.status_code == 200:
            return VerificationProbeResult(
                probe="idor_auth_bypass",
                succeeded=True,
                details=(
                    f"Unauthenticated request to {url} returned object data "
                    "without any access-control response."
                ),
                evidence_url=url,
                evidence_snippet=body[:400],
            )
    except Exception:
        pass
    return VerificationProbeResult(
        probe="idor_auth_bypass",
        succeeded=False,
        details="Unauthenticated access did not return protected object data.",
        evidence_url=url,
    )


def _normalize_url(base_url: str, route: str) -> str:
    """Return a requestable URL.

    DAST findings carry full URLs as their route; static findings carry
    paths. If route is already a full URL, use it as-is.
    """
    route = (route or "").strip()
    if route.startswith("http://") or route.startswith("https://"):
        return route
    base = base_url.rstrip("/")
    path = route if route.startswith("/") else "/" + route
    return f"{base}{path}"


def classify_finding(finding: Finding) -> str:
    """Map a finding to a probe category, using title heuristics as fallback.

    DAST alerts arrive with the generic category 'web'; their titles carry
    the actual vulnerability class (SQL injection / XSS / missing header).
    """
    category = (finding.category or "").lower()
    title = (finding.title or "").lower()
    if category in ("injection", "xss", "headers", "configuration", "authorization", "idor"):
        return category
    if category == "secrets" or category == "cryptography":
        return category
    if "sql" in title and ("inject" in title or "error" in title):
        return "injection"
    if "xss" in title or "cross-site" in title:
        return "xss"
    if "header" in title:
        return "headers"
    if "idor" in title or "object-level" in title or "authorization" in title:
        return "idor"
    return category


def verify_finding(
    finding: Finding,
    context: Any,
    attack_surface: Any | None = None,
) -> VerificationProbeResult | None:
    """Dispatch a category-specific verification probe. None = unverifiable."""
    base_url = getattr(context, "target_base_url", None) or ""
    if not base_url:
        return None
    route = finding.location.route or ""
    category = classify_finding(finding)

    # Extract the path from a full URL for probes that rebuild URLs.
    path = route
    if route.startswith("http"):
        from urllib.parse import urlparse

        parsed = urlparse(route)
        path = parsed.path or "/"
    if (not path or path == "/") and attack_surface is not None:
        routes = list(getattr(attack_surface, "routes", []) or [])
        routes += list(getattr(attack_surface, "api_endpoints", []) or [])
        route_paths = [getattr(r, "path", "") for r in routes]
        if category in ("injection", "xss"):
            for rp in route_paths:
                if "/search" in rp or "query" in rp or "find" in rp:
                    path = rp
                    break
        elif category in ("authorization", "idor"):
            for rp in route_paths:
                if "profile" in rp or "user" in rp or "account" in rp:
                    path = rp
                    break
    if not path:
        path = "/"

    # Normalize dynamic route placeholders for testing
    if "<user_id>" in path:
        path = path.replace("<user_id>", "1")
    if "{id}" in path:
        path = path.replace("{id}", "1")
    if "{user_id}" in path:
        path = path.replace("{user_id}", "1")

    if category == "injection" and path:
        return probe_sql_injection(base_url, path)
    if category == "xss" and path:
        return probe_xss_reflection(base_url, path)
    if category in ("headers", "configuration"):
        return probe_missing_headers(base_url, path)
    if category in ("authorization", "idor") and path:
        return probe_idor(base_url, path)
    # secrets / cryptography / dependencies: verified via source review only
    return None

