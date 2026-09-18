"""Application workflow discovery (PRD.md section 11 Phase F).

The MVP prioritizes a small number of representative workflows rather than
exhaustive exploration: the login flow if one exists, plus form extraction on
discovered pages. Every workflow run produces structured evidence records the
agent can attach to findings.
"""

from __future__ import annotations

from typing import Any

from breachlabs.browser.driver import BrowserDriver


def _same_origin(base_url: str, url: str) -> bool:
    from urllib.parse import urlparse

    return urlparse(base_url).netloc == urlparse(url).netloc


def discover_forms(driver: BrowserDriver) -> list[dict[str, Any]]:
    """Extract forms from the current page (delegates to the driver)."""
    return driver.discover_forms()


def run_login_workflow(
    driver: BrowserDriver,
    base_url: str,
    login_path: str = "/login",
    username: str = "admin",
    password: str = "admin123",
) -> dict[str, Any]:
    """Drive the demo login flow and report the outcome.

    Returns a workflow record safe to attach to findings as evidence.
    """
    open_result = driver.open_page(base_url.rstrip("/") + login_path)
    forms = discover_forms(driver)
    before_forms = len(forms)

    driver.fill("input[name='username']", username)
    driver.fill("input[name='password']", password)
    submit = driver.submit("form")
    logs = driver.collect_console_logs()

    landed_admin = "admin" in driver.page_content().lower()
    return {
        "workflow": "login",
        "login_page": login_path,
        "page_status": open_result.get("status"),
        "forms_on_login_page": before_forms,
        "form_fields": forms[0]["inputs"] if forms else [],
        "submitted_to": submit.get("after"),
        "authenticated": landed_admin,
        "console_errors": [
            m for m in logs.get("messages", []) if m.get("type") == "error"
        ],
    }


def discover_workflows(
    driver: BrowserDriver,
    base_url: str,
    candidate_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run the small set of representative workflows for an assessment.

    1. Visit the home page and enumerate forms.
    2. Drive the login workflow if a login page/form exists.
    The login path is prioritized so it survives the MVP workflow cap.
    """
    records: list[dict[str, Any]] = []
    paths = list(candidate_paths or ["/"])
    login_paths = [p for p in paths if "login" in p.lower()]
    other_paths = [p for p in paths if p not in login_paths]
    ordered = (["/"] if "/" in other_paths else []) + login_paths
    ordered += [p for p in other_paths if p != "/"]
    if "/" not in ordered:
        ordered.insert(0, "/")

    for path in ordered[:4]:  # MVP: cap the workflow surface
        if _is_parameterized(path):
            continue  # e.g. /api/profile/<user_id> is not browser-navigable
        url = base_url.rstrip("/") + path
        page = driver.open_page(url)
        forms = discover_forms(driver)
        records.append({
            "workflow": "page_visit",
            "path": path,
            "status": page.get("status"),
            "title": page.get("title"),
            "forms": forms,
        })
        has_login_form = any(
            any(i.get("type") == "password" for i in f.get("inputs", []))
            for f in forms
        )
        if has_login_form:
            records.append(run_login_workflow(driver, base_url, path))
            break  # login captured; its record covers the auth workflow
    return records


def _is_parameterized(path: str) -> bool:
    """True for framework-style patterns like /api/profile/<user_id>."""
    return "<" in path or "{" in path or ":" in path
