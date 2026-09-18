"""Playwright browser driver (lazy startup, PRD.md section 20).

One Chromium instance per assessment, started on first use. Every action is
budget-checked and scoped: only URLs inside the sandbox target are opened.

All Playwright work runs on a dedicated single-worker thread pool. The sync
API refuses to run inside an active asyncio loop, and this agent is invoked
both from plain scripts and from the FastAPI server (which runs under
uvicorn/asyncio), so thread isolation is required for correctness rather
than being a test workaround.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse


class BrowserUnavailable(Exception):
    """Playwright is not installed or the browser failed to launch."""


class BrowserDriver:
    """Thread-isolated wrapper over Playwright's Chromium."""

    def __init__(self, allowed_hosts: list[str] | None = None) -> None:
        self.allowed_hosts = allowed_hosts or []
        self._playwright: Any = None
        self._browser: Any = None
        self._page: Any = None
        self.console_messages: list[dict[str, str]] = []
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="breachlabs-browser"
        )

    # -- thread isolation ----------------------------------------------------

    def _run(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute Playwright work on the dedicated browser thread."""
        return self._executor.submit(fn, *args, **kwargs).result()

    # -- lifecycle -----------------------------------------------------------

    @property
    def started(self) -> bool:
        return self._page is not None

    def start(self) -> None:
        self._run(self._start_sync)

    def _start_sync(self) -> None:
        if self._page is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserUnavailable(
                "Playwright is not installed. Install with "
                "'pip install -e \".[browser]\" && playwright install chromium'."
            ) from exc
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=True)
            self._page = self._browser.new_page()
            self._page.on(
                "console",
                lambda msg: self.console_messages.append({
                    "type": msg.type,
                    "text": msg.text[:500],
                }),
            )
        except Exception as exc:
            raise BrowserUnavailable(f"Browser failed to launch: {exc}") from exc

    def stop(self) -> None:
        try:
            self._run(self._stop_sync)
        except Exception:  # noqa: S110 - best-effort teardown
            pass
        self._executor.shutdown(wait=False)

    def _stop_sync(self) -> None:
        for resource in (self._browser, self._playwright):
            try:
                if resource is not None:
                    resource.close()
            except Exception:  # noqa: S110 - best-effort teardown
                pass
        self._playwright = None
        self._browser = None
        self._page = None

    # -- scoping -------------------------------------------------------------

    def _assert_in_scope(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        if host not in ("localhost", "127.0.0.1", "0.0.0.0", "::1") and (
            host not in self.allowed_hosts
        ):
            raise BrowserUnavailable(
                f"Refusing to open out-of-scope host '{host}' in the browser."
            )

    def _require_page(self) -> Any:
        if not self.started:
            self._start_sync()
        return self._page


    # -- actions (PRD.md section 9.1 browser tools) ---------------------------

    def open_page(self, url: str) -> dict[str, Any]:
        self._assert_in_scope(url)
        return self._run(self._open_page_sync, url)

    def _open_page_sync(self, url: str) -> dict[str, Any]:
        page = self._require_page()
        response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
        return {
            "url": url,
            "status": response.status if response else None,
            "title": page.title(),
        }

    def get_accessibility_snapshot(self) -> dict[str, Any]:
        return self._run(self._snapshot_sync)

    def _snapshot_sync(self) -> dict[str, Any]:
        return {"snapshot": self._require_page().accessibility.snapshot()}

    def click(self, selector: str) -> dict[str, Any]:
        return self._run(self._click_sync, selector)

    def _click_sync(self, selector: str) -> dict[str, Any]:
        page = self._require_page()
        page.click(selector, timeout=5000)
        return {"clicked": selector, "url": page.url}

    def fill(self, selector: str, value: str) -> dict[str, Any]:
        return self._run(self._fill_sync, selector, value)

    def _fill_sync(self, selector: str, value: str) -> dict[str, Any]:
        self._require_page().fill(selector, value, timeout=5000)
        return {"filled": selector, "value_length": len(value)}

    def submit(self, form_selector: str = "form") -> dict[str, Any]:
        """Submit a form and capture the resulting navigation."""
        return self._run(self._submit_sync, form_selector)

    def _submit_sync(self, form_selector: str) -> dict[str, Any]:
        page = self._require_page()
        before = page.url
        try:
            with page.expect_navigation(timeout=10000):
                page.eval_on_selector(form_selector, "form => form.submit()")
        except Exception:  # noqa: S110 - non-navigating forms are valid too
            pass
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10000)
        except Exception:  # noqa: S110 - best-effort settle
            pass
        return {"submitted": form_selector, "before": before, "after": page.url}

    def capture_screenshot(self) -> dict[str, Any]:
        return self._run(self._screenshot_sync)

    def _screenshot_sync(self) -> dict[str, Any]:
        page = self._require_page()
        data = page.screenshot(type="png")
        return {"format": "png", "size_bytes": len(data), "url": page.url, "data": data}

    def collect_console_logs(self) -> dict[str, Any]:
        logs = list(self.console_messages)
        self.console_messages = []
        return {"count": len(logs), "messages": logs}

    def page_content(self) -> str:
        return self._run(self._content_sync)

    def _content_sync(self) -> str:
        """Read the DOM, tolerating in-flight navigation after a submit."""
        import time

        page = self._require_page()
        try:
            page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:  # noqa: S110 - settle is best-effort
            pass
        for _ in range(5):
            try:
                return page.content()
            except Exception:  # noqa: S110 - page still navigating; retry
                time.sleep(0.4)
        return ""

    def discover_forms(self) -> list[dict[str, Any]]:
        """Extract forms from the current page: action, method, inputs."""
        return self._run(self._forms_sync)

    def _forms_sync(self) -> list[dict[str, Any]]:
        return self._require_page().evaluate(
            """() => Array.from(document.forms).map(f => ({
                action: f.action,
                method: (f.method || 'get').toLowerCase(),
                inputs: Array.from(f.elements).map(e => ({
                    name: e.name || '',
                    type: (e.type || 'text').toLowerCase(),
                    id: e.id || '',
                })),
            }))"""
        )
