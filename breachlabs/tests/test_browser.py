"""Tests for browser tools and workflow discovery (Phase 3 - Phase F).

Playwright-dependent tests skip when the browser extra is not installed;
pure-registry and skip-path behavior are always tested.
"""

import pytest

from breachlabs.browser import browser_available

pytestmark = pytest.mark.skipif(
    not browser_available(), reason="Playwright not installed (browser extra)"
)

from breachlabs.browser.tools import (  # noqa: E402, F401
    ClickTool,
    CollectConsoleLogsTool,
    FillTool,
    GetAccessibilitySnapshotTool,
    OpenPageTool,
    ScreenshotTool,
    SubmitTool,
)
from breachlabs.browser.workflows import (  # noqa: E402, F401
    discover_forms,
    discover_workflows,
    run_login_workflow,
)
from breachlabs.mcp.tool import ToolContext  # noqa: E402


def _context(base_url="http://127.0.0.1:5950"):
    return ToolContext(assessment_id="B", target_base_url=base_url)


@pytest.fixture(scope="module")
def live_demo_browser():
    """Live demo target + started browser driver for workflow tests."""
    import os
    import subprocess
    import sys
    import time

    demo_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "demo")
    )
    port = 5950
    base_url = f"http://127.0.0.1:{port}"
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen(
        [
            sys.executable, "-c",
            "import sys; sys.path.insert(0, '.');"
            "from breachlabs.demo.vulnerable_app import app, _init_db;"
            "_init_db();"
            f"app.run(host='127.0.0.1', port={port}, debug=False, use_reloader=False)",
        ],
        cwd=demo_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, creationflags=creationflags,
    )
    import httpx

    deadline = time.time() + 30
    healthy = False
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            if httpx.get(base_url, timeout=3.0).status_code < 500:
                healthy = True
                break
        except Exception:  # noqa: S110
            time.sleep(0.5)
    if not healthy:
        proc.terminate()
        pytest.fail("Demo target failed to start for browser tests")

    from breachlabs.browser.driver import BrowserDriver

    driver = BrowserDriver()
    driver.start()
    yield {"driver": driver, "url": base_url, "proc": proc}
    driver.stop()
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:  # noqa: S110
        pass


class TestBrowserRegistry:
    def test_registry_lists_browser_tools(self):
        from breachlabs.browser import build_browser_registry

        names = build_browser_registry().names()
        for expected in (
            "open_page", "get_accessibility_snapshot", "click",
            "fill", "submit", "capture_screenshot", "collect_console_logs",
        ):
            assert expected in names

    def test_tools_expose_manifests(self):
        from breachlabs.browser import build_browser_registry

        for manifest in build_browser_registry().manifests():
            assert manifest["name"] and "risk_level" in manifest

    def test_registry_joined_into_default_when_available(self):
        from breachlabs.mcp.tools import build_default_registry

        assert "open_page" in build_default_registry().names()


class TestLiveBrowser:
    def test_login_workflow_authenticates_demo(self, live_demo_browser):
        record = run_login_workflow(live_demo_browser["driver"], live_demo_browser["url"])
        assert record["workflow"] == "login"
        assert record["forms_on_login_page"] >= 1
        assert record["authenticated"] is True

    def test_discover_forms_on_login_page(self, live_demo_browser):
        driver = live_demo_browser["driver"]
        driver.open_page(live_demo_browser["url"] + "/login")
        forms = discover_forms(driver)
        assert forms
        input_types = {
            i["type"] for f in forms for i in f["inputs"]
        }
        assert "password" in input_types

    def test_open_page_tool_returns_status(self, live_demo_browser):
        context = _context(live_demo_browser["url"])
        result = OpenPageTool().run(
            {"url": live_demo_browser["url"] + "/"}, context
        )
        assert result["status"] == 200

    def test_fill_then_submit_login(self, live_demo_browser):
        context = _context(live_demo_browser["url"])
        OpenPageTool().run({"url": live_demo_browser["url"] + "/login"}, context)
        FillTool().run({"selector": "input[name='username']", "value": "admin"}, context)
        FillTool().run(
            {"selector": "input[name='password']", "value": "admin123"}, context
        )
        result = SubmitTool().run({"form_selector": "form"}, context)
        assert "after" in result
