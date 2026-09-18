"""Browser automation layer (PRD.md sections 9.1, 10.2, 11 Phase F).

Playwright is an optional dependency: everything degrades to "unavailable"
when it is not installed, and the pipeline continues without the browser
phase. All browser activity runs against the isolated sandbox target only.
"""

from breachlabs.browser.driver import BrowserDriver, BrowserUnavailable  # noqa: F401
from breachlabs.browser.tools import (  # noqa: F401
    BrowserToolBase,
    ClickTool,
    CollectConsoleLogsTool,
    FillTool,
    GetAccessibilitySnapshotTool,
    OpenPageTool,
    ScreenshotTool,
    SubmitTool,
)
from breachlabs.browser.workflows import discover_workflows  # noqa: F401
from breachlabs.mcp.tool import ToolRegistry


def build_browser_registry() -> ToolRegistry:
    """Registry of browser tools. Callers must check browser_available()."""
    registry = ToolRegistry()
    for tool in (
        OpenPageTool(),
        GetAccessibilitySnapshotTool(),
        ClickTool(),
        FillTool(),
        SubmitTool(),
        ScreenshotTool(),
        CollectConsoleLogsTool(),
    ):
        registry.register(tool)
    return registry


def reset_browser_driver() -> None:
    """Tear down the shared browser driver (assessment cleanup)."""
    BrowserToolBase.reset_driver()


def browser_available() -> bool:
    """True when Playwright can be imported (browser phase runnable)."""
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    return True
