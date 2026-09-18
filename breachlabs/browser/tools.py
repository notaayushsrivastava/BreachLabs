"""Browser MCP tools (PRD.md section 9.1).

Each action is a narrow MCPTool: validated params, scope-checked URLs, and a
shared BrowserDriver owned by the agent. Tools are registered only when
Playwright is installed (check ``browser_available()`` first).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from breachlabs.browser.driver import BrowserDriver
from breachlabs.core.types import ToolRiskLevel
from breachlabs.mcp.tool import MCPTool, ToolContext, ToolError


class UrlParams(BaseModel):
    url: str = Field(description="Target URL (must be in assessment scope)")


class BrowserToolBase(MCPTool):
    """Shared driver plumbing for all browser tools."""

    risk_level = ToolRiskLevel.ACTIVE_SCAN
    _driver: BrowserDriver | None = None

    def _driver_for(self, context: ToolContext) -> BrowserDriver:
        # Always store on the base class: setting via type(self) would create
        # one driver per tool subclass instead of one shared browser session.
        if BrowserToolBase._driver is None:
            BrowserToolBase._driver = BrowserDriver(
                allowed_hosts=context.allowed_hosts,
            )
        return BrowserToolBase._driver

    @classmethod
    def reset_driver(cls) -> None:
        if BrowserToolBase._driver is not None:
            BrowserToolBase._driver.stop()
            BrowserToolBase._driver = None

    def _scoped(self, context: ToolContext, url: str) -> str:
        host = context.base_url_host() or ""
        self.validate_scope(context.allowed_hosts, host)
        target = url or context.target_base_url or ""
        if not target:
            raise ToolError("No target URL configured in tool context.")
        return target


class OpenPageTool(BrowserToolBase):
    """Open a page in the sandboxed browser (PRD: open_page)."""

    name = "open_page"
    description = "Open a page in the isolated browser and report status/title."
    Params = UrlParams

    def execute(self, validated: UrlParams, context: ToolContext) -> dict[str, Any]:
        target = self._scoped(context, validated.url)
        return self._driver_for(context).open_page(target)


class GetAccessibilitySnapshotTool(BrowserToolBase):
    """Capture the page's accessibility tree (PRD: get_accessibility_snapshot)."""

    name = "get_accessibility_snapshot"
    description = "Capture the current page accessibility snapshot."
    Params = UrlParams

    def execute(self, validated: UrlParams, context: ToolContext) -> dict[str, Any]:
        if validated.url:
            self._scoped(context, validated.url)
            self._driver_for(context).open_page(validated.url)
        return self._driver_for(context).get_accessibility_snapshot()


class ClickTool(BrowserToolBase):
    """Click a selector on the current page (PRD: click)."""

    name = "click"
    description = "Click a CSS selector on the current page."

    class Params(BaseModel):
        selector: str = Field(description="CSS selector to click")

    def execute(self, validated: ClickTool.Params, context: ToolContext) -> dict[str, Any]:
        return self._driver_for(context).click(validated.selector)


class FillTool(BrowserToolBase):
    """Fill a form field (PRD: fill)."""

    name = "fill"
    description = "Fill a form field identified by CSS selector."

    class Params(BaseModel):
        selector: str = Field(description="CSS selector of the input")
        value: str = Field(description="Value to type into the field")

    def execute(self, validated: FillTool.Params, context: ToolContext) -> dict[str, Any]:
        # Credentials discovered during the assessment must not be replayed
        # through the browser without explicit assessment policy.
        return self._driver_for(context).fill(validated.selector, validated.value)


class SubmitTool(BrowserToolBase):
    """Submit a form (PRD: submit)."""

    name = "submit"
    description = "Submit a form and capture the resulting navigation."

    class Params(BaseModel):
        form_selector: str = Field(default="form", description="CSS selector of the form")

    def execute(self, validated: SubmitTool.Params, context: ToolContext) -> dict[str, Any]:
        return self._driver_for(context).submit(validated.form_selector)


class ScreenshotTool(BrowserToolBase):
    """Capture a screenshot (PRD: capture_screenshot). Metadata only."""

    name = "capture_screenshot"
    description = "Capture a PNG screenshot of the current page (metadata only)."

    class Params(BaseModel):
        include_data: bool = Field(
            default=False,
            description="Include raw PNG bytes (default False: metadata only).",
        )

    def execute(self, validated: ScreenshotTool.Params, context: ToolContext) -> dict[str, Any]:
        shot = self._driver_for(context).capture_screenshot()
        if not validated.include_data:
            shot.pop("data", None)
        return shot


class CollectConsoleLogsTool(BrowserToolBase):
    """Collect browser console messages (PRD: collect_console_logs)."""

    name = "collect_console_logs"
    description = "Collect console messages emitted since the last call."

    def execute(self, validated: Any, context: ToolContext) -> dict[str, Any]:
        return self._driver_for(context).collect_console_logs()
