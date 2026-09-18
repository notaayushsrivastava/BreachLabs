from breachlabs.mcp.tool import ToolRegistry  # noqa: F401
from breachlabs.mcp.tools.scanners import (  # noqa: F401
    DastTool,
    HealthCheckTool,
    InspectRepositoryTool,
    ListRoutesTool,
    ReadSourceFileTool,
    SastScanTool,
    SecretScanTool,
)


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for tool in (
        InspectRepositoryTool(),
        ReadSourceFileTool(),
        ListRoutesTool(),
        SastScanTool(),
        SecretScanTool(),
        HealthCheckTool(),
        DastTool(),
    ):
        registry.register(tool)
    # Browser tools join the same registry only when Playwright is installed
    # (PRD.md section 20: lazy browser startup). Never fail imports without it.
    try:
        from breachlabs.browser import browser_available, build_browser_registry

        if browser_available():
            for tool in build_browser_registry()._tools.values():
                registry.register(tool)
    except (ImportError, Exception):  # noqa: BLE001, S110 - optional extra
        pass
    return registry
