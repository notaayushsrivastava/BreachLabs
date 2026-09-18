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
    return registry
