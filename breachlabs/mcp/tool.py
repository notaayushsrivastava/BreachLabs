"""MCP tool layer base classes.

Every capability exposed to the security agent is a narrow, allowlisted
MCPTool (PRD.md section 5.4 — least privilege, no arbitrary execute()).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ValidationError

from breachlabs.core.types import ToolRiskLevel


class ToolError(Exception):
    """Raised when a tool execution fails validation or execution."""


class ScopeViolationError(ToolError):
    """Raised when a tool attempts to operate outside declared scope."""


class MCPTool(ABC):
    """Base class for all MCP tools.

    Subclasses declare a pydantic `Params` model; arguments are validated
    before execution and rejected otherwise (tool argument validation is a
    PRD testing requirement, section 24).
    """

    name: str = "mcp_tool"
    description: str = ""
    risk_level: ToolRiskLevel = ToolRiskLevel.READ_ONLY

    #: pydantic model describing accepted parameters
    Params: type[BaseModel] | None = None

    def validate_params(self, params: dict[str, Any]) -> Any:
        if self.Params is None:
            return params
        try:
            return self.Params(**params)
        except ValidationError as exc:
            raise ToolError(f"Invalid arguments for tool '{self.name}': {exc}") from exc

    def validate_scope(self, allowed_hosts: list[str], target_host: str) -> None:
        """Reject any target outside the assessment's declared scope."""
        # Localhost/sandbox targets are always permitted; anything else must
        # appear in the allowlist.
        if target_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return
        if target_host not in allowed_hosts:
            raise ScopeViolationError(
                f"Target '{target_host}' is outside the declared assessment scope."
            )

    @abstractmethod
    def execute(self, validated: BaseModel, context: ToolContext) -> dict[str, Any]:
        """Execute the tool and return a JSON-serializable result."""

    def run(self, params: dict[str, Any], context: ToolContext) -> dict[str, Any]:
        """Public entrypoint: validate, scope-check, then execute."""
        validated = self.validate_params(params)
        return self.execute(validated, context)

    def manifest(self) -> dict[str, Any]:
        """Tool manifest for the registry / agent tool-selection prompt."""
        schema = None
        if self.Params is not None:
            schema = self.Params.model_json_schema()
        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "params_schema": schema,
        }


class ToolContext(BaseModel):
    """Execution context passed to every tool invocation."""

    assessment_id: str
    environment_id: str | None = None
    target_base_url: str | None = None
    repo_path: str | None = None
    allowed_hosts: list[str] = []
    active_checks_enabled: bool = True
    metadata: dict[str, Any] = {}

    def base_url_host(self) -> str | None:
        if not self.target_base_url:
            return None
        from urllib.parse import urlparse

        return urlparse(self.target_base_url).hostname


class ToolRegistry:
    """Registry of MCP tools available to the security agent."""

    def __init__(self) -> None:
        self._tools: dict[str, MCPTool] = {}

    def register(self, tool: MCPTool) -> None:
        if tool.name in self._tools:
            raise ToolError(f"Tool '{tool.name}' is already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> MCPTool:
        try:
            return self._tools[name]
        except KeyError:
            raise ToolError(f"Unknown tool: '{name}'.") from None

    def has(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> list[str]:
        return sorted(self._tools)

    def manifests(self) -> list[dict[str, Any]]:
        return [tool.manifest() for tool in self._tools.values()]

    def run(self, name: str, params: dict[str, Any], context: ToolContext) -> dict[str, Any]:
        tool = self.get(name)
        return tool.run(params, context)
