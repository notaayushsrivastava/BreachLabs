"""Tests for MCP tool layer: registry, validation, scope enforcement."""

import pytest

from breachlabs.mcp.tool import (
    ScopeViolationError,
    ToolContext,
    ToolError,
)
from breachlabs.mcp.tools import build_default_registry
from breachlabs.mcp.tools.scanners import (
    InspectRepositoryTool,
    ReadSourceFileTool,
    SastScanTool,
    SecretScanTool,
)


@pytest.fixture()
def registry():
    return build_default_registry()


class TestRegistry:
    def test_manifests_expose_name_and_schema(self, registry):
        names = registry.names()
        assert "run_static_scan" in names
        assert "run_dast" in names
        for manifest in registry.manifests():
            assert manifest["name"] and "risk_level" in manifest

    def test_unknown_tool_raises(self, registry):
        with pytest.raises(ToolError):
            registry.get("nope")

    def test_duplicate_registration_raises(self, registry):
        with pytest.raises(ToolError):
            registry.register(InspectRepositoryTool())


class TestParamValidation:
    def test_invalid_params_rejected(self, registry):
        context = ToolContext(assessment_id="A", repo_path=None)
        with pytest.raises(ToolError, match="Invalid arguments"):
            registry.run("read_source_file", {"path": 123, "max_bytes": "bad"}, context)


class TestScopeEnforcement:
    def test_out_of_scope_host_rejected(self):
        tool = ReadSourceFileTool()
        with pytest.raises(ScopeViolationError):
            tool.validate_scope(["example.com"], "evil.example.net")

    def test_localhost_always_allowed(self):
        tool = ReadSourceFileTool()
        tool.validate_scope([], "127.0.0.1")
        tool.validate_scope(["example.com"], "localhost")


class TestScanners:
    def test_sast_finds_eval(self, tmp_path):
        (tmp_path / "app.py").write_text("x = eval(user_input)\n")
        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        result = SastScanTool().run({}, context)
        titles = [s["title"] for s in result["signals"]]
        assert "eval() usage" in titles

    def test_secrets_are_redacted_in_output(self, tmp_path):
        (tmp_path / "config.py").write_text('API_KEY = "abcdefghij1234567890"\n')
        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        result = SecretScanTool().run({}, context)
        assert result["signal_count"] >= 1
        for signal in result["signals"]:
            assert "abcdefghij1234567890" not in signal["snippet"]

    def test_path_escape_rejected(self, tmp_path):
        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        with pytest.raises(ToolError, match="escapes"):
            ReadSourceFileTool().run({"path": "../../etc/passwd"}, context)

    def test_inspect_repository_lists_manifests(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask\n")
        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        result = InspectRepositoryTool().run({}, context)
        assert "requirements.txt" in result["dependency_manifests"]
