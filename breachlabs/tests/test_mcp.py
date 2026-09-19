"""Tests for MCP tool layer: registry, validation, scope enforcement."""

import os
import pytest

from breachlabs.mcp.tool import (
    ScopeViolationError,
    ToolContext,
    ToolError,
)
from breachlabs.mcp.tools import build_default_registry
from breachlabs.mcp.tools.scanners import (
    InspectRepositoryTool,
    ListRoutesTool,
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

    def test_inspect_repository_custom_repo_path_and_communication(self, tmp_path):
        app_file = tmp_path / "app.py"
        app_file.write_text("from flask import Flask\napp = Flask(__name__)\n")
        (tmp_path / "requirements.txt").write_text("flask>=2.0.0\n")

        tool = InspectRepositoryTool()
        # Agent calls tool with explicit repo_path argument
        result = tool.run({"repo_path": str(tmp_path)}, ToolContext(assessment_id="A"))
        assert "requirements.txt" in result["dependency_manifests"]
        assert result["framework"] == "Flask (Python)"
        assert "app.py" in result["entry_points"]
        assert "communication_summary" in result
        assert "Recommended Next Actions" in result["communication_summary"]
        assert "app.py" in result["directory_tree"]

    def test_communicate_tool(self):
        from breachlabs.mcp.tools.scanners import CommunicateTool

        tool = CommunicateTool()
        res_sql = tool.run({"message": "How do I fix SQL injection in my routes?"}, ToolContext(assessment_id="A"))
        assert res_sql["status"] == "success"
        assert "parameterized" in res_sql["response"].lower() or "placeholders" in res_sql["response"].lower()
        assert "run_static_scan" in res_sql["recommended_tools"]

        res_general = tool.run({"message": "Hello, what tools can I use?"}, ToolContext(assessment_id="A"))
        assert res_general["status"] == "success"
        assert "BreachLabs Security Advisor" in res_general["response"]

    def test_list_routes_multi_language(self, tmp_path):
        # Python Flask
        (tmp_path / "routes.py").write_text("@app.route('/api/py', methods=['POST'])\ndef handler(): pass\n")
        # JavaScript Express
        (tmp_path / "server.js").write_text("app.get('/api/node', (req, res) => res.json({}));\n")
        # Go Gin
        (tmp_path / "main.go").write_text('r.GET("/api/go", handleGo)\n')

        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        result = ListRoutesTool().run({}, context)
        paths = [r["path"] for r in result["routes"]]
        assert "/api/py" in paths
        assert "/api/node" in paths
        assert "/api/go" in paths

    def test_sast_scan_multi_language(self, tmp_path):
        # Node prototype pollution and DOM XSS
        (tmp_path / "vuln.js").write_text("Object.assign(target, req.body);\nel.innerHTML = userParam;\n")
        # Go SQL injection
        (tmp_path / "db.go").write_text('rows, err := db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))\n')
        # Java command injection
        (tmp_path / "App.java").write_text("Runtime.getRuntime().exec(userCmd);\n")
        # PHP shell exec
        (tmp_path / "index.php").write_text("<?php system($cmd); ?>\n")

        context = ToolContext(assessment_id="A", repo_path=str(tmp_path))
        result = SastScanTool().run({}, context)
        signal_ids = [s["rule_id"] for s in result["signals"]]
        assert "BL-SAST-008" in signal_ids  # Prototype pollution
        assert "BL-SAST-009" in signal_ids  # DOM XSS
        assert "BL-SAST-010" in signal_ids  # Go SQLi
        assert "BL-SAST-011" in signal_ids  # Java command execution
        assert "BL-SAST-012" in signal_ids  # PHP command execution

    def test_diagnose_error_tool(self):
        from breachlabs.mcp.tools.scanners import DiagnoseErrorTool

        tool = DiagnoseErrorTool()
        # Python traceback
        py_err = "Traceback (most recent call last):\n  File 'app.py', line 12, in <module>\nModuleNotFoundError: No module named 'jwt'\n"
        py_res = tool.run({"error_log": py_err}, ToolContext(assessment_id="A"))
        assert py_res["error_type"] == "ModuleNotFoundError"
        assert py_res["detected_language"] == "Python"
        assert "pip install jwt" in py_res["suggested_fix"]
        assert py_res["affected_line"] == 12

        # Port conflict
        port_err = "OSError: [Errno 10048] error while attempting to bind on address ('127.0.0.1', 5000): address already in use"
        port_res = tool.run({"error_log": port_err}, ToolContext(assessment_id="A"))
        assert port_res["error_type"] == "PortConflictError"
        assert "occupying the port" in port_res["diagnostic_summary"]

    def test_generate_remediation_tool(self):
        from breachlabs.mcp.tools.scanners import GenerateRemediationTool

        tool = GenerateRemediationTool()
        res_py = tool.run({
            "vulnerability_type": "sqli",
            "language": "python",
            "file_path": "database.py",
            "vulnerable_snippet": "cursor.execute(f'SELECT * FROM users WHERE u={user}')",
            "line_number": 45,
        }, ToolContext(assessment_id="A"))
        assert "cursor.execute(" in res_py["remediation_patch"]
        assert "--- a/database.py" in res_py["git_diff"]

        res_js = tool.run({
            "vulnerability_type": "sqli",
            "language": "javascript",
            "file_path": "db.js",
            "vulnerable_snippet": "db.query(`SELECT * FROM users WHERE u=${user}`)",
            "line_number": 20,
        }, ToolContext(assessment_id="A"))
        assert "$1" in res_js["remediation_patch"]

    def test_generate_security_test_tool(self):
        from breachlabs.mcp.tools.scanners import GenerateSecurityTestTool

        tool = GenerateSecurityTestTool()
        res_py = tool.run({
            "vulnerability_type": "sqli",
            "target_route": "/api/users",
            "language": "python",
            "parameter_name": "id",
        }, ToolContext(assessment_id="A"))
        assert "def test_security_id_sql_injection" in res_py["test_code"]
        assert "/api/users" in res_py["test_code"]

        res_js = tool.run({
            "vulnerability_type": "xss",
            "target_route": "/search",
            "language": "javascript",
            "parameter_name": "q",
        }, ToolContext(assessment_id="A"))
        assert "test(" in res_js["test_code"]
        assert "/search" in res_js["test_code"]


class TestSkillCheck:
    def test_skill_check_detects_local_skill(self, tmp_path):
        from breachlabs.mcp.skill_check import check_skill_installation, format_installation_prompt

        skill_dir = tmp_path / "skills" / "breachlabs"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("---\nname: breachlabs\n---\n")

        status = check_skill_installation(repo_path=str(tmp_path))
        assert status["skill_installed"] is True
        assert status["mcp_running"] is True
        assert status["status"] == "ready"

    def test_format_installation_prompt(self):
        from breachlabs.mcp.skill_check import format_installation_prompt

        both_msg = format_installation_prompt(skill_missing=True, mcp_missing=True)
        assert "npx -y skills add notaayushsrivastava/BreachLabs" in both_msg
        assert "python run_breachlabs.py" in both_msg

        skill_msg = format_installation_prompt(skill_missing=True, mcp_missing=False)
        assert "npx -y skills add notaayushsrivastava/BreachLabs" in skill_msg

        mcp_msg = format_installation_prompt(skill_missing=False, mcp_missing=True)
        assert "http://127.0.0.1:8000/mcp" in mcp_msg

        ready_msg = format_installation_prompt(skill_missing=False, mcp_missing=False)
        assert "Both BreachLabs MCP Server and Agent Skill are installed" in ready_msg
