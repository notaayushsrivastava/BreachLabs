"""Tests for the Streamable HTTP & SSE MCP server (/mcp)."""

import json
import pytest
import httpx
from fastapi.testclient import TestClient

from breachlabs.api.server import app


@pytest.fixture()
def client():
    return TestClient(app)


class TestMCPServer:
    def test_mcp_sse_endpoint_connects(self, client):
        res = client.get("/mcp/sse?max_events=1")
        assert res.status_code == 200
        assert "text/event-stream" in res.headers["content-type"]
        assert "event: endpoint" in res.text
        assert "/mcp/messages?session_id=" in res.text

    def test_mcp_get_root_sse_connects(self, client):
        res = client.get("/mcp?max_events=1")
        assert res.status_code == 200
        assert "text/event-stream" in res.headers["content-type"]
        assert "event: endpoint" in res.text

    def test_mcp_initialize(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] == 1
        assert data["result"]["protocolVersion"] == "2024-11-05"
        assert data["result"]["serverInfo"]["name"] == "breachlabs-mcp"
        assert "tools" in data["result"]["capabilities"]

    def test_mcp_notifications_initialized(self, client):
        payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code in (200, 204)

    def test_mcp_ping(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "ping",
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == 42
        assert data["result"] == {}

    def test_mcp_tools_list(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/list",
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == 100
        tools = data["result"]["tools"]
        assert len(tools) >= 5
        tool_names = [t["name"] for t in tools]
        assert "inspect_repository" in tool_names
        assert "read_source_file" in tool_names
        assert "list_routes" in tool_names
        assert "run_static_scan" in tool_names
        assert "scan_secrets" in tool_names

        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool
            assert tool["inputSchema"]["type"] == "object"

    def test_mcp_tools_call_inspect_repository(self, client, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')")
        payload = {
            "jsonrpc": "2.0",
            "id": 200,
            "method": "tools/call",
            "params": {
                "name": "inspect_repository",
                "arguments": {"path": ""},
                "context": {"repo_path": str(tmp_path)},
            },
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == 200
        assert data["result"]["isError"] is False
        content = data["result"]["content"]
        assert len(content) == 1
        assert "app.py" in content[0]["text"]

    def test_mcp_tools_call_unknown_tool(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 300,
            "method": "tools/call",
            "params": {
                "name": "non_existent_tool_123",
                "arguments": {},
            },
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["result"]["isError"] is True
        assert "not found" in data["result"]["content"][0]["text"].lower()

    def test_mcp_invalid_method(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 400,
            "method": "unknown_rpc_method",
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["error"]["code"] == -32601

    def test_mcp_invalid_json(self, client):
        res = client.post(
            "/mcp",
            content="invalid json {",
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["error"]["code"] == -32700

    def test_mcp_batch_request(self, client):
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        res = client.post("/mcp", json=batch)
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["id"] == 1
        assert data[1]["id"] == 2

    def test_mcp_prompts_list_and_get(self, client):
        res = client.post("/mcp", json={"jsonrpc": "2.0", "id": 500, "method": "prompts/list"})
        assert res.status_code == 200
        data = res.json()
        prompts = data["result"]["prompts"]
        prompt_names = [p["name"] for p in prompts]
        assert "verify_installation" in prompt_names
        assert "breachlabs_security_assessment" in prompt_names

        # Test prompts/get verify_installation
        res_get = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 501,
                "method": "prompts/get",
                "params": {"name": "verify_installation"},
            },
        )
        assert res_get.status_code == 200
        data_get = res_get.json()
        assert "messages" in data_get["result"]
        msg_text = data_get["result"]["messages"][0]["content"]["text"]
        assert "BreachLabs" in msg_text

    def test_mcp_tools_call_verify_installation(self, client, tmp_path):
        payload = {
            "jsonrpc": "2.0",
            "id": 600,
            "method": "tools/call",
            "params": {
                "name": "verify_installation",
                "arguments": {},
                "context": {"repo_path": str(tmp_path)},
            },
        }
        res = client.post("/mcp", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["result"]["isError"] is False
        content_text = data["result"]["content"][0]["text"]
        parsed = json.loads(content_text)
        assert "mcp_running" in parsed
        assert "skill_installed" in parsed
