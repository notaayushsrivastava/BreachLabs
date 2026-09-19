"""Integration tests for the unified FastAPI application.

Tests:
1. Core API at /api (health, tools, assessments)
2. Streamable HTTP MCP at /mcp
3. Website pages mounted at /
"""

import os
import pytest
from fastapi.testclient import TestClient

from breachlabs.api.server import app


@pytest.fixture()
def client():
    return TestClient(app)


class TestUnifiedApp:
    def test_health_endpoint(self, client):
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["endpoints"]["mcp"] == "/mcp"
        assert data["endpoints"]["api"] == "/api/assessments"

    def test_api_tools_list(self, client):
        res = client.get("/api/tools")
        assert res.status_code == 200
        data = res.json()
        assert "tools" in data
        assert len(data["tools"]) >= 5

    def test_api_create_assessment_and_get(self, client, tmp_path):
        payload = {
            "repository": str(tmp_path),
            "commit": "test-commit-001",
            "mode": "deep",
            "scope": {},
            "port": 5000,
        }
        res = client.post("/api/assessments", json=payload)
        assert res.status_code == 201
        data = res.json()
        assessment_id = data["id"]
        assert assessment_id

        # Get assessment
        get_res = client.get(f"/api/assessments/{assessment_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == assessment_id

        # Get events
        events_res = client.get(f"/api/assessments/{assessment_id}/events")
        assert events_res.status_code == 200
        assert isinstance(events_res.json(), list)

        # Get findings
        findings_res = client.get(f"/api/assessments/{assessment_id}/findings")
        assert findings_res.status_code == 200
        assert isinstance(findings_res.json(), list)

        # Get report
        report_res = client.get(f"/api/assessments/{assessment_id}/report")
        assert report_res.status_code == 200

        # Cancel assessment
        cancel_res = client.post(f"/api/assessments/{assessment_id}/cancel")
        assert cancel_res.status_code == 200

    def test_website_root_page(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert "BreachLabs" in res.text

    def test_website_install_page(self, client):
        res = client.get("/install")
        assert res.status_code == 200
        assert "MCP Server &amp; Agent Skills" in res.text or "MCP Server" in res.text
        assert "/mcp" in res.text

    def test_website_subpages(self, client):
        pages = [
            "/how-it-works",
            "/architecture",
            "/security",
            "/capabilities",
            "/demo",
            "/about",
        ]
        for page in pages:
            res = client.get(page)
            assert res.status_code == 200
            assert "BreachLabs" in res.text

    def test_demo_attack_endpoint(self, client):
        res = client.post("/api/demo/run")
        assert res.status_code == 201
        data = res.json()
        assert data["id"]
        assert data["repository"] == "demo/vulnerable_app"

        # Check streaming endpoint exists
        stream_res = client.get(f"/api/assessments/{data['id']}/stream")
        assert stream_res.status_code == 200
        assert "text/event-stream" in stream_res.headers["content-type"]

    def test_launcher_banner_generation(self, capsys):
        import run
        run.print_banner("127.0.0.1", 8000, demo=True, demo_port=5000)
        captured = capsys.readouterr()
        assert "Autonomous AI Application-Security Engineer" in captured.out
        assert "http://localhost:8000/install" in captured.out
        assert "http://localhost:8000/mcp" in captured.out
        assert "http://localhost:5000/" in captured.out
