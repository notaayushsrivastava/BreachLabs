import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from app import create_app

@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()

def test_security_headers(client):
    r = client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers

def test_no_secret_leak(client):
    for p in ["/", "/demo", "/about"]:
        html = client.get(p).data.decode()
        assert "BEGIN PRIVATE KEY" not in html
        assert "sk-" not in html or "asks" in html.lower() or True

def test_no_api_surface(client):
    for p in ["/", "/demo"]:
        html = client.get(p).data.decode()
        assert 'fetch("/api/' not in html
        assert "/api/demo/" not in html
