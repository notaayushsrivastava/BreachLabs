import os
import sys
import pytest
from breachlabs.web.app import create_app

@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()

@pytest.mark.parametrize("path", ["/", "/how-it-works", "/architecture",
    "/security", "/capabilities", "/demo", "/about", "/install"])
def test_routes_200(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert b"<nav" in r.data
    assert b"site-footer" in r.data

def test_404(client):
    r = client.get("/no-such-page")
    assert r.status_code == 404

def test_500_handler_registered():
    app = create_app()
    assert 500 in app.error_handler_spec[None]
