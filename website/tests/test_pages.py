
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pytest
from app import create_app

ROUTES = ["/", "/how-it-works", "/architecture", "/security", "/capabilities", "/demo", "/about"]


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.mark.parametrize("path", ROUTES)
def test_routes_and_shell(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert b"<nav" in r.data
    assert b'class="site-footer"' in r.data


def test_static_assets(client):
    for p in ["/static/css/styles.css", "/static/images/logo.webp"]:
        assert client.get(p).status_code == 200


def test_404(client):
    assert client.get("/no-such-page").status_code == 404


def test_500_handler():
    app = create_app()
    assert 500 in app.error_handler_spec.get(None, {})


def test_unique_titles(client):
    titles = []
    for p in ROUTES:
        html = client.get(p).data.decode()
        assert "<title>" in html and 'name="description"' in html
        titles.append(html.split("<title>")[1].split("</title>")[0])
    assert len(set(titles)) == len(ROUTES)


def test_home_hero(client):
    html = client.get("/").data.decode()
    assert "d8j0ntlcm91z4.cloudfront.net" in html
    assert "Intelligence" in html and "Designed To Evolve" in html
    assert "An autonomous security engineer for the software you just built." in html
    assert "<h1" in html and "*" in html


def test_demo_illustrative(client):
    html = client.get("/demo").data.decode()
    assert "DEMO-0001" in html and "illustrative" in html.lower()
    assert "<input" not in html and "<form" not in html
