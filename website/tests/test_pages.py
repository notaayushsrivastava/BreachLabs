import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from app import create_app

@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()

def test_home_hero(client):
    r = client.get("/")
    html = r.data.decode()
    assert "d8j0ntlcm91z4.cloudfront.net" in html
    assert "Intelligence" in html and "Designed To Evolve" in html
    assert "An autonomous security engineer for the software you just built." in html
    assert "<h1" in html

def test_unique_titles(client):
    titles = set()
    for p in ["/", "/how-it-works", "/architecture", "/security", "/capabilities", "/demo", "/about"]:
        html = client.get(p).data.decode()
        assert "<title>" in html and 'name="description"' in html
        titles.add(html.split("<title>")[1].split("</title>")[0])
    assert len(titles) == 7

def test_demo_mock(client):
    html = client.get("/demo").data.decode()
    assert "DEMO-0001" in html and "illustrative" in html.lower()
