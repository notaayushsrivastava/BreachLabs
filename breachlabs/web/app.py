"""BreachLabs Web Application & UI Routing.

Serves all public user interfaces:
- /             - Hero & platform overview
- /how-it-works - Security loop workflow
- /architecture - Technical architecture & components
- /security     - Security model & boundary definitions
- /capabilities - Feature matrix & scanning coverage
- /demo         - Deterministic interactive demo
- /install      - Streamable HTTP MCP & Agent Skill Hub
- /about        - About & roadmap
- /robots.txt   - Search crawler policy
"""

from __future__ import annotations

import os
from typing import TypedDict
from flask import Flask, Response, render_template, send_from_directory


class PageMeta(TypedDict):
    title: str
    description: str
    canonical_path: str
    og_image: str


class DemoFinding(TypedDict):
    id: str
    title: str
    severity: str
    confidence: str
    status: str
    surface: str


class DemoAssessment(TypedDict):
    assessment_id: str
    status: str
    target: str
    duration_ms: int
    routes_discovered: int
    findings: list[DemoFinding]


PAGE_META: dict[str, PageMeta] = {
    "home": {
        "title": "BreachLabs — Build. Break. Verify. Fix.",
        "description": "BreachLabs is an autonomous AI application-security engineer that inspects, tests, investigates, verifies, explains, and retests software.",
        "canonical_path": "/",
        "og_image": "/static/images/logo.webp",
    },
    "how-it-works": {
        "title": "How It Works — BreachLabs Security Loop",
        "description": "Follow the BreachLabs loop: build, discover, test, investigate, verify, fix, retest — with evidence at every step.",
        "canonical_path": "/how-it-works",
        "og_image": "/static/images/logo.webp",
    },
    "architecture": {
        "title": "Architecture — BreachLabs Orchestrator, Agent & MCP Tools",
        "description": "How the BreachLabs orchestrator, AI agent, MCP tools, sandbox, and evidence pipeline fit together.",
        "canonical_path": "/architecture",
        "og_image": "/static/images/logo.webp",
    },
    "security": {
        "title": "Security Model — BreachLabs Boundaries",
        "description": "Authorized scope, isolation, tool control, untrusted content handling, and limitations.",
        "canonical_path": "/security",
        "og_image": "/static/images/logo.webp",
    },
    "capabilities": {
        "title": "Capabilities — BreachLabs Assessment Coverage",
        "description": "Repository intake, SAST, dependency analysis, secret detection, DAST, browser investigation, verification, retesting.",
        "canonical_path": "/capabilities",
        "og_image": "/static/images/logo.webp",
    },
    "demo": {
        "title": "Demo — BreachLabs Deterministic Assessment",
        "description": "A safe, deterministic, clearly-labeled illustrative demo. No live scanning.",
        "canonical_path": "/demo",
        "og_image": "/static/images/logo.webp",
    },
    "about": {
        "title": "About — BreachLabs Hackathon Context & Roadmap",
        "description": "What BreachLabs is, why it exists, current MVP boundaries, and roadmap.",
        "canonical_path": "/about",
        "og_image": "/static/images/logo.webp",
    },
    "install": {
        "title": "Install — BreachLabs MCP Server & Agent Skills",
        "description": "Install BreachLabs Streamable HTTP MCP tools and autonomous security engineering skills in Antigravity, Claude, Cursor, Windsurf, Cline, and Universal agents.",
        "canonical_path": "/install",
        "og_image": "/static/images/logo.webp",
    },
}


def get_page_meta(key: str) -> PageMeta:
    return PAGE_META.get(key, PAGE_META["home"])


def get_demo_assessment() -> DemoAssessment:
    return {
        "assessment_id": "DEMO-0001",
        "status": "completed",
        "target": "breachlabs-demo",
        "duration_ms": 4820,
        "routes_discovered": 12,
        "findings": [
            {
                "id": "BL-DEMO-001",
                "title": "SQL injection in search parameter",
                "severity": "high",
                "confidence": "verified",
                "status": "verified",
                "surface": "GET /search?q=",
            },
            {
                "id": "BL-DEMO-002",
                "title": "Reflected XSS in comment field",
                "severity": "high",
                "confidence": "verified",
                "status": "verified",
                "surface": "POST /comments",
            },
            {
                "id": "BL-DEMO-003",
                "title": "Missing security response headers",
                "severity": "medium",
                "confidence": "verified",
                "status": "verified",
                "surface": "GET /",
            },
        ],
    }


def create_app() -> Flask:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-only-breachlabs-key")
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    @app.after_request
    def add_security_headers(resp: Response) -> Response:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://db.onlinewebfonts.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
            "https://db.onlinewebfonts.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://db.onlinewebfonts.com https://cdnjs.cloudflare.com data:; "
            "img-src 'self' data: blob:; "
            "media-src 'self' https://d8j0ntlcm91z4.cloudfront.net; "
            "connect-src 'self'; frame-ancestors 'none'"
        )
        return resp

    @app.route("/")
    def index():
        return render_template("index.html", meta=get_page_meta("home"))

    @app.route("/how-it-works")
    def how_it_works():
        return render_template("how-it-works.html", meta=get_page_meta("how-it-works"))

    @app.route("/architecture")
    def architecture():
        return render_template("architecture.html", meta=get_page_meta("architecture"))

    @app.route("/security")
    def security():
        return render_template("security.html", meta=get_page_meta("security"))

    @app.route("/capabilities")
    def capabilities():
        return render_template("capabilities.html", meta=get_page_meta("capabilities"))

    @app.route("/demo")
    def demo():
        return render_template(
            "demo.html", meta=get_page_meta("demo"), assessment=get_demo_assessment()
        )

    @app.route("/about")
    def about():
        return render_template("about.html", meta=get_page_meta("about"))

    @app.route("/install")
    def install():
        return render_template("install.html", meta=get_page_meta("install"))

    @app.route("/robots.txt")
    def robots():
        return send_from_directory(app.static_folder, "robots.txt", mimetype="text/plain")

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("404.html", meta=get_page_meta("home")), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("500.html", meta=get_page_meta("home")), 500

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)
