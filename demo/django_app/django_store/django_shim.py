"""Lightweight fallback server and Django compatibility shims for django_store.

Allows the deliberately vulnerable Django demo app to execute out of the box
with pure Python standard library when full Django is not installed.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable
from wsgiref.simple_server import make_server


class HttpResponse:
    def __init__(self, content: str = "", content_type: str = "text/html; charset=utf-8", status: int = 200) -> None:
        self.content = content.encode("utf-8") if isinstance(content, str) else content
        self.content_type = content_type
        self.status = status
        self.headers: dict[str, str] = {"Content-Type": content_type}

    def __iter__(self):
        yield self.content


class JsonResponse(HttpResponse):
    def __init__(self, data: Any, status: int = 200) -> None:
        content = json.dumps(data)
        super().__init__(content=content, content_type="application/json", status=status)


class SafeString(str):
    pass


def mark_safe(s: str) -> SafeString:
    return SafeString(s)


def csrf_exempt(view_func: Callable) -> Callable:
    return view_func


class HttpRequest:
    def __init__(self, environ: dict[str, Any]) -> None:
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET")
        self.path = environ.get("PATH_INFO", "/")
        
        # Parse query string
        from urllib.parse import parse_qs
        qs = environ.get("QUERY_STRING", "")
        self.raw_get = parse_qs(qs, keep_blank_values=True)
        self.GET = {k: v[0] if len(v) == 1 else v for k, v in self.raw_get.items()}
        
        # Parse POST form body
        self.POST: dict[str, Any] = {}
        if self.method == "POST":
            try:
                content_len = int(environ.get("CONTENT_LENGTH", 0) or 0)
                if content_len > 0:
                    body = environ["wsgi.input"].read(content_len).decode("utf-8", errors="replace")
                    post_qs = parse_qs(body, keep_blank_values=True)
                    self.POST = {k: v[0] if len(v) == 1 else v for k, v in post_qs.items()}
            except Exception:
                pass


def run_standalone_django_server(host: str, port: int) -> None:
    """Run pure-Python standard library WSGI server for django_store."""
    from django_store import views

    def wsgi_app(environ: dict[str, Any], start_response: Callable) -> list[bytes]:
        req = HttpRequest(environ)
        path = req.path.rstrip("/")
        if not path:
            path = "/"

        resp: HttpResponse
        try:
            if path == "/" or path == "":
                resp = views.index_view(req)
            elif path == "/search":
                resp = views.search_view(req)
            elif path.startswith("/api/orders"):
                # Extract order_id
                parts = path.strip("/").split("/")
                order_id = int(parts[-1]) if len(parts) >= 3 and parts[-1].isdigit() else 1
                resp = views.order_detail_view(req, order_id)
            elif path == "/api/comments":
                resp = views.comment_submit_view(req)
            elif path == "/api/ping":
                resp = views.diagnostic_ping_view(req)
            elif path == "/api/calculator":
                resp = views.discount_calculator_view(req)
            elif path == "/api/reset-token":
                resp = views.generate_session_token_view(req)
            else:
                resp = HttpResponse("<h1>404 Not Found</h1>", status=404)
        except Exception as exc:
            resp = HttpResponse(f"<h1>500 Server Error</h1><pre>{exc}</pre>", status=500)

        status_line = f"{resp.status} OK" if resp.status == 200 else f"{resp.status} Error"
        headers = [(k, v) for k, v in resp.headers.items()]
        start_response(status_line, headers)
        return [resp.content]

    print(f"[*] Starting Standalone Django Store Server on http://{host}:{port}/ ...", flush=True)
    server = make_server(host, port, wsgi_app)
    server.serve_forever()
