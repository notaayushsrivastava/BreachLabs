#!/usr/bin/env python3
"""BreachLabs Application Launcher.

Runs the unified BreachLabs platform serving:
  - Interactive Web Application at http://127.0.0.1:8000/
  - Core Security Assessment API at http://127.0.0.1:8000/api
  - Streamable HTTP & SSE MCP Server at http://127.0.0.1:8000/mcp

Usage:
  python run.py                   # Run default server on 127.0.0.1:8000
  python run.py --port 8080       # Custom port
  python run.py --host 0.0.0.0    # Bind all network interfaces
  python run.py --reload          # Auto-reload on code edits (dev mode)
  python run.py --demo            # Also launch the local vulnerable demo app on port 5000
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import uvicorn


def run_demo_server(port: int = 5000) -> None:
    """Run the vulnerable demo target in a background daemon thread."""
    try:
        from breachlabs.demo.vulnerable_app import app as demo_app, _init_db

        _init_db()
        print(f"[*] Vulnerable Demo Target active at http://127.0.0.1:{port}/")
        demo_app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except Exception as exc:
        print(f"[!] Could not start demo target: {exc}")


def print_banner(host: str, port: int, demo: bool = False, demo_port: int = 5000) -> None:
    display_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    banner = f"""
======================================================================
  ____                      _     _          _     
 | __ ) _ __ ___  __ _  ___| |__ | |    __ _| |__  ___ 
 |  _ \\| '__/ _ \\/ _` |/ __| '_ \\| |   / _` | '_ \\/ __|
 | |_) | | |  __/ (_| | (__| | | | |__| (_| | |_) \\__ \\
 |____/|_|  \\___|\\__,_|\\___|_| |_|_____\\__,_|_.__/|___/
  Autonomous AI Application-Security Engineer & MCP Server
======================================================================

  [+] Web Portal:       http://{display_host}:{port}/
  [+] Installation Hub: http://{display_host}:{port}/install
  [+] Core REST API:    http://{display_host}:{port}/api/assessments
  [+] Health Check:     http://{display_host}:{port}/api/health
  [+] Streamable MCP:   http://{display_host}:{port}/mcp
  [+] MCP SSE Stream:   http://{display_host}:{port}/mcp/sse
"""
    if demo:
        banner += f"  [+] Demo Target:      http://{display_host}:{demo_port}/\n"
    banner += "======================================================================\n"
    print(banner)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BreachLabs Unified Platform (Web + Core API + Streamable MCP Server)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.environ.get("HOST", "127.0.0.1"),
        help="Host interface to bind to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8000")),
        help="Port to listen on",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("WORKERS", "1")),
        help="Number of worker processes",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Also start the intentional vulnerable demo target on port 5000",
    )
    parser.add_argument(
        "--demo-port",
        type=int,
        default=int(os.environ.get("DEMO_PORT", "5000")),
        help="Port for the demo target if --demo is enabled",
    )

    args = parser.parse_args()

    # Ensure repository root is on sys.path
    repo_root = os.path.dirname(os.path.abspath(__file__))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    if args.demo:
        demo_thread = threading.Thread(
            target=run_demo_server, args=(args.demo_port,), daemon=True
        )
        demo_thread.start()

    print_banner(args.host, args.port, demo=args.demo, demo_port=args.demo_port)

    app_target = "breachlabs.api.server:app"

    uvicorn.run(
        app_target,
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers if not args.reload else 1,
        log_level="info",
    )


if __name__ == "__main__":
    main()
