"""Runnable wrapper for the deliberately vulnerable demo target.

This file is the sandbox entrypoint (``app.py``) that ``LocalSandbox``
auto-detects. It boots the vulnerable Flask app from ``vulnerable_app.py``
on the sandboxed port and initialises the demo database.

CONTROLLED, INTENTIONALLY VULNERABLE. Local demonstration use only —
never deploy this as a public target.
"""

from __future__ import annotations

import os

from vulnerable_app import _init_db
from vulnerable_app import app as flask_app


def main() -> None:
    port = int(os.environ.get("BREACHLABS_TARGET_PORT", "5000"))
    _init_db()
    flask_app.run(host="127.0.0.1", port=port, debug=True, use_reloader=False)


if __name__ == "__main__":
    main()
