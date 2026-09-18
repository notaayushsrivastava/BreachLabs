"""Deliberately vulnerable demo application (PRD.md section 15).

CONTROLLED, INTENTIONALLY VULNERABLE. Local demonstration use only —
never deploy this as a public target.

Deterministic weaknesses for the BreachLabs MVP demo:
  1. SQL injection via string-formatted query on /search (DAST-verifiable).
  2. Reflected XSS on /search (DAST-verifiable).
  3. Hardcoded admin credentials + API key (secret-scan detectable).
  4. Debug mode enabled (SAST detectable).
  5. Broken object-level authorization on /api/profile/<user_id>
     (correlatable: SAST route + code review; browser-verifiable).
  6. Weak MD5 password hashing (SAST detectable).
  7. Missing security headers (DAST-verifiable).
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile

from flask import Flask, jsonify, request

app = Flask(__name__)

# --- Intentional weakness: hardcoded credentials (demo-only) --------------
ADMIN_PASSWORD = "super-admin-password-123"
API_KEY = "breachlabs-demo-api-key-0123456789"

# File-backed DB so state persists across the process's requests.
_DB_FILE = os.path.join(tempfile.gettempdir(), "breachlabs-demo.db")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    if os.path.exists(_DB_FILE):
        os.remove(_DB_FILE)
    conn = _db()
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        INSERT INTO users (username, password, role) VALUES
            ('admin', 'admin123', 'admin'),
            ('alice', 'alice123', 'user'),
            ('bob', 'bob123', 'user');
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
        INSERT INTO notes (owner, body) VALUES ('alice', 'first note'), ('bob', 'second note');
        """
    )
    conn.commit()
    conn.close()


@app.get("/")
def index():
    return "<h1>Vulnerable Demo App</h1><p>Local BreachLabs demo target.</p>"


@app.get("/search")
def search():
    # --- Intentional weakness: SQL injection + reflected XSS --------------
    q = request.args.get("q", "")
    conn = _db()
    # String formatting straight into SQL (weakness 1) — deliberate.
    query = f"SELECT * FROM notes WHERE body LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
        results = [dict(r) for r in rows]
    except sqlite3.Error as exc:
        # database error text is echoed back → error-based SQLi evidence
        conn.close()
        return f"<p>Error: {exc}</p>", 500
    conn.close()
    # q is echoed unescaped (weakness 2)
    return f"<h1>Search results for: {q}</h1><pre>{results}</pre>"


@app.get("/api/profile/<user_id>")
def profile(user_id: int):
    # --- Intentional weakness: no authentication / IDOR (weakness 5) ------
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row["id"], "username": row["username"], "role": row["role"]})


@app.get("/login")
def login_page():
    return "<form method='POST' action='/login'><input name='username'><input name='password' type='password'><button>Log in</button></form>"


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # --- Intentional weakness: MD5 hashing (weakness 6) -------------------
    hashed = hashlib.md5(password.encode()).hexdigest()  # deliberate: weak hash
    conn = _db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed)
    ).fetchone()
    conn.close()
    if row is None:
        return "Invalid credentials", 401
    return f"Welcome {row['username']} ({row['role']})"


if __name__ == "__main__":
    # --- Intentional weakness: debug mode (weakness 4) --------------------
    _init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
