/**
 * BreachLabs Demo Code Inspector
 * Interactive viewer for demo targets (Flask, Django, Node.js)
 * Features syntax highlighting, line numbers, vulnerability markers,
 * and automated remediation diffs.
 */

const DEMO_PROJECTS = {
  flask: {
    id: "flask",
    title: "Flask (Python) Vulnerable Microservice",
    badge: "PYTHON 3.14 / FLASK",
    description: "Lightweight Python web application demonstrating OWASP Top 10 vulnerabilities including direct SQL query formatting, unescaped HTML reflection, IDOR / broken object-level authorization, and weak MD5 hashing.",
    files: [
      {
        path: "vulnerable_app.py",
        lang: "python",
        badge: "6 Vulns",
        badgeType: "bad",
        content: `"""Deliberately vulnerable demo application.
CONTROLLED, INTENTIONALLY VULNERABLE. Local demonstration use only.
"""

from __future__ import annotations
import hashlib
import os
import sqlite3
import tempfile
from flask import Flask, jsonify, request

app = Flask(__name__)

# --- Intentional weakness: hardcoded credentials ---
ADMIN_PASSWORD = "super-admin-password-123"
API_KEY = "breachlabs-demo-api-key-0123456789"

_DB_FILE = os.path.join(tempfile.gettempdir(), "breachlabs-demo.db")

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db() -> None:
    if os.path.exists(_DB_FILE):
        os.remove(_DB_FILE)
    conn = _db()
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
    """)
    
    # --- Intentional weakness: MD5 password hashing ---
    def _weak_hash(raw: str) -> str:
        return hashlib.md5(raw.encode()).hexdigest()  # deliberate: weak hash

    for username, password, role in (
        ("admin", "admin123", "admin"),
        ("alice", "alice123", "user"),
        ("bob", "bob123", "user"),
    ):
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, _weak_hash(password), role),
        )
    conn.commit()
    conn.close()

@app.get("/")
def index():
    return "<h1>Vulnerable Demo App</h1><p>Local BreachLabs demo target.</p>"

@app.get("/search")
def search():
    # --- Intentional weakness: SQL injection + reflected XSS ---
    q = request.args.get("q", "")
    conn = _db()
    # String formatting straight into SQL
    query = f"SELECT * FROM notes WHERE body LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
        results = [dict(r) for r in rows]
    except sqlite3.Error as exc:
        conn.close()
        return f"<p>Error: {exc}</p>", 500
    conn.close()
    # q is echoed unescaped (Reflected XSS)
    return f"<h1>Search results for: {q}</h1><pre>{results}</pre>"

@app.get("/api/profile/<user_id>")
def profile(user_id: int):
    # --- Intentional weakness: no authentication / IDOR ---
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row["id"], "username": row["username"], "role": row["role"]})

@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Weak MD5 hash validation
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = _db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed)
    ).fetchone()
    conn.close()
    if row is None:
        return "Invalid credentials", 401
    return f"Welcome {row['username']} ({row['role']})"

if __name__ == "__main__":
    _init_db()
    # Debug mode enabled in production code
    app.run(host="127.0.0.1", port=5000, debug=True)`,
        vulns: [
          {
            id: "BL-SAST-007",
            line: 14,
            title: "Hardcoded Admin Credentials & API Secrets",
            severity: "critical",
            cwe: "CWE-798",
            description: "High-entropy secrets and plaintext administrator passwords committed directly in source code.",
            before: 'ADMIN_PASSWORD = "super-admin-password-123"\nAPI_KEY = "breachlabs-demo-api-key-0123456789"',
            after: 'ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")\nAPI_KEY = os.environ.get("BREACHLABS_API_KEY")'
          },
          {
            id: "BL-SAST-001",
            line: 54,
            title: "SQL Injection via String Interpolation",
            severity: "critical",
            cwe: "CWE-89",
            description: "Unsanitized user search parameter formatted directly into SQL query string allowing UNION and stacked query manipulation.",
            before: 'query = f"SELECT * FROM notes WHERE body LIKE \'%{q}%\'"\nrows = conn.execute(query).fetchall()',
            after: 'query = "SELECT * FROM notes WHERE body LIKE ?"\nrows = conn.execute(query, (f"%{q}%",)).fetchall()'
          },
          {
            id: "BL-SAST-009",
            line: 62,
            title: "Reflected Cross-Site Scripting (XSS)",
            severity: "high",
            cwe: "CWE-79",
            description: "Unescaped search query returned directly in HTML markup, allowing execution of arbitrary client JavaScript in visitor browsers.",
            before: 'return f"<h1>Search results for: {q}</h1><pre>{results}</pre>"',
            after: 'from markupsafe import escape\nreturn f"<h1>Search results for: {escape(q)}</h1><pre>{escape(str(results))}</pre>"'
          },
          {
            id: "BL-SAST-005",
            line: 65,
            title: "Broken Object Level Authorization (IDOR)",
            severity: "high",
            cwe: "CWE-639",
            description: "Profile record fetched by sequential numeric identifier without validating requesting user permissions or session token.",
            before: '@app.get("/api/profile/<user_id>")\ndef profile(user_id: int):\n    conn = _db()\n    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()',
            after: '@app.get("/api/profile/<user_id>")\n@require_auth\ndef profile(user_id: int):\n    if current_user.id != user_id and not current_user.is_admin:\n        return jsonify({"error": "forbidden"}), 403\n    conn = _db()\n    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()'
          },
          {
            id: "BL-SAST-006",
            line: 73,
            title: "Weak Cryptographic Hash (MD5)",
            severity: "medium",
            cwe: "CWE-328",
            description: "MD5 hashing is cryptographically broken and vulnerable to rapid collision attacks and rainbow table precomputation.",
            before: 'hashed = hashlib.md5(password.encode()).hexdigest()',
            after: 'import bcrypt\n# Use salted bcrypt password verification\nis_valid = bcrypt.checkpw(password.encode(), user_record["password_hash"])'
          },
          {
            id: "BL-SAST-004",
            line: 87,
            title: "Debug Mode Enabled in Server Initialization",
            severity: "medium",
            cwe: "CWE-489",
            description: "Running Flask in debug mode opens interactive Werkzeug console pin exploitations and verbose traceback leakage.",
            before: 'app.run(host="127.0.0.1", port=5000, debug=True)',
            after: 'app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)'
          }
        ]
      },
      {
        path: "requirements.txt",
        lang: "text",
        badge: "Clean",
        badgeType: "ok",
        content: `flask>=3.0.0
pytest>=8.0.0
requests>=2.31.0
markupsafe>=2.1.5
bcrypt>=4.1.2`,
        vulns: []
      }
    ]
  },

  django: {
    id: "django",
    title: "Django (Python) Store Application",
    badge: "PYTHON 3.14 / DJANGO",
    description: "Multi-file Django backend with SQL cursor injection, unsafe mark_safe rendering, unauthenticated order querying, shell command injection, and intentional syntax bugs for error diagnosis.",
    files: [
      {
        path: "django_store/views.py",
        lang: "python",
        badge: "5 Vulns",
        badgeType: "bad",
        content: `"""Views for django_store vulnerable application.
INTENTIONALLY VULNERABLE DEMO TARGET FOR BREACHLABS.
"""

import hashlib
import json
import os
import subprocess
from django.http import HttpResponse, JsonResponse
from django.utils.safestring import mark_safe

AWS_SECRET_KEY = "AKIA1234567890ABCDEF"
INTERNAL_API_KEY = "django-store-internal-api-key-secret-9999"

def search_view(request):
    """Product search view."""
    q = request.GET.get('q', '')
    
    # --- Vulnerability 1: SQL Injection via Raw SQL Query ---
    from django.db import connection
    cursor = connection.cursor()
    query = f"SELECT id, name, price FROM django_store_product WHERE name LIKE '%{q}%'"
    
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        products = [{"id": r[0], "name": r[1], "price": float(r[2])} for r in rows]
    except Exception as exc:
        return HttpResponse(f"<p>Database Error: {exc}</p>", status=500)

    # --- Vulnerability 2: Reflected XSS via mark_safe ---
    html_output = mark_safe(f"<h1>Search Results for: {q}</h1><pre>{json.dumps(products)}</pre>")
    return HttpResponse(html_output)

def order_detail_view(request, order_id):
    """Order detail API endpoint (BOLA / IDOR)."""
    from django_store.models import Order
    order = Order.objects.filter(id=order_id).first()
    if not order:
        return JsonResponse({"error": "Order not found"}, status=404)
    return JsonResponse({"id": order.id, "total": float(order.total_amount)})

def diagnostic_ping_view(request):
    """Diagnostic system utility (Command Injection)."""
    host = request.GET.get('host', '127.0.0.1')
    # Vulnerability: Subprocess shell execution with user input
    cmd = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, timeout=3)
        return HttpResponse(f"<pre>{output}</pre>")
    except Exception as err:
        return HttpResponse(f"<pre>Error: {err}</pre>", status=500)`,
        vulns: [
          {
            id: "BL-SAST-007",
            line: 11,
            title: "Hardcoded AWS & Internal API Keys",
            severity: "critical",
            cwe: "CWE-798",
            description: "High privilege AWS and internal orchestration tokens stored in plaintext in view controller.",
            before: 'AWS_SECRET_KEY = "AKIA1234567890ABCDEF"\nINTERNAL_API_KEY = "django-store-internal-api-key-secret-9999"',
            after: 'AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")\nINTERNAL_API_KEY = os.environ.get("DJANGO_INTERNAL_API_KEY", "")'
          },
          {
            id: "BL-SAST-001",
            line: 20,
            title: "Raw SQL Cursor Injection",
            severity: "critical",
            cwe: "CWE-89",
            description: "Django database cursor executes f-string without parameterized binding tuple.",
            before: 'query = f"SELECT id, name, price FROM django_store_product WHERE name LIKE \'%{q}%\'"\ncursor.execute(query)',
            after: 'query = "SELECT id, name, price FROM django_store_product WHERE name LIKE %s"\ncursor.execute(query, [f"%{q}%"])'
          },
          {
            id: "BL-SAST-009",
            line: 30,
            title: "XSS via mark_safe Bypass",
            severity: "high",
            cwe: "CWE-79",
            description: "Django automatic template escaping bypassed via explicit mark_safe invocation on raw query string.",
            before: 'html_output = mark_safe(f"<h1>Search Results for: {q}</h1><pre>{json.dumps(products)}</pre>")',
            after: 'from django.utils.html import escape\nhtml_output = f"<h1>Search Results for: {escape(q)}</h1><pre>{escape(json.dumps(products))}</pre>"'
          },
          {
            id: "BL-SAST-003",
            line: 45,
            title: "Remote Command Injection via subprocess",
            severity: "critical",
            cwe: "CWE-78",
            description: "subprocess.check_output called with shell=True on untrusted host argument allowing command chaining.",
            before: 'cmd = f"ping -c 1 {host}"\noutput = subprocess.check_output(cmd, shell=True, text=True, timeout=3)',
            after: 'import ipaddress\ntry:\n    ipaddress.ip_address(host)\nexcept ValueError:\n    return HttpResponse("Invalid IP", status=400)\noutput = subprocess.check_output(["ping", "-n" if os.name == "nt" else "-c", "1", host], shell=False, text=True, timeout=3)'
          }
        ]
      },
      {
        path: "django_store/broken_helper.py",
        lang: "python",
        badge: "Syntax Error",
        badgeType: "warn",
        content: `"""Helper utilities for django_store with intentional syntax/diagnostic glitches."""

# --- Intentional Syntax / Runtime Flaw for Error Diagnosis Testing ---
def calculate_vat_tax(amount)
    # Missing colon syntax error on function signature
    rate = 0.20
    return amount * rate
`,
        vulns: [
          {
            id: "BL-SYNTAX-001",
            line: 4,
            title: "SyntaxError: Expected ':' after function definition header",
            severity: "syntax",
            cwe: "SYNTAX-ERR",
            description: "BreachLabs Language Server diagnosed missing colon on Python def statement preventing application compilation.",
            before: "def calculate_vat_tax(amount)",
            after: "def calculate_vat_tax(amount):"
          }
        ]
      },
      {
        path: "django_store/settings.py",
        lang: "python",
        badge: "2 Flaws",
        badgeType: "bad",
        content: `"""Django settings for demo django_store project."""

SECRET_KEY = 'django-insecure-hardcoded-secret-key-for-breachlabs-demo'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django_store',
]

SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False`,
        vulns: [
          {
            id: "BL-SAST-004",
            line: 4,
            title: "Production DEBUG and Wildcard ALLOWED_HOSTS",
            severity: "high",
            cwe: "CWE-489",
            description: "DEBUG=True leaks stack traces and environment variables, while ALLOWED_HOSTS=['*'] permits Host header poisoning.",
            before: "DEBUG = True\nALLOWED_HOSTS = ['*']",
            after: "DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'\nALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',')"
          },
          {
            id: "BL-SAST-010",
            line: 14,
            title: "Insecure Session & CSRF Cookie Flags",
            severity: "medium",
            cwe: "CWE-614",
            description: "SESSION_COOKIE_HTTPONLY and SECURE flags disabled, allowing JavaScript cookie exfiltration via XSS.",
            before: "SESSION_COOKIE_SECURE = False\nSESSION_COOKIE_HTTPONLY = False",
            after: "SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Lax'"
          }
        ]
      },
      {
        path: "django_store/models.py",
        lang: "python",
        badge: "Clean",
        badgeType: "ok",
        content: `"""Models for django_store."""
from django.db import models

class Product(models.Model):
    name = models.CharField(max_length=200)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField(blank=True)

class Order(models.Model):
    user_id = models.IntegerField()
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)`,
        vulns: []
      }
    ]
  },

  nodejs: {
    id: "nodejs",
    title: "Node.js (Express) Microservice API",
    badge: "NODE.JS 20 / EXPRESS",
    description: "Modern JavaScript backend featuring prototype pollution, arbitrary code evaluation via Node vm module, shell command injection, hardcoded JWT secrets, and syntax errors.",
    files: [
      {
        path: "routes/api.js",
        lang: "javascript",
        badge: "4 Vulns",
        badgeType: "bad",
        content: `/**
 * API Routes for node-vulnerable-api.
 * Contains intentional subtle and obvious security vulnerabilities.
 */

const express = require('express');
const { exec } = require('child_process');
const vm = require('vm');
const router = express.Router();

// Simulated in-memory database store
const itemsDb = [
  { id: 1, name: "Wireless Headphones", category: "electronics", price: 99.99 },
  { id: 2, name: "Mechanical Keyboard", category: "electronics", price: 149.50 },
];

// --- Vulnerability 1: SQL / Query Injection via Template String ---
router.get('/items', (req, res) => {
  const category = req.query.category || '';
  const query = \`SELECT * FROM items WHERE category = '\${category}'\`;
  
  if (category.includes("' OR '1'='1")) {
    return res.json({ query: query, results: itemsDb });
  }
  const filtered = itemsDb.filter(i => i.category.toLowerCase() === category.toLowerCase());
  res.json({ query: query, results: filtered });
});

// --- Vulnerability 2: Reflected XSS via Direct HTML output ---
router.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  // User input concatenated directly into HTML response
  res.send(\`<h1>Hello, \${name}!</h1><p>Welcome to our platform portal.</p>\`);
});

// --- Vulnerability 3: Prototype Pollution via Object.assign ---
router.post('/preferences', (req, res) => {
  const userConfig = {};
  // Unvalidated body merged onto object allows __proto__ tampering
  Object.assign(userConfig, req.body);
  res.json({ status: "updated", config: userConfig });
});

// --- Vulnerability 4: Command Injection via child_process.exec ---
router.get('/lookup', (req, res) => {
  const domain = req.query.domain || 'localhost';
  exec(\`nslookup \${domain}\`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ domain: domain, result: stdout });
  });
});

module.exports = router;`,
        vulns: [
          {
            id: "BL-SAST-001",
            line: 18,
            title: "Unescaped Template String Query Interpolation",
            severity: "critical",
            cwe: "CWE-89",
            description: "Dynamic SQL/NoSQL query string assembled via raw ES6 template literals allowing tautology injection.",
            before: "const query = `SELECT * FROM items WHERE category = '${category}'`;",
            after: "const query = 'SELECT * FROM items WHERE category = ?';\n// Execute with parameterized bindings: db.query(query, [category])"
          },
          {
            id: "BL-SAST-009",
            line: 29,
            title: "Reflected Cross-Site Scripting (XSS)",
            severity: "high",
            cwe: "CWE-79",
            description: "Direct response string sending unescaped client input inside HTML h1 tags.",
            before: "res.send(`<h1>Hello, ${name}!</h1><p>Welcome to our platform portal.</p>`);",
            after: "const sanitizeHtml = require('sanitize-html');\nres.send(`<h1>Hello, ${sanitizeHtml(name)}!</h1><p>Welcome to our platform portal.</p>`);"
          },
          {
            id: "BL-SAST-008",
            line: 36,
            title: "Prototype Pollution via Unsanitized Object Merge",
            severity: "critical",
            cwe: "CWE-1321",
            description: "Object.assign with untrusted JSON payload allows property injection on Object.prototype, corrupting global server state.",
            before: "const userConfig = {};\nObject.assign(userConfig, req.body);",
            after: "const allowedKeys = ['theme', 'notifications', 'locale'];\nconst userConfig = {};\nfor (const key of allowedKeys) {\n  if (req.body && req.body[key] !== undefined) userConfig[key] = req.body[key];\n}"
          },
          {
            id: "BL-SAST-003",
            line: 43,
            title: "OS Command Injection via child_process.exec",
            severity: "critical",
            cwe: "CWE-78",
            description: "Passing user parameters to child_process.exec spawns a subshell where semicolons and pipe characters trigger arbitrary command execution.",
            before: "exec(`nslookup ${domain}`, (err, stdout, stderr) => { ... });",
            after: "const { execFile } = require('child_process');\n// Use execFile without shell expansion\nexecFile('nslookup', [domain], (err, stdout, stderr) => { ... });"
          }
        ]
      },
      {
        path: "helpers/broken_syntax.js",
        lang: "javascript",
        badge: "Syntax Error",
        badgeType: "warn",
        content: `/**
 * Helper with intentional syntax / compiler error for BreachLabs error diagnosis.
 */

// Intentional syntax glitch: missing closing parenthesis in parameter list
function parseUserPayload(payload {
  return JSON.parse(payload);
}

module.exports = { parseUserPayload };
`,
        vulns: [
          {
            id: "BL-SYNTAX-002",
            line: 6,
            title: "SyntaxError: Unexpected token '{', expected ')'",
            severity: "syntax",
            cwe: "SYNTAX-ERR",
            description: "JavaScript compiler parsing error on function argument declaration line.",
            before: "function parseUserPayload(payload {",
            after: "function parseUserPayload(payload) {"
          }
        ]
      },
      {
        path: "routes/auth.js",
        lang: "javascript",
        badge: "2 Vulns",
        badgeType: "bad",
        content: `const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const router = express.Router();

const JWT_SECRET = "super-secret-jwt-key-999-breachlabs";

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Weak SHA-1 password hashing
  const hash = crypto.createHash('sha1').update(password).digest('hex');
  
  if (username === 'admin' && hash === 'd033e22ae348aeb5660fc2140aec35850c4da997') {
    const token = jwt.sign({ username: 'admin', role: 'admin' }, JWT_SECRET);
    return res.json({ token });
  }
  res.status(401).json({ error: "Invalid credentials" });
});

module.exports = router;`,
        vulns: [
          {
            id: "BL-SAST-007",
            line: 6,
            title: "Hardcoded JWT Signing Secret Key",
            severity: "critical",
            cwe: "CWE-798",
            description: "Static JWT secret key allows attackers to forge tokens with administrative claims.",
            before: 'const JWT_SECRET = "super-secret-jwt-key-999-breachlabs";',
            after: 'const JWT_SECRET = process.env.JWT_SECRET_KEY;\nif (!JWT_SECRET) throw new Error("JWT_SECRET_KEY environment variable required");'
          },
          {
            id: "BL-SAST-006",
            line: 11,
            title: "Weak SHA-1 Password Hash",
            severity: "medium",
            cwe: "CWE-328",
            description: "SHA-1 lacks adequate collision resistance for credential storage.",
            before: "const hash = crypto.createHash('sha1').update(password).digest('hex');",
            after: "const argon2 = require('argon2');\nconst isValid = await argon2.verify(user.passwordHash, password);"
          }
        ]
      },
      {
        path: "config.js",
        lang: "javascript",
        badge: "Secret Flaw",
        badgeType: "bad",
        content: `module.exports = {
  db: {
    host: "db.production.internal",
    user: "db_admin",
    password: "ProductionAdminSecretPassword99!",
    database: "production_store"
  },
  cors: {
    origin: "*"
  }
};`,
        vulns: [
          {
            id: "BL-SAST-007",
            line: 5,
            title: "Production Database Password in Version Control",
            severity: "critical",
            cwe: "CWE-798",
            description: "Plaintext database connection secret in committed configuration file.",
            before: 'password: "ProductionAdminSecretPassword99!"',
            after: 'password: process.env.DATABASE_PASSWORD'
          }
        ]
      }
    ]
  }
};

class DemoCodeInspector {
  constructor() {
    this.currentFrameworkKey = "flask";
    this.currentFileIndex = 0;
    this.showHighlights = true;
    this.showDiffMode = false;
    this.activeVulnIndex = 0;

    this.initElements();
    this.attachEventListeners();
    this.render();
  }

  initElements() {
    this.frameworkBtns = document.querySelectorAll("[data-app-framework]");
    this.frameworkEnvBadge = document.getElementById("framework-env-badge");
    this.frameworkTitle = document.getElementById("framework-title");
    this.frameworkDesc = document.getElementById("framework-desc");
    
    this.fileTreeContainer = document.getElementById("file-tree-container");
    this.fileVulnCount = document.getElementById("file-vuln-count");
    this.fileVulnList = document.getElementById("file-vuln-list");
    
    this.currentFilename = document.getElementById("current-filename");
    this.currentFileMeta = document.getElementById("current-file-meta");
    this.codeBodyContainer = document.getElementById("code-body-container");
    this.viewDiffToggleBtn = document.getElementById("view-diff-toggle-btn");
    
    this.toggleHighlightsBtn = document.getElementById("toggle-highlights-btn");
    this.copyCodeBtn = document.getElementById("copy-code-btn");
    
    this.remediationBox = document.getElementById("remediation-box");
    this.remediationSeverity = document.getElementById("remediation-severity");
    this.remediationTitle = document.getElementById("remediation-title");
    this.remediationCwe = document.getElementById("remediation-cwe");
    this.remediationDesc = document.getElementById("remediation-desc");
    this.remediationBeforeCode = document.getElementById("remediation-before-code");
    this.remediationAfterCode = document.getElementById("remediation-after-code");
  }

  attachEventListeners() {
    this.frameworkBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        const fw = btn.getAttribute("data-app-framework");
        if (fw && DEMO_PROJECTS[fw]) {
          this.currentFrameworkKey = fw;
          this.currentFileIndex = 0;
          this.activeVulnIndex = 0;
          this.frameworkBtns.forEach((b) => {
            const active = b === btn;
            b.classList.toggle("is-active", active);
            b.setAttribute("aria-pressed", active ? "true" : "false");
          });
          this.render();
        }
      });
    });

    if (this.toggleHighlightsBtn) {
      this.toggleHighlightsBtn.addEventListener("click", () => {
        this.showHighlights = !this.showHighlights;
        this.toggleHighlightsBtn.classList.toggle("is-active", this.showHighlights);
        this.renderCode();
      });
    }

    if (this.copyCodeBtn) {
      this.copyCodeBtn.addEventListener("click", () => {
        const project = DEMO_PROJECTS[this.currentFrameworkKey];
        const file = project.files[this.currentFileIndex];
        if (file) {
          navigator.clipboard.writeText(file.content).then(() => {
            const orig = this.copyCodeBtn.innerHTML;
            this.copyCodeBtn.innerHTML = '<i class="fa-solid fa-check" style="margin-right:5px;color:#7fd1a8"></i> Copied!';
            setTimeout(() => {
              this.copyCodeBtn.innerHTML = orig;
            }, 2000);
          });
        }
      });
    }

    if (this.viewDiffToggleBtn) {
      this.viewDiffToggleBtn.addEventListener("click", () => {
        this.showDiffMode = !this.showDiffMode;
        this.viewDiffToggleBtn.classList.toggle("is-active", this.showDiffMode);
        this.viewDiffToggleBtn.innerHTML = this.showDiffMode
          ? '<i class="fa-solid fa-code" style="margin-right:4px"></i> Show Source Code'
          : '<i class="fa-solid fa-code-compare" style="margin-right:4px"></i> Show Auto-Patch Diff';
        this.renderCode();
      });
    }
  }

  render() {
    const project = DEMO_PROJECTS[this.currentFrameworkKey];
    if (!project) return;

    if (this.frameworkEnvBadge) this.frameworkEnvBadge.textContent = project.badge;
    if (this.frameworkTitle) this.frameworkTitle.textContent = project.title;
    if (this.frameworkDesc) this.frameworkDesc.textContent = project.description;

    this.renderFileTree();
    this.renderActiveFile();
  }

  renderFileTree() {
    const project = DEMO_PROJECTS[this.currentFrameworkKey];
    if (!this.fileTreeContainer) return;

    this.fileTreeContainer.innerHTML = "";
    project.files.forEach((file, idx) => {
      const itemBtn = document.createElement("button");
      itemBtn.type = "button";
      itemBtn.className = `file-tree-item ${idx === this.currentFileIndex ? "is-active" : ""}`;
      
      const icon = file.path.endsWith(".py")
        ? '<i class="fa-brands fa-python" style="color:#7fd1a8;margin-right:6px"></i>'
        : file.path.endsWith(".js")
        ? '<i class="fa-brands fa-js" style="color:#fde047;margin-right:6px"></i>'
        : '<i class="fa-regular fa-file-code" style="color:#93c5fd;margin-right:6px"></i>';
        
      const badgeStyle = file.badgeType === "bad" 
        ? "background:rgba(244,63,94,0.15);color:#fda4af;border:1px solid rgba(244,63,94,0.3)" 
        : file.badgeType === "warn"
        ? "background:rgba(234,179,8,0.15);color:#fde047;border:1px solid rgba(234,179,8,0.3)"
        : "background:rgba(16,185,129,0.15);color:#86efac;border:1px solid rgba(16,185,129,0.3)";

      itemBtn.innerHTML = `
        <span style="display:flex;align-items:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${icon}
          <span>${file.path}</span>
        </span>
        <span class="badge" style="${badgeStyle}">${file.badge}</span>
      `;

      itemBtn.addEventListener("click", () => {
        this.currentFileIndex = idx;
        this.activeVulnIndex = 0;
        this.renderFileTree();
        this.renderActiveFile();
      });

      this.fileTreeContainer.appendChild(itemBtn);
    });
  }

  renderActiveFile() {
    const project = DEMO_PROJECTS[this.currentFrameworkKey];
    const file = project.files[this.currentFileIndex];
    if (!file) return;

    const lines = file.content.split("\n");
    if (this.currentFilename) this.currentFilename.textContent = file.path;
    if (this.currentFileMeta) {
      this.currentFileMeta.textContent = `${lines.length} lines · ${file.lang.toUpperCase()} · ${file.vulns.length} findings`;
    }

    this.renderVulnList(file);
    this.renderCode();
    this.renderRemediationDetails(file);
  }

  renderVulnList(file) {
    if (!this.fileVulnCount || !this.fileVulnList) return;

    this.fileVulnCount.textContent = `${file.vulns.length} ${file.vulns.length === 1 ? "Finding" : "Findings"}`;
    this.fileVulnList.innerHTML = "";

    if (file.vulns.length === 0) {
      this.fileVulnList.innerHTML = `
        <div style="padding:12px;color:var(--fg-faint);font-size:12px;font-style:italic;text-align:center">
          No security flaws detected in this configuration file.
        </div>
      `;
      return;
    }

    file.vulns.forEach((vuln, vIdx) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `vuln-item-btn ${vIdx === this.activeVulnIndex ? "is-active" : ""}`;
      
      const isSyntax = vuln.severity === "syntax";
      const sevBadge = isSyntax
        ? '<span class="status status--investigating" style="font-size:10px;padding:2px 6px"><i aria-hidden="true"></i>SYNTAX</span>'
        : vuln.severity === "critical"
        ? '<span class="status status--critical" style="font-size:10px;padding:2px 6px"><i aria-hidden="true"></i>CRITICAL</span>'
        : '<span class="status status--unconfirmed" style="font-size:10px;padding:2px 6px"><i aria-hidden="true"></i>HIGH</span>';

      btn.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;width:100%">
          <span style="font-weight:600;font-size:11px;color:var(--fg-bright)">${vuln.id}</span>
          ${sevBadge}
        </div>
        <div style="font-size:12px;color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${vuln.title}</div>
        <div style="font-size:10px;color:var(--fg-faint);font-family:var(--font-mono)">Line ${vuln.line} · ${vuln.cwe}</div>
      `;

      btn.addEventListener("click", () => {
        this.activeVulnIndex = vIdx;
        this.renderVulnList(file);
        this.renderRemediationDetails(file);
        this.scrollToLine(vuln.line);
      });

      this.fileVulnList.appendChild(btn);
    });
  }

  renderCode() {
    const project = DEMO_PROJECTS[this.currentFrameworkKey];
    const file = project.files[this.currentFileIndex];
    if (!this.codeBodyContainer || !file) return;

    this.codeBodyContainer.innerHTML = "";

    if (this.showDiffMode && file.vulns.length > 0) {
      this.renderDiffView(file);
      return;
    }

    const lines = file.content.split("\n");
    const vulnMap = new Map();
    file.vulns.forEach((v) => vulnMap.set(v.line, v));

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      const vuln = vulnMap.get(lineNum);
      const isVuln = this.showHighlights && !!vuln;

      const lineDiv = document.createElement("div");
      lineDiv.className = `code-line ${isVuln ? (vuln.severity === "syntax" ? "hl-syntax" : "hl-vuln") : ""}`;
      lineDiv.id = `code-line-${lineNum}`;

      const numSpan = document.createElement("span");
      numSpan.className = "line-num";
      numSpan.textContent = String(lineNum).padStart(2, "0");

      const contentSpan = document.createElement("span");
      contentSpan.className = "line-content";
      contentSpan.innerHTML = this.highlightSyntax(lineText, file.lang);

      if (isVuln) {
        const tag = document.createElement("span");
        tag.className = vuln.severity === "syntax" ? "syntax-tag" : "vuln-tag";
        tag.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${vuln.id}: ${vuln.title.split(":")[0]}`;
        contentSpan.appendChild(tag);

        lineDiv.style.cursor = "pointer";
        lineDiv.addEventListener("click", () => {
          const vIdx = file.vulns.findIndex((v) => v.line === lineNum);
          if (vIdx !== -1) {
            this.activeVulnIndex = vIdx;
            this.renderVulnList(file);
            this.renderRemediationDetails(file);
          }
        });
      }

      lineDiv.appendChild(numSpan);
      lineDiv.appendChild(contentSpan);
      this.codeBodyContainer.appendChild(lineDiv);
    });
  }

  renderDiffView(file) {
    const activeVuln = file.vulns[this.activeVulnIndex] || file.vulns[0];
    if (!activeVuln) return;

    const diffContainer = document.createElement("div");
    diffContainer.style.padding = "0 16px";

    const header = document.createElement("div");
    header.style.marginBottom = "14px";
    header.style.padding = "8px 12px";
    header.style.background = "rgba(127,209,168,0.06)";
    header.style.border = "1px solid rgba(127,209,168,0.2)";
    header.style.borderRadius = "4px";
    header.innerHTML = `
      <span style="font-weight:600;color:var(--ok);font-size:12px">BREACHLABS UNIFIED REMEDIATION PATCH:</span>
      <span style="color:var(--fg-soft);font-size:12px"> ${file.path} (${activeVuln.id} ${activeVuln.title})</span>
    `;
    diffContainer.appendChild(header);

    const beforeLines = activeVuln.before.split("\n");
    beforeLines.forEach((l, i) => {
      const lineDiv = document.createElement("div");
      lineDiv.className = "code-line del";
      lineDiv.innerHTML = `<span class="line-num">-${i + 1}</span><span class="line-content">${this.escapeHtml(l)}</span>`;
      diffContainer.appendChild(lineDiv);
    });

    const afterLines = activeVuln.after.split("\n");
    afterLines.forEach((l, i) => {
      const lineDiv = document.createElement("div");
      lineDiv.className = "code-line add";
      lineDiv.innerHTML = `<span class="line-num">+${i + 1}</span><span class="line-content">${this.escapeHtml(l)}</span>`;
      diffContainer.appendChild(lineDiv);
    });

    this.codeBodyContainer.appendChild(diffContainer);
  }

  renderRemediationDetails(file) {
    if (!this.remediationBox) return;

    const vuln = file.vulns[this.activeVulnIndex];
    if (!vuln) {
      this.remediationBox.style.display = "none";
      return;
    }

    this.remediationBox.style.display = "block";
    if (this.remediationSeverity) {
      if (vuln.severity === "syntax") {
        this.remediationSeverity.className = "status status--investigating";
        this.remediationSeverity.innerHTML = '<i aria-hidden="true"></i>SYNTAX DIAGNOSTIC';
      } else if (vuln.severity === "critical") {
        this.remediationSeverity.className = "status status--critical";
        this.remediationSeverity.innerHTML = '<i aria-hidden="true"></i>CRITICAL SEVERITY';
      } else {
        this.remediationSeverity.className = "status status--unconfirmed";
        this.remediationSeverity.innerHTML = '<i aria-hidden="true"></i>HIGH SEVERITY';
      }
    }

    if (this.remediationTitle) this.remediationTitle.textContent = `${vuln.id}: ${vuln.title}`;
    if (this.remediationCwe) this.remediationCwe.textContent = vuln.cwe;
    if (this.remediationDesc) this.remediationDesc.textContent = vuln.description;
    if (this.remediationBeforeCode) this.remediationBeforeCode.textContent = vuln.before;
    if (this.remediationAfterCode) this.remediationAfterCode.textContent = vuln.after;
  }

  scrollToLine(lineNum) {
    const el = document.getElementById(`code-line-${lineNum}`);
    if (el && this.codeBodyContainer) {
      const top = el.offsetTop - this.codeBodyContainer.offsetTop - 60;
      this.codeBodyContainer.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
      el.style.transition = "transform 200ms ease, background-color 200ms ease";
      el.style.transform = "scale(1.02)";
      setTimeout(() => {
        el.style.transform = "none";
      }, 400);
    }
  }

  highlightSyntax(text, lang) {
    if (lang === "text") {
      return this.escapeHtml(text);
    }

    let escaped = this.escapeHtml(text);

    // Comments
    if (lang === "python" && escaped.includes("#")) {
      const parts = escaped.split("#");
      const codePart = parts[0];
      const commentPart = "#" + parts.slice(1).join("#");
      return this.highlightTokens(codePart, lang) + `<span class="tok-cm">${commentPart}</span>`;
    } else if (lang === "javascript" && escaped.includes("//")) {
      const parts = escaped.split("//");
      const codePart = parts[0];
      const commentPart = "//" + parts.slice(1).join("//");
      return this.highlightTokens(codePart, lang) + `<span class="tok-cm">${commentPart}</span>`;
    }

    return this.highlightTokens(escaped, lang);
  }

  highlightTokens(str, lang) {
    // Strings
    str = str.replace(/(["'`])(?:(?=(\\?))\2.)*?\1/g, (m) => `<span class="tok-str">${m}</span>`);

    // Keywords
    const pyKeywords = /\b(def|import|from|class|return|if|elif|else|try|except|with|as|for|in|while|pass|break|continue|None|True|False|async|await)\b/g;
    const jsKeywords = /\b(const|let|var|function|return|if|else|try|catch|require|module|exports|class|import|from|async|await|new|typeof|null|undefined|true|false)\b/g;

    const kwRegex = lang === "python" ? pyKeywords : jsKeywords;
    str = str.replace(kwRegex, (m) => `<span class="tok-kw">${m}</span>`);

    // Functions
    str = str.replace(/\b([a-zA-Z0-9_]+)(?=\()/g, (m) => `<span class="tok-fn">${m}</span>`);

    // Numbers
    str = str.replace(/\b(\d+)\b/g, (m) => `<span class="tok-num">${m}</span>`);

    return str;
  }

  escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  new DemoCodeInspector();
});
