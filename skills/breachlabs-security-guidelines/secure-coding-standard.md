# BreachLabs Secure Coding Standard

> Concrete code implementation patterns, hardened snippets, and anti-patterns across Python, TypeScript/Node.js, Go, and Java.

---

## 1. Relational Database Queries & ORM Usage

### Python (SQLAlchemy / raw psycopg2 / sqlite3)

#### ❌ Vulnerable (SQL Injection):
```python
# Raw string formatting into SQL
def find_user(username: str):
    query = f"SELECT id, email, role FROM users WHERE username = '{username}'"
    return db.session.execute(text(query)).fetchall()
```

#### ✅ Secure (Parameterized SQL & ORM):
```python
from sqlalchemy import select, text
from sqlalchemy.orm import Session

# Pattern 1: Raw SQL with parameterized binding dictionary
def find_user_raw(session: Session, username: str):
    query = text("SELECT id, email, role FROM users WHERE username = :uname")
    return session.execute(query, {"uname": username}).mappings().all()

# Pattern 2: SQLAlchemy Type-safe ORM query
def find_user_orm(session: Session, username: str):
    stmt = select(User).where(User.username == username)
    return session.scalars(stmt).all()
```

---

### Node.js / TypeScript (pg / Prisma / TypeORM)

#### ❌ Vulnerable:
```typescript
// Unescaped template literal in SQL query
async function getProducts(category: string) {
  const query = `SELECT * FROM products WHERE category = '${category}'`;
  return await db.query(query);
}
```

#### ✅ Secure:
```typescript
import { PrismaClient } from '@prisma/client';
import { Pool } from 'pg';

const prisma = new PrismaClient();
const pool = new Pool();

// Pattern 1: Parameterized array bindings ($1, $2)
async function getProductsRaw(category: string) {
  const query = 'SELECT id, name, price FROM products WHERE category = $1';
  const res = await pool.query(query, [category]);
  return res.rows;
}

// Pattern 2: Prisma ORM with automatic parameterization
async function getProductsPrisma(category: string) {
  return await prisma.product.findMany({
    where: { category },
    select: { id: true, name: true, price: true },
  });
}
```

---

## 2. Command Execution & Subprocesses

### Python

#### ❌ Vulnerable (Command Injection):
```python
import subprocess

def ping_host(host: str):
    # Shell interpolation allows cmd chaining: "127.0.0.1; rm -rf /"
    return subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
```

#### ✅ Secure:
```python
import ipaddress
import subprocess
import os

def ping_host(host: str) -> str:
    # 1. Strict input validation
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("Invalid IP address provided")

    # 2. Argument vector execution without shell
    flag = "-n" if os.name == "nt" else "-c"
    cmd = ["ping", flag, "1", host]
    result = subprocess.run(
        cmd,
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
        check=True
    )
    return result.stdout
```

---

### Node.js

#### ❌ Vulnerable:
```javascript
const { exec } = require('child_process');

function generateThumbnail(filePath) {
  // Vulnerable to shell injection if filePath contains quotes or backticks
  exec(`ffmpeg -i ${filePath} thumb.png`, (err, stdout) => { ... });
}
```

#### ✅ Secure:
```javascript
const { execFile } = require('child_process');
const path = require('path');

function generateThumbnail(filePath) {
  // Validate path is within allowed directory
  const safePath = path.resolve('/var/app/uploads', path.basename(filePath));
  
  // Direct binary execution with argument array, no shell wrapper
  return new Promise((resolve, reject) => {
    execFile('ffmpeg', ['-i', safePath, '-y', 'thumb.png'], { timeout: 10000 }, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}
```

---

## 3. Password Hashing & Secret Verification

### Python (Argon2id & bcrypt)

```python
import argon2
import hmac
import secrets

# Argon2id password hasher instance
ph = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    type=argon2.Type.ID
)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hashed: str, candidate_password: str) -> bool:
    try:
        return ph.verify(hashed, candidate_password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
        return False

def verify_api_token(user_provided_token: str, stored_token: str) -> bool:
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(user_provided_token.encode(), stored_token.encode())
```

---

## 4. Cross-Site Scripting (XSS) & Content Security

### React / Next.js / TypeScript

```tsx
import DOMPurify from 'dompurify';
import React from 'react';

interface CommentProps {
  author: string;
  rawBioHtml?: string;
  content: string;
}

export function CommentCard({ author, rawBioHtml, content }: CommentProps) {
  // Standard JSX auto-escapes all strings inside brackets
  return (
    <div className="comment-card">
      <h4>{author}</h4>
      <p>{content}</p>
      {rawBioHtml && (
        // When rich HTML is required, sanitize through DOMPurify with strict config
        <div
          dangerouslySetInnerHTML={{
            __html: DOMPurify.sanitize(rawBioHtml, {
              ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
              ALLOWED_ATTR: ['href', 'target', 'rel'],
            }),
          }}
        />
      )}
    </div>
  );
}
```

---

## 5. Broken Object Level Authorization (IDOR) & Multi-Tenancy

### FastAPI & Python

```python
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from uuid import UUID

router = APIRouter(prefix="/api/documents", tags=["documents"])

class DocumentOut(BaseModel):
    id: UUID
    title: str
    body: str

@router.get("/{doc_id}", response_model=DocumentOut)
def get_document(
    doc_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    # Enforce tenant isolation and user authorization in the primary database query
    doc = db.query(Document).filter(
        Document.id == doc_id,
        Document.tenant_id == current_user.tenant_id,
        (Document.owner_id == current_user.id) | (current_user.is_admin == True)
    ).first()

    if not doc:
        # Return generic 404 to avoid leaking existence of objects owned by other users
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    return doc
```

---

## 6. Server-Side Request Forgery (SSRF) Protection

### Python (Requests / Urllib3 with DNS Pinning)

```python
import ipaddress
import socket
import urllib.parse
import requests

BANNED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),     # AWS / Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_ip_allowed(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not any(ip in net for net in BANNED_NETWORKS)
    except ValueError:
        return False

def safe_fetch_url(user_url: str, timeout: int = 5) -> str:
    parsed = urllib.parse.urlparse(user_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https schemes are permitted")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target hostname")

    # 1. Resolve IP addresses for hostname
    addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    resolved_ips = [info[4][0] for info in addr_info]

    # 2. Check all resolved IPs against prohibited private/metadata networks
    for ip in resolved_ips:
        if not is_ip_allowed(ip):
            raise PermissionError(f"Target address {ip} resolves to a restricted internal network")

    # 3. Fetch with disabled redirects to prevent open-redirect SSRF pivoting
    response = requests.get(user_url, timeout=timeout, allow_redirects=False)
    return response.text
```
