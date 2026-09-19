/**
 * Zero-dependency standalone HTTP server for node-vulnerable-api.
 * 
 * Runs all vulnerable endpoints out of the box using Node.js standard library
 * when express/cors node_modules are not installed.
 */

const http = require('http');
const url = require('url');
const { exec } = require('child_process');
const vm = require('vm');
const config = require('../config');

const itemsDb = [
  { id: 1, name: "Wireless Headphones", category: "electronics", price: 99.99 },
  { id: 2, name: "Mechanical Keyboard", category: "electronics", price: 149.50 },
  { id: 3, name: "Office Chair", category: "furniture", price: 299.00 }
];

const documentsStore = {
  "101": { id: "101", title: "Quarterly Financials", ownerId: 1, content: "Confidential Q3 Revenue" },
  "102": { id: "102", title: "Architecture Blueprint", ownerId: 2, content: "Internal infrastructure map" }
};

function startStandaloneServer(port, host = '127.0.0.1') {
  const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname.replace(/\/$/, '') || '/';
    const query = parsedUrl.query || {};

    // Enable permissive CORS (BL-SAST-005)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let parsedBody = {};
      try {
        if (body) parsedBody = JSON.parse(body);
      } catch (e) {
        parsedBody = { raw: body };
      }

      const sendJson = (obj, status = 200) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(obj));
      };

      const sendHtml = (html, status = 200) => {
        res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
      };

      try {
        if (pathname === '/' || pathname === '') {
          return sendHtml('<h1>Node.js Vulnerable API</h1><p>BreachLabs Microservice Target</p>');
        }
        if (pathname === '/health') {
          return sendJson({ status: 'ok', uptime: process.uptime() });
        }
        // SQL injection probe (BL-SAST-001)
        if (pathname === '/api/items' || pathname === '/search') {
          const category = query.category || query.q || '';
          const sqlQuery = `SELECT * FROM items WHERE category = '${category}'`;
          if (category.includes("' OR '1'='1") || category.includes('" OR "1"="1') || category.includes("' OR 1=1")) {
            return sendJson({ query: sqlQuery, results: itemsDb });
          }
          const filtered = itemsDb.filter(i => i.category.toLowerCase() === category.toLowerCase());
          return sendJson({ query: sqlQuery, results: filtered });
        }
        // Reflected XSS (BL-SAST-009)
        if (pathname === '/api/greet' || pathname === '/greet') {
          const name = query.name || query.q || 'Guest';
          return sendHtml(`<h1>Hello, ${name}!</h1><p>Welcome to our platform portal.</p>`);
        }
        // Prototype pollution (BL-SAST-008)
        if (pathname === '/api/preferences' && req.method === 'POST') {
          const userConfig = {};
          Object.assign(userConfig, parsedBody);
          return sendJson({ status: "updated", config: userConfig });
        }
        // Command injection (BL-SAST-003)
        if (pathname === '/api/lookup' || pathname === '/api/ping') {
          const domain = query.domain || query.host || 'localhost';
          exec(`nslookup ${domain}`, (err, stdout, stderr) => {
            if (err) {
              return sendJson({ error: err.message, stderr: stderr }, 500);
            }
            sendJson({ domain: domain, result: stdout });
          });
          return;
        }
        // IDOR / BOLA
        if (pathname.startsWith('/api/documents/')) {
          const docId = pathname.split('/').pop();
          const doc = documentsStore[docId];
          if (!doc) return sendJson({ error: "Document not found" }, 404);
          return sendJson(doc);
        }
        // Dynamic VM eval (BL-SAST-002)
        if (pathname === '/api/evaluate' && req.method === 'POST') {
          const formula = parsedBody.formula || '1 + 1';
          try {
            const result = vm.runInNewContext(formula, {});
            return sendJson({ formula: formula, result: result });
          } catch (err) {
            return sendJson({ error: err.message }, 400);
          }
        }
        // Auth login & verify
        if (pathname === '/auth/login' && req.method === 'POST') {
          const username = parsedBody.username || 'admin';
          return sendJson({
            token: `demo-token-${Buffer.from(username).toString('base64')}`,
            user: { username, role: 'administrator' }
          });
        }
        if (pathname === '/auth/verify') {
          return sendJson({ valid: true, user: { id: 1, username: 'admin' } });
        }

        return sendHtml('<h1>404 Not Found</h1>', 404);
      } catch (err) {
        return sendJson({ error: err.message }, 500);
      }
    });
  });

  server.listen(port, host, () => {
    console.log(`Standalone Node Vulnerable Server listening on http://${host}:${port}`);
  });
  return server;
}

module.exports = { startStandaloneServer };
