/**
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
  { id: 3, name: "Office Chair", category: "furniture", price: 299.00 }
];

const documentsStore = {
  "101": { id: "101", title: "Quarterly Financials", ownerId: 1, content: "Confidential Q3 Revenue" },
  "102": { id: "102", title: "Architecture Blueprint", ownerId: 2, content: "Internal infrastructure map" }
};

// --- Vulnerability 1: SQL / Database Query Injection via Template String ---
router.get('/items', (req, res) => {
  const category = req.query.category || '';
  // Raw template string concatenation simulates unescaped SQL query
  const query = `SELECT * FROM items WHERE category = '${category}'`;
  console.log(`[SQL EXEC] ${query}`);
  
  if (category.includes("' OR '1'='1") || category.includes('" OR "1"="1')) {
    // Deliberate simulated tautology response
    return res.json({ query: query, results: itemsDb });
  }
  const filtered = itemsDb.filter(i => i.category.toLowerCase() === category.toLowerCase());
  res.json({ query: query, results: filtered });
});

// --- Vulnerability 2: Reflected XSS via Direct HTML output (BL-SAST-009) ---
router.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  // User input concatenated directly into HTML response without escaping
  res.send(`<h1>Hello, ${name}!</h1><p>Welcome to our platform portal.</p>`);
});

// --- Vulnerability 3: Prototype Pollution via Object.assign (BL-SAST-008) ---
router.post('/preferences', (req, res) => {
  const userConfig = {};
  // Unvalidated body merged onto object allows __proto__ property tampering
  Object.assign(userConfig, req.body);
  res.json({ status: "updated", config: userConfig });
});

// --- Vulnerability 4: Command Injection via child_process.exec (BL-SAST-003) ---
router.get('/lookup', (req, res) => {
  const domain = req.query.domain || 'localhost';
  // Unsanitized shell command interpolation
  exec(`nslookup ${domain}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message, stderr: stderr });
    }
    res.json({ domain: domain, result: stdout });
  });
});

// --- Vulnerability 5: Broken Object-Level Authorization (IDOR) ---
router.get('/documents/:docId', (req, res) => {
  const docId = req.params.docId;
  const doc = documentsStore[docId];
  if (!doc) {
    return res.status(404).json({ error: "Document not found" });
  }
  // Missing caller ownership verification (tenant isolation bypass)
  res.json(doc);
});

// --- Vulnerability 6: Dynamic Expression Evaluation via vm (BL-SAST-002) ---
router.post('/evaluate', (req, res) => {
  const formula = req.body.formula || '1 + 1';
  try {
    const result = vm.runInNewContext(formula, {});
    res.json({ formula: formula, result: result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;
