/**
 * Authentication routes for node-vulnerable-api.
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config');
const router = express.Router();

// --- Vulnerability: Hardcoded admin login ---
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'admin' && password === 'admin-secret-pass-2026') {
    const token = jwt.sign(
      { sub: username, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );
    return res.json({ token: token, role: 'admin' });
  }
  
  res.status(401).json({ error: "Invalid username or password" });
});

// --- Vulnerability: JWT Verification Bypass / Insecure decode ---
router.get('/verify', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: "Token missing" });
  }
  
  try {
    // Deliberate flaw: decode without verifying signature
    const decoded = jwt.decode(token);
    res.json({ valid: true, payload: decoded });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;
