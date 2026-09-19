/**
 * Main Express server for node-vulnerable-api.
 * 
 * INTENTIONALLY VULNERABLE DEMO TARGET FOR BREACHLABS.
 * Local demonstration use only.
 */

const express = require('express');
const cors = require('cors');
const config = require('./config');
const apiRoutes = require('./routes/api');
const authRoutes = require('./routes/auth');

const app = express();

// --- Vulnerability: Permissive CORS policy (BL-SAST-005) ---
app.use(cors({
  origin: '*',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Root landing page
app.get('/', (req, res) => {
  res.send('<h1>Node.js Vulnerable API</h1><p>BreachLabs Microservice Target</p>');
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Mount modular subrouters
app.use('/api', apiRoutes);
app.use('/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err);
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = config.PORT;
if (require.main === module) {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`Node Vulnerable Server listening on http://127.0.0.1:${PORT}`);
  });
}

module.exports = app;
