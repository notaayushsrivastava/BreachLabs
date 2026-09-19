/**
 * Configuration for node-vulnerable-api.
 * 
 * INTENTIONALLY VULNERABLE DEMO TARGET FOR BREACHLABS.
 * Local demonstration use only.
 */

module.exports = {
  PORT: process.env.PORT || 3000,
  
  // --- Vulnerability: Hardcoded JWT signing secret key (BL-SAST-007) ---
  JWT_SECRET: "jwt-super-secret-key-123456789-do-not-use-in-production",
  
  // --- Vulnerability: Hardcoded AWS API token (BL-SEC-001) ---
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
  
  // --- Vulnerability: Hardcoded Database API Key ---
  DATABASE_API_KEY: "node-api-key-9876543210-master-key",
  
  // --- Vulnerability: Permissive CORS Configuration (BL-SAST-005) ---
  CORS_ORIGIN: "*",
  
  // Environment mode
  NODE_ENV: "development"
};
