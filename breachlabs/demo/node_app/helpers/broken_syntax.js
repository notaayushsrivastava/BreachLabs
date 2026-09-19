/**
 * Helper with intentional syntax / compiler error for BreachLabs error diagnosis.
 */

// Intentional syntax glitch: missing parenthesis in parameter list
function parseUserPayload(payload {
  return JSON.parse(payload);
}

module.exports = { parseUserPayload };
