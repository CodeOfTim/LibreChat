const {
  resolveForwardedIdentity,
  decodeJwtPayload,
} = require('~/strategies/forwardedAuthStrategy');

/**
 * Debug endpoint for forwarded auth configuration.
 * Shows what headers are configured, what values were received, and whether
 * authentication would succeed.  Only active when FORWARD_AUTH_ENABLED=true.
 *
 * GET /api/auth/forwarded-auth/debug
 */
const forwardedAuthDebugController = (req, res) => {
  if (process.env.FORWARD_AUTH_ENABLED !== 'true') {
    return res.status(404).json({ error: 'FORWARD_AUTH_ENABLED is not set to "true"' });
  }

  // ── Config snapshot ─────────────────────────────────────────────────────────
  const config = {
    mode: process.env.FORWARD_AUTH_HEADER_JWT ? 'jwt-header' : 'plain-header',
    // JWT header mode
    jwtHeader: process.env.FORWARD_AUTH_HEADER_JWT || null,
    jwtUsernameClaim: process.env.FORWARD_AUTH_JWT_USERNAME_CLAIM || 'email',
    jwtEmailClaim: process.env.FORWARD_AUTH_JWT_EMAIL_CLAIM || 'email',
    // Plain header mode
    usernameHeader: process.env.FORWARD_AUTH_USERNAME_HEADER || null,
    emailHeader: process.env.FORWARD_AUTH_EMAIL_HEADER || null,
  };

  // ── Inspect received headers ─────────────────────────────────────────────────
  // Headers that are relevant to forwarded auth
  const candidateHeaders = [
    config.jwtHeader,
    config.usernameHeader,
    config.emailHeader,
    'x-amzn-oidc-data',
    'x-amzn-oidc-identity',
    'x-forwarded-user',
    'x-forwarded-email',
    'x-forwarded-for',
    'x-real-ip',
  ]
    .filter(Boolean)
    .map((h) => h.toLowerCase());

  const headers = {};
  for (const name of [...new Set(candidateHeaders)]) {
    const raw = req.headers[name];
    if (!raw) {
      headers[name] = { present: false };
      continue;
    }

    // If this is the configured JWT header, decode it
    if (name === config.jwtHeader?.toLowerCase()) {
      const claims = decodeJwtPayload(raw);
      headers[name] = {
        present: true,
        length: raw.length,
        type: 'jwt',
        decoded: claims
          ? { ...claims }
          : null,
        decodeError: claims ? null : 'Failed to base64-decode or JSON-parse payload',
      };
    } else {
      headers[name] = { present: true, value: raw, length: raw.length };
    }
  }

  // ── Attempt to resolve identity ──────────────────────────────────────────────
  const resolution = resolveForwardedIdentity(req);

  // ── Diagnose issues ──────────────────────────────────────────────────────────
  const issues = [];

  if (!config.jwtHeader && !config.usernameHeader) {
    issues.push(
      'Neither FORWARD_AUTH_HEADER_JWT nor FORWARD_AUTH_USERNAME_HEADER is set. ' +
        'Set one of them in your .env file.',
    );
  }

  if (config.jwtHeader) {
    const h = headers[config.jwtHeader.toLowerCase()];
    if (!h?.present) {
      issues.push(
        `JWT header "${config.jwtHeader}" was not received. ` +
          'Check that your reverse proxy (nginx/ALB) is forwarding it.',
      );
    } else if (h.decodeError) {
      issues.push(
        `JWT header "${config.jwtHeader}" is present but could not be decoded. ` +
          'Make sure the header contains a valid JWT (header.payload.signature).',
      );
    } else if (!h.decoded?.[config.jwtUsernameClaim]) {
      issues.push(
        `JWT claim "${config.jwtUsernameClaim}" is missing from the decoded payload. ` +
          `Available claims: ${Object.keys(h.decoded || {}).join(', ')}. ` +
          'Set FORWARD_AUTH_JWT_USERNAME_CLAIM to the correct claim name.',
      );
    }
  }

  if (config.usernameHeader) {
    const h = headers[config.usernameHeader.toLowerCase()];
    if (!h?.present || !h.value) {
      issues.push(
        `Username header "${config.usernameHeader}" is absent or empty. ` +
          'Check your reverse proxy configuration.',
      );
    }
  }

  if (!resolution.username && issues.length === 0) {
    issues.push('Username could not be resolved from the configured source(s).');
  }

  return res.json({
    status: resolution.username ? 'would-authenticate' : 'would-fail',
    config,
    resolution,
    headers,
    issues,
    hint:
      issues.length > 0
        ? 'Fix the issues listed above, then restart the server and refresh this page.'
        : null,
  });
};

module.exports = { forwardedAuthDebugController };
