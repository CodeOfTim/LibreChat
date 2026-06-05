const { SystemRoles } = require('librechat-data-provider');
const passportCustom = require('passport-custom');
const { getUserById, updateUser, findUser, createUser, countUsers } = require('~/models');
const { logger } = require('~/config');

/**
 * Decode a JWT payload without verifying the signature.
 * Signature verification is the upstream proxy's responsibility (e.g. AWS ALB with OIDC).
 * @param {string} jwt
 * @returns {Record<string,unknown>|null}
 */
const decodeJwtPayload = (jwt) => {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    // Convert base64url → standard base64 and pad
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '=');
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch {
    return null;
  }
};

/**
 * Resolve username + email from the request.
 *
 * Two modes, tried in order:
 *  1. JWT header mode  — set FORWARD_AUTH_HEADER_JWT (e.g. X-Amzn-Oidc-Data)
 *     The header value is treated as a signed JWT; the payload is base64-decoded and
 *     FORWARD_AUTH_JWT_USERNAME_CLAIM / FORWARD_AUTH_JWT_EMAIL_CLAIM are read from it.
 *     This is the correct approach for AWS ALB OIDC.
 *  2. Plain header mode — set FORWARD_AUTH_USERNAME_HEADER / FORWARD_AUTH_EMAIL_HEADER
 *     The header values are used directly (e.g. values already extracted by a trusted proxy).
 *
 * @param {import('express').Request} req
 * @returns {{ username: string|null, email: string|null, source: string }}
 */
const resolveForwardedIdentity = (req) => {
  const jwtHeaderName = process.env.FORWARD_AUTH_HEADER_JWT;

  // ── Mode 1: JWT header (AWS ALB X-Amzn-Oidc-Data or similar) ──────────────
  if (jwtHeaderName) {
    const rawJwt = req.headers[jwtHeaderName.toLowerCase()];
    if (rawJwt) {
      const claims = decodeJwtPayload(rawJwt);
      if (claims) {
        const usernameClaim = process.env.FORWARD_AUTH_JWT_USERNAME_CLAIM || 'email';
        const emailClaim = process.env.FORWARD_AUTH_JWT_EMAIL_CLAIM || 'email';
        const username = (claims[usernameClaim] || null);
        const email = (claims[emailClaim] || null);
        logger.debug(
          `[forwardedAuthStrategy] JWT decoded from ${jwtHeaderName}: ` +
            `username="${username}", email="${email}"`,
        );
        return { username, email, source: `jwt-header:${jwtHeaderName}` };
      }
      logger.warn(
        `[forwardedAuthStrategy] Header ${jwtHeaderName} is present but could not be decoded as JWT`,
      );
    } else {
      logger.warn(
        `[forwardedAuthStrategy] JWT header "${jwtHeaderName}" is absent or empty in the request. ` +
          'Ensure your reverse proxy (nginx/ALB) is forwarding it.',
      );
    }
  }

  // ── Mode 2: Plain header ────────────────────────────────────────────────────
  const usernameHeader = process.env.FORWARD_AUTH_USERNAME_HEADER;
  const emailHeader = process.env.FORWARD_AUTH_EMAIL_HEADER;
  if (usernameHeader) {
    const username = req.headers[usernameHeader.toLowerCase()] || null;
    const email = emailHeader ? req.headers[emailHeader.toLowerCase()] || null : null;
    logger.debug(
      `[forwardedAuthStrategy] Plain headers: ${usernameHeader}="${username}", ` +
        `${emailHeader ?? 'none'}="${email}"`,
    );
    return { username, email, source: `header:${usernameHeader}` };
  }

  return { username: null, email: null, source: 'none' };
};

/**
 * Strategy for authentication using forwarded HTTP headers from a reverse proxy.
 * @returns {passportCustom.Strategy}
 */
const forwardedAuthStrategy = () => {
  return new passportCustom.Strategy(async (req, done) => {
    try {
      if (process.env.FORWARD_AUTH_ENABLED !== 'true') {
        return done(null, false);
      }

      const usernameHeader = process.env.FORWARD_AUTH_USERNAME_HEADER;
      const jwtHeaderName = process.env.FORWARD_AUTH_HEADER_JWT;

      if (!usernameHeader && !jwtHeaderName) {
        logger.error(
          '[forwardedAuthStrategy] Neither FORWARD_AUTH_USERNAME_HEADER nor ' +
            'FORWARD_AUTH_HEADER_JWT is configured. Set one of them.',
        );
        return done(null, false);
      }

      const { username, email, source } = resolveForwardedIdentity(req);

      if (!username) {
        logger.warn(
          `[forwardedAuthStrategy] No username could be resolved (source: ${source}). ` +
            'Check that your reverse proxy is forwarding the expected headers.',
        );
        return done(null, false);
      }

      // Find or create the user
      let user = null;
      if (email) {
        user = await findUser({ email }, '-password -__v -totpSecret');
      }
      if (!user) {
        user = await findUser({ username }, '-password -__v -totpSecret');
      }

      if (user) {
        const updates = { provider: 'forwardedAuth' };
        if (email && user.email !== email) updates.email = email;
        if (Object.keys(updates).length > 0) {
          user = await updateUser(user._id, updates);
        }
        logger.info(`[forwardedAuthStrategy] Authenticated existing user: ${username}`);
      } else {
        logger.info(`[forwardedAuthStrategy] Creating new user: ${username}`);
        const isFirstRegisteredUser = (await countUsers()) === 0;
        const newUserData = {
          provider: 'forwardedAuth',
          username,
          name: username,
          emailVerified: true,
          role: isFirstRegisteredUser ? SystemRoles.ADMIN : SystemRoles.USER,
        };
        if (email) newUserData.email = email;
        const newUserId = await createUser(newUserData);
        user = await getUserById(newUserId, '-password -__v -totpSecret');
      }

      user.id = user._id.toString();
      return done(null, user);
    } catch (err) {
      logger.error('[forwardedAuthStrategy] Error:', err);
      return done(err);
    }
  });
};

module.exports = forwardedAuthStrategy;
module.exports.resolveForwardedIdentity = resolveForwardedIdentity;
module.exports.decodeJwtPayload = decodeJwtPayload;
