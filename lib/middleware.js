import express from "express";

/**
 * `protect(client)` — Express middleware that enforces a valid Bearer token.
 *
 * Calls client.getUser(accessToken) against the userinfo endpoint.
 * On success, attaches the claims to req.user and calls next().
 * On failure, responds 401.
 *
 * @param {import("./client.js").KerliixClient} client
 */
export function protect(client) {
  return async (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "unauthorized",
        error_description: "Bearer token required.",
      });
    }
    try {
      const token = auth.slice(7);
      req.user = await client.getUser(token);
      next();
    } catch {
      res.status(401).json({
        error: "unauthorized",
        error_description: "Invalid or expired token.",
      });
    }
  };
}

/**
 * `routes(client)` — Mounts pre-built login and callback routes on an Express router.
 *
 * Requires `express-session` (or compatible session middleware) to be set up
 * before these routes so that PKCE state can be persisted across the redirect.
 *
 * Mounted routes:
 *   GET /login    — redirect user to Kerliix accounts
 *   GET /callback — exchange code, store tokens in session, call next()
 *
 * After /callback succeeds, req.oauthResult contains { tokens, user }.
 * Add your own next() handler after this router to redirect or respond.
 *
 * @param {import("./client.js").KerliixClient} client
 */
export function routes(client) {
  const router = express.Router();

  router.get("/login", async (req, res, next) => {
    try {
      const { url, codeVerifier, state, nonce } = await client.getLoginUrl();
      // Persist PKCE and CSRF state in session before redirecting
      req.session = req.session ?? {};
      req.session.oauthCodeVerifier = codeVerifier;
      req.session.oauthState = state;
      req.session.oauthNonce = nonce;
      res.redirect(url);
    } catch (err) {
      next(err);
    }
  });

  router.get("/callback", async (req, res, next) => {
    try {
      const { code, state, error, error_description } = req.query;

      if (error) {
        return res.status(400).json({ error, error_description });
      }

      const session = req.session ?? {};

      // Validate state to prevent CSRF
      if (session.oauthState && state !== session.oauthState) {
        return res.status(400).json({
          error: "invalid_state",
          error_description: "State parameter mismatch.",
        });
      }

      const result = await client.handleCallback(
        code,
        session.oauthCodeVerifier,
        { expectedNonce: session.oauthNonce }
      );

      // Clean up PKCE state from session
      delete session.oauthCodeVerifier;
      delete session.oauthState;
      delete session.oauthNonce;

      // Make result available to the next handler
      req.oauthResult = result;
      next();
    } catch (err) {
      next(err);
    }
  });

  return router;
}
