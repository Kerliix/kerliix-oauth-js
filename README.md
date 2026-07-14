# kerliix-oauth

Official Kerliix OAuth 2.0 / OIDC SDK for Node.js — v2.0.0.

Supports the full authorization code flow with PKCE, token refresh, introspection, revocation, client credentials, and RP-initiated logout against the Kerliix Accounts Center.

## Install

```bash
npm install kerliix-oauth
```

## Requirements

- Node.js ≥ 18
- ESM project (`"type": "module"` in `package.json`)

---

## Quick start

```js
import { kerliixClient } from "kerliix-oauth";

const auth = kerliixClient({
  clientId:     "YOUR_CLIENT_ID",
  clientSecret: "YOUR_CLIENT_SECRET",   // omit for public clients
  redirectUri:  "https://yourapp.com/auth/callback",
  // issuer defaults to "https://accounts.kerliix.com"
  // scope  defaults to "openid profile email"
});
```

---

## Authorization code flow (with PKCE)

### 1 — Build the login URL

```js
app.get("/auth/login", async (req, res) => {
  const { url, codeVerifier, state, nonce } = await auth.getLoginUrl();

  // Persist PKCE state in the user's session before redirecting
  req.session.oauthCodeVerifier = codeVerifier;
  req.session.oauthState        = state;
  req.session.oauthNonce        = nonce;

  res.redirect(url);
});
```

### 2 — Handle the callback

```js
app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;

  // Validate state to prevent CSRF
  if (state !== req.session.oauthState) {
    return res.status(400).send("State mismatch");
  }

  const { tokens, user } = await auth.handleCallback(
    code,
    req.session.oauthCodeVerifier,
    { expectedNonce: req.session.oauthNonce }
  );

  // Clean up PKCE state
  delete req.session.oauthCodeVerifier;
  delete req.session.oauthState;
  delete req.session.oauthNonce;

  // Store tokens in session
  req.session.accessToken  = tokens.access_token;
  req.session.refreshToken = tokens.refresh_token;
  req.session.user         = user;

  res.redirect("/dashboard");
});
```

---

## Token operations

### Refresh

```js
const newTokens = await auth.refresh(req.session.refreshToken);
req.session.accessToken  = newTokens.access_token;
req.session.refreshToken = newTokens.refresh_token;
```

### Fetch user info

```js
const user = await auth.getUser(req.session.accessToken);
// { sub, name, email, email_verified, ... }
```

### Introspect a token

```js
const info = await auth.introspect(req.session.accessToken);
if (!info.active) {
  // token is expired or revoked
}
```

### Revoke a token

```js
await auth.revoke(req.session.refreshToken);
```

### Client credentials

```js
// Server-to-server — no user involved
const tokens = await auth.clientCredentials({ scope: "openid" });
```

---

## Logout

```js
app.get("/auth/logout", async (req, res) => {
  const logoutUrl = await auth.getLogoutUrl({
    idTokenHint:            req.session.idToken,
    postLogoutRedirectUri:  "https://yourapp.com",
  });
  req.session.destroy();
  res.redirect(logoutUrl);
});
```

---

## Pre-built Express routes (optional helper)

```js
import { middleware } from "kerliix-oauth";

// Mount login + callback routes at /auth
app.use("/auth", middleware.routes(auth));

// After /auth/callback succeeds, req.oauthResult contains { tokens, user }
// Add your own handler at /auth/callback to redirect:
app.get("/auth/callback", (req, res) => {
  req.session.user = req.oauthResult.user;
  res.redirect("/dashboard");
});

// Protect routes
app.get("/api/me", middleware.protect(auth), (req, res) => {
  res.json(req.user);
});
```

> **Note:** `middleware.routes()` requires `express-session` (or compatible) to be configured before the route.

---

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `clientId` | `string` | **required** | Your OAuth client ID |
| `clientSecret` | `string` | `undefined` | Client secret (omit for public clients) |
| `redirectUri` | `string` | **required** | Registered redirect URI |
| `issuer` | `string` | `"https://accounts.kerliix.com"` | Accounts Center base URL |
| `scope` | `string` | `"openid profile email"` | Default scope |

---

## Migration from v1

| v1 | v2 |
|---|---|
| `auth.loginUrl(scope)` | `auth.getLoginUrl({ scope })` — also returns `codeVerifier`, `state`, `nonce` |
| `auth.handleCallback(req)` | `auth.handleCallback(code, codeVerifier, { expectedNonce })` — PKCE state no longer stored on the client instance |
| `createVerifier(issuer)` (jwks.js) | Internal — JWKS URI is taken from the discovery document |
| No introspect / revoke | `auth.introspect(token)`, `auth.revoke(token)` |
| No client credentials | `auth.clientCredentials({ scope })` |
| No logout URL | `auth.getLogoutUrl({ idTokenHint, postLogoutRedirectUri })` |

---

## Contributing

1. Fork the repository.
2. Create a branch for your feature or fix.
3. Commit with clear messages.
4. Open a pull request.

Questions? [Open an issue](https://github.com/Kerliix/kerliix-oauth-js/issues) or email [dev@kerliix.com](mailto:dev@kerliix.com).

## License

Apache 2.0 — © Kerliix Corporation Limited
