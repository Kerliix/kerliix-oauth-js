import axios from "axios";
import { generatePKCE } from "./pkce.js";
import { createVerifier } from "./jwks.js";
import { generateState, generateNonce } from "./utils.js";
import {
  exchangeCode,
  refreshAccessToken,
  introspectToken,
  revokeToken,
  clientCredentialsGrant,
} from "./token.js";

export class KerliixClient {
  /**
   * @param {object} config
   * @param {string} config.clientId
   * @param {string} [config.clientSecret]          - omit for public clients
   * @param {string} config.redirectUri
   * @param {string} [config.issuer]                - accounts-center base URL, default https://accounts.kerliix.com
   * @param {string} [config.scope]                 - default scope, default "openid profile email"
   */
  constructor({
    clientId,
    clientSecret,
    redirectUri,
    issuer = "https://accounts.kerliix.com",
    scope = "openid profile email",
  }) {
    this.clientId = clientId;
    this.clientSecret = clientSecret || null;
    this.redirectUri = redirectUri;
    this.issuer = issuer.replace(/\/$/, "");
    this.defaultScope = scope;
    this._endpoints = null;
    this._verify = null;
  }

  // ─── Discovery ──────────────────────────────────────────────────────────────

  /**
   * Fetch the OIDC discovery document and cache it.
   * The discovery URL is <issuer>/oauth/.well-known/openid-configuration.
   */
  async init() {
    if (this._endpoints) return;
    const discoveryUrl = `${this.issuer}/oauth/.well-known/openid-configuration`;
    const res = await axios.get(discoveryUrl);
    this._endpoints = res.data;
    this._verify = createVerifier(this._endpoints.jwks_uri, this._endpoints.issuer);
  }

  // ─── Authorization ──────────────────────────────────────────────────────────

  /**
   * Build an authorization URL and return it alongside the PKCE verifier, state,
   * and nonce that MUST be persisted in the user session before redirecting.
   *
   * @param {object} [opts]
   * @param {string} [opts.scope]   - overrides the default scope
   * @param {string} [opts.state]   - supply your own; one is auto-generated if omitted
   * @param {string} [opts.nonce]   - supply your own; one is auto-generated if omitted
   * @returns {{ url: string, codeVerifier: string, state: string, nonce: string }}
   */
  async getLoginUrl({ scope, state, nonce } = {}) {
    await this.init();
    const pkce = generatePKCE();
    const usedState = state ?? generateState();
    const usedNonce = nonce ?? generateNonce();

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: "code",
      scope: scope ?? this.defaultScope,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      state: usedState,
      nonce: usedNonce,
    });

    return {
      url: `${this._endpoints.authorization_endpoint}?${params.toString()}`,
      codeVerifier: pkce.verifier,
      state: usedState,
      nonce: usedNonce,
    };
  }

  // ─── Callback ───────────────────────────────────────────────────────────────

  /**
   * Exchange the authorization code for tokens and verify the ID token.
   *
   * @param {string} code           - `code` query param from the callback URL
   * @param {string} codeVerifier   - PKCE verifier from getLoginUrl()
   * @param {object} [opts]
   * @param {string} [opts.expectedNonce] - nonce from getLoginUrl(); verified if supplied
   * @returns {{ tokens: object, user: object|null }}
   */
  async handleCallback(code, codeVerifier, { expectedNonce } = {}) {
    await this.init();

    const tokens = await exchangeCode({
      code,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      redirectUri: this.redirectUri,
      codeVerifier,
      tokenEndpoint: this._endpoints.token_endpoint,
    });

    let user = null;
    if (tokens.id_token) {
      user = await this._verify(tokens.id_token, this.clientId, expectedNonce);
    }

    return { tokens, user };
  }

  // ─── Token management ───────────────────────────────────────────────────────

  /**
   * Refresh an access token using a refresh token.
   * @param {string} token - the refresh_token
   */
  async refresh(token) {
    await this.init();
    return refreshAccessToken({
      refreshToken: token,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      tokenEndpoint: this._endpoints.token_endpoint,
    });
  }

  /**
   * Fetch the UserInfo claims for an access token.
   * @param {string} accessToken
   */
  async getUser(accessToken) {
    await this.init();
    const res = await axios.get(this._endpoints.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return res.data;
  }

  /**
   * Introspect a token (RFC 7662). Requires client credentials.
   * @param {string} token - access_token or refresh_token to introspect
   */
  async introspect(token) {
    await this.init();
    return introspectToken({
      token,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      introspectEndpoint: this._endpoints.introspection_endpoint,
    });
  }

  /**
   * Revoke a token (RFC 7009).
   * @param {string} token - access_token or refresh_token to revoke
   */
  async revoke(token) {
    await this.init();
    await revokeToken({
      token,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      revokeEndpoint: this._endpoints.revocation_endpoint,
    });
  }

  /**
   * Obtain an access token using the client_credentials grant.
   * Only available for confidential clients.
   * @param {object} [opts]
   * @param {string} [opts.scope]
   */
  async clientCredentials({ scope } = {}) {
    await this.init();
    return clientCredentialsGrant({
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      scope: scope ?? this.defaultScope,
      tokenEndpoint: this._endpoints.token_endpoint,
    });
  }

  // ─── Logout ─────────────────────────────────────────────────────────────────

  /**
   * Build an RP-initiated logout URL (OIDC Session Management).
   * Redirect the user's browser to this URL to end their session.
   *
   * @param {object} [opts]
   * @param {string} [opts.idTokenHint]            - ID token from the session
   * @param {string} [opts.postLogoutRedirectUri]  - where to send the user after logout
   * @param {string} [opts.state]
   */
  async getLogoutUrl({ idTokenHint, postLogoutRedirectUri, state } = {}) {
    await this.init();
    const base = this._endpoints.end_session_endpoint;
    if (!base) throw new Error("end_session_endpoint not advertised by this server.");
    const params = new URLSearchParams();
    if (idTokenHint) params.set("id_token_hint", idTokenHint);
    if (postLogoutRedirectUri) params.set("post_logout_redirect_uri", postLogoutRedirectUri);
    if (state) params.set("state", state);
    const qs = params.toString();
    return qs ? `${base}?${qs}` : base;
  }
}
