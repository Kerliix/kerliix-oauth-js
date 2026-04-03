import axios from "axios";
import { generatePKCE } from "./pkce.js";
import { createVerifier } from "./jwks.js";
import { buildQueryString } from "./utils.js";
import { exchangeToken, refreshToken } from "./token.js";

export class KerliixClient {
  constructor({ clientId, clientSecret, redirectUri, issuer = "https://accounts.kerliix.com" }) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.issuer = issuer;
    this.pkce = generatePKCE();
    this.verifier = createVerifier(`${issuer}`);
    this.endpoints = null;
  }

  async init() {
    const res = await axios.get(`${this.issuer}/.well-known/openid-configuration`);
    this.endpoints = res.data;
  }

  async loginUrl(scope = "openid profile email") {
    if (!this.endpoints) await this.init();
    const params = {
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: "code",
      scope,
      code_challenge: this.pkce.challenge,
      code_challenge_method: "S256"
    };
    return `${this.endpoints.authorization_endpoint}?${buildQueryString(params)}`;
  }

  async handleCallback(req) {
    if (!this.endpoints) await this.init();
    const code = req.query.code;
    const tokens = await exchangeToken(code, this.clientId, this.clientSecret, this.redirectUri, this.pkce.verifier, this.endpoints.token_endpoint);
    const user = await this.verifier(tokens.id_token, this.clientId);
    return { user, tokens };
  }

  async refresh(refreshTokenStr) {
    if (!this.endpoints) await this.init();
    return await refreshToken(refreshTokenStr, this.clientId, this.clientSecret, this.endpoints.token_endpoint);
  }

  async getUser(accessToken) {
    if (!this.endpoints) await this.init();
    const res = await axios.get(this.endpoints.userinfo_endpoint, { headers: { Authorization: `Bearer ${accessToken}` } });
    return res.data;
  }
}
