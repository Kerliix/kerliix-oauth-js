import axios from "axios";

/**
 * Build an HTTP Basic Authorization header from clientId and clientSecret.
 * Percent-encodes each value per RFC 6749 §2.3.1.
 */
function basicAuth(clientId, clientSecret) {
  const encoded = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
  ).toString("base64");
  return `Basic ${encoded}`;
}

/**
 * POST to a token endpoint with application/x-www-form-urlencoded body.
 * Uses client_secret_basic (Authorization header) when a clientSecret is present,
 * falling back to including client_id in the body for public clients.
 */
async function postToken(endpoint, params, clientId, clientSecret) {
  const body = new URLSearchParams(params);
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };

  if (clientSecret) {
    headers.Authorization = basicAuth(clientId, clientSecret);
  } else {
    body.set("client_id", clientId);
  }

  const res = await axios.post(endpoint, body.toString(), { headers });
  return res.data;
}

// ─── Grant handlers ──────────────────────────────────────────────────────────

export async function exchangeCode({
  code,
  clientId,
  clientSecret,
  redirectUri,
  codeVerifier,
  tokenEndpoint,
}) {
  const params = {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    ...(codeVerifier ? { code_verifier: codeVerifier } : {}),
  };
  return postToken(tokenEndpoint, params, clientId, clientSecret);
}

export async function refreshAccessToken({
  refreshToken,
  clientId,
  clientSecret,
  tokenEndpoint,
}) {
  return postToken(
    tokenEndpoint,
    { grant_type: "refresh_token", refresh_token: refreshToken },
    clientId,
    clientSecret
  );
}

export async function introspectToken({
  token,
  clientId,
  clientSecret,
  introspectEndpoint,
}) {
  const body = new URLSearchParams({ token });
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization: basicAuth(clientId, clientSecret),
  };
  const res = await axios.post(introspectEndpoint, body.toString(), { headers });
  return res.data;
}

export async function revokeToken({
  token,
  clientId,
  clientSecret,
  revokeEndpoint,
}) {
  const body = new URLSearchParams({ token });
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization: basicAuth(clientId, clientSecret),
  };
  await axios.post(revokeEndpoint, body.toString(), { headers });
}

export async function clientCredentialsGrant({
  clientId,
  clientSecret,
  scope,
  tokenEndpoint,
}) {
  return postToken(
    tokenEndpoint,
    { grant_type: "client_credentials", scope },
    clientId,
    clientSecret
  );
}
