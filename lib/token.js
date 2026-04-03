import axios from "axios";

export async function exchangeToken(code, clientId, clientSecret, redirectUri, codeVerifier, tokenEndpoint) {
  const res = await axios.post(tokenEndpoint, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: clientSecret,
    code_verifier: codeVerifier
  });
  return res.data;
}

export async function refreshToken(refreshTokenStr, clientId, clientSecret, tokenEndpoint) {
  const res = await axios.post(tokenEndpoint, {
    grant_type: "refresh_token",
    refresh_token: refreshTokenStr,
    client_id: clientId,
    client_secret: clientSecret
  });
  return res.data;
}

