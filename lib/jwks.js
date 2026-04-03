import { createRemoteJWKSet, jwtVerify } from "jose";

export function createVerifier(issuer) {
  const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
  return async function verify(idToken, audience) {
    const { payload } = await jwtVerify(idToken, jwks, { issuer, audience });
    return payload;
  };
}

