import { createRemoteJWKSet, jwtVerify } from "jose";

// Cache JWKS key sets by URI so we don't refetch on every token verification
const _jwksCache = new Map();

/**
 * Create a JWT verifier for RS256 ID tokens.
 *
 * @param {string} jwksUri  - from the OIDC discovery document (jwks_uri)
 * @param {string} issuer   - from the OIDC discovery document (issuer)
 * @returns {(idToken: string, audience: string, nonce?: string) => Promise<object>}
 */
export function createVerifier(jwksUri, issuer) {
  if (!_jwksCache.has(jwksUri)) {
    _jwksCache.set(jwksUri, createRemoteJWKSet(new URL(jwksUri)));
  }
  const jwks = _jwksCache.get(jwksUri);

  return async function verify(idToken, audience, nonce) {
    const { payload } = await jwtVerify(idToken, jwks, {
      issuer,
      audience,
      algorithms: ["RS256"],
    });

    if (nonce !== undefined && payload.nonce !== nonce) {
      throw new Error(
        `Nonce mismatch: expected "${nonce}", got "${payload.nonce}"`
      );
    }

    return payload;
  };
}
