import crypto from "crypto";

/**
 * Generate a PKCE (Proof Key for Code Exchange) pair.
 * Returns a random `verifier` and its S256 `challenge`.
 *
 * RFC 7636 §4.1 — verifier must be 43-128 characters of [A-Z a-z 0-9 - . _ ~]
 */
export function generatePKCE() {
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}
