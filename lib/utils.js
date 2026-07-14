import crypto from "crypto";

export function buildQueryString(params) {
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

/** Generate a cryptographically random state value (hex). */
export function generateState() {
  return crypto.randomBytes(16).toString("hex");
}

/** Generate a cryptographically random nonce value (hex). */
export function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}
