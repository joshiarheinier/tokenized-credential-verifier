// The wallet's side of the challenge-response protocol
// (docs/challenge_response_protocol.md). No DOM access, so it can be tested in
// Node (see demo-wallet/webtest).

export const MESSAGE_HEADER = "tcv-challenge-response/v1";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The challenge's expiry as the verifier writes it into the signed text: UTC,
// to the second, truncated. The server may send fractional seconds, which Go's
// RFC 3339 layout drops, so they are dropped here before parsing too.
export function expiryText(expiresAt) {
  const t = new Date(String(expiresAt).replace(/\.\d+(?=Z$|[+-]\d\d:\d\d$)/, ""));
  if (Number.isNaN(t.getTime())) throw new Error("the challenge has no valid expiry time");
  return t.toISOString().slice(0, 19) + "Z";
}

// The exact text the holder signs to answer `challenge` with credential `token`.
// It is also what Phantom shows the user.
export async function signedMessage(challenge, token) {
  return [
    MESSAGE_HEADER,
    `audience: ${challenge.audience}`,
    `challenge: ${challenge.challenge_id}`,
    `type: ${challenge.credential_type}`,
    `claims: ${[...challenge.claims].sort().join(",")}`,
    `credential: sha256:${await sha256Hex(token)}`,
    `expires: ${expiryText(challenge.expires_at)}`,
  ].join("\n");
}

export function toBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64UrlToBytes(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

// Reads what a credential says about itself, for display and for choosing which
// credential can answer a challenge. It does not verify anything: only the
// verifier does that.
export function decodeCredential(token) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("this is not a credential");
  let payload;
  try {
    payload = JSON.parse(decoder.decode(base64UrlToBytes(parts[1])));
  } catch {
    throw new Error("this is not a credential");
  }
  if (typeof payload.credential_type !== "string" || typeof payload.sub !== "string" || !Number.isFinite(payload.exp)) {
    throw new Error("this is not a credential");
  }
  return {
    issuer: String(payload.iss ?? ""),
    subject: payload.sub,
    type: payload.credential_type,
    expiresAt: payload.exp * 1000,
    claims: payload.claims && typeof payload.claims === "object" ? payload.claims : {},
  };
}

// What the wallet stores for a credential.
export async function makeEntry(token, now = Date.now()) {
  return { id: (await sha256Hex(token)).slice(0, 12), credential: token, ...decodeCredential(token), storedAt: now };
}

export function holderId(address) {
  return `solana:${address}`;
}

// Why `entry` cannot answer `challenge` for the account `address`, or "" if it
// can. The verifier would refuse it anyway; this tells the user first.
export function whyUnusable(entry, challenge, address, nowMs = Date.now()) {
  if (entry.type !== challenge.credential_type) return `it is a ${entry.type} credential`;
  if (entry.subject !== holderId(address)) return "it was issued to a different account";
  if (entry.expiresAt <= nowMs) return "it has expired";
  const missing = challenge.claims.filter((name) => !(name in entry.claims));
  if (missing.length > 0) return `it does not contain ${missing.join(", ")}`;
  return "";
}

// The callback to send the user back to, or null. It must be http(s) and have the
// audience's origin, so a challenge cannot turn the wallet into an open redirect.
export function callbackUrl(challenge) {
  if (!challenge.callback_url) return null;
  let url;
  try {
    url = new URL(challenge.callback_url);
  } catch {
    return null;
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.origin !== challenge.audience) return null;
  url.searchParams.set("challenge", challenge.challenge_id);
  return url.toString();
}
