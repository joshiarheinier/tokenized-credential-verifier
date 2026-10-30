// Run with: node --test   (from demo-wallet; Node 20 or newer)
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  callbackUrl,
  decodeCredential,
  expiryText,
  holderId,
  makeEntry,
  signedMessage,
  toBase64,
  whyUnusable,
} from "../web/js/protocol.js";

const challenge = {
  audience: "http://localhost:9090",
  challenge_id: "AAAAAAAAAAAAAAAAAAAAAA",
  credential_type: "KYCStatus",
  claims: ["over_18"],
  expires_at: "2026-11-03T10:15:00Z",
  callback_url: "http://localhost:9090/callback",
};

// Pinned in Go as well (internal/domain/challenge): the two must agree byte for byte.
const PINNED =
  "tcv-challenge-response/v1\n" +
  "audience: http://localhost:9090\n" +
  "challenge: AAAAAAAAAAAAAAAAAAAAAA\n" +
  "type: KYCStatus\n" +
  "claims: over_18\n" +
  "credential: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n" +
  "expires: 2026-11-03T10:15:00Z";

function credentialToken(payload) {
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${b64url({ alg: "EdDSA" })}.${b64url(payload)}.${Buffer.from("sig").toString("base64url")}`;
}

test("the signed text is exactly what the verifier rebuilds", async () => {
  assert.equal(await signedMessage(challenge, "test"), PINNED);
});

test("claims are sorted and joined", async () => {
  const message = await signedMessage({ ...challenge, claims: ["tier", "active", "over_18"] }, "test");
  assert.match(message, /\nclaims: active,over_18,tier\n/);
});

test("the expiry is written to the second, in UTC, truncated like Go does", () => {
  assert.equal(expiryText("2026-11-03T10:15:00Z"), "2026-11-03T10:15:00Z");
  assert.equal(expiryText("2026-11-03T10:15:00.999999999Z"), "2026-11-03T10:15:00Z");
  assert.equal(expiryText("2026-11-03T17:15:00.5+07:00"), "2026-11-03T10:15:00Z");
  assert.throws(() => expiryText("soon"), /expiry/);
});

// The vector Go verifies in TestVerifiesASignatureMadeByTheWalletsJavaScript.
test("a signature over the text, made in JavaScript, is the one Go verifies", async () => {
  const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const key = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  const signature = crypto.sign(null, Buffer.from(await signedMessage(challenge, "test")), key);
  assert.equal(
    toBase64(signature),
    "I5Uh4HRDnZhfeAtM260c3m4koTqzH5+88iXNixq/4DNZDXCbGFMYP8vFHsM6lzHFfdakEHfmT2vjPE5Ev3EDDw==",
  );
});

test("decodeCredential reads what a credential says, and refuses non-credentials", () => {
  const token = credentialToken({
    iss: "did:example:issuer",
    sub: "solana:abc",
    credential_type: "KYCStatus",
    exp: 1_900_000_000,
    claims: { over_18: true },
  });
  assert.deepEqual(decodeCredential(token), {
    issuer: "did:example:issuer",
    subject: "solana:abc",
    type: "KYCStatus",
    expiresAt: 1_900_000_000_000,
    claims: { over_18: true },
  });
  for (const bad of ["", "a.b", "a.!!!.c", credentialToken({ sub: "x" }), `a.${Buffer.from("not json").toString("base64url")}.c`]) {
    assert.throws(() => decodeCredential(bad), /not a credential/, `accepted ${JSON.stringify(bad)}`);
  }
});

test("a stored entry gets a stable id", async () => {
  const token = credentialToken({ iss: "i", sub: "s", credential_type: "T", exp: 1, claims: {} });
  const a = await makeEntry(token, 1);
  const b = await makeEntry(token, 2);
  assert.equal(a.id, b.id);
  assert.equal(a.id.length, 12);
  assert.equal(a.credential, token);
});

test("whyUnusable explains each way a credential cannot answer", () => {
  const address = "ABC";
  const entry = {
    type: "KYCStatus",
    subject: holderId(address),
    expiresAt: Date.now() + 60_000,
    claims: { over_18: true, country: "ID" },
  };
  assert.equal(whyUnusable(entry, challenge, address), "");
  assert.match(whyUnusable({ ...entry, type: "Membership" }, challenge, address), /Membership/);
  assert.match(whyUnusable(entry, challenge, "OTHER"), /different account/);
  assert.match(whyUnusable({ ...entry, expiresAt: Date.now() - 1 }, challenge, address), /expired/);
  assert.match(whyUnusable({ ...entry, claims: {} }, challenge, address), /does not contain over_18/);
});

test("the callback is only ever the application's own origin", () => {
  assert.equal(callbackUrl(challenge), "http://localhost:9090/callback?challenge=AAAAAAAAAAAAAAAAAAAAAA");
  assert.equal(
    callbackUrl({ ...challenge, callback_url: "http://localhost:9090/cb?x=1" }),
    "http://localhost:9090/cb?x=1&challenge=AAAAAAAAAAAAAAAAAAAAAA",
  );
  assert.equal(callbackUrl({ ...challenge, callback_url: "https://evil.example/cb" }), null);
  assert.equal(callbackUrl({ ...challenge, callback_url: "javascript:alert(1)" }), null);
  assert.equal(callbackUrl({ ...challenge, callback_url: "not a url" }), null);
  assert.equal(callbackUrl({ ...challenge, callback_url: undefined }), null);
});
