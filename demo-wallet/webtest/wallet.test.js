import assert from "node:assert/strict";
import test from "node:test";

import { getChallenge, requestCredential, respond, revokeCredential } from "../web/js/api.js";
import { connect, getProvider, signMessage, userRejected } from "../web/js/phantom.js";
import { loadAll, remove, save } from "../web/js/storage.js";

// --- Phantom ---------------------------------------------------------------

test("only a real Phantom provider is used", () => {
  assert.equal(getProvider({}), null);
  assert.equal(getProvider({ phantom: { solana: { isPhantom: false } } }), null);
  const provider = { isPhantom: true };
  assert.equal(getProvider({ phantom: { solana: provider } }), provider);
});

test("connect returns the address, and a silent connect asks for no popup", async () => {
  let seen;
  const provider = {
    connect: async (options) => {
      seen = options;
      return { publicKey: { toString: () => "ADDR" } };
    },
  };
  assert.equal(await connect(provider), "ADDR");
  assert.equal(seen, undefined);
  await connect(provider, { silent: true });
  assert.deepEqual(seen, { onlyIfTrusted: true });
});

test("signMessage sends the UTF-8 bytes and insists on a 64-byte signature", async () => {
  let sent;
  const good = { signMessage: async (bytes, encoding) => ((sent = [bytes, encoding]), { signature: new Uint8Array(64) }) };
  assert.equal((await signMessage(good, "hello")).length, 64);
  assert.deepEqual([...sent[0]], [...new TextEncoder().encode("hello")]);
  assert.equal(sent[1], "utf8");

  const bad = { signMessage: async () => ({ signature: new Uint8Array(10) }) };
  await assert.rejects(signMessage(bad, "x"), /unexpected signature/);
});

test("a refusal in Phantom is recognised", () => {
  assert.equal(userRejected({ code: 4001 }), true);
  assert.equal(userRejected(new Error("boom")), false);
});

// --- storage ---------------------------------------------------------------

function memoryStorage() {
  const data = new Map();
  return {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => data.set(k, v),
  };
}

const entry = (id, extra = {}) => ({
  id, credential: `token-${id}`, type: "KYCStatus", subject: "solana:A", issuer: "did:example:i", expiresAt: 1, claims: {}, ...extra,
});

test("storage keeps, replaces and removes credentials", () => {
  const storage = memoryStorage();
  save(entry("a"), storage);
  save(entry("b"), storage);
  save(entry("a", { issuer: "changed" }), storage);
  assert.deepEqual(loadAll(storage).map((e) => e.id), ["a", "b"]);
  assert.equal(loadAll(storage)[0].issuer, "changed");
  remove("a", storage);
  assert.deepEqual(loadAll(storage).map((e) => e.id), ["b"]);
});

test("storage ignores damaged contents instead of breaking the page", () => {
  const storage = memoryStorage();
  storage.setItem("tcv-wallet-credentials-v1", "{not json");
  assert.deepEqual(loadAll(storage), []);
  storage.setItem("tcv-wallet-credentials-v1", JSON.stringify([entry("ok"), { id: "bad" }, null, 5]));
  assert.deepEqual(loadAll(storage).map((e) => e.id), ["ok"]);
});

test("storage says so when the browser will not store", () => {
  const blocked = { getItem: () => null, setItem: () => { throw new Error("quota"); } };
  assert.throws(() => save(entry("a"), blocked), /would not let the wallet store/);
});

// --- backend calls ---------------------------------------------------------

function stubFetch(handler) {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method ?? "GET", body: options.body ? JSON.parse(options.body) : undefined });
    const { status, body } = handler(url, options);
    return { status, json: async () => { if (body === undefined) throw new Error("no body"); return body; } };
  };
  return calls;
}

test("getChallenge maps the verifier's answers to messages", async () => {
  stubFetch(() => ({ status: 200, body: { challenge_id: "c1" } }));
  assert.equal((await getChallenge("http://v", "c1")).challenge_id, "c1");

  stubFetch(() => ({ status: 404, body: { error: "x" } }));
  await assert.rejects(getChallenge("http://v", "c1"), /unknown to the verifier/);
  stubFetch(() => ({ status: 410, body: { error: "x" } }));
  await assert.rejects(getChallenge("http://v", "c1"), /expired/);
  stubFetch(() => ({ status: 500, body: { error: "boom" } }));
  await assert.rejects(getChallenge("http://v", "c1"), /HTTP 500: boom/);
});

test("respond puts the challenge id in the path and the signature in the body", async () => {
  const calls = stubFetch(() => ({ status: 200, body: { status: "verified" } }));
  assert.deepEqual(await respond("http://v", "c 1", "tok", "c2ln"), { status: "verified" });
  assert.equal(calls[0].url, "http://v/v1/challenges/c%201/response");
  assert.equal(calls[0].method, "POST");
  assert.deepEqual(calls[0].body, { credential: "tok", holder_signature: "c2ln" });
});

test("respond passes on an unavailable verifier and explains a spent challenge", async () => {
  stubFetch(() => ({ status: 503, body: { status: "unavailable", reason: "verification_unavailable" } }));
  assert.equal((await respond("http://v", "c", "t", "s")).status, "unavailable");
  stubFetch(() => ({ status: 409, body: { error: "used" } }));
  await assert.rejects(respond("http://v", "c", "t", "s"), /already answered/);
  stubFetch(() => ({ status: 410, body: { error: "gone" } }));
  await assert.rejects(respond("http://v", "c", "t", "s"), /expired/);
});

test("requesting a credential asks for an approval bound to the account, then issues it", async () => {
  const calls = stubFetch((url) =>
    url.endsWith("/simulate")
      ? { status: 201, body: { approval_id: "ap1" } }
      : { status: 201, body: { credential: "the-token" } },
  );
  assert.equal(await requestCredential("http://i", "ADDR", { over_18: true }), "the-token");
  assert.equal(calls[0].body.subject, "solana:ADDR");
  assert.equal(calls[0].body.credential_type, "KYCStatus");
  assert.deepEqual(calls[1].body, { approval_id: "ap1" });
});

test("an unreachable backend is explained, with the likely cause", async () => {
  globalThis.fetch = async () => { throw new TypeError("fetch failed"); };
  await assert.rejects(getChallenge("http://v", "c"), /Could not reach http:\/\/v.*CORS_ALLOWED_ORIGINS/);
});

// --- explicit disconnect ----------------------------------------------------

test("pressing Disconnect is remembered, so a reload does not reconnect silently", async () => {
  const { setDisconnected, wasDisconnected } = await import("../web/js/storage.js");
  const data = new Map();
  const storage = { getItem: (k) => data.get(k) ?? null, setItem: (k, v) => data.set(k, v), removeItem: (k) => data.delete(k) };
  assert.equal(wasDisconnected(storage), false);
  setDisconnected(true, storage);
  assert.equal(wasDisconnected(storage), true);
  setDisconnected(false, storage);
  assert.equal(wasDisconnected(storage), false);
  // storage that throws must not break the wallet
  const broken = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => { throw new Error("blocked"); } };
  assert.equal(wasDisconnected(broken), false);
  assert.doesNotThrow(() => setDisconnected(true, broken));
});

test("revoking asks the issuer with the credential and explains each refusal", async () => {
  const calls = stubFetch(() => ({ status: 200, body: { revoked: true } }));
  await revokeCredential("http://i", "the-token");
  assert.equal(calls[0].url, "http://i/v1/credentials/revoke");
  assert.equal(calls[0].method, "POST");
  assert.deepEqual(calls[0].body, { credential: "the-token" });

  for (const [status, message] of [
    [422, /not a valid, unexpired credential/],
    [404, /not registered on chain/],
    [501, /no registry configured/],
    [503, /registry is unavailable/],
    [500, /HTTP 500/],
  ]) {
    stubFetch(() => ({ status, body: { error: "x" } }));
    await assert.rejects(revokeCredential("http://i", "t"), message, `status ${status}`);
  }
});
