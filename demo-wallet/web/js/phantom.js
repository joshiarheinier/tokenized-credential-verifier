// Phantom: the holder's key. Phantom holds the keypair and signs messages; it
// stores nothing of ours and no transaction is ever sent, so the account needs no
// funds and no network.

export function getProvider(win = globalThis.window) {
  const provider = win?.phantom?.solana;
  return provider?.isPhantom ? provider : null;
}

// Connects and returns the account's address (base58). With `silent`, only
// reconnects if the user already approved this site, without a popup.
export async function connect(provider, { silent = false } = {}) {
  const result = await provider.connect(silent ? { onlyIfTrusted: true } : undefined);
  const key = result?.publicKey ?? provider.publicKey;
  if (!key) throw new Error("Phantom did not return an account");
  return key.toString();
}

// Asks Phantom to sign `text` and returns the 64-byte Ed25519 signature. Phantom
// shows the text to the user, who can refuse.
export async function signMessage(provider, text) {
  const result = await provider.signMessage(new TextEncoder().encode(text), "utf8");
  const signature = result?.signature;
  if (!signature || signature.length !== 64) throw new Error("Phantom returned an unexpected signature");
  return signature;
}

// Phantom reports a refusal as an error with code 4001.
export function userRejected(error) {
  return error?.code === 4001;
}
