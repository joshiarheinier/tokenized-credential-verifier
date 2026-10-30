// The wallet's credential storage: this browser's localStorage, for this origin.
// Credentials are kept as they are, unencrypted. They are personal data, so this
// is a demo-grade store; the page says so.

const KEY = "tcv-wallet-credentials-v1";

// Whether `e` has the shape the wallet writes. Anything else in storage (an old
// version, hand editing) is ignored rather than allowed to break the page.
function isEntry(e) {
  return (
    typeof e?.id === "string" &&
    typeof e.credential === "string" &&
    typeof e.type === "string" &&
    typeof e.subject === "string" &&
    typeof e.issuer === "string" &&
    Number.isFinite(e.expiresAt) &&
    e.claims !== null &&
    typeof e.claims === "object"
  );
}

export function loadAll(storage = globalThis.localStorage) {
  try {
    const list = JSON.parse(storage.getItem(KEY) ?? "[]");
    return Array.isArray(list) ? list.filter(isEntry) : [];
  } catch {
    return [];
  }
}

function write(list, storage) {
  try {
    storage.setItem(KEY, JSON.stringify(list));
  } catch {
    throw new Error("This browser would not let the wallet store the credential (private window or blocked site data?).");
  }
}

const DISCONNECTED = "tcv-wallet-phantom-disconnected";

// Whether the user pressed Disconnect. Phantom itself keeps approving this site,
// so without this note the wallet would reconnect silently on every reload.
export function wasDisconnected(storage = globalThis.localStorage) {
  try {
    return storage.getItem(DISCONNECTED) === "1";
  } catch {
    return false;
  }
}

export function setDisconnected(disconnected, storage = globalThis.localStorage) {
  try {
    if (disconnected) storage.setItem(DISCONNECTED, "1");
    else storage.removeItem(DISCONNECTED);
  } catch {
    // best effort: the worst case is a silent reconnect
  }
}

// Stores an entry, replacing one with the same id.
export function save(entry, storage = globalThis.localStorage) {
  write([entry, ...loadAll(storage).filter((e) => e.id !== entry.id)], storage);
}

export function remove(id, storage = globalThis.localStorage) {
  write(loadAll(storage).filter((e) => e.id !== id), storage);
}
