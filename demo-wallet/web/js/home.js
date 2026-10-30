// The wallet's home page: connect Phantom, see and delete credentials, get one
// from the demo issuer.

import { createAccount } from "./account.js";
import { requestCredential, revokeCredential } from "./api.js";
import { loadConfig } from "./config.js";
import { el, formatTime, show } from "./dom.js";
import { holderId, makeEntry } from "./protocol.js";
import * as store from "./storage.js";

const $ = (id) => document.getElementById(id);
const status = $("status");

let config;
let credentials = [];

const account = createAccount($("account"), render, (message) => show(status, message, true));

function render() {
  const box = $("credentials");
  box.replaceChildren();
  if (credentials.length === 0) {
    box.append(el("p", { class: "hint" }, "No credentials yet. Get one below."));
  }
  for (const c of credentials) {
    const mine = account.state.address && c.subject === holderId(account.state.address);
    box.append(
      el("div", { class: "credential" },
        el("div", { class: "title" },
          el("strong", {}, c.type),
          el("span", {},
            c.revokedAt ? el("span", { class: "badge bad" }, "revoked ") : null,
            el("span", { class: mine ? "badge ok" : "badge" }, mine ? "bound to this account" : "bound to another account"))),
        el("div", { class: "meta" }, `Issued by ${c.issuer}. Expires ${formatTime(c.expiresAt)}.`),
        el("details", {},
          el("summary", {}, "Claims"),
          el("dl", {}, Object.entries(c.claims).flatMap(([name, value]) => [el("dt", {}, name), el("dd", {}, String(value))]))),
        el("p", { class: "actions" },
          c.revokedAt ? null : el("button", { onclick: () => askToRevoke(c) }, "Revoke (demo)"),
          el("button", { onclick: () => removeCredential(c) }, "Remove from wallet"))),
    );
  }
  $("where").textContent = `This wallet is at ${location.origin} and holds ${credentials.length} credential${credentials.length === 1 ? "" : "s"}. ` +
    "A credential is kept at the address where you got it.";
  $("request-button").disabled = !account.state.address;
}

async function askToRevoke(entry) {
  const ok = confirm(
    `Ask the issuer to revoke this ${entry.type} credential?\n\n` +
      "Revoking is permanent: every verifier will refuse it from now on. In real life the issuer revokes, not the holder; this button is a demo shortcut.",
  );
  if (!ok) return;
  show(status, "Asking the issuer to revoke it…");
  try {
    await revokeCredential(config.issuer, entry.credential);
    store.save({ ...entry, revokedAt: Date.now() });
    credentials = store.loadAll();
    show(status, "Revoked on chain. Every verifier will now refuse this credential. It is still in this wallet; remove it if you like.");
  } catch (error) {
    show(status, error.message, true);
  }
  window.scrollTo({ top: 0 });
  render();
}

function removeCredential(entry) {
  const ok = confirm(
    `Remove this ${entry.type} credential from this wallet?\n\n` +
      "Only this wallet's copy is removed. The credential stays valid until it expires or its issuer revokes it, and anyone holding a copy can still use it. Use Revoke first if you want it refused.",
  );
  if (!ok) return;
  try {
    store.remove(entry.id);
    credentials = store.loadAll();
    show(status, "Removed from this wallet. It is not revoked: it stays valid on chain until it expires or the issuer revokes it.");
  } catch (error) {
    show(status, error.message, true);
  }
  render();
}

$("request-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!account.state.address) return;
  $("request-button").disabled = true;
  show(status, "Asking the issuer…");
  try {
    const token = await requestCredential(config.issuer, account.state.address, {
      kyc_verified: $("kyc").checked,
      over_18: $("over18").checked,
      country: $("country").value.trim().toUpperCase(),
    });
    store.save(await makeEntry(token));
    credentials = store.loadAll();
    show(status, `Credential stored in this wallet, which now holds ${credentials.length}.`);
    window.scrollTo({ top: 0 });
  } catch (error) {
    show(status, error.message, true);
    window.scrollTo({ top: 0 });
  }
  render();
});

try {
  config = await loadConfig();
  credentials = store.loadAll();
  await account.init();
} catch (error) {
  show(status, error.message, true);
}
render();
