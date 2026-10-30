// The consent page. An application opens it as /present?challenge=<id>; the user
// sees who is asking and for what, picks a credential, and approves by signing in
// Phantom. Nothing is sent before they approve.

import { createAccount } from "./account.js";
import { getChallenge, respond } from "./api.js";
import { loadConfig } from "./config.js";
import { el, formatTime, show } from "./dom.js";
import { signMessage, userRejected } from "./phantom.js";
import { callbackUrl, signedMessage, toBase64, whyUnusable } from "./protocol.js";
import * as store from "./storage.js";

const $ = (id) => document.getElementById(id);
const status = $("status");

let config;
let challenge;
let chosenId = null;
let busy = false;

const account = createAccount($("account"), render, (message) => show(status, message, true));

// Plain-language versions of the verifier's reasons.
const REASONS = {
  revoked: "The credential has been revoked by its issuer.",
  expired: "The credential has expired.",
  untrusted_issuer: "The credential's issuer is not trusted.",
  invalid_signature: "The credential's signature is not valid.",
  holder_binding_failed: "The credential is not bound to the account that signed.",
  claim_unavailable: "The credential does not provide what was asked for.",
  wrong_credential_type: "The credential is not of the requested type.",
  policy_not_satisfied: "The credential does not meet the application's requirements.",
  not_registered: "The credential is not registered with the trust registry.",
};

function sameBackend(a, b) {
  return a.replace(/\/+$/, "") === b.replace(/\/+$/, "");
}

function fail(message) {
  show(status, message, true);
}

function render() {
  if (!challenge) return;
  $("request-section").hidden = false;
  const box = $("request");
  box.replaceChildren();

  box.append(
    el("p", {}, el("strong", {}, challenge.audience), ` wants to verify a ${challenge.credential_type} credential.`),
    el("p", {}, "It is asking for: ", el("strong", {}, challenge.claims.join(", "))),
    el("p", { class: "hint" },
      "The verifier service checks the whole credential, but passes on to the application only what is asked for above. " +
        `This request expires ${formatTime(Date.parse(challenge.expires_at))}.`),
  );

  const address = account.state.address;
  if (!address) {
    box.append(el("p", {}, "Connect Phantom to choose a credential."));
    return;
  }

  const options = store.loadAll().map((entry) => ({ entry, why: whyUnusable(entry, challenge, address) }));
  const usable = options.filter((o) => !o.why);
  const unusable = options.filter((o) => o.why);

  if (options.length === 0) {
    box.append(
      el("p", {},
        `This wallet has no credentials at ${location.origin}. A credential is kept at the web address where you got it, ` +
          "so one obtained at another address (for example 127.0.0.1 instead of localhost) is not here. ",
        el("a", { href: "/" }, "Get one"), " for this Phantom account first."),
    );
  } else if (usable.length === 0) {
    box.append(el("p", {}, "None of the credentials in this wallet can answer this request, for the reasons below. ", el("a", { href: "/" }, "Get a new one"), " for this Phantom account if needed."));
  } else {
    if (!usable.some((o) => o.entry.id === chosenId)) chosenId = usable[0].entry.id;
    for (const { entry } of usable) {
      box.append(
        el("label", { class: "choice" },
          el("input", { type: "radio", name: "credential", checked: entry.id === chosenId, onchange: () => { chosenId = entry.id; render(); } }),
          ` ${entry.type} from ${entry.issuer}`,
          el("div", { class: "meta" }, `What would be shared: ${challenge.claims.map((n) => `${n} = ${String(entry.claims[n])}`).join(", ")}${entry.revokedAt ? " (revoked: the verifier will refuse it)" : ""}`)),
      );
    }
    box.append(
      el("div", { class: "actions" },
        el("button", { class: "primary", onclick: approve, disabled: busy }, "Approve and sign with Phantom"),
        el("button", { onclick: decline, disabled: busy }, "Decline")),
    );
  }
  for (const { entry, why } of unusable) {
    box.append(el("p", { class: "unusable" }, `Not usable: ${entry.type} from ${entry.issuer}, because ${why}.`));
  }
}

function showResult(headline, detail, isError) {
  $("request-section").hidden = true;
  $("result-section").hidden = false;
  const box = $("result");
  box.replaceChildren(el("p", { class: isError ? "notice error" : "notice" }, headline));
  if (detail) box.append(el("p", {}, detail));
  const back = callbackUrl(challenge);
  if (back) box.append(el("p", {}, el("a", { href: back }, `Return to ${challenge.audience}`)));
}

function showOutcome(outcome) {
  if (outcome.status === "verified") {
    showResult("Verified.", `${challenge.audience} can now see: ${challenge.claims.join(", ")}.`, false);
  } else if (outcome.status === "rejected") {
    showResult("The verifier refused this credential.", REASONS[outcome.reason] ?? `Reason: ${outcome.reason}.`, true);
  } else {
    showResult("The verifier could not check right now.", "Nothing was accepted. Start again from the application.", true);
  }
}

function decline() {
  showResult("You declined. Nothing was shared.", "", false);
}

async function approve() {
  const entry = store.loadAll().find((c) => c.id === chosenId);
  if (!entry || busy) return;
  busy = true;
  render();
  try {
    const message = await signedMessage(challenge, entry.credential);
    show(status, "Waiting for you in Phantom…");
    const signature = await signMessage(account.state.provider, message);
    show(status, "Sending to the verifier…");
    const outcome = await respond(config.verifier, challenge.challenge_id, entry.credential, toBase64(signature));
    show(status, "");
    showOutcome(outcome);
  } catch (error) {
    show(status, userRejected(error) ? "You declined in Phantom. Nothing was shared." : error.message, true);
  }
  busy = false;
  render();
}

async function main() {
  const params = new URLSearchParams(location.search);
  const id = params.get("challenge");
  if (!id) {
    fail("This page is opened by an application that wants to verify a credential, with a challenge id.");
    return;
  }
  config = await loadConfig();

  // The wallet sends credentials only to the verifier it is set up with, never to
  // one a link names: otherwise any application could point the wallet at its own
  // server and collect credentials.
  const named = params.get("verifier");
  if (named && !sameBackend(named, config.verifier)) {
    fail(`This request names a verifier this wallet is not set up to trust (${named}). It only talks to ${config.verifier}.`);
    return;
  }

  show(status, "Loading the request…");
  const loaded = await getChallenge(config.verifier, id);
  if (loaded.status === "completed") {
    fail("This request was already answered.");
    return;
  }
  challenge = loaded;
  show(status, "");
  $("account-section").hidden = false;
  await account.init();
  render();
}

main().catch((error) => fail(error.message));
