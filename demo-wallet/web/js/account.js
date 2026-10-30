// The Phantom connection, shared by both pages: holds who is connected and draws
// the connect / disconnect controls.

import { el } from "./dom.js";
import { connect, getProvider } from "./phantom.js";
import { setDisconnected, wasDisconnected } from "./storage.js";

// `onChange` runs after the connected account changes. `onError` gets messages.
export function createAccount(container, onChange, onError) {
  const provider = getProvider();
  const state = { provider, address: null };

  function draw() {
    container.replaceChildren();
    if (!provider) {
      container.append(
        el("p", {}, "Phantom was not found in this browser. ",
          el("a", { href: "https://phantom.app/download", target: "_blank", rel: "noopener" }, "Install Phantom"),
          " and reload this page."),
      );
    } else if (state.address) {
      container.append(
        el("p", {}, "Connected: ", el("code", {}, state.address)),
        el("button", { onclick: disconnect }, "Disconnect"),
      );
    } else {
      container.append(
        el("p", { class: "hint" }, "Connect your Phantom account. Nothing is sent to anyone and no funds are needed."),
        el("button", { class: "primary", onclick: pressConnect }, "Connect Phantom"),
      );
    }
  }

  async function pressConnect() {
    try {
      state.address = await connect(provider);
      setDisconnected(false);
    } catch (error) {
      onError(error?.code === 4001 ? "Phantom connection was declined." : (error?.message ?? "Could not connect to Phantom."));
    }
    draw();
    onChange();
  }

  async function disconnect() {
    try {
      await provider.disconnect();
    } catch {
      // already disconnected
    }
    state.address = null;
    setDisconnected(true);
    draw();
    onChange();
  }

  // Reconnects silently if this site was approved before and the user did not
  // press Disconnect, then draws.
  async function init() {
    if (provider) {
      provider.on?.("accountChanged", (key) => {
        state.address = key ? key.toString() : null;
        draw();
        onChange();
      });
      provider.on?.("disconnect", () => {
        state.address = null;
        draw();
        onChange();
      });
      if (!wasDisconnected()) {
        try {
          state.address = await connect(provider, { silent: true });
        } catch {
          // not approved yet: the user connects with the button
        }
      }
    }
    draw();
  }

  return { state, init };
}
