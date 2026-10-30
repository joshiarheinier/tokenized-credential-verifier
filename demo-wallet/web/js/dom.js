// Tiny DOM helpers. Text is always added as text nodes, never parsed as HTML:
// what the wallet shows (challenges, credential claims) comes from outside.

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (name === "class") node.className = value;
    else if (name.startsWith("on")) node.addEventListener(name.slice(2), value);
    else if (value === true) node.setAttribute(name, "");
    else if (value !== false && value != null) node.setAttribute(name, value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function show(node, text, isError = false) {
  node.textContent = text;
  node.className = isError ? "notice error" : "notice";
  node.hidden = !text;
}

export function formatTime(ms) {
  return new Date(ms).toLocaleString();
}
