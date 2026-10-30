// Which backend the page talks to, as set by `demo-wallet serve`.
export async function loadConfig() {
  const response = await fetch("/config.json");
  if (!response.ok) throw new Error("The wallet could not load its configuration.");
  return response.json();
}
