// Calls to the backend: the verifier (challenges) and the demo issuer.

async function call(base, path, { method = "GET", body } = {}) {
  let response;
  try {
    response = await fetch(base + path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error(`Could not reach ${base}. Is it running, and does it allow this wallet's origin (CORS_ALLOWED_ORIGINS)?`);
  }
  let data = null;
  try {
    data = await response.json();
  } catch {
    // an empty or non-JSON body: the status still tells the story
  }
  return { status: response.status, data };
}

function failure(what, { status, data }) {
  return new Error(`${what} (HTTP ${status}${data?.error ? `: ${data.error}` : ""})`);
}

// The challenge a relying application posed, for the consent screen.
export async function getChallenge(verifier, id) {
  const res = await call(verifier, `/v1/challenges/${encodeURIComponent(id)}`);
  if (res.status === 404) throw new Error("This request is unknown to the verifier, or it was forgotten.");
  if (res.status === 410) throw new Error("This request has expired. Go back to the application and start again.");
  if (res.status !== 200) throw failure("Could not read the request", res);
  return res.data;
}

// Answers a challenge. Resolves to the verifier's outcome: {status, reason?}.
export async function respond(verifier, id, credential, holderSignature) {
  const res = await call(verifier, `/v1/challenges/${encodeURIComponent(id)}/response`, {
    method: "POST",
    body: { credential, holder_signature: holderSignature },
  });
  if (res.status === 200 || res.status === 503) return res.data;
  if (res.status === 409) throw new Error("This request was already answered.");
  if (res.status === 410) throw new Error("This request expired before it was answered.");
  throw failure("The verifier refused the response", res);
}

// Asks the issuer to revoke a credential it issued. Revocation is the issuer's
// act and is permanent; this wallet offers it only as a demo shortcut, against the
// development-only endpoint.
export async function revokeCredential(issuer, credential) {
  const res = await call(issuer, "/v1/credentials/revoke", { method: "POST", body: { credential } });
  if (res.status === 200) return;
  if (res.status === 422) throw new Error("The issuer would not revoke it: it is not a valid, unexpired credential from this issuer.");
  if (res.status === 404) throw new Error("The credential is not registered on chain, so there is nothing to revoke.");
  if (res.status === 501) throw new Error("This issuer has no registry configured, so it cannot revoke.");
  if (res.status === 503) throw new Error("The registry is unavailable right now. Nothing was revoked: try again.");
  throw failure("The issuer did not revoke the credential", res);
}

// Gets a KYC credential bound to `address` from the demo issuer. The issuer's
// approval step is simulated: development only.
export async function requestCredential(issuer, address, claims) {
  const approval = await call(issuer, "/v1/approvals/simulate", {
    method: "POST",
    body: { subject: `solana:${address}`, credential_type: "KYCStatus", outcome: "approved", claims },
  });
  if (approval.status !== 201) throw failure("The issuer did not record the approval", approval);
  const issued = await call(issuer, "/v1/credentials", {
    method: "POST",
    body: { approval_id: approval.data.approval_id },
  });
  if (issued.status !== 201) throw failure("The issuer did not issue the credential", issued);
  return issued.data.credential;
}
