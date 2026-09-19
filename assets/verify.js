/*
 * A second implementation of Verifyum verification, written from the
 * published protocol rather than copied from the Verifyum client.
 *
 * That is deliberate. Running Verifyum's own code against Verifyum's own
 * answer shows only that the code is self-consistent. An independent
 * implementation that reaches the same verdict is evidence about the
 * protocol. Everything below is the standard library: SHA-256 and Ed25519
 * come from WebCrypto, and nothing is bundled.
 *
 * Nothing here is served by Verifyum. The page it runs in is not either.
 */

const enc = new TextEncoder();

/* ---- RFC 8785 (JCS) -------------------------------------------------- *
 * Object keys sorted by UTF-16 code unit, which is what Array#sort does to
 * strings by default; no insignificant whitespace; UTF-8 output. The
 * documents Verifyum signs hold only strings, integers, objects, arrays and
 * null, so the number rules beyond integers are not needed and a value that
 * would need them is refused rather than guessed at.
 */
export function jcs(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("only integers are canonicalized here");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  throw new Error("value cannot be canonicalized: " + typeof value);
}

/* ---- bytes and digests ----------------------------------------------- */

export function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function base64url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

export function digestBytes(value) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error("not a digest string: " + String(value));
  }
  return Uint8Array.from(value.slice(7).match(/../g), (byte) => parseInt(byte, 16));
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export async function digest(bytes) {
  return "sha256:" + hex(await sha256(bytes));
}

function join(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}

/* ---- the commitment -------------------------------------------------- *
 * commitment = "sha256:" + hex(SHA-256("verifyum:commitment:v2" + LF + JCS(manifest)))
 */
export async function commitmentOf(manifest) {
  return digest(join(enc.encode("verifyum:commitment:v2\n"), enc.encode(jcs(manifest))));
}

/* ---- the Merkle tree -------------------------------------------------- *
 * A leaf is prefixed 0x00 and an interior node 0x01, so no leaf can be
 * replayed as a node.
 */
export async function proofLeafHash(metadata) {
  return digest(join(new Uint8Array([0]), enc.encode("verifyum:witness:proof-leaf:v1\n"), enc.encode(jcs(metadata))));
}

export async function checkpointLeafHash(hourlyCheckpointHash) {
  return digest(join(new Uint8Array([0]), enc.encode("verifyum:witness:checkpoint-leaf:v1\n"), digestBytes(hourlyCheckpointHash)));
}

async function nodeHash(left, right) {
  return digest(join(new Uint8Array([1]), enc.encode("verifyum:witness:node:v1\n"), digestBytes(left), digestBytes(right)));
}

/** Folds a path and returns the root it actually reaches. */
export async function foldPath(leafHash, path) {
  if (!Array.isArray(path) || path.length > 64) throw new Error("path must be an array of at most 64 steps");
  let current = leafHash;
  for (const [index, step] of path.entries()) {
    const keys = step && typeof step === "object" ? Object.keys(step).sort().join(",") : "";
    if (keys !== "hash,side") throw new Error(`path step ${index} must have exactly side and hash`);
    if (step.side === "left") current = await nodeHash(step.hash, current);
    else if (step.side === "right") current = await nodeHash(current, step.hash);
    else throw new Error(`path step ${index}: side must be left or right`);
  }
  return current;
}

/* ---- the service signature -------------------------------------------- *
 * Over JCS of the metadata with service_signature removed, verified against
 * the registry key named by key_id for the document's own network.
 */
export function ed25519Available() {
  return typeof crypto !== "undefined" && !!crypto.subtle;
}

export async function verifySignature(metadata, registry) {
  const signature = metadata.service_signature;
  if (!signature || typeof signature !== "object") return { ok: false, reason: "no service_signature" };
  if (Object.keys(signature).sort().join(",") !== "algorithm,key_id,value") {
    return { ok: false, reason: "service_signature must hold exactly algorithm, key_id and value" };
  }
  if (signature.algorithm !== "ed25519") return { ok: false, reason: "algorithm is not ed25519" };

  const network = metadata?.anchor?.network;
  const matches = (Array.isArray(registry?.keys) ? registry.keys : []).filter(
    (k) => k && k.key_id === signature.key_id && k.network === network && k.algorithm === "ed25519"
  );
  if (matches.length !== 1) {
    return { ok: false, reason: `the registry holds ${matches.length} keys named ${signature.key_id} for ${network}` };
  }

  const publicKey = base64url(matches[0].public_key);
  if (publicKey.length !== 32) return { ok: false, reason: "registry key is not 32 bytes" };
  const signatureBytes = base64url(signature.value);
  if (signatureBytes.length !== 64) return { ok: false, reason: "signature is not 64 bytes" };

  const { service_signature: _omitted, ...unsigned } = metadata;
  const message = enc.encode(jcs(unsigned));

  let key;
  try {
    key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return { ok: null, reason: "this browser has no Ed25519 in WebCrypto, so the signature was not checked here", bytes: message.length };
  }
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, message);
  return { ok, reason: ok ? null : "the signature does not verify", bytes: message.length, keyId: signature.key_id };
}

/* ---- the anchor, read from somebody else's node ----------------------- *
 * The public RPCs that allow a browser keep a shallow history, so this looks
 * through the anchor account's recent signatures for the memo and says so
 * plainly when it runs off the end rather than claiming a failure.
 */
export async function findAnchor(rpcUrl, address, memo, { pages = 3, limit = 1000 } = {}) {
  let before = null;
  let seen = 0;
  for (let page = 0; page < pages; page++) {
    const params = before ? { limit, before } : { limit };
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getSignaturesForAddress", params: [address, params] }),
    });
    if (!response.ok) throw new Error(`the RPC answered HTTP ${response.status}`);
    const payload = await response.json();
    if (payload.error) throw new Error(`the RPC answered: ${payload.error.message ?? "error"}`);
    const rows = payload.result ?? [];
    if (rows.length === 0) return { found: null, seen, exhausted: true };
    seen += rows.length;
    for (const row of rows) {
      if (typeof row.memo === "string" && row.memo.endsWith(memo)) return { found: row, seen, exhausted: false };
    }
    before = rows[rows.length - 1].signature;
  }
  return { found: null, seen, exhausted: false };
}
