/*
 * Drives the checks and writes what each one found. Every line the page
 * prints is a verdict this tab reached, never a field copied out of an
 * answer that claimed success.
 */
import {
  jcs, hex, digestBytes, sha256, commitmentOf,
  proofLeafHash, checkpointLeafHash, foldPath, verifySignature, findAnchor,
} from "./verify.js";

const PROOF_DOMAIN = "verifyum.com";
const REGISTRY_URL = "https://verifyum.com/.well-known/verifyum-service-keys.json";
const FEED_URL = "https://verifyum.com/feed.xml";
const DEFAULT_RPC = "https://solana-rpc.publicnode.com";
const PROOF_ID = /^[0-7][0-9a-hjkmnp-tv-z]{25}$/;

const $ = (id) => document.getElementById(id);
const results = $("results");
const summary = $("summary");

function row(label) {
  const item = document.createElement("li");
  item.className = "check running";
  item.innerHTML = `<span class="mark" aria-hidden="true"></span><div><p class="label"></p><p class="detail"></p></div>`;
  item.querySelector(".label").textContent = label;
  item.querySelector(".detail").textContent = "checking…";
  results.append(item);
  return {
    pass: (detail) => { item.className = "check pass"; item.querySelector(".detail").textContent = detail; return true; },
    fail: (detail) => { item.className = "check fail"; item.querySelector(".detail").textContent = detail; return false; },
    note: (detail) => { item.className = "check note"; item.querySelector(".detail").textContent = detail; return null; },
  };
}

async function getJSON(url) {
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`${url} answered HTTP ${response.status}`);
  return response.json();
}

/** The newest proof, so the shallow public RPC can always reach its anchor. */
async function newestProofId() {
  const response = await fetch(FEED_URL);
  if (!response.ok) throw new Error(`the feed answered HTTP ${response.status}`);
  const match = (await response.text()).match(/Proof ([0-7][0-9a-hjkmnp-tv-z]{25}) anchored/);
  return match ? match[1] : null;
}

function tampering() {
  return [...document.querySelectorAll("input[name=tamper]:checked")].map((input) => input.value);
}

function describeTampering(list) {
  const names = {
    commitment: "the commitment was changed",
    key: "the registry key was swapped for another",
    path: "a Merkle path step was altered",
  };
  return list.map((t) => names[t]).join(", ");
}

async function run() {
  results.replaceChildren();
  summary.textContent = "";
  summary.className = "summary";
  $("run").disabled = true;

  const broken = tampering();
  let proofId = $("proof").value.trim();
  const rpcUrl = $("rpc").value.trim() || DEFAULT_RPC;
  let verdicts = [];

  try {
    if (!PROOF_ID.test(proofId)) throw new Error(`"${proofId}" is not a proof id`);
    if (broken.length) {
      const warning = document.createElement("p");
      warning.className = "tampered-banner";
      warning.textContent = `Deliberately broken for this run: ${describeTampering(broken)}. The checks below should refuse it.`;
      results.append(warning);
    }

    /* 1. The signed document, read straight from the proof's own host. */
    const fetched = row("The proof answers a page it does not host");
    const metadataUrl = `https://${proofId}.${PROOF_DOMAIN}/.well-known/verifyum.json`;
    const metadata = await getJSON(metadataUrl);
    verdicts.push(fetched.pass(`${proofId}.${PROOF_DOMAIN} served its signed metadata to ${location.origin}`));

    if (broken.includes("commitment")) metadata.commitment = "sha256:" + "0".repeat(64);

    /* 2. The signature, against the published key registry. */
    const signed = row("The service signature verifies against the published key");
    const registry = await getJSON(REGISTRY_URL);
    if (broken.includes("key")) {
      const other = registry.keys.find((k) => k.key_id !== metadata.service_signature.key_id);
      if (other) registry.keys = registry.keys.map((k) => (k.key_id === metadata.service_signature.key_id ? { ...k, public_key: other.public_key } : k));
    }
    const signature = await verifySignature(metadata, registry);
    if (signature.ok === null) verdicts.push(signed.note(signature.reason));
    else if (signature.ok) verdicts.push(signed.pass(`Ed25519 over ${signature.bytes} canonical bytes, key ${signature.keyId}`));
    else verdicts.push(signed.fail(signature.reason));

    /* 3. The anchor, read from a node that is not Verifyum's. */
    const anchored = row("The anchor is on Solana, read from a node that is not Verifyum's");
    const anchor = metadata.anchor ?? {};
    try {
      const { found, seen, exhausted } = await findAnchor(rpcUrl, anchor.anchor_address, anchor.memo);
      if (found && found.err === null && found.signature === anchor.transaction_signature) {
        const when = new Date(found.blockTime * 1000).toISOString().replace("T", " ").slice(0, 16);
        verdicts.push(anchored.pass(`slot ${found.slot}, ${found.confirmationStatus}, ${when} UTC, memo matches, no error`));
      } else if (found) {
        verdicts.push(anchored.fail(`the memo is on chain but ${found.err !== null ? "the transaction failed" : "under a different signature"}`));
      } else {
        verdicts.push(anchored.note(
          `${new URL(rpcUrl).host} keeps a shallow history and this proof was not in the ${seen} most recent signatures${exhausted ? "" : " looked at"}. Open the explorer link below.`
        ));
      }
    } catch (error) {
      verdicts.push(anchored.note(`${new URL(rpcUrl).host} could not be asked: ${error.message}`));
    }

    /* 4. The memo says what the metadata says. */
    const memo = row("The on-chain memo carries this proof's own commitment");
    const expected = `verifyum:v2:id=${metadata.proof_id};alg=sha256;commitment=${String(metadata.commitment).slice(7)}`;
    verdicts.push(anchor.memo === expected
      ? memo.pass(`${expected.length} bytes, rebuilt here from the metadata and identical`)
      : memo.fail("the memo does not match the commitment in this document"));

    /* 5 and 6. The witness chain: the proof is in an hourly checkpoint, and
       that checkpoint is inside a daily one. */
    const chain = await getJSON(`https://${proofId}.${PROOF_DOMAIN}/.well-known/verifyum-witness-chain.json`);
    const membership = chain.proof_membership?.membership;
    const hourly = chain.proof_membership?.checkpoint;

    const inHour = row("The proof is inside the hourly checkpoint, by Merkle path");
    if (!membership || !hourly) {
      verdicts.push(inHour.note("this proof has no checkpoint yet; checkpoints are built shortly after the hour"));
    } else {
      const path = broken.includes("path") && membership.path.length
        ? membership.path.map((step, index) => (index === 0 ? { ...step, hash: "sha256:" + "1".repeat(64) } : step))
        : membership.path;
      const leaf = await proofLeafHash(metadata);
      const reached = await foldPath(leaf, path);
      verdicts.push(reached === hourly.merkle_root
        ? inHour.pass(`${path.length} steps from leaf ${leaf.slice(7, 19)}… to root ${reached.slice(7, 19)}…`)
        : inHour.fail(`the path reaches ${reached.slice(7, 19)}…, not the published root ${hourly.merkle_root.slice(7, 19)}…`));

      const inDay = row("That hourly checkpoint is inside the daily one");
      const daily = chain.daily_checkpoint;
      const dailyMembership = chain.daily_membership;
      if (!daily || !dailyMembership) {
        verdicts.push(inDay.note("the daily checkpoint is built just after midnight UTC and is not published yet"));
      } else {
        const leafOfHour = await checkpointLeafHash(hourly.checkpoint_hash);
        const dailyRoot = await foldPath(leafOfHour, dailyMembership.path);
        verdicts.push(dailyRoot === daily.merkle_root
          ? inDay.pass(`${dailyMembership.path.length} steps to the daily root for ${daily.period_start.slice(0, 10)}`)
          : inDay.fail("the hourly checkpoint does not fold into the published daily root"));
      }

      /* 7. Who else holds this, and it is not us. */
      const witnesses = row("Other parties hold the same checkpoint");
      if (!chain.daily_receipts_url) {
        verdicts.push(witnesses.note("no daily receipts are published for this checkpoint yet"));
      } else {
        const receipts = await getJSON(chain.daily_receipts_url);
        const confirmed = (receipts.channels ?? []).filter((c) => c.state === "confirmed").map((c) => c.channel);
        verdicts.push(confirmed.length
          ? witnesses.pass(`${confirmed.length} confirmed: ${confirmed.join(", ")}`)
          : witnesses.note("no channel has confirmed this checkpoint yet"));
      }
    }

    const links = $("links");
    links.hidden = false;
    links.innerHTML = "";
    for (const [text, href] of [
      ["The document this page read", metadataUrl],
      ["The same transaction in an explorer", `https://explorer.solana.com/tx/${anchor.transaction_signature}`],
      ["The witness chain", `https://${proofId}.${PROOF_DOMAIN}/.well-known/verifyum-witness-chain.json`],
    ]) {
      const a = document.createElement("a");
      a.href = href; a.textContent = text; a.rel = "noreferrer noopener"; a.target = "_blank";
      links.append(a);
    }
  } catch (error) {
    const failed = row("The run finished");
    verdicts.push(failed.fail(error.message));
  }

  const failures = verdicts.filter((v) => v === false).length;
  const passes = verdicts.filter((v) => v === true).length;
  if (broken.length) {
    summary.className = failures ? "summary good" : "summary bad";
    summary.textContent = failures
      ? `${failures} check${failures === 1 ? "" : "s"} refused the altered proof. That is the demonstration: it can say no.`
      : "Nothing refused the altered proof. That is a defect in this page, and worth reporting.";
  } else {
    summary.className = failures ? "summary bad" : "summary good";
    summary.textContent = failures
      ? `${failures} check${failures === 1 ? "" : "s"} failed.`
      : `${passes} checks passed, none of them on Verifyum's word.`;
  }
  $("run").disabled = false;
}

/* ---- the optional half: a file you hold ------------------------------- */

async function checkFile() {
  const fileInput = $("file");
  const receiptInput = $("receipt");
  const output = $("file-result");
  output.className = "summary";
  if (!fileInput.files[0] || !receiptInput.files[0]) {
    output.textContent = "Choose both the original file and the receipt written beside it.";
    return;
  }
  try {
    const receipt = JSON.parse(await receiptInput.files[0].text());
    const manifest = receipt?.private_draft?.manifest;
    // Receipts from `verifyum stamp` in the Node client 1.2.0 to 1.4.0 are
    // real receipts with private_draft: null, so say that rather than that the
    // file is not a receipt at all.
    if (!manifest && typeof receipt?.proof_id === "string" && receipt?.private_draft === null) {
      throw new Error("this receipt holds no private draft with a nonce, so nothing can tie the file to its proof. The Node verifyum stamp from 1.2.0 to 1.4.0, which the GitHub action ran until 9 November 2026, wrote receipts like this. Stamp the file again with 1.4.1 or later.");
    }
    if (!manifest) throw new Error("that file is not a Verifyum receipt: no private_draft.manifest");

    const bytes = new Uint8Array(await fileInput.files[0].arrayBuffer());
    const fileHash = hex(await sha256(bytes));
    if (fileHash !== manifest.file?.hash?.value) throw new Error("this is not the file the receipt describes: the SHA-256 differs");
    if (String(bytes.length) !== String(manifest.file?.size)) throw new Error("the file length differs from the receipt");

    const rebuilt = await commitmentOf(manifest);
    if (rebuilt !== receipt.commitment) throw new Error("the receipt's own commitment does not follow from its manifest");

    const proofId = receipt.proof_id;
    const metadata = await getJSON(`https://${proofId}.${PROOF_DOMAIN}/.well-known/verifyum.json`);
    if (metadata.commitment !== rebuilt) throw new Error("the anchored commitment is for different bytes");

    output.className = "summary good";
    output.textContent = `These exact bytes are the ones committed in proof ${proofId}. Recomputed here from your file and the nonce in your receipt; nothing was uploaded.`;
  } catch (error) {
    output.className = "summary bad";
    output.textContent = error.message;
  }
}

/* ---- wiring ----------------------------------------------------------- */

$("run").addEventListener("click", run);
$("check-file").addEventListener("click", checkFile);
$("rpc").placeholder = DEFAULT_RPC;

(async () => {
  try {
    const newest = await newestProofId();
    if (newest) {
      $("proof").value = newest;
      $("proof-note").textContent = "Prefilled with the most recently anchored proof, taken from the public feed.";
    }
  } catch {
    $("proof-note").textContent = "Enter a proof id to verify.";
  }
})();
