# Verifyum, checked in your own browser

One page that verifies a Verifyum proof in the tab and reports its own verdict,
including when it refuses one. Live at
[aisenseapi.github.io/verifyum-browser-demo](https://aisenseapi.github.io/verifyum-browser-demo/).

It fetches a proof's signed metadata from the proof's own host, verifies the
Ed25519 service signature against the published key registry, looks for the
anchor on a Solana node you choose, rebuilds the on-chain memo, folds both
Merkle paths to the hourly and daily checkpoint roots, and reads which
independent parties hold that checkpoint. Three checkboxes break the proof on
purpose so you can watch the checks refuse it.

## Why it is hosted here

A verifier served by the service it verifies proves very little. This one is on
GitHub Pages, and nothing on the page is served by Verifyum: no library, no
framework, no bundle. SHA-256 and Ed25519 come from the browser's own WebCrypto.

The canonicalization (RFC 8785) and the Merkle rules in `assets/verify.js` are
written from the published protocol rather than copied from the Verifyum client,
on purpose. Running the service's own code against the service's own answer
would only show that the code agrees with itself. A second implementation that
reaches the same verdict is evidence about the protocol.

That still does not make this page neutral. AI SENSE wrote it. What it removes
is the host. What it adds is that the verdict is computed where you can watch
it happen.

## What it needed from the service

Until 2026-09-19 a proof's `/.well-known/verifyum.json` was served without
`Access-Control-Allow-Origin`, while the witness documents beside it were not.
A page anywhere else could therefore follow a proof's witnesses and never check
the signature on the proof itself. Building this demo is what found that, and
the header was added before the page could work.

## Limits worth knowing

- The public Solana RPCs that allow a browser keep a shallow history. The page
  says so plainly when a proof is older than what the node serves, rather than
  reporting a failure, and links to an explorer instead.
- Ed25519 in WebCrypto is recent. In an older browser the signature check
  reports that it was not performed here rather than showing a pass.
- The file panel needs the receipt written beside your file, because the nonce
  in it is the secret half. Verifyum never had it and cannot reproduce it.

## Layout

    index.html         the page
    assets/verify.js   the protocol, reimplemented from the specification
    assets/demo.js     drives the checks and writes what each one found
    assets/demo.css    styling

Every path is relative, never root relative, so the site works both at a domain
root and under a project path prefix. `.nojekyll` keeps GitHub from running
Jekyll over it.

## Licence

MIT. See `LICENSE`.
