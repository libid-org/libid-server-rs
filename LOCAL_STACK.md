# libID ceremony stack — local runbook

Everything below is running right now. Working copies are git **worktrees**, so
your own `libid` and `notary` checkouts were never touched.

    STACK=/home/horacio/.claude/jobs/48929bf8/tmp/stack

| port | what | note |
|---|---|---|
| 4691 | dev UI (vite, TLS) | the application origin |
| 4682 | **OAuth Bridge** (TLS) | → 8842 |
| 4683 | CCDP Distribution (TLS) | → 8787 |
| 7047 | notary TCP wire | what the **bridge** dials (MPC-TLS) |
| 7048 | notary WebSocket | what the **browser** reaches |

4682/4683/4691 are TLS because a browser will not run a ceremony over http.
`tls-front.mjs` terminates them onto the plain ports behind.

## Start, in this order

    # 1. notary  (anvil key #0 — a public test key, not a secret)
    $STACK/notary/target/release/notary \
      --signing-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

    # 2. CCDP distribution (pinned SWS image, already built)
    docker start libid-ccdp

    # 3. TLS front
    node /home/horacio/.claude/jobs/48929bf8/tmp/tls-front.mjs

    # 4. bridge
    /home/horacio/.claude/jobs/48929bf8/tmp/run-bridge.sh

    # 5. dev UI
    cd $STACK/libid/ts/packages/ceremony && pnpm dev

Then open **https://localhost:4691** (accept the self-signed cert).

## To run a REAL GitHub ceremony

The only thing missing. Create a GitHub OAuth app whose **Authorization
callback URL** is exactly:

    https://localhost:4682/auth/callback

then restart the bridge with its credentials:

    CEREMONY_PLATFORMS='[{"id":"github","clientId":"<CLIENT_ID>","versions":[1]}]' \
    GH_OAUTH_CLIENT_SECRET='<CLIENT_SECRET>' \
    /home/horacio/.claude/jobs/48929bf8/tmp/run-bridge.sh

## Rebuilding the CCDP artifacts

`@libid/ledger` and `@libid/popup` must be built first — their missing `dist/`
is what breaks `build:ccdp-artifacts` with an unhelpful error.

    cd $STACK/libid/ts && pnpm install
    pnpm --filter @libid/ledger build && pnpm --filter @libid/popup build
    pnpm --filter @libid/ceremony build:ccdp-artifacts

## Probing the bridge without a browser

    T=https://localhost:4682/api/v1/ceremony/github-token
    curl -sk -H 'Origin: https://localhost:4691' \
      https://localhost:4682/api/v1/ceremony/config
    curl -sk -X POST -H 'Origin: https://localhost:4683' \
      -H 'Content-Type: application/json' --data @/home/horacio/.claude/jobs/48929bf8/tmp/tok.json $T

## Rebuilding the CCDP artifacts — the three things that are easy to miss

    cd $STACK/libid/ts/packages/ceremony
    LIBID_LEDGER_FIXTURE=1 LIBID_NOTARY_ADDRESS=https://localhost:7048 \
      node build/distribution.ts --out-dir "$PWD/.cache/qualification"

- **`LIBID_LEDGER_FIXTURE=1`** or `@libid/ledger` ships a stub whose `decode`
  always throws, and the prover dies on `test:testnet`. The build then refuses
  any `--out-dir` outside `.cache`, which is why the path is spelled out.
- **`LIBID_NOTARY_ADDRESS`** or the artifacts name `notary.lib.id` and
  `testnet.notary.lib.id`. The bridge refuses the request
  (*"does not serve the notary this request names"*) and it also lands in the
  prover document's `connect-src`.
- **The container serves its own copy.** `libid-ccdp:local` bakes `public/` and
  `sws.toml` in, so a rebuild changes nothing until the image is rebuilt — or,
  better, run it with the artifacts bind-mounted:

      docker run -d --name libid-ccdp -p 8787:8787 \
        -v "$Q/public":/home/sws/public:ro \
        -v "$Q/sws.toml":/etc/sws.toml:ro libid-ccdp:local

Restart the bridge after any rebuild: it reads `callback.html` once, at startup,
and computes the CSP hash from those bytes.
