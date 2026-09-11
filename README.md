# libid-server-rs

The server side of a libID ceremony, and deliberately almost nothing.

A platform ceremony runs in the browser: it opens the provider, consumes the
redirect against its own live state, notarizes what it needs, and builds the
proof. The one thing a browser cannot hold is a confidential client secret,
which is why GitHub's token exchange happens here and why this service exists
at all. Google and X need no confidential route from it, and get none.

It keeps no ceremony state, no session, no challenge and no result. A timeout,
a duplicate request, a restart or a lost response leave no record here, and
recovery is a fresh ceremony rather than a lookup. It holds no wallet, pays no
gas, keeps no database, and talks to no chain.

Built on the [libid-rs](https://github.com/libid-org/libid-rs) crates
(MPC-TLS session driver, transcript math, ceremony wire constructions).

## How a GitHub claim works

1. The browser derives its PKCE verifier, opens GitHub's authorization page,
   and consumes the redirect against the ceremony it started. None of that
   reaches this service.
2. It calls `POST /api/v1/ceremony/github-token` with the authorization code
   and that verifier. This service performs the token exchange **inside a
   TLSNotary session**, revealing the client id, the code, the redirect URI
   and the verifier, and committing the client secret and the returned bearer
   rather than disclosing them.
3. It returns the bearer, the notary's attestation of that session, and the
   opening for the bearer commitment — one result from one session — and
   forgets all of it.
4. The browser checks that response against what it asked for, then runs its
   own notarized `GET /user` and builds the proof. This service sees none of
   that and verifies nothing.

## Trust model

**The notary is the only trust root.** This service signs nothing and holds no
key of its own: the single signature in a proof is the notary's, and this
service only carries what the notary said, byte for byte.

What it does hold is GitHub's client secret, and that is a real power — it can
perform an exchange nobody asked for. What it cannot do is make that exchange
look like someone else's ceremony: the browser checks that the returned
attestation reveals the exact code and verifier it supplied, and discards the
response otherwise. The secret buys a token, not a proof.

The configured origin and everything it serves are a code-supply-chain
boundary besides. A malicious server can replace the browser code it hands
out; origin checks and a closed input surface cannot constrain its owner.


## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe. Returns `OK`. Not one of the contract's routes — see below. |
| `GET` | `/api/v1/ceremony/config` | The public ceremony configuration. Readable only from an admitted origin. |
| `GET` | `{CALLBACK_PATH}` (default `/auth/callback`) | The registered OAuth callback document: the CCDP Distribution's artifact with this deployment's data inserted, identical for every request. |
| `POST` | `/api/v1/ceremony/github-token` | The confidential token exchange, run inside a TLSNotary session. Callable only from the configured CCDP origin — narrower than `/config`, which admits the whole allowlist — and it answers that origin's preflight. The body carries `notaryAddress`, the notary the browser resolved from the ledger; this bridge dials the same host on the wire port, refusing a private or internal one. `403` for any other origin or a refused notary, `400` for a query, `415` for any media type but exactly `application/json`. |

The contract's route surface is closed — "the bridge exposes only" the last
three — so `/health` is a deliberate deviation, kept because the published
image declares a `HEALTHCHECK` against it and an orchestrator needs somewhere
to ask. It takes no ceremony input, reads nothing from the request and answers
two bytes. It is also the one route that tolerates a query: a liveness probe
that answered `400` to a cache-buster would report a healthy service as
unhealthy and be restarted for it.

### `POST /api/v1/ceremony/github-token`

The one route a platform ceremony genuinely requires of a server, because it is
the one step needing a client secret.

Request — the code, the PKCE verifier and the notary the browser resolved from
the ledger; the client, secret, redirect URI and endpoint are this server's own:

```json
{ "code": "…", "codeVerifier": "…", "notaryAddress": "https://notary.example" }
```

Response. `accessToken` is the bearer as GitHub spelled it; the other two are
byte strings, unpadded URL-safe base64:

```json
{
  "accessToken": "…",
  "tokenAttestation": { "attestedData": "…", "signature": "…" },
  "bearerOpening": "…"
}
```

No `schema` member is carried: the route's path already versions this
transport. `attestedData` decodes to at most 2 MiB and `signature` to exactly
the 65 bytes a notary signature is; the whole encoded body is at most 3 MiB.

The exchange reveals what proves the request belongs to the ceremony — the
client id, the code, the redirect URI and the PKCE verifier — and commits the
`client_secret` and the returned bearer instead of disclosing them. The secret
is ordered last in the request body so the committed run is a suffix rather
than a hole, which is what lets the transcript tile.

The three values are one result. The attestation without the opening proves
nothing about the bearer, and the opening without the attestation proves
nothing at all, so a failure returns none of them and the caller starts a fresh
ceremony. Nothing about the request is stored: a timeout, a duplicate or a
restart leaves nothing to resume from.

Neither X nor Google gets a confidential route. Both run browser ↔ notary, and
a server-side X callback was proposed and rejected: X's flow is browser-only by
design and its callback belongs on the UI origin.


## The CCDP Distribution

The contract this server implements is `ts/packages/ceremony/OAUTH_BRIDGE.md`
in the libid repository (branch `docs/ceremony-browser-architecture`). Where
`specs/platform-ceremonies.md` §6.3 describes the same wire differently — route
path, a `schema` member, a single-string attestation — this server follows
OAUTH_BRIDGE.md, by decision.

This server is the **OAuth Bridge**, and only that. Everything the browser
executes — the Callback implementation, the prover, the circuits and
notarization client — is served by a separate static **CCDP Distribution** at
`CCDP_ORIGIN`, which may be cross-site and knows nothing about this bridge. The
bridge publishes configuration, serves one callback document, and performs
GitHub's exchange. It serves no CCDP resource and no proving asset.

### The callback document

The bridge does not write it. The Distribution builds one self-contained
artifact at `/ccdp/callback.html` carrying every supported Callback
implementation, with one non-executable slot for deployment data. The bridge
reads that artifact, substitutes **one unversioned list** —
`[allowedOrigins, ccdpOrigin]` — the effective admission set, which is
`ALLOWED_APP_ORIGINS` plus the resolved CCDP origin, and that origin —
into the slot, computes the response policy from the bytes it is about to
serve, and publishes the pair. It parses no OAuth `state`, selects no CCDP
version, and holds no version list: a compatible Callback change needs no
bridge rebuild.

The policy's `script-src` carries **only hashes, computed here over the served
bytes** — never copied from an upstream header, because a policy taken on trust
from the document it constrains is not a constraint. The artifact bundles its
dependencies, so no external script source appears at all.

The document is composed once at startup and never varies: no request field —
`Origin`, `Referer`, query, fragment — changes a byte of it or its policy. The
server never sees the provider's return: the handler reads nothing from the
request, and there is no request-logging middleware. **Any proxy in front of
this server must redact the callback path's query string from its access
logs** — that half of the contract is the operator's.

The artifact comes from `CALLBACK_ARTIFACT_PATH`, or from the binary when that
is unset. Both go through the same validation and the same composition — where
the bytes came from changes what is logged and nothing else, because a supplied
artifact is not more trusted than a compiled-in one.

The compiled-in one is a **floor**, deliberately not a working Callback: it
clears the OAuth return, renders fixed text and completes no ceremony, and the
process warns on every start while it is serving. It exists so the bridge always
has a valid document — the contract's "inert unavailable response" has no
representation here. **Set `CALLBACK_ARTIFACT_PATH` to run real ceremonies.**

The bridge does not fetch the artifact itself yet; obtaining it from the
Distribution is the deployment's job.

## What the operator has to supply

Two things this server deliberately does not do for itself.

**Redact the callback query from proxy access logs.** The handler reads
nothing from the request, so the authorization code never reaches this
process — but a proxy that logs request lines by default writes it to disk
before this server sees the request at all.

**Rate-limit `/api/v1/ceremony/github-token` by client.** The route caps
concurrent exchanges at 8 and answers `503` past that, which bounds how much
of this process one caller can hold at once. It is not rate limiting: the
`Origin` check is not caller authentication and says so, an anonymous caller
can retry as fast as it likes, and every accepted request spends the GitHub
client secret against the OAuth app's standing with GitHub. A per-client
limit belongs in the proxy, where the client is identified.

## Configuration

The bridge reads a TOML configuration file named by `LIBID_CONFIG` or
`--config`. Every key in it can be overridden by the environment variable or
flag of the same name; precedence is flag, then environment variable, then
file, then default. `bridge.toml.example` beside this README is a complete
starting point:

```toml
base_url            = "https://bridge.example"
allowed_app_origins = ["https://app.example", "https://wallet.example"]

[[platforms]]
id        = "github"
client_id = "Iv1.0123456789abcdef"
versions  = [1]
```

An unknown key is refused at startup. The platforms are set only in the file,
one `[[platforms]]` table per enabled platform: its `id` (`github`, `google` or
`x`), its public `client_id`, and the ceremony `versions` it advertises; the
GitHub token exchange implements version 1. `gh_oauth_client_secret` may be set
in the file or in the environment; a file that carries it stays out of version
control (`bridge.toml` is ignored by git).

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `host` | `HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in the container image). |
| `port` | `PORT` | `8722` | Bind port. |
| `base_url` | `BASE_URL` | `http://127.0.0.1:8722` | Public URL of this server, as a bare origin; HTTPS unless loopback. Every provider's registered callback URL must be exactly `{BASE_URL}{CALLBACK_PATH}`. |
| `allowed_app_origins` | `ALLOWED_APP_ORIGINS`, comma-separated | *(required)* | Application origins. Exact origins, no patterns; HTTPS unless loopback. Each must already be canonical — a trailing slash, an uppercase host or a default port is refused with the canonical spelling named, not folded — and a duplicate is refused. The **effective** admission set is this list plus the resolved `CCDP_ORIGIN`, added exactly once, and it governs the configuration route and what the callback document is told. The token route is deliberately narrower: it admits `CCDP_ORIGIN` alone, because the Prover is its only caller. |
| `callback_path` | `CALLBACK_PATH` | `/auth/callback` | The path providers redirect back to. The one route whose name a deployment chooses; there is no alias and no redirect. |
| `ccdp_origin` | `CCDP_ORIGIN` | `https://lib.id` | The CCDP Distribution this bridge selects: one origin serving `/ccdp/callback.html` and everything the browser runs after it, HTTPS unless loopback. Published in the configuration and inserted into the callback document. Omitting it selects the canonical libID Distribution. |
| `callback_artifact_path` | `CALLBACK_ARTIFACT_PATH` | *(empty)* | A `callback.html` obtained from the CCDP Distribution, served instead of the compiled-in floor. Read once at startup and held to the same shape either way. **Unset means the floor, which completes no ceremony** — set this to run real ceremonies. |
| `notary_wire_port` | `NOTARY_WIRE_PORT` | `7047` | The port of the notary's MPC-TLS wire listener. The notary itself is named by each token request's `notaryAddress`; this bridge dials that host on this port. A private or internal address is refused; loopback is not. |
| `platforms` | — | *(required)* | The enabled platforms, as `[[platforms]]` tables. File only. |
| `gh_oauth_client_secret` | `GH_OAUTH_CLIENT_SECRET` | *(none)* | GitHub OAuth App client secret. Required exactly when a platform is `github`, and refused otherwise. |
| — | `LIBID_CONFIG`, `--config` | *(none)* | Path to the configuration file. |

### On Google

Nothing here serves the Google ceremony. It gets no confidential route by
design — its identity evidence is a signed ID Token the browser reads out of
the redirect fragment, so there is no secret to hold and nothing to exchange.
The fragment relay this server used to serve is gone: the redirect document
that replaces it belongs to the ceremony's own redirect runtime, which handles
every platform, clears the fragment, and hands the response to the code in the
popup rather than bouncing it through a URL.

Google binds also revert with `UntrustedModulus` until a JWKS rotator runs
somewhere and publishes Google's current signing moduli on chain. This server
is not that rotator either.

## Running with Docker

```sh
docker run --rm -p 8722:8722 \
  -v ./bridge.toml:/etc/libid/bridge.toml:ro \
  -e LIBID_CONFIG=/etc/libid/bridge.toml \
  -e GH_OAUTH_CLIENT_SECRET=... \
  ghcr.io/libid-org/libid-server-rs:latest
```

Images are published on every GitHub release as
`ghcr.io/libid-org/libid-server-rs:<version>` and `:latest`. The image
listens on `0.0.0.0:8722` and carries a `/health` healthcheck.

## Building from source

```sh
cargo build --release          # rustc >= 1.95 (see rust-version in Cargo.toml)
cargo test
```

## License

Dual-licensed under MIT and Apache-2.0 — see `LICENSE-MIT`,
`LICENSE-APACHE` and `NOTICE`.
