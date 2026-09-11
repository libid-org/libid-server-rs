# libid-server-rs

The server side of a libID ceremony.

A platform ceremony runs in the browser: it opens the provider, consumes the
redirect against its own live state, notarizes what it needs, and builds the
proof. The one thing a browser cannot hold is a confidential client secret, so
GitHub's token exchange happens here. Google and X have no confidential route.

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
| `GET` | `/api/v1/ceremony/config` | The public ceremony configuration: `{ callbackPath, ccdpOrigin, platforms }`. Readable only from an admitted origin. |
| `GET` | `{CALLBACK_PATH}` (default `/auth/callback`) | The registered OAuth callback document: the CCDP Distribution's artifact with this deployment's data inserted, identical for every request, revalidated every five minutes. |
| `POST` | `/api/v1/ceremony/github-token` | The confidential token exchange, run inside a TLSNotary session. Callable only from the configured CCDP origin, whose preflight it answers. The body carries `notaryAddress`, the notary the browser resolved from the ledger; this bridge dials the same host on the wire port, refusing a private or internal one. `403` for any other origin or a refused notary, `400` for a query, `415` for any media type but exactly `application/json`. |

`/health` is not one of the contract's three routes. The published image's
`HEALTHCHECK` targets it; it reads nothing from the request, answers two bytes,
and is the one route that accepts a query.

### `POST /api/v1/ceremony/github-token`

The one route needing a client secret.

Request — the code, the PKCE verifier, the redirect URI the authorization
request carried, and the notary the browser resolved from the ledger; the
client, secret and endpoint are this server's own. `redirectUri` must be this
bridge's callback path under a canonical origin; GitHub checks it against the
App's registration:

```json
{
  "code": "…",
  "codeVerifier": "…",
  "redirectUri": "https://bridge.example/auth/callback",
  "notaryAddress": "https://notary.example"
}
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

No `schema` member is carried. `attestedData` decodes to at most 2 MiB and
`signature` to exactly 65 bytes; the whole encoded body is at most 3 MiB.

The exchange reveals the client id, the code, the redirect URI and the PKCE
verifier, and commits the `client_secret` and the returned bearer. The secret
is last in the request body, so the committed range is a suffix and the
transcript tiles.

A failure returns none of the three values, and the caller starts a fresh
ceremony. Nothing about the request is stored.

Neither X nor Google has a confidential route; both run browser ↔ notary.


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
bytes**, never copied from an upstream header. The artifact bundles its
dependencies, so no external script source appears.

The document is composed once at startup and never varies: no request field —
`Origin`, `Referer`, query, fragment — changes a byte of it or its policy. The
server never sees the provider's return: the handler reads nothing from the
request, and there is no request-logging middleware. **Any proxy in front of
this server must redact the callback path's query string from its access
logs** — that half of the contract is the operator's.

The artifact is **retrieved from the Distribution**: `{CCDP_ORIGIN}/ccdp/callback.html`,
once before the listener binds and then every five minutes, conditionally on the
`ETag` it came with. A refresh that returns `304`, fails to reach the
Distribution, or returns something this bridge will not serve leaves the document
already being served as it is; only a valid replacement replaces it, and the
document and the policy naming its hashes are published as one value. Redirects
are refused, and the request carries no cookie, credential, query, or anything
derived from a callback request.

**A deployment that cannot retrieve its artifact does not start.** There is no
fallback document and no file override. A development stack serves its own
Distribution over HTTP on `localhost` or `127.0.0.1`, the one plaintext
exception the origin rules make.

## What the operator has to supply

Two things this server does not do.

**Redact the callback query from proxy access logs.** The handler reads
nothing from the request, so the authorization code never reaches this
process — but a proxy that logs request lines by default writes it to disk
before this server sees the request at all.

**Rate-limit `/api/v1/ceremony/github-token` by client.** The route caps
concurrent exchanges at 8 and answers `503` past that; it does not limit by
client, and the `Origin` check is not caller authentication. A per-client
limit belongs in the proxy, where the client is identified.

## Configuration

The bridge reads a TOML configuration file named by `LIBID_CONFIG` or
`--config`. Every key in it can be overridden by the environment variable or
flag of the same name; precedence is flag, then environment variable, then
file, then default. `bridge.toml.example` beside this README is a complete
starting point:

```toml
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
| `allowed_app_origins` | `ALLOWED_APP_ORIGINS`, comma-separated | *(required)* | Application origins. Exact origins, no patterns; HTTPS, or HTTP on `localhost` or `127.0.0.1`. Each must already be canonical — a trailing slash, an uppercase host or a default port is refused with the canonical spelling named, not folded — and a duplicate is refused. The **effective** admission set is this list plus the resolved `CCDP_ORIGIN`, added exactly once, and it governs the configuration route and what the callback document is told. The token route admits `CCDP_ORIGIN` alone. |
| `callback_path` | `CALLBACK_PATH` | `/auth/callback` | The path providers redirect back to; the registered OAuth callback URL is this bridge's public origin followed by it, and `/config` publishes it as `callbackPath`. There is no alias and no redirect. |
| `ccdp_origin` | `CCDP_ORIGIN` | `https://lib.id` | The CCDP Distribution this bridge selects: one origin serving `/ccdp/callback.html` and everything the browser runs after it, HTTPS unless loopback. Published in the configuration and inserted into the callback document. Omitting it selects the canonical libID Distribution. |
| `notary_wire_port` | `NOTARY_WIRE_PORT` | `7047` | The port of the notary's MPC-TLS wire listener. The notary itself is named by each token request's `notaryAddress`; this bridge dials that host on this port. A private or internal address is refused; loopback is not. |
| `platforms` | — | *(required)* | The enabled platforms, as `[[platforms]]` tables. File only. |
| `gh_oauth_client_secret` | `GH_OAUTH_CLIENT_SECRET` | *(none)* | GitHub OAuth App client secret. Required exactly when a platform is `github`, and refused otherwise. |
| — | `LIBID_CONFIG`, `--config` | *(none)* | Path to the configuration file. |

### On Google

Nothing here serves the Google ceremony: its identity evidence is a signed ID
Token the browser reads out of the redirect fragment, so there is no secret to
hold and nothing to exchange.

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

## Testing

`cargo test` is hermetic: it opens no socket outside the process and needs no
credentials.

The token route's last gate, an MPC-TLS session through a notary to
`github.com`, is covered by a second suite behind a feature:

```sh
cargo test --features live-ceremony --test ceremony
```

The notary is in-process, built from the same `libid-tlsn` this service
uses. The suite reads its settings from the environment, or from a gitignored
`.env.test` where an exported variable wins; a missing variable fails the run.

| Variable | Rungs | Meaning |
|---|---|---|
| `GH_OAUTH_CLIENT_ID`, `GH_OAUTH_CLIENT_SECRET` | all | The OAuth App the sessions authenticate as. |
| `LIBID_TEST_REDIRECT_URI` | all | The App's registered callback URL; its path becomes the deployment's callback path. |
| `GH_TEST_ALICE_USERNAME`, `GH_TEST_ALICE_PASSWORD` | success | The test account. |
| `GH_TEST_ALICE_TOTP_SECRET` | success, optional | The base32 key of the account's authenticator app, when it has one; the browser answers the TOTP prompt with it. |
| `GH_TEST_ALICE_COOKIES` | success, optional | The account's session, as the export test prints it. With it the browser is signed in already; without it, it signs in with the form. |
| `BROWSER_HEAD=1` | success | A visible Chrome. |
| `CHROME` | success | The Chrome binary, when it is not on the `PATH`. |

Three rungs need no account: a refused code (`400`), refused credentials
(`502`), and a notary that never speaks (`502` after the 120-second session
budget). The fourth signs in as the test account in Chrome, authorizes the
App, and checks the bearer, the attestation and its signature. A run that
stops on a page it does not handle prints that page's URL and text.

To export the account's session for `GH_TEST_ALICE_COOKIES`:

```sh
BROWSER_HEAD=1 cargo test --features live-ceremony --test ceremony -- --ignored --nocapture a_fresh_session
```

A visible Chrome signs in; a device-verification prompt is completed by hand
there, once. Headless, that prompt fails the run.

In CI (`ceremony.yml`) pull requests run the two refusal rungs; the scheduled
and dispatched runs run every rung, one at a time. The job is skipped where
the secrets are absent.

## License

Dual-licensed under MIT and Apache-2.0 — see `LICENSE-MIT`,
`LICENSE-APACHE` and `NOTICE`.
