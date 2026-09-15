# libid-server-rs

The OAuth Bridge of a libID ceremony.

A platform ceremony runs in the browser: it opens the provider, consumes the
redirect against its own live state, exchanges the code where its ceremony
takes a token, notarizes what it needs, and builds the proof. This service
publishes the configuration an application starts from and serves the one
callback document the providers redirect back to. It performs no token
exchange and opens no notary connection. GitHub's exchange, which GitHub
answers only with the App's `client_secret`, runs in the browser too; the
bridge publishes that value as public application configuration.

It keeps no ceremony state, no session, no challenge and no result. A timeout,
a duplicate request, a restart or a lost response leave no record here, and
recovery is a fresh ceremony rather than a lookup. It holds no wallet, pays no
gas, keeps no database, and talks to no chain.

## How a claim works

1. The application reads `GET /api/v1/ceremony/config` from an admitted
   origin: the CCDP Distribution to load and, per enabled platform, the public
   client id, the ceremony versions and, for GitHub, the public
   `clientCredential`. It derives the redirect URI itself from the
   bridge origin it already knows: `{bridgeOrigin}/auth/callback`.
2. The browser derives its PKCE verifier, opens the provider's authorization
   page, and is redirected to `GET /auth/callback` on this bridge: one
   document, the same bytes for every request, written by the Distribution.
   The handler reads nothing from the request; the code in the query never
   reaches this process.
3. Everything after that runs in the browser on the Distribution's code: the
   token exchange, the notarized sessions, the proof. GitHub's token request
   carries the published credential as `client_secret` and is revealed whole.
   This service sees none of it and verifies nothing.

## Trust model

**The notary is the only trust root.** This service signs nothing and holds
no key and no secret: the single signature in a proof is the notary's.

GitHub's `client_secret` is published on purpose. GitHub requires it in every
token request, PKCE or not, so a browser client has to carry it; libID treats
it as public application configuration, and the GitHub ceremony's proof
statement covers the complete revealed token request, the credential
included. It identifies the App, not a user, and the ledger accepts nothing
the notary did not attest.

The configured origin and everything it serves are a code-supply-chain
boundary besides. A malicious server can replace the browser code it hands
out; origin checks and a closed input surface cannot constrain its owner.


## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe. Returns `OK`. Not one of the contract's routes — see below. |
| `GET` | `/api/v1/ceremony/config` | The public ceremony configuration: `{ ccdpOrigin, platforms }`. Readable from an admitted origin, or by a same-origin `GET` without `Origin` on `Sec-Fetch-Site: same-origin`. `403` for any other origin, `400` for a query. |
| `GET` | `/auth/callback` | The registered OAuth callback document: the CCDP Distribution's artifact with this deployment's data inserted, identical for every request. |

`/health` is not one of the contract's two routes. The published image's
`HEALTHCHECK` targets it; it reads nothing from the request, answers two bytes,
and is the one route that accepts a query.

Any other path, `POST /api/v1/ceremony/github-token` included, is answered
`404` with no CORS header.

### `GET /api/v1/ceremony/config`

```json
{
  "ccdpOrigin": "https://lib.id",
  "platforms": {
    "github": {
      "clientId": "Iv1.0123456789abcdef",
      "ceremonyVersions": [1],
      "clientCredential": "…"
    },
    "x": {
      "clientId": "…",
      "ceremonyVersions": [1]
    }
  }
}
```

`clientCredential` is present on exactly the entries whose ceremony
sends one: GitHub's. It is nonempty printable ASCII without whitespace,
checked at startup. The record carries no redirect URI, no allowlist, no
notary setting and no user token.

## The CCDP Distribution

The contract this server implements is `specs/oauth-bridge.md` in the libid
repository (pull request 13); the GitHub profile whose token request carries
the public credential is `specs/platform-ceremonies.md` (pull request 35).

This server is the **OAuth Bridge**, and only that. Everything the browser
executes — the Callback implementation, the prover, the circuits and
notarization client — is served by a separate static **CCDP Distribution** at
`CCDP_ORIGIN`, which may be cross-site and knows nothing about this bridge. The
bridge publishes configuration and serves one callback document. It serves no
CCDP resource and no proving asset.

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

One thing this server does not do.

**Redact the callback query from proxy access logs.** The handler reads
nothing from the request, so the authorization code never reaches this
process — but a proxy that logs request lines by default writes it to disk
before this server sees the request at all.

## Configuration

The bridge reads a TOML configuration file named by `LIBID_CONFIG` or
`--config`. Every key in it can be overridden by the environment variable or
flag of the same name; precedence is flag, then environment variable, then
file, then default. `bridge.toml.example` beside this README is a complete
starting point:

```toml
allowed_app_origins = ["https://app.example", "https://wallet.example"]

[[platforms]]
id                        = "github"
client_id                 = "Iv1.0123456789abcdef"
versions                  = [1]
client_credential = "…"
```

An unknown key is refused at startup, `host` and `port` among them: where the
process listens is set with `HOST`/`PORT` or `--host`/`--port`. The platforms
are set only in the file,
one `[[platforms]]` table per enabled platform: its `id` (`github`, `google` or
`x`), its public `client_id`, the ceremony `versions` it advertises and, for
`github`, the App's client secret as `client_credential`, which the
bridge publishes. There is no notary setting and no environment variable for
the credential.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| — | `HOST`, `--host` | `127.0.0.1` | Bind address (`0.0.0.0` in the container image). Not a file key: the image sets it in the environment, which beats a file. |
| — | `PORT`, `--port` | `8722` | Bind port. Not a file key, for the same reason. |
| `allowed_app_origins` | `ALLOWED_APP_ORIGINS`, comma-separated | *(required)* | Application origins. Exact origins, no patterns; HTTPS, or HTTP on `localhost` or `127.0.0.1`. Each must already be canonical — a trailing slash, an uppercase host or a default port is refused with the canonical spelling named, not folded — and a duplicate is refused. The **effective** admission set is this list plus the resolved `CCDP_ORIGIN`, added exactly once. It is the one admission rule: the configuration route admits exactly one `Origin` from it, and the callback document is told the same set. A same-origin read carries no `Origin` and is admitted on `Sec-Fetch-Site: same-origin` alone. |
| `ccdp_origin` | `CCDP_ORIGIN` | `https://lib.id` | The CCDP Distribution this bridge selects: one origin serving `/ccdp/callback.html` and everything the browser runs after it, HTTPS, or HTTP on `localhost` or `127.0.0.1`. Published in the configuration and inserted into the callback document. Omitting it selects the canonical libID Distribution. |
| `platforms` | — | *(required)* | The enabled platforms, as `[[platforms]]` tables: `id`, `client_id`, `versions`, and for `github` its `client_credential`. File only. |
| — | `LIBID_CONFIG`, `--config` | *(none)* | Path to the configuration file. |

### Per platform

GitHub's entry carries the App's client secret as the public
`clientCredential`; the browser's token request sends it as
`client_secret`. X runs a public PKCE client, browser to notary, and Google's
identity evidence is a signed ID Token the browser reads out of the redirect
fragment: neither entry carries a credential, and nothing here takes part in
either ceremony beyond the configuration and the callback document.

## Running with Docker

```sh
docker run --rm -p 8722:8722 \
  -v ./bridge.toml:/etc/libid/bridge.toml:ro \
  -e LIBID_CONFIG=/etc/libid/bridge.toml \
  ghcr.io/libid-org/libid-server-rs:latest
```

Images are published on every GitHub release as
`ghcr.io/libid-org/libid-server-rs:<version>` and `:latest`. The image sets
`HOST=0.0.0.0` and `PORT=8722` and carries a `/health` healthcheck on that
port; `-e PORT=` moves both.

## Testing

`cargo test` is hermetic: it opens no socket outside the process and needs no
credentials.

The ceremonies the published configuration starts are covered by a second
suite behind a feature:

```sh
cargo test --features live-ceremony --test ceremony
```

It runs the real binary on a configuration file, reads `/config` from it as
an application would, and runs the notarized sessions of the GitHub and X
ceremonies with a prover of its own through an in-process notary built from
`libid-tlsn`; both records of each ceremony are checked against the rules the
Platform Verifier applies on chain. The suite reads its settings from the
environment, or from a gitignored `.env.test` where an exported variable
wins; a missing variable fails the run.

| Variable | Rungs | Meaning |
|---|---|---|
| `GH_OAUTH_CLIENT_ID`, `GH_OAUTH_CLIENT_SECRET` | GitHub | The OAuth App. The bridge under test is configured with both and publishes the secret as `clientCredential`; the suite reads them back from `/config` and sends them in the token request. |
| `LIBID_TEST_PUBLIC_ORIGIN` | GitHub | The bridge origin the App's callback URL is registered under; the suite derives `/auth/callback` from it as the application would. |
| `GH_TEST_ALICE_USERNAME`, `GH_TEST_ALICE_PASSWORD` | GitHub authorization | The test account. |
| `GH_TEST_ALICE_TOTP_SECRET` | GitHub authorization | The base32 key of the account's authenticator app; the browser answers the TOTP prompt with it. An account without one is asked to verify the device by mail, which a headless run cannot answer. |
| `BROWSER_HEAD=1` | authorization | A visible Chrome. |
| `CHROME` | authorization | The Chrome binary, when it is not on the `PATH`. |

Three GitHub rungs need no account: a refused code and a refused credential
each fail the token session with GitHub's own answer, past a real session to
`github.com`; a bearer GitHub did not issue fails the identity session. The
fourth signs in as the test account in Chrome, authorizes the App, and runs
the token session with the published credential and the identity session,
checking the bearer, both records and their signatures. A run that stops on a
page it does not handle prints that page's URL and text.

Two rungs run the X ceremony, in which the bridge takes no part. One needs
no account: an identity read with a bearer X did not issue fails with X's
own answer, past a real session to `api.x.com`. The other signs in as the X
test account in Chrome and authorizes the app, then runs the two sessions
the same way. It reads its own variables:

| Variable | Meaning |
|---|---|
| `X_OAUTH_CLIENT_ID` | The X app, a public PKCE client. |
| `LIBID_TEST_X_REDIRECT_URI` | The redirect URI registered on that app, byte for byte. |
| `X_TEST_ALICE_USERNAME`, `X_TEST_ALICE_PASSWORD` | The X test account. |
| `X_TEST_ALICE_EMAIL` | Its e-mail address, typed when X asks for it on a sign-in it examines. |
| `X_TEST_ALICE_COOKIES` | Optional: a saved session, which the rung restores instead of signing in. The value is what the export prints. |
| `BROWSER_TRACE` | Optional: a directory; the driver writes a numbered screenshot and a dump of the page's controls and text into it at each step. |

The export signs in once in a visible Chrome, where a person may complete
whatever X asks of a new sign-in, and prints the value:

```sh
BROWSER_HEAD=1 cargo test --features live-ceremony --test ceremony -- --ignored --nocapture a_fresh_x_session
```

In CI (`ceremony.yml`) pull requests run the rungs that need no account; the
scheduled and dispatched runs add the GitHub authorization, one rung at a
time. The X authorization runs only on a manual dispatch with the `x` input
set. Each job is skipped where its secrets are absent.

## Building from source

```sh
cargo build --release          # rustc >= 1.95 (see rust-version in Cargo.toml)
cargo test
```

## License

Dual-licensed under MIT and Apache-2.0 — see `LICENSE-MIT`,
`LICENSE-APACHE` and `NOTICE`.
