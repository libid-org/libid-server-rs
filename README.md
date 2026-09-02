# libid-server-rs

The server side of a libID ceremony, and deliberately almost nothing.

A platform ceremony runs in the browser: it opens the provider, consumes the
redirect against its own live state, notarizes what it needs, and builds the
proof. The one thing a browser cannot hold is a confidential client secret,
which is why GitHub's token exchange happens here and why this service exists
at all. Google and X need no confidential route from it.

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
| `GET` | `/health` | Liveness probe. Returns `OK`. |
| `GET` | `/auth/gmail/callback` | Static, CSP-locked fragment relay for the Google OIDC flow: forwards `location.hash` — the id_token, which never reaches any server — to `{APP_URL}/auth/gmail/callback`. Requires `APP_URL`. |

`POST /api/v1/ceremony/github-token` lands next; it is the one route a
platform ceremony genuinely requires of a server.

Neither X nor Google gets a confidential route. Both run browser ↔ notary, and
a server-side X callback was proposed and rejected: X's flow is browser-only by
design and its callback belongs on the UI origin.


## Configuration

All settings come from environment variables (or the matching `--flag`).

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in the container image). |
| `PORT` | `8722` | Bind port. |
| `BASE_URL` | `http://127.0.0.1:8722` | Public URL of this server. The GitHub OAuth App's callback URL must be exactly `{BASE_URL}/api/v1/ceremony/callback`. |
| `APP_URL` | *(empty)* | Public URL of the web app; target of the Gmail fragment relay. Https required except for localhost. Empty disables the relay. |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS allow-list. `*.suffix` and `prefix*` wildcards supported. |
| `NOTARY_URL` | `tcp://127.0.0.1:7047` | The notary server's TCP endpoint. |
| `GH_OAUTH_CLIENT_ID` | *(required)* | GitHub OAuth App client id (a plain read-only OAuth App; no GitHub App needed). |
| `GH_OAUTH_CLIENT_SECRET` | *(required)* | GitHub OAuth App client secret. |

There is no signing key to configure, and no AWS/KMS grant to provision: the
server signs nothing (see [Trust model](#trust-model)). `BACKEND_SIGNING_KEY`
is gone — a deployment that still sets it is not broken, but the value is
ignored, so drop it from your secrets. The only secret this server needs is
`GH_OAUTH_CLIENT_SECRET`.

### Note on Google binds

This server does not run a JWKS rotator. Until a rotator runs somewhere and
publishes Google's current signing moduli on-chain, Google/Gmail binds
revert with `UntrustedModulus`. GitHub and X are unaffected. The
`/auth/gmail/callback` relay is served regardless, so the browser side of
the Google flow works the moment a rotator exists.

## Running with Docker

```sh
docker run --rm -p 8722:8722 \
  -e BASE_URL=https://handles.example.com \
  -e APP_URL=https://app.example.com \
  -e ALLOWED_ORIGINS=https://app.example.com \
  -e NOTARY_URL=tcp://notary.example.com:7047 \
  -e GH_OAUTH_CLIENT_ID=... \
  -e GH_OAUTH_CLIENT_SECRET=... \
  ghcr.io/libid-org/libid-server-rs:latest
```

Images are published on every GitHub release as
`ghcr.io/libid-org/libid-server-rs:<version>` and `:latest`. The image
listens on `0.0.0.0:8722` and carries a `/health` healthcheck.

## Building from source

```sh
cargo build --release          # rustc >= 1.94.1
cargo test
```

## License

Dual-licensed under MIT and Apache-2.0 — see `LICENSE-MIT`,
`LICENSE-APACHE` and `NOTICE`.
