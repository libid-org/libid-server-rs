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
2. It calls `POST /oauth/github/token-exchange` with the authorization code
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
| `POST` | `/oauth/github/token-exchange` | The confidential token exchange, run inside a TLSNotary session. Callable only from this server's own origin. |

### `POST /oauth/github/token-exchange`

The one route a platform ceremony genuinely requires of a server, because it is
the one step needing a client secret.

Request — and nothing else; the client, secret, redirect URI, endpoint and
notary are this server's own, and none of them is selectable by a caller:

```json
{ "schema": 1, "code": "…", "codeVerifier": "…" }
```

Response. `accessToken` is the bearer as GitHub spelled it; the other two are
byte strings, unpadded URL-safe base64:

```json
{
  "schema": 1,
  "accessToken": "…",
  "tokenAttestation": "…",
  "bearerOpening": "…"
}
```

`tokenAttestation` decodes to the section 9.1 record followed by the notary's
65-byte signature over its keccak256 digest. That layout is fixed by
`TokenAttestation::encode` in `libid-ceremony`, which both sides of the wire
read; the specification requires the attestation to carry the signature
(REQ-PLAT-45) but does not say where in the string it sits.

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


## Configuration

All settings come from environment variables (or the matching `--flag`).

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in the container image). |
| `PORT` | `8722` | Bind port. |
| `BASE_URL` | `http://127.0.0.1:8722` | Public URL of this server. The GitHub OAuth App's callback URL must be exactly `{BASE_URL}/api/v1/ceremony/callback`. |
| `NOTARY_URL` | `tcp://127.0.0.1:7047` | The notary server's TCP endpoint. |
| `GH_OAUTH_CLIENT_ID` | *(required)* | GitHub OAuth App client id (a plain read-only OAuth App; no GitHub App needed). |
| `GH_OAUTH_CLIENT_SECRET` | *(required)* | GitHub OAuth App client secret. |

There is no signing key to configure, and no AWS/KMS grant to provision: the
server signs nothing (see [Trust model](#trust-model)). `BACKEND_SIGNING_KEY`
is gone — a deployment that still sets it is not broken, but the value is
ignored, so drop it from your secrets. The only secret this server needs is
`GH_OAUTH_CLIENT_SECRET`.

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
  -e BASE_URL=https://handles.example.com \
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
