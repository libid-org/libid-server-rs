# Local end-to-end ceremony run — findings

2026-09-09. Full stack: dev app (4691), bridge (4682), CCDP Distribution (4683),
notary (TCP 7047 / WSS 7048), real GitHub OAuth app, real authorization code.

## Result

The ceremony runs end to end and **completes a real GitHub token exchange inside
MPC-TLS**. It fails at the last step — the notary's attestation hand-back.

Bridge log, one uninterrupted session:

    Setting up MPC-TLS
    MPC-TLS setup complete
    Connecting to github.com API
    TLS handshake complete
    Sending POST /login/oauth/access_token
    Response: 255 bytes          <- GitHub answered with a real bearer
    MPC-TLS proof complete
    Attestation request built
    ERROR ... MPC-TLS failed: the notary sent no record for the session it
              ran: io: early eof

Notary, same session:

    starting MPC-TLS
    finished MPC-TLS
    ERROR ... MPC-TLS failed: driver task finished before the session completed

`Verification complete` never appears, so `libid_tlsn::verifier()` returned the
driver-finished-early error and `handle_verified_session` — which signs and
writes the section 9.1 record — never ran. The prover then read EOF where the
record should have been.

**Hypothesis, not yet proven:** `prover_generic` calls `prover.close()` and
`handle.close()` before the caller reads the attestation off the reclaimed
socket. If that closes the mux, the notary's driver completes and it can never
write the record.

**Distinct from the panic in TLSN_FORK_PANIC.md.** Same phase, different
faults, and each was reproduced with the other absent:

| run | GitHub answers | result | panic |
|---|---|---|---|
| success path | 200 with a real bearer | `early eof`, no record | **0** |
| non-2xx path | 404 | 502 | **1** |

So they should be filed separately. An earlier note here called them likely one
bug; the success-path run panics zero times, which does not support that.

Verified twice on independent runs, each with a fresh real authorization
code.

## Bug 1 — GitHub's RFC 9207 `iss` breaks every GitHub ceremony

`ts/packages/ceremony/src/platforms/codeReturn.ts:20`

    if (key !== 'state' && key !== 'code' && key !== 'error') return null

GitHub returns `iss` (RFC 9207, Authorization Server Issuer Identification).
Measured from a real callback:

    queryKeys: "code,iss,state"

One unrecognised key rejects the **entire** return, so `parseCodeOAuthReturn`
yields null and the prover throws `Invalid GitHub return`. No GitHub ceremony
can complete against the live provider.

The fix is not simply to allow the key: RFC 9207 exists so the client can
**validate** the issuer. Accepting and checking `iss` against the expected
GitHub issuer is the correct change; ignoring it silently discards a defence
against mix-up attacks.

## Bug 2 — errors are swallowed with no diagnostic

Three sites discard the exception entirely:

- `src/ccdp/documents/prefetch.ts:26` — `} catch {` then a generic view
- `src/ccdp/documents/prover.ts` — `catch { fail() }`, and `fail()` takes no
  argument at 4 of its call sites
- `src/platforms/github/1/prover.ts:37` — throws a message that names no cause

A user sees "Unable to complete proof", the console is empty, and no server logs
anything, because the failure happens before any network call. Bug 1 was
invisible for this reason; finding it required patching the package to log.

Minimum fix: bind the error (`catch (e)`) and log it. Better: give `fail` a
reason and surface it in the abort message.

## Local-environment requirements (not bugs, but undocumented)

Standing this up needs four things nothing states:

1. **Trusted certificates.** Chrome refuses `serviceWorker.register()` on an
   untrusted-cert origin even on localhost and even after the interstitial is
   clicked through — while a plain `fetch()` of the same script succeeds. Use
   mkcert (`dev/tls.ts` already does; the CCDP and bridge origins need it too).
2. **`LIBID_NOTARY_ADDRESS`** at artifact build time, or the browser prover
   reaches for `https://testnet.notary.lib.id` on the public internet.
3. **`LIBID_LEDGER_FIXTURE=1`**, or `@libid/ledger`'s default export is a stub
   that throws `No ledger definitions are available` and the prover rejects
   `test:testnet`. Note the build restricts fixture output to `.cache`, so it
   needs `--out-dir <pkg>/.cache/<name>`.
4. **TLS in front of the notary's WebSocket.** It serves plain `ws`; the browser
   opens `wss://`. Without a terminating proxy the prover cannot reach it and
   nothing appears in any log.

Also: the bridge compares the request's `notaryAddress` by host, so the
browser's `localhost` and a bridge configured with `127.0.0.1` will not match —
configure both as the same host.
