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

**Proven, in `libid-tlsn@cafd9a0b` `crates/libid-tlsn/src/session.rs`.** Both
sides race their own mux driver against their own session work, and the prover
wins:

    prover_generic  :659   prover.close().await     <- right after the log line above
                    :662   handle.close();          <- the mux dies here
                    :680   driver task completes, hands the socket back
                           caller then reads the record off `recovered_io`

    verifier        :760   verifier.verify().await  <- still in here, or in
                    :776   verifier.accept().await     one of these two
                    :794   info!("Verified server")  <- NEVER REACHED (see below)
                    :818   driver finishes first -> driver_finished_early
                           `handle_verified_session` never runs, so nothing is
                           signed and nothing is written

The notary log pins where it was: `finished MPC-TLS` is the last line
`verifier.run()` writes, and `Verified server` never appears — so when the mux
died the notary was inside `verify()` or `accept()`, both of which still need
mux round-trips. It was not shutting down. It was mid-protocol.

So the prover treats `prover.close()` as the end of the session and drops the
transport, while the notary still needs that transport to finish verifying. The
47 ms between the bridge's `Attestation request built` and the notary's error is
exactly that teardown.

**Where the fix is not.** Not "read the record before `handle.close()`": on both
sides `recovered_io` comes from `driver_task.into_inner().await` (:689, :831),
so the socket does not exist until after the mux is closed and the driver has
finished. Neither side can touch the raw socket earlier. That ordering is the
design, not the bug.

**Where it is.** Two candidates, both upstream of this service:

  * the prover's `handle.close()` (:662) is premature — it must not drop the mux
    until the notary has finished `verify()`/`accept()`, which needs a shutdown
    handshake the protocol currently does not have; and
  * the notary's `select!` (:818) cannot tell a peer closing gracefully from a
    socket dying under it. Both arrive as `Ok(Ok(_))`. Its comment names only
    the second ("a health probe that connected and immediately closed"), and
    that is the case the check was written for.

**Distinct from the panic in TLSN_FORK_PANIC.md.** Same phase, different
faults, and each was reproduced with the other absent:

| run | GitHub answers | result | panic |
|---|---|---|---|
| success path | 200 with a real bearer | `early eof`, no record | **0** |
| non-2xx path | 404 | 502 | **1** |

So they should be filed separately. An earlier note here called them likely one
bug; the success-path run panics zero times, which does not support that.

Verified three times on independent runs, each with a fresh real
authorization code. The third was against the bridge's split `routes/github_token/`
modules, which reproduced it identically — the refactor changed nothing on the
live path.

## FIXED locally, and verified — the hand-back now works

Two changes to `libid-tlsn`, both in `crates/libid-tlsn/src/session.rs`. Kept as
`libid-tlsn-handback.patch` beside this file, applied through a `[patch]` on a
worktree of `libid-rs@cafd9a0b`.

**1. The verifier's driver guard, which is the actual bug.** Not fixed on any
ref, including PR #2's head. The `select!` treated a finished driver as a dead
connection at every stage; past `run()` it is the prover closing the mux, which
is normal. An `AtomicBool` set after `run()` now tells the two apart.

One trap worth stating: the check cannot be a `select!` precondition
(`, if !established`). Tokio evaluates those ONCE, when the select is entered,
and nothing is established by then — the first attempt built, ran, and failed
exactly as before. It has to be tested inside the branch body, keeping the
driver's result rather than re-awaiting a finished handle.

**2. The commitment hash, a backport.** With (1) alone the notary reached the
signing step and refused there: `a commitment uses HashAlgId(2), but
REQ-COMMON-38 pins SHA-256`. `prover_generic` builds `TranscriptCommitConfig`
without naming an algorithm, so it gets the library default of BLAKE3, while
this same crate's `attest.rs` accepts only SHA-256 — the two halves disagreed.
**PR #2's head already fixes this** (`default_kind(Hash { alg: SHA256 })`);
backported here only because our pin is 46 commits behind it and the notary
cannot move to that head yet: `libid-attestations` is gone there, folded into
`libid-transcript`, and `notary@86c179d` still depends on it.

### What the run looks like now

    notary:  starting MPC-TLS -> finished MPC-TLS
             Verified server: github.com
             Verification complete: 425 sent, 4829 recv bytes
             Domain from SNI: github.com
             Ceremony attestation sent to prover      <- NEW

    bridge:  ... MPC-TLS proof complete
             Attestation request built
             (no error)                               <- NEW

Reproduced twice, each with a fresh real authorization code.

The failure has moved past this service entirely: the browser leg now reports
`Ceremony failed` with nothing in the app console — which is Bug 2 below,
swallowed diagnostics, in the way again.

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
