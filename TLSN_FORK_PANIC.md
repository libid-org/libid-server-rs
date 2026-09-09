# `Task polled after completion` in the prover's finalize, on a non-2xx platform response

Found standing up the libID ceremony stack locally on 2026-09-09.
Against `libid-org/tlsn@8a5de746` + `libid-org/mpz@c0379ef`
(the pins `libid-org/notary@feat/ws-attestations` uses), driven by
`libid-tlsn::prover_generic` from `libid-rs@cafd9a0b`.

## Symptom

    thread 'tokio-rt-worker' panicked at async-task-4.7.1/src/task.rs:452:45:
    Task polled after completion

`async_task::Task::poll` does `t.expect("Task polled after completion")` — it
is one of the few futures that detects a poll-after-`Ready` loudly instead of
misbehaving quietly.

## Trigger — controlled A/B, one variable

Same stack, same request, same notary; only the OAuth `clientId` differs, which
changes only what github.com answers:

| github.com answers | bridge returns | panic |
|---|---|---|
| `200` + `{"error":"bad_verification_code"}` | 400 | **no** |
| `404` + `{"error":"Not Found"}` (unregistered app) | 502 | **yes** |

So it is the **non-2xx** path. `prover_generic` returns early on a non-2xx
status (`API returned 404 Not Found: ...`), abandoning the session while the
prover is still finalizing. The 2xx path is clean even when the ceremony then
fails downstream on layout selection.

Not fully deterministic: 3 panics in 4 attempts on the 404 path, 1 in 1 on the
controlled run. Racy, but frequent.

## Blast radius

The panic kills one tokio worker task. The process survives and keeps serving —
`/api/v1/ceremony/config` still answers 200 afterwards. So it is not fatal, but
it is an unwind through MPC state on every misconfigured deployment's first
request, and it is noise that hides the real error.

## Stack (RUST_BACKTRACE=full, trimmed to the interesting frames)

    async_task::task::Task<T,M>::poll                     <- panic
    futures_util::future::either::Either::poll
    futures_util::future::try_maybe_done::TryMaybeDone::poll
    futures_util::future::try_join::TryJoin<Fut1,Fut2>::poll
    mpz_garble::store::garbler::GarblerStore<COT>::flush
    mpz_garble::protocol::semihonest::garbler::Garbler<COT>::flush
    mpz_vm_core::Execute::execute_all
    tlsn::prover::client::mpc::InnerState::finalize
    tlsn::prover::client::mpc::MpcTlsClient::poll   (x3, the tail recursion
                                                    CloseActive -> CloseBusy
                                                    -> Finalizing)
    tlsn::prover::Prover<Connected<S>>::poll
    tlsn::prover::future::ProverFuture::poll

`GarblerStore::flush` (mpz `crates/garble/src/store/garbler.rs:124`) loops
`while self.core.wants_flush()`, and each iteration builds a `ctx.try_join(..)`
whose branches are spawned as `async_task::Task`s. One of those handles is
polled after it already returned `Ready`.

The `MpcTlsClient` state machine already anticipates re-polling — `State::Finished`
returns `"mpc tls client polled again in finished state"` — but the completed
future here is *inside* `finalize`, below that guard, so it panics before the
guard can fire.

## Notary side

The notary logs the mirror image for the same session and never panics itself:

    MPC-TLS failed: driver task finished before the session completed
    MPC-TLS failed: driver task: io error: ... Connection reset by peer

## Why no existing test catches it

No test in `libid-rs`, the notary, or this repo drives a live MPC-TLS session to
a server that answers non-2xx. `libid-tlsn`'s ceremony tests are layout-only
(0.00s); `driver_task_leak` aborts before the protocol starts; the notary's
fixture tests use `SdkProver` in proxy mode and a fixture that answers 200.

## Reproducing

Point `prover_generic` at any HTTPS endpoint that answers non-2xx, through a
notary on the same pins. In this stack: configure the bridge with a well-formed
but unregistered GitHub `clientId` and POST a token request.
