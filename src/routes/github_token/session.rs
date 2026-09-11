//! The notarized session the exchange runs inside, and what the notary hands
//! back when it finishes.
//!
//! Two budgets here and a third in `egress`, because three different things
//! can stall: reaching the notary, the protocol itself, and the record written
//! after the protocol is over. Without separate budgets the first would eat
//! the second's, and the third would have none at all.
//!
//! This is also where a layout refusal becomes a session failure -- the driver
//! speaks its own error vocabulary, and `layout_failed` is the one place a
//! transcript's refusal is restated in it, so `transcript` need not know the
//! driver's error type.

use std::{
    ops::Range,
    time::Duration,
};

use libid_ceremony::token_exchange::{
    TokenAttestation,
    TokenRequest,
    TokenResponse,
};
use libid_transcript::{
    ceremony,
    AttestationWire,
};

use crate::{
    error::Error,
    state::GithubExchange,
};

use super::{
    request::token_http_request,
    transcript::{
        bearer_blinder,
        platform_refusal,
        PlatformAnswer,
        Selection,
    },
};

/// How long the session itself may take once the notary has answered.
///
/// An MPC-TLS session is a conversation with two other parties, and a notary
/// that stops answering mid-protocol leaves the prover waiting on a message
/// that will not come. Generous enough for a real session on a slow link, and
/// finite so a wedged notary costs one request rather than a connection held
/// until the process restarts.
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the notary may take to hand back the record for a session it has
/// already run.
///
/// Its own budget, because the session's is spent by this point and all that
/// remains is a write. Without one, a notary that completes a session and then
/// stalls -- or writes half a length prefix and stops -- parks this request
/// until the process restarts, which is the failure the budget above exists to
/// rule out.
const RECORD_TIMEOUT: Duration = Duration::from_secs(30);

/// Restate a layout refusal as a session failure.
///
/// A layout that will not form is a transcript this service cannot describe —
/// most often GitHub answering with an error object where the profile expects
/// `access_token`, which is a bad code or a spent one rather than a fault here.
pub(super) fn layout_failed(e: &ceremony::LayoutError) -> libid_tlsn::Error {
    libid_tlsn::Error::Transcript(libid_transcript::Error::Transcript {
        detail: e.to_string(),
    })
}

/// Run the exchange inside one notarized session and assemble what it produced.
pub(super) async fn exchange(
    github: &GithubExchange,
    request: &TokenRequest,
    redirect_uri: &str,
    notary_host: &str,
) -> Result<TokenResponse, Error> {
    let http_request = token_http_request(&github.credentials, request, redirect_uri);
    let socket = github.egress.reach(notary_host).await?;

    // What the layout decided, kept from inside the session. The bearer's
    // offsets index the raw received transcript, so neither they nor the bytes
    // at them can be recovered afterwards from the decoded body.
    let mut selected: Option<(Range<usize>, Vec<u8>)> = None;
    // Why the layout would not form, for the same reason: the error
    // `prover_generic` propagates says a transcript was refused, not which of
    // the two parties has something to fix.
    let mut refusal: Option<ceremony::LayoutError> = None;
    // Whose refusal it was, decided here because this is the only place the
    // received transcript exists. Read, never kept: what survives the closure
    // is one enum value, and this service's own words are what get logged.
    let mut answer = PlatformAnswer::Unusable;

    // The layouts state what this session discloses, and each direction's
    // commitments are the complement of its reveals — so the transcript tiles
    // by construction, which is what the Platform Verifier's coverage check
    // demands.
    let session = tokio::time::timeout(
        SESSION_TIMEOUT,
        libid_tlsn::prover_generic(
            socket,
            http_request,
            |sent, recv| match Selection::of(sent, recv) {
                Ok(Selection {
                    sent,
                    recv,
                    bearer,
                    bearer_bytes,
                }) => {
                    selected = Some((bearer, bearer_bytes));
                    Ok((sent, recv))
                }
                Err(e) => {
                    answer = PlatformAnswer::in_response(recv);
                    let failed = layout_failed(&e);
                    refusal = Some(e);
                    Err(failed)
                }
            },
            |_step| {},
        ),
    )
    .await
    .map_err(|_| Error::MpcTlsFailed {
        detail: "the notarized session did not finish in time".into(),
    })?;

    let mut result = match session {
        Ok(result) => result,
        Err(e) => {
            return Err(
                platform_refusal(refusal.as_ref(), answer).unwrap_or_else(|| e.into())
            )
        }
    };

    let (bearer, bearer_bytes) = selected.ok_or_else(|| Error::MpcTlsFailed {
        detail: "the session produced no layout".into(),
    })?;

    let bearer_opening = bearer_blinder(
        result.commitment_openings.iter().map(|opening| {
            (
                opening.direction,
                opening.ranges.as_slice(),
                opening.blinder.as_slice(),
            )
        }),
        &bearer,
    )?;

    // The notary answers a completed session on the socket the session ran
    // over. It reads no attestation request: everything it signs it observed
    // itself, so there is nothing left for this side to ask for.
    let wire: AttestationWire = tokio::time::timeout(
        RECORD_TIMEOUT,
        libid_transcript::read_msg(&mut result.recovered_io),
    )
    .await
    .map_err(|_| Error::MpcTlsFailed {
        detail: "the notary ran the session and then sent no record in time".into(),
    })?
    .map_err(|e| Error::MpcTlsFailed {
        // Most often an end of file: the notary refused the session after
        // running it — its own signer failing, say — and closed without
        // writing a record. Said plainly here, because a bare io error at
        // this point reads as a network fault rather than a refusal.
        detail: format!("the notary sent no record for the session it ran: {e}"),
    })?;

    // The committed bytes, not a second reading of the same value: what the
    // browser is handed has to be what the attestation's commitment opens.
    let access_token =
        String::from_utf8(bearer_bytes).map_err(|e| Error::MpcTlsFailed {
            detail: format!("the committed bearer is not valid UTF-8: {e}"),
        })?;

    Ok(TokenResponse {
        access_token,
        token_attestation: TokenAttestation {
            attested_data: wire.attested_data,
            signature: wire.notary_signature,
        },
        bearer_opening,
    })
}
