//! The notarized session the exchange runs inside, and what the notary hands
//! back when it finishes. Three budgets bound it: reaching the notary (in
//! `egress`), the protocol, and the record written after it.

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

/// How long the session may take once the notary has answered.
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the notary may take to hand back the record for a session it has
/// run.
const RECORD_TIMEOUT: Duration = Duration::from_secs(30);

/// Restate a layout refusal in the session driver's error vocabulary.
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

    // Kept from inside the session, which is the only place the raw received
    // transcript exists: the bearer's range and bytes, the layout refusal, and
    // whose refusal it was.
    let mut selected: Option<(Range<usize>, Vec<u8>)> = None;
    let mut refusal: Option<ceremony::LayoutError> = None;
    let mut answer = PlatformAnswer::Unusable;

    // Each direction's commitments are the complement of its reveals, so the
    // transcript tiles.
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

    // The notary writes the record on the socket the session ran over; it
    // reads no request.
    let wire: AttestationWire = tokio::time::timeout(
        RECORD_TIMEOUT,
        libid_transcript::read_msg(&mut result.recovered_io),
    )
    .await
    .map_err(|_| Error::MpcTlsFailed {
        detail: "the notary ran the session and then sent no record in time".into(),
    })?
    .map_err(|e| Error::MpcTlsFailed {
        // Usually end of file: the notary closed without writing a record.
        detail: format!("the notary sent no record for the session it ran: {e}"),
    })?;

    // The committed bytes: what the browser is handed is what the commitment
    // opens.
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
