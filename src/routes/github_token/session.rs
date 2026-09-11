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
use libid_tlsn::CommitmentOpening;
use libid_transcript::{
    ceremony,
    AttestationWire,
};
use tokio::io::AsyncRead;

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

/// What the layout selection keeps from inside the session, where the raw
/// received transcript exists: the bearer's range and bytes when the layouts
/// formed, or the layout refusal and the platform's answer when they did not.
struct Kept {
    selected: Option<(Range<usize>, Vec<u8>)>,
    refusal: Option<ceremony::LayoutError>,
    answer: PlatformAnswer,
}

impl Kept {
    fn new() -> Self {
        Kept {
            selected: None,
            refusal: None,
            answer: PlatformAnswer::Unusable,
        }
    }

    /// The two layouts for the session. Each direction's commitments are the
    /// complement of its reveals, so the transcript tiles.
    fn select(
        &mut self,
        sent: &[u8],
        recv: &[u8],
    ) -> Result<(ceremony::Layout, ceremony::Layout), libid_tlsn::Error> {
        match Selection::of(sent, recv) {
            Ok(Selection {
                sent,
                recv,
                bearer,
                bearer_bytes,
            }) => {
                self.selected = Some((bearer, bearer_bytes));
                Ok((sent, recv))
            }
            Err(e) => {
                self.answer = PlatformAnswer::in_response(recv);
                let failed = layout_failed(&e);
                self.refusal = Some(e);
                Err(failed)
            }
        }
    }

    /// What a failed session is answered with: the platform's refusal where
    /// the layout found no bearer, otherwise the session driver's error.
    fn refusal(&self, e: libid_tlsn::Error) -> Error {
        platform_refusal(self.refusal.as_ref(), self.answer).unwrap_or_else(|| e.into())
    }
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

    let mut kept = Kept::new();
    let session = tokio::time::timeout(
        SESSION_TIMEOUT,
        libid_tlsn::prover_generic(
            socket,
            http_request,
            |sent, recv| kept.select(sent, recv),
            |_step| {},
        ),
    )
    .await
    .map_err(|_| Error::MpcTlsFailed {
        detail: "the notarized session did not finish in time".into(),
    })?;

    let mut result = match session {
        Ok(result) => result,
        Err(e) => return Err(kept.refusal(e)),
    };
    assemble(kept, &result.commitment_openings, &mut result.recovered_io).await
}

/// The response, from what the session produced: the committed bearer, the
/// opening of its commitment, and the record the notary writes on the socket
/// the session ran over.
async fn assemble<R: AsyncRead + Unpin>(
    kept: Kept,
    openings: &[CommitmentOpening],
    io: &mut R,
) -> Result<TokenResponse, Error> {
    let (bearer, bearer_bytes) = kept.selected.ok_or_else(|| Error::MpcTlsFailed {
        detail: "the session produced no layout".into(),
    })?;

    let bearer_opening = bearer_blinder(
        openings.iter().map(|opening| {
            (
                opening.direction,
                opening.ranges.as_slice(),
                opening.blinder.as_slice(),
            )
        }),
        &bearer,
    )?;

    // The notary reads no request before writing the record.
    let wire: AttestationWire =
        tokio::time::timeout(RECORD_TIMEOUT, libid_transcript::read_msg(io))
            .await
            .map_err(|_| Error::MpcTlsFailed {
                detail: "the notary ran the session and then sent no record in time"
                    .into(),
            })?
            .map_err(|e| Error::MpcTlsFailed {
                detail: format!("the notary sent no record for the session it ran: {e}"),
            })?;

    // What the browser is handed is what the commitment opens.
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

#[cfg(test)]
mod tests {
    use libid_tlsn::Direction;

    use super::{
        super::fixtures::{
            credentials,
            request,
            sent,
        },
        *,
    };

    /// GitHub's answer to a code it accepts.
    const RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"access_token\":\"gho_16C7e42F292c6912E7710c838347Ae178B4a\",\"token_type\":\"bearer\",\"scope\":\"\"}";

    /// The bearer's bytes in [`RECV`].
    const BEARER: &[u8] = b"gho_16C7e42F292c6912E7710c838347Ae178B4a";

    fn bearer_range() -> Range<usize> {
        let start = RECV
            .windows(BEARER.len())
            .position(|w| w == BEARER)
            .unwrap();
        start..start + BEARER.len()
    }

    fn opening(
        direction: Direction,
        range: Range<usize>,
        blinder: u8,
    ) -> CommitmentOpening {
        CommitmentOpening {
            direction,
            ranges: Vec::from([range]),
            blinder: vec![blinder; 16],
        }
    }

    /// The opening of exactly the bearer's range.
    fn bearer_opening() -> CommitmentOpening {
        opening(Direction::Received, bearer_range(), 0x03)
    }

    /// A selection that kept the bearer of [`RECV`].
    fn selected() -> Kept {
        let mut kept = Kept::new();
        kept.select(&sent(&credentials("ghs_secret"), &request()), RECV)
            .expect("the layouts form");
        kept
    }

    /// A record as the notary writes it.
    fn record() -> AttestationWire {
        AttestationWire {
            attested_data: vec![0xAB; 96],
            notary_signature: vec![0xCD; 65],
        }
    }

    /// What the notary does on the socket after the session.
    enum Notary {
        WritesTheRecord,
        ClosesWithoutOne,
        StaysSilent,
    }

    /// The assembly, over a socket the notary behaves as `notary` on.
    async fn assembled(
        kept: Kept,
        openings: &[CommitmentOpening],
        notary: Notary,
    ) -> Result<TokenResponse, Error> {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let held = match notary {
            Notary::WritesTheRecord => {
                libid_transcript::write_msg(&mut writer, &record())
                    .await
                    .unwrap();
                Some(writer)
            }
            Notary::ClosesWithoutOne => {
                drop(writer);
                None
            }
            Notary::StaysSilent => Some(writer),
        };
        let result = assemble(kept, openings, &mut reader).await;
        drop(held);
        result
    }

    /// The detail of a session failure.
    fn detail(failed: Error) -> String {
        match failed {
            Error::MpcTlsFailed { detail } => detail,
            other => panic!("{other}"),
        }
    }

    /// The two layouts form on an accepted code, and the bearer is kept as the
    /// bytes the received transcript carries.
    #[test]
    fn a_bearer_is_kept_off_the_received_transcript() {
        let kept = selected();
        let (range, bytes) = kept.selected.expect("a bearer");
        assert_eq!(range, bearer_range());
        assert_eq!(bytes, BEARER);
        assert!(kept.refusal.is_none());
    }

    /// A refused code is answered as the caller's; a refusal naming another
    /// error as this deployment's; a response naming nothing as the session's.
    #[test]
    fn a_response_without_a_bearer_is_answered_by_whose_refusal_it_is() {
        let driver_error = || libid_tlsn::Error::MpcTlsFailed {
            detail: "the driver's own words".into(),
        };
        for (recv, expected) in [
            (
                b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"bad_verification_code\"}"
                    .as_slice(),
                "OAuthFailed",
            ),
            (
                b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"incorrect_client_credentials\"}"
                    .as_slice(),
                "PlatformMisconfigured",
            ),
            (
                b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\"}".as_slice(),
                "MpcTlsFailed",
            ),
        ] {
            let mut kept = Kept::new();
            let failed = kept
                .select(&sent(&credentials("ghs_secret"), &request()), recv)
                .expect_err("no bearer, no layout");
            assert!(
                matches!(failed, libid_tlsn::Error::Transcript(_)),
                "{failed}"
            );
            assert!(kept.selected.is_none());
            let variant = match kept.refusal(driver_error()) {
                Error::OAuthFailed { .. } => "OAuthFailed",
                Error::PlatformMisconfigured { .. } => "PlatformMisconfigured",
                Error::MpcTlsFailed { .. } => "MpcTlsFailed",
                other => panic!("{other}"),
            };
            assert_eq!(variant, expected, "{}", String::from_utf8_lossy(recv));
        }
    }

    /// A refusal that is not about the bearer is the session driver's.
    #[test]
    fn a_refusal_that_is_not_about_the_bearer_is_the_drivers() {
        let mut kept = Kept::new();
        let failed = kept
            .select(b"not a token request", RECV)
            .expect_err("no request layout");
        let answered = kept.refusal(failed);
        assert!(matches!(answered, Error::Tlsn(_)), "{answered}");
    }

    /// The bearer, its opening and the notary's record, assembled; the other
    /// openings are passed over.
    #[tokio::test]
    async fn the_response_is_the_bearer_its_opening_and_the_record() {
        let openings = [
            opening(Direction::Sent, 10..20, 0x01),
            opening(Direction::Received, 0..bearer_range().start, 0x02),
            bearer_opening(),
        ];

        let response = assembled(selected(), &openings, Notary::WritesTheRecord)
            .await
            .unwrap();

        assert_eq!(response.access_token.as_bytes(), BEARER);
        assert_eq!(response.bearer_opening, vec![0x03; 16]);
        assert_eq!(
            response.token_attestation.attested_data,
            record().attested_data
        );
        assert_eq!(
            response.token_attestation.signature,
            record().notary_signature
        );
    }

    /// A notary that closes the socket without writing a record.
    #[tokio::test]
    async fn a_notary_that_writes_no_record_fails_the_exchange() {
        let failed = assembled(selected(), &[bearer_opening()], Notary::ClosesWithoutOne)
            .await
            .unwrap_err();
        assert!(detail(failed).contains("for the session it ran"));
    }

    /// A notary that keeps the socket open and writes nothing, past the
    /// record budget.
    #[tokio::test(start_paused = true)]
    async fn a_notary_that_never_writes_the_record_is_not_waited_for() {
        let failed = assembled(selected(), &[bearer_opening()], Notary::StaysSilent)
            .await
            .unwrap_err();
        assert!(detail(failed).contains("in time"));
    }

    /// The session committed the bearer as part of a wider run, so no opening
    /// covers exactly it.
    #[tokio::test]
    async fn an_opening_that_does_not_cover_the_bearer_fails_the_exchange() {
        let wider = [opening(Direction::Received, 0..RECV.len(), 0x03)];
        let failed = assembled(selected(), &wider, Notary::WritesTheRecord)
            .await
            .unwrap_err();
        assert!(detail(failed).contains("exactly once"));
    }

    /// A session that ran to completion without ever selecting a layout.
    #[tokio::test]
    async fn a_session_that_produced_no_layout_fails_the_exchange() {
        let failed = assembled(Kept::new(), &[], Notary::WritesTheRecord)
            .await
            .unwrap_err();
        assert!(detail(failed).contains("no layout"));
    }

    /// Committed bearer bytes that are not text are refused, not lossily
    /// decoded.
    #[tokio::test]
    async fn a_bearer_that_is_not_text_fails_the_exchange() {
        let mut kept = selected();
        kept.selected = Some((bearer_range(), vec![0xFF, 0xFE]));
        let failed = assembled(kept, &[bearer_opening()], Notary::WritesTheRecord)
            .await
            .unwrap_err();
        assert!(detail(failed).contains("UTF-8"));
    }
}
