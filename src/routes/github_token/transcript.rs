//! What one session discloses, and what the platform answered.
//!
//! The layouts decide what the notary is shown and what it only commits to, so
//! everything downstream rests on them: the Platform Verifier reads the record
//! the notary signs over these ranges, and the browser's proof rests on the
//! committed run in between.
//!
//! Nothing the platform wrote leaves this module. A refusal is read off the
//! received transcript and survives as one enum value; what reaches a log or a
//! caller is this service's own words.

use std::ops::Range;

use libid_tlsn::Direction;
use libid_transcript::ceremony;

use crate::error::Error;

use super::request::SECRET_FIELD;

/// Where the bearer sits in the received transcript, per the response layout.
///
/// It is the run framed by the two revealed anchors: the `"access_token":"`
/// delimiter and the quote that closes the value. That framing is the whole
/// reason those two runs are revealed — it is what tells the committed bearer
/// apart from a `refresh_token`, or from any other substring a prover chose to
/// commit.
pub(super) fn bearer_range(
    layout: &ceremony::Layout,
) -> Result<Range<usize>, ceremony::LayoutError> {
    let [anchor, closing_quote] = layout.reveal.as_slice() else {
        return Err(ceremony::LayoutError::MissingField("access_token".into()));
    };
    Ok(anchor.end..closing_quote.start)
}

/// The blinder that opens the committed bearer, picked out of everything the
/// session committed.
///
/// Matched on the range it covers rather than taken by position. Upstream does
/// document the order -- `commitment_openings` is "one opening per commitment
/// this session made, in the order the layouts stated them" -- but that is a
/// doc comment over a `Vec`, not an invariant anything checks, and the wrong
/// blinder opens nothing while looking like an answer. Matching on the range
/// costs a comparison and does not depend on the promise holding.
///
/// Exactly one must match. None means the session did not commit what the
/// layout said it would; more than one means the bearer is not identified by
/// its range, and handing back either would be a guess.
pub(super) fn bearer_blinder<'a>(
    openings: impl Iterator<Item = (Direction, &'a [Range<usize>], &'a [u8])>,
    bearer: &Range<usize>,
) -> Result<Vec<u8>, Error> {
    let mut matching = openings.filter_map(|(direction, ranges, blinder)| {
        (direction == Direction::Received && ranges == [bearer.clone()])
            .then_some(blinder)
    });
    match (matching.next(), matching.next()) {
        (Some(blinder), None) => Ok(blinder.to_vec()),
        _ => Err(Error::MpcTlsFailed {
            detail: "the session did not commit the bearer exactly once".into(),
        }),
    }
}

/// What one session discloses, and the bearer it committed.
pub(super) struct Selection {
    /// What the request reveals, and what it commits.
    pub(super) sent: ceremony::Layout,
    /// The same for the response.
    pub(super) recv: ceremony::Layout,
    /// Where the bearer sits in the received transcript.
    pub(super) bearer: Range<usize>,
    /// The bearer itself, taken from that range of that transcript.
    pub(super) bearer_bytes: Vec<u8>,
}

/// What this session discloses, and where the bearer ends up.
///
/// The single decision that matters to everyone downstream: the notary signs
/// what these two layouts revealed, the Platform Verifier reads that record,
/// and the browser's proof rests on the committed run in between. Each
/// direction's commitments are the complement of its reveals, so both tile by
/// construction — which is what the verifier's coverage check demands.
impl Selection {
    pub(super) fn of(sent: &[u8], recv: &[u8]) -> Result<Self, ceremony::LayoutError> {
        let sent_layout = ceremony::token_request(sent, Some(SECRET_FIELD))?;
        let recv_layout = ceremony::token_response(recv)?;
        let bearer = bearer_range(&recv_layout)?;
        // `"access_token":""` frames an empty run, which the layout's complement
        // never commits -- so no opening would match it, and the failure would
        // surface as a notary fault. It is the same thing as no bearer at all, and
        // it is GitHub's answer, not ours.
        if bearer.is_empty() {
            return Err(ceremony::LayoutError::MissingField("access_token".into()));
        }
        // Read here, off the transcript the notary attests, and never off the
        // decoded response body. OAUTH_BRIDGE.md asks for the exact bearer the
        // attestation commits, and the two are not always the same string: a JSON
        // escape decodes, and a chunk boundary landing inside the value shifts
        // everything after it. Handing back a bearer the commitment does not open
        // fails later, in the circuit, where the reason is invisible.
        let bearer_bytes = recv
            .get(bearer.clone())
            .ok_or_else(|| ceremony::LayoutError::MissingField("access_token".into()))?
            .to_vec();
        Ok(Selection {
            sent: sent_layout,
            recv: recv_layout,
            bearer,
            bearer_bytes,
        })
    }
}

/// The error code GitHub returns for a code that was spent, replayed or never
/// valid. The one refusal in its catalogue that the caller can act on.
const BAD_CODE: &[u8] = b"bad_verification_code";

/// The field GitHub names a refusal in. Its presence says the platform decided
/// something; its absence says the response was not a refusal at all.
const ERROR_FIELD: &[u8] = b"\"error\":\"";

/// What the platform actually answered, as far as this service can tell from
/// the received transcript.
///
/// Three outcomes, because there are three, and answering them alike is how an
/// operator ends up paged for a spent code or a user ends up told to retry
/// something that cannot succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlatformAnswer {
    /// `bad_verification_code`: spent, replayed, or never valid.
    RefusedTheCode,
    /// Some other named error -- `incorrect_client_credentials`,
    /// `redirect_uri_mismatch`. This deployment is broken for everybody.
    RefusedThisDeployment,
    /// No named error, and no bearer either: a `200` this service cannot use.
    /// Neither party can fix it by trying again.
    Unusable,
}

/// Read that answer off the transcript, where it exists and nowhere else.
///
/// The whole reading survives as one enum value. Nothing the platform wrote
/// travels further: what reaches a log or a caller is this service's own words.
impl PlatformAnswer {
    pub(super) fn in_response(recv: &[u8]) -> Self {
        let holds = |needle: &[u8]| recv.windows(needle.len()).any(|w| w == needle);
        if holds(BAD_CODE) {
            PlatformAnswer::RefusedTheCode
        } else if holds(ERROR_FIELD) {
            PlatformAnswer::RefusedThisDeployment
        } else {
            PlatformAnswer::Unusable
        }
    }
}

/// GitHub answering the exchange with something other than a bearer.
///
/// The session ran and the response arrived carrying no `access_token` for the
/// layout to anchor on. WHOSE fault that is decides the answer, and GitHub
/// returns `200` for every one of them, so the status cannot decide it -- the
/// error code can, and [`PlatformAnswer::in_response`] reads it.
///
/// `bad_verification_code` is the caller's: a double-clicked button, a reloaded
/// callback, a stale link. Every other named code --
/// `incorrect_client_credentials`, `redirect_uri_mismatch` -- is this
/// deployment, broken for everybody until a setting changes. Answering those as
/// the caller's would tell every user to retry something that cannot succeed,
/// and leave nothing above `warn` in the log while it happened.
///
/// And a `200` naming NO error while carrying no bearer is neither. It is a
/// response this service cannot use, and calling it a bad code would page an
/// operator over credentials that are fine while telling a user to retry.
pub(super) fn platform_refusal(
    refusal: Option<&ceremony::LayoutError>,
    answer: PlatformAnswer,
) -> Option<Error> {
    if !matches!(refusal, Some(ceremony::LayoutError::MissingField(f)) if f == "access_token")
    {
        return None;
    }
    Some(match answer {
        PlatformAnswer::RefusedTheCode => Error::OAuthFailed {
            platform: "github".into(),
            detail: "the token endpoint returned no access_token".into(),
        },
        PlatformAnswer::RefusedThisDeployment => Error::PlatformMisconfigured {
            platform: "github".into(),
            detail: "the token endpoint refused with an error that is not a bad \
                     verification code; check GH_OAUTH_CLIENT_SECRET and that the \
                     registered callback URL is exactly this deployment's redirect \
                     URI"
            .into(),
        },
        PlatformAnswer::Unusable => Error::MpcTlsFailed {
            detail: "the token endpoint answered with neither a bearer nor an error"
                .into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;

    const RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"access_token\":\"gho_16C7e42F292c6912E7710c838347Ae178B4a\",\"token_type\":\"bearer\",\"scope\":\"\"}";

    use super::super::{
        fixtures::{
            credentials,
            request,
            sent,
        },
        session::layout_failed,
        TokenError,
    };

    /// Both directions must tile — reveals and commitments accounting for every
    /// byte, with no gap and no overlap — or the Platform Verifier refuses the
    /// record the notary signs over them.
    #[test]
    fn both_directions_of_the_session_tile() {
        let credentials = credentials("ghs_averyrealisticlookingclientsecret00");
        let sent = sent(&credentials, &request());
        let found = Selection::of(&sent, RECV).unwrap();

        for (layout, len, what) in [
            (&found.sent, sent.len(), "request"),
            (&found.recv, RECV.len(), "response"),
        ] {
            let mut spans: Vec<_> = layout
                .reveal
                .iter()
                .chain(layout.commit.iter())
                .cloned()
                .collect();
            spans.sort_by_key(|r| r.start);
            let mut at = 0;
            for span in spans {
                assert_eq!(span.start, at, "{what}: gap or overlap at {at}");
                assert!(span.end > span.start, "{what}: empty span at {at}");
                at = span.end;
            }
            assert_eq!(at, len, "{what}: coverage stops short");
        }

        assert_eq!(
            &RECV[found.bearer.clone()],
            b"gho_16C7e42F292c6912E7710c838347Ae178B4a"
        );
        // OAUTH_BRIDGE.md: what this route returns is the bearer the attestation
        // commits, read off the attested transcript rather than re-parsed from
        // the decoded body, which need not spell it the same way.
        assert_eq!(found.bearer_bytes, &RECV[found.bearer]);
    }

    /// GitHub answers a spent or forged code with `200` and an error object.
    /// There is no bearer to commit, so the session is refused rather than
    /// completed around an anchor that is not there.
    #[test]
    fn a_response_carrying_no_bearer_is_refused() {
        let credentials = credentials("ghs_secret");
        let sent = sent(&credentials, &request());
        const ERROR: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"bad_verification_code\"}";
        assert!(Selection::of(&sent, ERROR).is_err());
    }

    /// GitHub answers `200` to a spent code AND to a wrong client secret, so
    /// the status tells the two apart from nothing. The error code does, and
    /// the two deserve opposite answers: one caller retries, the other means
    /// every ceremony on this deployment fails until somebody changes a
    /// setting.
    #[test]
    fn a_refused_code_and_a_broken_deployment_are_not_the_same_answer() {
        let refused = ceremony::LayoutError::MissingField("access_token".into());

        let callers =
            platform_refusal(Some(&refused), PlatformAnswer::RefusedTheCode).unwrap();
        assert!(matches!(callers, Error::OAuthFailed { .. }));
        assert_eq!(
            TokenError::from_exchange(callers).status,
            StatusCode::BAD_REQUEST,
            "a spent code is the caller's to fix"
        );

        let ours =
            platform_refusal(Some(&refused), PlatformAnswer::RefusedThisDeployment)
                .unwrap();
        assert!(matches!(ours, Error::PlatformMisconfigured { .. }));
        assert_eq!(
            TokenError::from_exchange(ours).status,
            StatusCode::BAD_GATEWAY,
            "a rejected client secret is not, and must not tell a user to retry"
        );

        // And nothing this service writes about it quotes the platform.
        let Some(Error::PlatformMisconfigured { detail, .. }) =
            platform_refusal(Some(&refused), PlatformAnswer::RefusedThisDeployment)
        else {
            panic!("a deployment fault")
        };
        assert!(!detail.contains("bad_verification_code"), "{detail}");
    }

    /// Which of the two it is comes off the received transcript, and the only
    /// thing that survives that reading is one bit.
    #[test]
    fn the_bad_code_marker_is_read_from_the_response_the_session_saw() {
        let names = |body: &[u8]| body.windows(BAD_CODE.len()).any(|w| w == BAD_CODE);
        assert!(names(
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"bad_verification_code\"}"
        ));
        for other in [
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"incorrect_client_credentials\"}"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"redirect_uri_mismatch\"}".as_slice(),
            b"HTTP/1.1 500 Internal Server Error\r\n\r\n{}".as_slice(),
        ] {
            assert!(!names(other), "{}", String::from_utf8_lossy(other));
        }
    }

    /// Everything else is this service, the notary or the network. A request
    /// body that will not form a layout is THIS service disagreeing with
    /// itself, and a caller can do nothing about it — so it must not be
    /// reported as the caller's fault.
    #[test]
    fn every_other_failure_stays_an_upstream_fault() {
        for other in [
            Some(&ceremony::LayoutError::MissingCredential),
            Some(&ceremony::LayoutError::NoHeadBoundary),
            None,
        ] {
            for answer in [
                PlatformAnswer::RefusedTheCode,
                PlatformAnswer::RefusedThisDeployment,
                PlatformAnswer::Unusable,
            ] {
                assert!(platform_refusal(other, answer).is_none(), "{other:?}");
            }
        }
        assert_eq!(
            TokenError::from_exchange(Error::MpcTlsFailed {
                detail: "the notary went away".into(),
            })
            .status,
            StatusCode::BAD_GATEWAY
        );
    }

    /// The opening this route hands back must open the bearer and not one of
    /// the two runs around it, so the range it is matched on has to be the
    /// framed value exactly.
    #[test]
    fn the_bearer_range_is_the_value_between_the_anchors() {
        let layout = ceremony::token_response(RECV).unwrap();
        let range = bearer_range(&layout).unwrap();

        assert_eq!(
            &RECV[range.clone()],
            b"gho_16C7e42F292c6912E7710c838347Ae178B4a"
        );
        assert!(
            layout.commit.contains(&range),
            "and it is a committed range, so an opening exists for it"
        );
    }

    const BEARER: Range<usize> = 64..96;

    /// One commitment opening, in the shape `exchange` maps them into.
    type Opening = (Direction, Vec<Range<usize>>, &'static [u8]);

    fn opening(
        direction: Direction,
        range: Range<usize>,
        blinder: &'static [u8],
    ) -> Opening {
        (direction, core::iter::once(range).collect(), blinder)
    }

    fn pick(openings: &[Opening]) -> Result<Vec<u8>, Error> {
        bearer_blinder(
            openings.iter().map(|(d, r, b)| (*d, r.as_slice(), *b)),
            &BEARER,
        )
    }

    /// The session commits three runs of the response and one of the request.
    /// Only one of them opens the bearer, and it is not the first.
    #[test]
    fn the_opening_is_chosen_by_the_range_it_covers() {
        let picked = pick(&[
            opening(Direction::Sent, BEARER, b"wrong direction"),
            opening(Direction::Received, 0..64, b"the run before"),
            opening(Direction::Received, BEARER, b"the bearer"),
            opening(Direction::Received, 96..128, b"the run after"),
        ])
        .unwrap();
        assert_eq!(picked, b"the bearer");
    }

    /// Handing back a blinder that opens something else would fail far from
    /// here, where the reason is no longer visible.
    #[test]
    fn an_ambiguous_or_absent_opening_is_refused_rather_than_guessed() {
        assert!(pick(&[opening(Direction::Received, 0..64, b"only the head")]).is_err());
        assert!(pick(&[
            opening(Direction::Received, BEARER, b"one"),
            opening(Direction::Received, BEARER, b"two"),
        ])
        .is_err());
        assert!(pick(&[]).is_err());
    }

    /// A response layout of an unexpected shape is refused rather than sliced
    /// blindly: the wrong range would select an opening that opens the wrong
    /// bytes, which fails far from here.
    #[test]
    fn a_response_layout_without_both_anchors_is_refused() {
        let layout = ceremony::Layout {
            reveal: core::iter::once(0..8).collect(),
            commit: core::iter::once(8..16).collect(),
        };
        assert!(bearer_range(&layout).is_err());
    }

    /// `"access_token":""` frames an empty run. The layout forms -- both
    /// anchors are there -- and the complement never commits a zero-length
    /// range, so no opening would open it and the failure would arrive as a
    /// notary fault. It is GitHub answering with no bearer, which is the
    /// caller's to fix, so it is told apart here and answered as one.
    #[test]
    fn an_empty_bearer_is_refused_as_a_platform_refusal_and_not_a_notary_fault() {
        let credentials = credentials("ghs_secret");
        let sent = sent(&credentials, &request());
        let recv = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"access_token\":\"\",\"token_type\":\"bearer\"}";

        // Destructured rather than `unwrap_err`, which would need `Debug` on
        // `Selection` -- and `Selection` carries the bearer.
        let Err(refusal) = Selection::of(&sent, recv) else {
            panic!("an empty bearer must not produce a selection")
        };
        assert!(
            matches!(&refusal, ceremony::LayoutError::MissingField(f) if f == "access_token"),
            "got {refusal:?}"
        );
        // Classified from the SAME bytes production classifies, not from a
        // value the test chose. That distinction is the whole point: this
        // response names no error at all, so it is neither a spent code nor
        // wrong credentials -- and answering it as either would tell a user to
        // retry what cannot succeed, or page an operator over a secret that is
        // fine.
        let answer = PlatformAnswer::in_response(recv);
        assert_eq!(answer, PlatformAnswer::Unusable);
        let told = platform_refusal(Some(&refusal), answer).expect("a platform refusal");
        assert!(matches!(told, Error::MpcTlsFailed { .. }));
        assert_eq!(
            TokenError::from_exchange(told).status,
            StatusCode::BAD_GATEWAY
        );
    }

    /// The three answers a `200` can carry, read off the transcript the way the
    /// session reads it.
    #[test]
    fn the_platform_answer_is_read_from_the_response_the_session_saw() {
        let body = |json: &str| {
            format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{json}")
                .into_bytes()
        };
        for (json, expected) in [
            (
                r#"{"error":"bad_verification_code"}"#,
                PlatformAnswer::RefusedTheCode,
            ),
            (
                r#"{"error":"incorrect_client_credentials"}"#,
                PlatformAnswer::RefusedThisDeployment,
            ),
            (
                r#"{"error":"redirect_uri_mismatch"}"#,
                PlatformAnswer::RefusedThisDeployment,
            ),
            (r#"{"access_token":""}"#, PlatformAnswer::Unusable),
            (r#"{}"#, PlatformAnswer::Unusable),
        ] {
            assert_eq!(PlatformAnswer::in_response(&body(json)), expected, "{json}");
        }

        // And each maps to a different answer, which is why they are told
        // apart at all.
        let refused = ceremony::LayoutError::MissingField("access_token".into());
        for (answer, status) in [
            (PlatformAnswer::RefusedTheCode, StatusCode::BAD_REQUEST),
            (
                PlatformAnswer::RefusedThisDeployment,
                StatusCode::BAD_GATEWAY,
            ),
            (PlatformAnswer::Unusable, StatusCode::BAD_GATEWAY),
        ] {
            let told = platform_refusal(Some(&refused), answer).expect("a refusal");
            assert_eq!(TokenError::from_exchange(told).status, status, "{answer:?}");
        }
    }

    /// A response carrying no `access_token` anchor at all is the same
    /// refusal as one carrying an empty value, and both are answered the same
    /// way: GitHub had no bearer for this code, so the caller gets a `400` and
    /// is told to start a fresh ceremony.
    ///
    /// Every OTHER layout refusal is this service, the notary, or a transcript
    /// nobody can describe, and the caller can only try again later. That is
    /// the half `NoHeadBoundary` stands for here.
    #[test]
    fn a_missing_access_token_is_a_refused_code_and_every_other_refusal_is_not() {
        let credentials = credentials("ghs_secret");
        let sent = sent(&credentials, &request());
        let recv = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"error\":\"bad_verification_code\"}";

        let Err(refusal) = Selection::of(&sent, recv) else {
            panic!("a response with no bearer must not produce a selection")
        };
        let told = platform_refusal(Some(&refusal), PlatformAnswer::in_response(recv))
            .expect("a refusal");
        assert_eq!(
            TokenError::from_exchange(told).status,
            StatusCode::BAD_REQUEST,
            "no access_token plus a bad-code marker is the caller's to act on"
        );

        // And nothing else is. A layout that would not form for any other
        // reason is this service's or the notary's, and says so with a 502.
        for other in [
            ceremony::LayoutError::NoHeadBoundary,
            ceremony::LayoutError::MissingCredential,
            ceremony::LayoutError::MissingHeader("host"),
        ] {
            assert!(
                platform_refusal(Some(&other), PlatformAnswer::RefusedTheCode).is_none(),
                "{other} is not the caller's to fix"
            );
        }
        assert!(platform_refusal(None, PlatformAnswer::RefusedTheCode).is_none());
        assert_eq!(
            TokenError::upstream("anything at all").status,
            StatusCode::BAD_GATEWAY
        );

        // Restated for the session driver, it says a transcript was refused
        // and carries the reason, not a second guess at whose fault it is.
        let restated = layout_failed(&refusal);
        assert!(restated.to_string().contains("access_token"), "{restated}");
    }
}
