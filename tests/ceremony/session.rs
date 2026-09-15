//! One platform's two notarized sessions, as the client runs them: the token
//! exchange of a public client and the identity read with the bearer it
//! yields, laid out by the platform's profile; and what the Platform Verifier
//! demands of both records on chain, shape by shape.

use std::ops::Range;

use libid_ceremony::attestation::{
    AttestedData,
    DirectionBlock,
};
use libid_tlsn::Direction;
use libid_transcript::ceremony::{
    IdShape,
    IdentitySession,
    Layout,
    TokenSession,
};

use super::{
    notary::Notary,
    prover::{
        self,
        Failed,
        Notarized,
    },
};

/// A request as the suite's prover sends it.
pub type Request = hyper::Request<http_body_util::Full<bytes::Bytes>>;

/// The bearer the token response carries: where it sits in the received
/// transcript, and its value, read off the transcript itself.
#[derive(Clone, Debug)]
pub struct Bearer {
    pub range: Range<usize>,
    pub value: String,
}

/// The token session, run: the bearer, the opening of its commitment, and
/// the session's record.
pub struct Exchange {
    pub blinder: Vec<u8>,
    pub session: Notarized<Bearer>,
}

/// A failure in the session driver's transcript vocabulary.
fn transcript(detail: String) -> libid_tlsn::Error {
    libid_tlsn::Error::Transcript(libid_transcript::Error::Transcript { detail })
}

/// The `error` member of a JSON body in `recv`, when the platform answered
/// with one.
fn platform_error(recv: &[u8]) -> Option<String> {
    let delimiter = b"\"error\":\"";
    let at =
        recv.windows(delimiter.len()).position(|w| w == delimiter)? + delimiter.len();
    let end = recv[at..].iter().position(|&b| b == b'"')?;
    Some(String::from_utf8_lossy(&recv[at..at + end]).into_owned())
}

impl Exchange {
    /// `request` through `notary`, laid out as `token`: the request as the
    /// profile reveals it, the response revealing the bearer's framing. A
    /// response framing no bearer fails with the platform's `error` member
    /// when it carries one.
    pub async fn notarized(
        notary: &Notary,
        request: Request,
        token: &TokenSession,
    ) -> Result<Exchange, Failed> {
        let token = *token;
        let session = prover::notarized(notary, request, move |sent, recv| {
            let sent_layout =
                Layout::token_request(sent, &token).map_err(prover::refused)?;
            let recv_layout = Layout::token_response(recv).map_err(|e| {
                transcript(match platform_error(recv) {
                    Some(error) => format!("{e}; the platform said: {error}"),
                    None => e.to_string(),
                })
            })?;
            let [anchor, closing_quote] = recv_layout.reveal.as_slice() else {
                return Err(transcript("the response layout frames no bearer".into()));
            };
            let range = anchor.end..closing_quote.start;
            if range.is_empty() {
                return Err(transcript("the response carries an empty bearer".into()));
            }
            let value = String::from_utf8(recv[range.clone()].to_vec())
                .map_err(|_| transcript("the bearer is not UTF-8".into()))?;
            Ok((sent_layout, recv_layout, Bearer { range, value }))
        })
        .await?;
        let blinder =
            prover::blinder(&session.openings, Direction::Received, &session.kept.range);
        Ok(Exchange { blinder, session })
    }
}

/// The identity session, run.
pub struct Identity {
    pub session: Notarized<()>,
}

impl Identity {
    /// `request` through `notary`, laid out as `identity`: the bearer
    /// committed, the two identity members revealed.
    pub async fn notarized(
        notary: &Notary,
        request: Request,
        identity: &IdentitySession,
    ) -> Result<Identity, Failed> {
        let identity = *identity;
        let session = prover::notarized(notary, request, move |sent, recv| {
            let sent_layout = Layout::identity_request(sent).map_err(prover::refused)?;
            let recv_layout =
                Layout::identity_response(recv, &identity).map_err(prover::refused)?;
            Ok((sent_layout, recv_layout, ()))
        })
        .await?;
        Ok(Identity { session })
    }
}

/// `requireExactCoverage`: revealed ranges and commitments account for
/// `[0, length)` with no gap and no overlap.
fn assert_tiles(block: &DirectionBlock, length: usize, what: &str) {
    let mut spans: Vec<(usize, usize)> = block
        .revealed
        .iter()
        .map(|r| (r.start as usize, r.start as usize + r.bytes.len()))
        .chain(
            block
                .commitments
                .iter()
                .map(|c| (c.start as usize, c.end as usize)),
        )
        .collect();
    spans.sort_unstable();
    let mut at = 0;
    for (start, end) in spans {
        assert_eq!(start, at, "{what}: gap or overlap at {at}");
        assert!(end > start, "{what}: empty span at {start}");
        at = end;
    }
    assert_eq!(
        at, length,
        "{what}: coverage stops short of the signed length"
    );
}

/// The revealed bytes of one direction, joined in offset order: what the
/// verifier's cross-range delimiter count reads.
pub fn joined(block: &DirectionBlock) -> Vec<u8> {
    let mut ranges: Vec<_> = block.revealed.iter().collect();
    ranges.sort_by_key(|r| r.start);
    ranges.iter().flat_map(|r| r.bytes.clone()).collect()
}

/// How many times `needle` occurs in `haystack`.
pub fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

/// Where `delimiter` ends in `revealed`.
fn after(revealed: &[u8], delimiter: &[u8]) -> usize {
    revealed
        .windows(delimiter.len())
        .position(|w| w == delimiter)
        .unwrap_or_else(|| panic!("{} is revealed", String::from_utf8_lossy(delimiter)))
        + delimiter.len()
}

/// The value of the JSON string member `delimiter` opens in `revealed`: the
/// bytes up to the next quote.
fn member(revealed: &[u8], delimiter: &[u8]) -> String {
    let at = after(revealed, delimiter);
    let end = revealed[at..]
        .iter()
        .position(|&b| b == b'"')
        .expect("the member's closing quote is revealed");
    String::from_utf8_lossy(&revealed[at..at + end]).into_owned()
}

/// The digits of the bare integer member `delimiter` opens in `revealed`,
/// closed by the `,` or `}` the layout reveals with them.
fn integer_member(revealed: &[u8], delimiter: &[u8]) -> String {
    let at = after(revealed, delimiter);
    let digits = revealed[at..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    assert!(digits > 0, "the integer member carries digits");
    assert!(
        matches!(revealed.get(at + digits), Some(b',') | Some(b'}')),
        "the byte closing the integer is revealed with it"
    );
    String::from_utf8_lossy(&revealed[at..at + digits]).into_owned()
}

/// What the verifier demands of a token record of `token`'s session over
/// transcripts of these lengths that carried `bearer`: the request revealed
/// whole with nothing committed, its request line and required headers the
/// profile's, the bearer's commitment framed by its delimiter and the bearer
/// readable nowhere. The revealed request, for the platform's own checks on
/// its body.
pub fn check_token(
    record: &AttestedData,
    sent_len: usize,
    recv_len: usize,
    bearer: &Bearer,
    token: &TokenSession,
) -> Vec<u8> {
    assert_eq!(
        record.authority_id,
        AttestedData::authority_id_of(token.session.authority),
        "the authority is the profile's"
    );
    assert_eq!(record.sent_transcript_length as usize, sent_len);
    assert_eq!(record.recv_transcript_length as usize, recv_len);
    assert_tiles(&record.sent, sent_len, "token request");
    assert_tiles(&record.received, recv_len, "token response");

    // `_tokenBody`: one revealed sent range, anchored at the origin, and no
    // commitment: a public client's request hides nothing.
    assert_eq!(record.sent.revealed.len(), 1);
    assert_eq!(record.sent.revealed[0].start, 0);
    assert!(
        record.sent.commitments.is_empty(),
        "a public client's request hides nothing"
    );
    let request = &record.sent.revealed[0].bytes;
    assert!(
        request.starts_with(token.session.request_line.as_bytes()),
        "the request line is the profile's"
    );
    assert_eq!(count(request, b"\r\n\r\n"), 1, "exactly one head boundary");
    for line in token.required_headers {
        assert_eq!(
            count(request, format!("\r\n{line}\r\n").as_bytes()),
            1,
            "{line} once"
        );
    }

    // `requireFramedCommitment`: one commitment carries the bearer's framing,
    // it covers exactly the bearer, and the bearer is readable nowhere.
    let framed: Vec<_> = record
        .received
        .commitments
        .iter()
        .filter(|c| {
            record.received.revealed.iter().any(|r| {
                r.start as usize + r.bytes.len() == c.start as usize
                    && r.bytes.ends_with(b"\"access_token\":\"")
            })
        })
        .collect();
    assert_eq!(
        framed.len(),
        1,
        "exactly one commitment is framed as the bearer"
    );
    assert_eq!(
        framed[0].start as usize..framed[0].end as usize,
        bearer.range,
        "the framed commitment is the bearer the prover kept"
    );
    assert!(
        record
            .received
            .revealed
            .iter()
            .any(|r| r.start as usize == bearer.range.end && r.bytes.starts_with(b"\"")),
        "the quote closing the bearer is revealed"
    );
    assert_eq!(count(&joined(&record.received), bearer.value.as_bytes()), 0);
    request.clone()
}

/// What the verifier demands of an identity record of `identity`'s session
/// over transcripts of these lengths, read with `bearer`: the account's id
/// and handle, as revealed, the id in the shape the profile declares.
pub fn check_identity(
    record: &AttestedData,
    sent_len: usize,
    recv_len: usize,
    bearer: &str,
    identity: &IdentitySession,
) -> (String, String) {
    assert_eq!(
        record.authority_id,
        AttestedData::authority_id_of(identity.session.authority),
        "the authority is the profile's"
    );
    assert_eq!(record.sent_transcript_length as usize, sent_len);
    assert_eq!(record.recv_transcript_length as usize, recv_len);
    assert_tiles(&record.sent, sent_len, "identity request");
    assert_tiles(&record.received, recv_len, "identity response");

    // `_identitySession`: the request line sits at offset 0.
    let first = record
        .sent
        .revealed
        .iter()
        .min_by_key(|r| r.start)
        .expect("a revealed request line");
    assert_eq!(first.start, 0);
    assert!(
        first
            .bytes
            .starts_with(identity.session.request_line.as_bytes()),
        "the request line is the profile's"
    );

    // `requireBearerHeaderRequest`: exactly one commitment, framed by the
    // header bytes REQ-COMMON-40 names, covering exactly the bearer.
    assert_eq!(record.sent.commitments.len(), 1);
    let committed = &record.sent.commitments[0];
    let before = record
        .sent
        .revealed
        .iter()
        .find(|r| r.start as usize + r.bytes.len() == committed.start as usize)
        .expect("a revealed range ends where the commitment begins");
    assert!(before.bytes.ends_with(b"\r\nauthorization: Bearer "));
    let after = record
        .sent
        .revealed
        .iter()
        .find(|r| r.start == committed.end)
        .expect("a revealed range begins where the commitment ends");
    assert!(after.bytes.starts_with(b"\r\n"));
    assert_eq!(
        (committed.end - committed.start) as usize,
        bearer.len(),
        "the commitment covers the bearer and nothing else"
    );
    let sent = joined(&record.sent);
    assert_eq!(
        count(&sent, bearer.as_bytes()),
        0,
        "the bearer is readable nowhere"
    );

    // REQ-COMMON-39, counted over the concatenation: one authorization header.
    let mut normalized = sent.to_ascii_lowercase();
    normalized.retain(|&b| b != b' ' && b != b'\t');
    assert_eq!(count(&normalized, b"\r\nauthorization:bearer"), 1);

    // What the verifier can read of the response is the two identity
    // members, each once; the rest is committed.
    assert!(
        !record.received.commitments.is_empty(),
        "the rest of the response is committed, not published"
    );
    assert_eq!(
        record.received.revealed.len(),
        2,
        "two members, nothing else"
    );
    let body = joined(&record.received);
    let handle_delimiter = format!("\"{}\":\"", identity.handle_field);
    assert_eq!(count(&body, handle_delimiter.as_bytes()), 1);
    let handle = member(&body, handle_delimiter.as_bytes());
    let id = match identity.id_shape {
        IdShape::JsonString => {
            let delimiter = format!("\"{}\":\"", identity.id_field);
            assert_eq!(count(&body, delimiter.as_bytes()), 1);
            member(&body, delimiter.as_bytes())
        }
        IdShape::JsonInteger => {
            let delimiter = format!("\"{}\":", identity.id_field);
            assert_eq!(count(&body, delimiter.as_bytes()), 1);
            integer_member(&body, delimiter.as_bytes())
        }
    };
    (id, handle)
}

/// Records and wire bytes for the hermetic tests of each platform module.
#[cfg(test)]
pub mod fixtures {
    use http_body_util::BodyExt;
    use libid_ceremony::attestation::{
        AttestedData,
        DirectionBlock,
        RangeCommitment,
        RevealedRange,
    };
    use libid_transcript::ceremony::Layout;

    use super::{
        Bearer,
        Request,
    };

    /// `request` as hyper writes it: the request line in origin form,
    /// headers lowercase in builder order, `content-length` last for a
    /// body, then the body.
    pub async fn wire(request: Request) -> Vec<u8> {
        let (parts, body) = request.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let mut out = format!(
            "{} {} HTTP/1.1\r\n",
            parts.method,
            parts.uri.path_and_query().unwrap()
        )
        .into_bytes();
        for (name, value) in &parts.headers {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if parts.method == hyper::Method::POST {
            out.extend_from_slice(
                format!("content-length: {}\r\n", body.len()).as_bytes(),
            );
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&body);
        out
    }

    /// One direction of a record, from its bytes and layout, with a
    /// placeholder commitment per committed range.
    pub fn block(bytes: &[u8], layout: &Layout) -> DirectionBlock {
        DirectionBlock {
            revealed: layout
                .reveal
                .iter()
                .map(|r| RevealedRange {
                    start: r.start as u32,
                    bytes: bytes[r.clone()].to_vec(),
                })
                .collect(),
            commitments: layout
                .commit
                .iter()
                .map(|c| RangeCommitment {
                    start: c.start as u32,
                    end: c.end as u32,
                    commitment: [0xAB; 32],
                })
                .collect(),
        }
    }

    /// The record a notary signs over these transcripts and layouts, for a
    /// session with `authority`.
    pub fn record(
        authority: &str,
        sent: &[u8],
        recv: &[u8],
        sent_layout: &Layout,
        recv_layout: &Layout,
    ) -> AttestedData {
        AttestedData {
            authority_id: AttestedData::authority_id_of(authority),
            created_at: 1_770_000_000,
            sent_transcript_length: sent.len() as u32,
            recv_transcript_length: recv.len() as u32,
            sent: block(sent, sent_layout),
            received: block(recv, recv_layout),
        }
    }

    /// The bearer `value` where it sits in `recv`.
    pub fn bearer_in(recv: &[u8], value: &str) -> Bearer {
        let start = recv
            .windows(value.len())
            .position(|w| w == value.as_bytes())
            .expect("the bearer is in the transcript");
        Bearer {
            range: start..start + value.len(),
            value: value.into(),
        }
    }
}
