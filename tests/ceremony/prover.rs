//! The suite's own prover: one notarized session through a notary of this
//! suite, and everything it produced. The layouts are the caller's, chosen
//! inside the session where the raw transcripts exist.

use std::{
    ops::Range,
    sync::Mutex,
    time::{
        Duration,
        Instant,
    },
};

use libid_tlsn::{
    CommitmentOpening,
    Direction,
    ProverStep,
};
use libid_transcript::{
    ceremony::Layout,
    AttestationWire,
};
use tokio::net::TcpStream;

use super::notary::Notary;

/// How long the session may take once the notary has been reached.
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the notary may take to hand back the record for a session it
/// has run.
const RECORD_TIMEOUT: Duration = Duration::from_secs(30);

/// A session that ran: what the layout selection kept, the lengths of the
/// two transcripts, the openings of every commitment, the record the notary
/// wrote, and when each step was reached.
pub struct Notarized<K> {
    pub kept: K,
    pub sent_len: usize,
    pub recv_len: usize,
    pub openings: Vec<CommitmentOpening>,
    pub wire: AttestationWire,
    pub steps: Vec<(ProverStep, Duration)>,
}

/// A session that did not produce a record: what stopped it, how far it got
/// and when, and how long it had run.
pub struct Failed {
    pub detail: String,
    pub steps: Vec<(ProverStep, Duration)>,
    pub elapsed: Duration,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} after {:?}; steps reached:",
            self.detail, self.elapsed
        )?;
        if self.steps.is_empty() {
            write!(f, " none")?;
        }
        for (step, at) in &self.steps {
            write!(f, " {step:?} at {at:?}")?;
        }
        Ok(())
    }
}

/// Run `request` through `notary` in one session, with `select` choosing the
/// two layouts over the full transcripts and keeping what the caller needs
/// from them.
pub async fn notarized<K>(
    notary: &Notary,
    request: hyper::Request<http_body_util::Full<bytes::Bytes>>,
    select: impl FnOnce(&[u8], &[u8]) -> Result<(Layout, Layout, K), libid_tlsn::Error>,
) -> Result<Notarized<K>, Failed> {
    let started = Instant::now();
    let steps: Mutex<Vec<(ProverStep, Duration)>> = Mutex::new(Vec::new());
    let failed = |detail: String| Failed {
        detail,
        steps: steps.lock().unwrap().clone(),
        elapsed: started.elapsed(),
    };

    let socket = TcpStream::connect(("127.0.0.1", notary.wire_port()))
        .await
        .map_err(|e| failed(format!("the notary was not reached: {e}")))?;

    let mut kept = None;
    let session = tokio::time::timeout(
        SESSION_TIMEOUT,
        libid_tlsn::prover_generic(
            socket,
            request,
            |sent, recv| {
                let (sent_layout, recv_layout, k) = select(sent, recv)?;
                kept = Some((k, sent.len(), recv.len()));
                Ok((sent_layout, recv_layout))
            },
            |step| steps.lock().unwrap().push((step, started.elapsed())),
        ),
    )
    .await;
    let mut result = match session {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => return Err(failed(format!("the session failed: {e}"))),
        Err(_) => {
            return Err(failed(format!(
                "the session did not finish within {SESSION_TIMEOUT:?}"
            )))
        }
    };
    let (kept, sent_len, recv_len) =
        kept.ok_or_else(|| failed("the session ran without selecting a layout".into()))?;

    let wire: AttestationWire = tokio::time::timeout(
        RECORD_TIMEOUT,
        libid_transcript::read_msg(&mut result.recovered_io),
    )
    .await
    .map_err(|_| failed("the notary ran the session and sent no record in time".into()))?
    .map_err(|e| {
        failed(format!(
            "the notary sent no record for the session it ran: {e}"
        ))
    })?;

    Ok(Notarized {
        kept,
        sent_len,
        recv_len,
        openings: result.commitment_openings,
        wire,
        steps: steps.into_inner().unwrap(),
    })
}

/// The public key `wire`'s signature recovers to, as hex: the signature is
/// over `keccak256(attested_data)`.
pub fn recovered(wire: &AttestationWire) -> String {
    let key = libid_crypto::recover_eth_claim(
        &wire.notary_signature,
        &libid_crypto::keccak256(&wire.attested_data),
    )
    .expect("a signature over the record it accompanies");
    libid_crypto::pubkey_to_hex(&key)
}

/// The blinder of the one commitment covering exactly `range` in
/// `direction`.
pub fn blinder(
    openings: &[CommitmentOpening],
    direction: Direction,
    range: &Range<usize>,
) -> Vec<u8> {
    let mut matching = openings.iter().filter(|opening| {
        opening.direction == direction && opening.ranges == [range.clone()]
    });
    match (matching.next(), matching.next()) {
        (Some(opening), None) => opening.blinder.clone(),
        (None, _) => panic!("no commitment covers exactly {range:?} in {direction:?}"),
        (Some(_), Some(_)) => {
            panic!("{range:?} in {direction:?} was committed more than once")
        }
    }
}

/// A layout refusal, in the session driver's error vocabulary.
pub fn refused(e: libid_transcript::ceremony::LayoutError) -> libid_tlsn::Error {
    libid_tlsn::Error::Transcript(libid_transcript::Error::Transcript {
        detail: e.to_string(),
    })
}
