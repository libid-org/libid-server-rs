//! A notary for the suite's sessions: the MPC-TLS verifier of `libid_tlsn`,
//! the crate the suite's prover is built from, on an ephemeral loopback port.
//! It runs each session, signs the record with its own key and writes the
//! record back on the session's socket. It is the notary's protocol role
//! only: no session cap, no WebSocket transport, no JWKS, no managed signer.

use std::{
    net::SocketAddr,
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use libid_ceremony::attestation::AttestedData;
use libid_tlsn::attest::{
    FromObserved,
    ObservedSession,
};
use libid_transcript::{
    write_msg,
    AttestationWire,
};
use tokio::{
    net::TcpListener,
    sync::mpsc,
};

/// How long a test waits for the record of a session that ran.
const RECORD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A running notary on an ephemeral loopback port.
pub struct Notary {
    addr: SocketAddr,
    /// The public half of its signing key, as hex.
    pubkey: String,
    accepting: tokio::task::JoinHandle<()>,
    /// The records it signed, in session order.
    records: mpsc::UnboundedReceiver<AttestedData>,
}

impl Drop for Notary {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl Notary {
    /// A notary that runs each session and attests it, listening before this
    /// returns, on the fixture runtime, one session per connection on its own
    /// task.
    pub async fn attesting() -> Notary {
        let (signing, verifying) = libid_crypto::generate_keypair();
        let pubkey = libid_crypto::pubkey_to_hex(&verifying);
        let (bound, address) = tokio::sync::oneshot::channel();
        let (recorded, records) = mpsc::unbounded_channel();

        let accepting = libid_server_rs::fixtures::runtime().spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a loopback port for the fixture notary");
            let _ = bound.send(
                listener
                    .local_addr()
                    .expect("the fixture notary's own address"),
            );
            while let Ok((socket, _)) = listener.accept().await {
                let signing = signing.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let sign = |digest: &[u8; 32]| {
                        libid_crypto::sign_eth_claim(&signing, digest)
                            .expect("the fixture notary signs what it observed")
                    };
                    let _ = serve(socket, sign, &recorded).await;
                });
            }
        });
        let addr = address.await.expect("the fixture notary bound");

        Notary {
            addr,
            pubkey,
            accepting,
            records,
        }
    }

    /// The record of the next session this notary signed, as the struct it
    /// encoded; its `encode()` is the `attested_data` written to the prover.
    /// Thirty seconds at most.
    pub async fn record(&mut self) -> AttestedData {
        tokio::time::timeout(RECORD_TIMEOUT, self.records.recv())
            .await
            .expect("the notary signed a record within the record budget")
            .expect("the notary is running")
    }

    /// The port its wire listener is on: where the suite's prover dials it.
    pub fn wire_port(&self) -> u16 {
        self.addr.port()
    }

    /// The public key a record it signed recovers to, as hex.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }
}

/// One session, from accepted socket to written record; the record goes to
/// `recorded` before it is written.
async fn serve(
    socket: tokio::net::TcpStream,
    sign: impl Fn(&[u8; 32]) -> Vec<u8>,
    recorded: &mpsc::UnboundedSender<AttestedData>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut result = libid_tlsn::verifier(socket).await?;

    // The authority is the name the verifier authenticated during the
    // handshake.
    let attested = AttestedData::from_observed(ObservedSession {
        transcript: &result.partial_transcript,
        authority: &result.server_name.to_string(),
        commitments: &result.transcript_commitments,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_secs(),
    })?;
    let encoded = attested.encode()?;
    let _ = recorded.send(attested);

    // The signature is over keccak256(attestedData).
    let notary_signature = sign(&libid_crypto::keccak256(&encoded));
    write_msg(
        &mut result.recovered_io,
        &AttestationWire {
            attested_data: encoded,
            notary_signature,
        },
    )
    .await?;
    Ok(())
}
