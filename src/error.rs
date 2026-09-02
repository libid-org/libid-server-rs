//! Error types for the handles backend.

/// Errors from the handle-claim flow.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration was missing or malformed.
    #[error("config: {detail}")]
    Config {
        /// Human-readable failure detail.
        detail: String,
    },

    /// OAuth token exchange or authorization failed.
    #[error("OAuth failed for {platform}: {detail}")]
    OAuthFailed {
        /// The platform whose OAuth flow failed.
        platform: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// A cryptographic operation failed.
    #[error("{op}: {detail}")]
    CryptoFailed {
        /// The operation that failed.
        op: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// Connecting to the notary failed.
    #[error("failed to connect to notary at {addr}: {detail}")]
    NotaryConnect {
        /// The notary address that was dialled.
        addr: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// The notary URL was malformed.
    #[error("invalid notary URL: {detail}")]
    NotaryUrl {
        /// Human-readable failure detail.
        detail: String,
    },

    /// The MPC-TLS protocol failed.
    #[error("MPC-TLS failed: {detail}")]
    MpcTlsFailed {
        /// Human-readable failure detail.
        detail: String,
    },

    /// The recomputed Merkle root did not match the proof's transcript root.
    #[error("transcript root mismatch")]
    TranscriptRootMismatch,

    /// Socket I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The MPC-TLS session driver failed.
    #[error(transparent)]
    Tlsn(#[from] libid_tlsn::Error),

    /// Transcript parsing or the notary wire protocol failed.
    #[error(transparent)]
    Transcript(#[from] libid_transcript::Error),

    /// A libid-crypto primitive failed.
    #[error(transparent)]
    Crypto(#[from] libid_crypto::Error),
    // No signing variant: this service holds no key and signs nothing.
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
