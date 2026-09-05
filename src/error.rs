//! What can go wrong, as the few shapes this service can actually produce.
//!
//! Every variant here has a producer. A variant with none is a failure mode
//! the reader is invited to handle and the service never reaches, and a
//! `#[from]` with none silently admits a whole foreign error type into this
//! one the first time somebody writes `?` -- which is how an error nothing
//! shaped reaches a caller.

/// A failure this service can produce.
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

    /// The MPC-TLS session driver failed.
    #[error(transparent)]
    Tlsn(#[from] libid_tlsn::Error),
    // No signing variant: this service holds no key and signs nothing.
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
