//! The failures this service produces.

/// A failure this service can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration was missing or malformed.
    #[error("config: {detail}")]
    Config {
        /// Human-readable failure detail.
        detail: String,
    },

    /// The platform refused the exchange for a reason the caller can act on:
    /// a spent, replayed or invalid code.
    #[error("OAuth failed for {platform}: {detail}")]
    OAuthFailed {
        /// The platform whose OAuth flow failed.
        platform: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// The platform refused this deployment's own credentials or
    /// registration; every exchange fails until a setting changes.
    #[error("{platform} refused this deployment's own credentials: {detail}")]
    PlatformMisconfigured {
        /// The platform that refused.
        platform: String,
        /// Human-readable failure detail, written by this service.
        detail: String,
    },

    /// The request named a notary that resolved to a private or internal
    /// address. Nothing was dialled.
    #[error("refused to dial the notary: {detail}")]
    NotaryRefused {
        /// Human-readable failure detail, written by this service.
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

    /// The MPC-TLS protocol failed.
    #[error("MPC-TLS failed: {detail}")]
    MpcTlsFailed {
        /// Human-readable failure detail.
        detail: String,
    },

    /// The callback artifact could not be retrieved from the Distribution at
    /// startup; the process does not start.
    #[error("callback artifact {url}: {detail}")]
    ArtifactUnavailable {
        /// The URL that was retrieved.
        url: String,
        /// Human-readable failure detail.
        detail: String,
    },

    /// The MPC-TLS session driver failed.
    #[error(transparent)]
    Tlsn(#[from] libid_tlsn::Error),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
