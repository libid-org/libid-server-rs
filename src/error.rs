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

    /// The callback artifact could not be retrieved from the Distribution at
    /// startup; the process does not start.
    #[error("callback artifact {url}: {detail}")]
    ArtifactUnavailable {
        /// The URL that was retrieved.
        url: String,
        /// Human-readable failure detail.
        detail: String,
    },
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
