//! What the bridge holds while it runs: configuration read once at startup,
//! and the callback document as last retrieved.
//!
//! There is no ceremony state. Each request is answered in isolation and
//! shares nothing mutable with another; a restart or a lost response leaves
//! no record.

use std::sync::Arc;

use tokio::sync::watch;

/// Configuration every route reads.
pub struct AppState {
    /// The callback document, the policy it is served under, and the validator
    /// it was retrieved with. Never empty: startup retrieves an artifact or the
    /// process does not start. A refresh replaces the whole value at once.
    pub(crate) callback: watch::Receiver<Arc<crate::artifact::Published>>,
    /// The publishing end, for the refresh task.
    pub(crate) callback_tx: watch::Sender<Arc<crate::artifact::Published>>,
    /// The Distribution the artifact was retrieved from, and is revalidated
    /// against on the refresh schedule.
    pub(crate) upstream: crate::artifact::upstream::Upstream,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule the configuration route applies, and what the callback document
    /// is told.
    pub(crate) allowed_origins: Arc<[crate::origin::Origin]>,
    /// The public ceremony configuration, serialized once: the exact bytes
    /// every admitted caller receives.
    pub(crate) ceremony_config: bytes::Bytes,
}
