//! Retrieving the callback artifact from the Distribution at startup and
//! revalidating it on a schedule. Nothing here sees a request: one connection
//! is opened per retrieval, carrying no cookie, credential or query, and a
//! redirect is refused.

use std::{
    sync::{
        Arc,
        LazyLock,
    },
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{
    BodyExt,
    Empty,
    Limited,
};
use hyper::{
    header,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{
        AsyncRead,
        AsyncWrite,
    },
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{
        pki_types::ServerName,
        ClientConfig,
        RootCertStore,
    },
    TlsConnector,
};

use super::{
    scan,
    CallbackDocument,
    DeploymentInputs,
    Published,
};
use crate::state::AppState;

/// The artifact's path under the CCDP origin.
pub(crate) const ARTIFACT_PATH: &str = "/ccdp/callback.html";

/// How long opening the transport may take: resolution, the connection, and
/// the TLS handshake over it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the request and its answer may take once the transport is open.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// When the refresh loop revalidates. Not configurable.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Schedule {
    /// Between revalidations when the last one succeeded, and the ceiling the
    /// backoff climbs to.
    interval: Duration,
    /// The first retry delay after a failure, doubling up to `interval`.
    floor: Duration,
}

impl Schedule {
    /// What a deployment runs on.
    pub(crate) const DEPLOYED: Schedule = Schedule {
        interval: Duration::from_secs(300),
        floor: Duration::from_secs(30),
    };
}

/// The TLS configuration every retrieval shares, built once. The anchors are
/// compiled in from `webpki-root-certs`, the crate `libid-tlsn` builds its
/// root store from; no system trust store is read.
static TLS: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    let (added, refused) = roots
        .add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec());
    assert!(
        added > 0 && refused == 0,
        "the compiled-in trust anchors did not parse: {added} added, {refused} refused"
    );
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
});

/// Why a retrieval did not produce a document. Every variant is a refusal,
/// never a repair.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FetchError {
    /// The Distribution could not be reached, or did not finish answering.
    #[error("{0}")]
    Unreachable(String),
    /// The Distribution answered with a redirect, which is refused.
    #[error("answered {0}, a redirect this bridge does not follow")]
    Redirect(StatusCode),
    /// The Distribution answered, and not with the artifact.
    #[error("answered {0}")]
    Status(StatusCode),
    /// The response was not HTML, so whatever it is, it is not the artifact.
    #[error("answered {0:?}, and the artifact is text/html")]
    Media(String),
    /// The body arrived encoded, which is not what the request admitted.
    #[error("answered Content-Encoding {0:?}, and the request admitted only identity")]
    Encoded(String),
    /// A `304` to a request that carried no validator.
    #[error("answered 304 Not Modified to a request carrying no If-None-Match")]
    UnaskedNotModified,
    /// The body ran past the bound before it ended.
    #[error("the body is over the {}-byte bound", scan::MAX_ARTIFACT_BYTES)]
    TooLarge,
    /// The body was not text.
    #[error("the body is not UTF-8")]
    NotUtf8,
    /// The artifact arrived and this bridge will not serve it.
    #[error(transparent)]
    Artifact(#[from] scan::ArtifactError),
}

impl FetchError {
    /// A Distribution that could not be reached, or stopped answering.
    fn unreachable(why: impl std::fmt::Display) -> FetchError {
        FetchError::Unreachable(why.to_string())
    }
}

/// What a conditional GET produced.
enum Fetched {
    /// `304`: the document in hand is still the current one.
    Unchanged,
    /// `200`: a body, and the validator to revalidate it with next time.
    Fresh {
        /// The artifact, decoded.
        html: String,
        /// Its `ETag`, when it sent one; without one every refresh is an
        /// unconditional GET.
        etag: Option<String>,
    },
}

/// The Distribution this deployment retrieves its artifact from, parsed once
/// at startup from the canonical CCDP origin.
pub(crate) struct Upstream {
    /// The origin as configured: what `compose` inserts and what the policy
    /// admits a frame from.
    origin: String,
    /// The host to dial and to name in SNI.
    host: String,
    /// The `Host` header, which carries the port only when it is not the
    /// scheme's default.
    authority: String,
    /// The port to dial.
    port: u16,
    /// Whether to speak TLS; false for a loopback `http` origin.
    tls: bool,
}

impl Upstream {
    /// Parse a canonical origin into something dialable.
    pub(crate) fn new(origin: &str) -> Result<Upstream, crate::error::Error> {
        let refuse = |why: &str| crate::error::Error::Config {
            detail: format!("CCDP_ORIGIN {origin} {why}"),
        };
        let url = url::Url::parse(origin).map_err(|e| refuse(&format!("{e}")))?;
        // The scheme decides the transport and the default port.
        let tls = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return Err(refuse("is not http or https")),
        };
        let Some(spelling) = url.host_str() else {
            return Err(refuse("names no host"));
        };
        // A `Host` header carries an IPv6 literal in brackets; a socket
        // address and a TLS server name take it without.
        let host = match url.host() {
            Some(url::Host::Ipv6(address)) => address.to_string(),
            _ => spelling.to_owned(),
        };
        // `Url` drops a port that is its scheme's default, so `port()` is the
        // non-default port `Host` carries.
        Ok(Upstream {
            origin: origin.to_owned(),
            host,
            authority: match url.port() {
                Some(port) => format!("{spelling}:{port}"),
                None => spelling.to_owned(),
            },
            port: url.port().unwrap_or(if tls { 443 } else { 80 }),
            tls,
        })
    }

    /// The URL this bridge retrieves, for a log line or a failure message.
    pub(crate) fn url(&self) -> String {
        format!("{}{ARTIFACT_PATH}", self.origin)
    }

    /// Retrieve the artifact and compose what would be served from it.
    /// `Ok(None)` is a `304`: the document in hand is current. Startup and the
    /// refresh loop both take this path.
    pub(crate) async fn retrieve(
        &self,
        allowed_origins: &[String],
        etag: Option<&str>,
    ) -> Result<Option<Published>, FetchError> {
        match self.fetch(etag).await? {
            Fetched::Unchanged => Ok(None),
            Fetched::Fresh { html, etag } => {
                let document = CallbackDocument::compose(
                    &html,
                    &DeploymentInputs {
                        ccdp_origin: &self.origin,
                        allowed_origins,
                    },
                )?;
                Ok(Some(Published { document, etag }))
            }
        }
    }

    /// One conditional GET, under one budget.
    async fn fetch(&self, etag: Option<&str>) -> Result<Fetched, FetchError> {
        let io = tokio::time::timeout(CONNECT_TIMEOUT, self.connect())
            .await
            .map_err(|_| FetchError::unreachable("opening the transport timed out"))??;
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(io, etag))
            .await
            .map_err(|_| FetchError::unreachable("the exchange timed out"))?
    }

    /// Open the transport: TCP, and TLS over it unless the origin is loopback
    /// `http`.
    async fn connect(&self) -> Result<Box<dyn Transport>, FetchError> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(FetchError::unreachable)?;
        if !self.tls {
            return Ok(Box::new(tcp));
        }
        let name = ServerName::try_from(self.host.clone())
            .map_err(|e| FetchError::unreachable(format!("{}: {e}", self.host)))?;
        let tls = TlsConnector::from(TLS.clone())
            .connect(name, tcp)
            .await
            .map_err(FetchError::unreachable)?;
        Ok(Box::new(tls))
    }

    /// Send the request and read the answer.
    async fn exchange(
        &self,
        io: Box<dyn Transport>,
        etag: Option<&str>,
    ) -> Result<Fetched, FetchError> {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(FetchError::unreachable)?;
        // One exchange per connection; it is dropped with the response.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let response = sender
            .send_request(self.request(etag))
            .await
            .map_err(FetchError::unreachable)?;
        let status = response.status();
        match status {
            // A `304` is refused unless the request carried a validator.
            StatusCode::NOT_MODIFIED if etag.is_some() => return Ok(Fetched::Unchanged),
            StatusCode::NOT_MODIFIED => return Err(FetchError::UnaskedNotModified),
            StatusCode::OK => {}
            // A redirect is refused, not followed.
            s if s.is_redirection() => return Err(FetchError::Redirect(s)),
            s => return Err(FetchError::Status(s)),
        }

        artifact(response).await
    }

    /// The request: no cookie, credential or query, and `Accept-Encoding:
    /// identity`, so the bytes hashed are the bytes read.
    fn request(&self, etag: Option<&str>) -> hyper::Request<Empty<Bytes>> {
        let mut request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(ARTIFACT_PATH)
            .header(header::HOST, &self.authority)
            .header(header::ACCEPT, "text/html")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(
                header::USER_AGENT,
                concat!("libid-bridge/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(etag) = etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        request
            .body(Empty::new())
            .expect("a request built from a validated origin and fixed headers")
    }
}

/// Whether a `Content-Type` names exactly `text/html`, case-insensitively,
/// with parameters after optional whitespace and a `;`. `text/htmlx` does not.
fn is_html(media: &str) -> bool {
    const HTML: &[u8] = b"text/html";

    let named = media.trim_start().as_bytes();
    named.len() >= HTML.len()
        && named[..HTML.len()].eq_ignore_ascii_case(HTML)
        && matches!(
            named.get(HTML.len()),
            None | Some(b';') | Some(b' ') | Some(b'\t')
        )
}

/// Read an artifact out of a `200`.
async fn artifact(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<Fetched, FetchError> {
    let (parts, body) = response.into_parts();
    let header =
        |name: header::HeaderName| parts.headers.get(name).and_then(|v| v.to_str().ok());
    let media = header(header::CONTENT_TYPE).unwrap_or_default();
    if !is_html(media) {
        return Err(FetchError::Media(media.to_owned()));
    }
    // The request admitted `identity` alone; an encoded body is refused.
    if let Some(encoding) = header(header::CONTENT_ENCODING)
        .filter(|e| !e.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(FetchError::Encoded(encoding.to_owned()));
    }
    let etag = header(header::ETAG).map(str::to_owned);

    // Bounded while it is read, whatever `content-length` declares.
    let body = Limited::new(body, scan::MAX_ARTIFACT_BYTES)
        .collect()
        .await
        .map_err(
            |e| match e.downcast_ref::<http_body_util::LengthLimitError>() {
                Some(_) => FetchError::TooLarge,
                None => FetchError::unreachable(format!("reading the body: {e}")),
            },
        )?;
    let html =
        String::from_utf8(Vec::from(body.to_bytes())).map_err(|_| FetchError::NotUtf8)?;
    Ok(Fetched::Fresh { html, etag })
}

/// What a retrieval reads and writes: TCP, or TLS over it.
trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for T {}

/// Revalidate the artifact for as long as the process runs. Replace-only: a
/// refresh either publishes a valid replacement or leaves the served document
/// as it is.
pub(crate) async fn refresh(state: Arc<AppState>, schedule: Schedule) {
    let upstream = &state.upstream;
    let url = upstream.url();
    let mut delay = schedule.interval;
    let mut backoff = schedule.floor;
    loop {
        tokio::time::sleep(delay).await;
        match revalidate(&state, upstream).await {
            Ok(replaced) => {
                if replaced {
                    let published = state.callback.borrow();
                    tracing::info!(
                        url,
                        etag = published.etag.as_deref().unwrap_or("<none>"),
                        policy =
                            published.document.csp.to_str().unwrap_or("<unreadable>"),
                        "the callback artifact was replaced"
                    );
                } else {
                    tracing::debug!(url, "the callback artifact is unchanged");
                }
                delay = schedule.interval;
                backoff = schedule.floor;
            }
            Err(e) => {
                tracing::warn!(
                    url,
                    detail = %e,
                    "the callback artifact could not be refreshed; still serving the last valid one"
                );
                delay = backoff;
                backoff = (backoff * 2).min(schedule.interval);
            }
        }
    }
}

/// One revalidation: `true` replaced the document, `false` was a `304`, and
/// an error left everything as it was.
async fn revalidate(
    state: &Arc<AppState>,
    upstream: &Upstream,
) -> Result<bool, FetchError> {
    // The borrow guard must not survive into the await below.
    let etag = state.callback.borrow().etag.clone();
    let Some(published) = upstream
        .retrieve(&state.allowed_origins, etag.as_deref())
        .await?
    else {
        return Ok(false);
    };
    // The document and its policy replace the old pair together.
    state.callback_tx.send_replace(Arc::new(published));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        Distribution,
        Reply,
    };

    /// A Distribution as a deployment retrieves from it.
    fn upstream(distribution: &Distribution) -> Upstream {
        Upstream::new(distribution.origin()).expect("a loopback origin parses")
    }

    /// An `https` origin that presents a certificate nothing trusts.
    async fn untrusted_tls_origin() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                    cert.key_pair.serialize_der().into(),
                ),
            )
            .expect("a server configuration");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(socket).await;
                });
            }
        });
        format!("https://localhost:{port}")
    }

    /// Retrieve, and answer with the refusal.
    async fn refused(upstream: Upstream, unless: &str) -> FetchError {
        match upstream.retrieve(&origins(), None).await {
            Err(refusal) => refusal,
            Ok(_) => panic!("{unless}"),
        }
    }

    /// The origins a deployment admits.
    fn origins() -> Vec<String> {
        vec!["https://app.example".to_owned()]
    }

    /// A deployment pointed at a fixture Distribution, built through
    /// `build_state`.
    async fn bridge(distribution: &Distribution) -> Arc<AppState> {
        crate::build_state(&config(distribution.origin()))
            .await
            .unwrap()
    }

    /// A deployment pointed at this test's own Distribution.
    fn config(ccdp_origin: &str) -> crate::config::Config {
        crate::fixtures::config(&["--ccdp-origin", ccdp_origin])
    }

    fn served(state: &Arc<AppState>) -> String {
        String::from_utf8(state.callback.borrow().document.body.to_vec()).unwrap()
    }

    /// A deployment serves the artifact its Distribution built.
    #[tokio::test]
    async fn a_retrieved_artifact_is_what_gets_served() {
        let distribution = Distribution::healthy().await;
        let state = bridge(&distribution).await;

        let published = state.callback.borrow().clone();
        assert_eq!(published.etag.as_deref(), Some("W/\"the-artifact\""));
        // Composed: the deployment's data is in the document, the marker gone.
        assert!(served(&state).contains("https://app.example"));
        assert!(!served(&state).contains(scan::MARKER));
        // And the policy names the hash of what is being served.
        assert!(published
            .document
            .csp
            .to_str()
            .unwrap()
            .contains("'sha256-"));
    }

    /// A deployment that cannot retrieve its artifact does not start, and the
    /// error names the URL.
    #[tokio::test]
    async fn a_deployment_that_cannot_retrieve_does_not_start() {
        let distribution = Distribution::serving(Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Reply::artifact()
        })
        .await;
        let Err(refusal) = crate::build_state(&config(distribution.origin())).await
        else {
            panic!("a deployment with no artifact must not build")
        };
        assert!(
            matches!(refusal, crate::error::Error::ArtifactUnavailable { ref url, .. }
                if url.ends_with(ARTIFACT_PATH)),
            "{refusal}"
        );
        assert!(
            format!("{refusal}").contains(distribution.origin()),
            "{refusal}"
        );
    }

    /// A Distribution that has nothing new says so, and nothing is republished.
    #[tokio::test]
    async fn an_unchanged_artifact_leaves_the_published_document_alone() {
        let distribution = Distribution::healthy().await;
        let state = bridge(&distribution).await;
        let before = state.callback.borrow().clone();

        let replaced = revalidate(&state, &upstream(&distribution)).await.unwrap();
        assert!(!replaced, "a 304 replaces nothing");
        // The same value, not an equal one: nothing was composed again.
        assert!(Arc::ptr_eq(&before, &state.callback.borrow()));
    }

    /// A failed refresh retains the last valid result and its validator.
    #[tokio::test]
    async fn an_artifact_that_will_not_scan_retains_the_last_valid_one() {
        let distribution = Distribution::healthy().await;
        let state = bridge(&distribution).await;
        let before = state.callback.borrow().clone();

        distribution.now_serves(Reply {
            etag: Some("W/\"the-replacement\""),
            body: "<!doctype html><body><p>not an artifact".to_owned(),
            ..Reply::artifact()
        });
        let refusal = revalidate(&state, &upstream(&distribution))
            .await
            .expect_err("an artifact with no slot is not serveable");
        assert!(matches!(refusal, FetchError::Artifact(_)), "{refusal}");

        assert!(Arc::ptr_eq(&before, &state.callback.borrow()));
        assert_eq!(
            state.callback.borrow().etag.as_deref(),
            Some("W/\"the-artifact\"")
        );
    }

    /// The publish itself: a Distribution with something new produces a new
    /// document, a new policy and a new validator, all at once.
    #[tokio::test]
    async fn a_new_artifact_replaces_the_published_one_whole() {
        let distribution = Distribution::healthy().await;
        let state = bridge(&distribution).await;
        let before = state.callback.borrow().clone();
        distribution.now_serves(Reply::replacement());

        assert!(revalidate(&state, &upstream(&distribution)).await.unwrap());

        let after = state.callback.borrow().clone();
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.etag.as_deref(), Some("W/\"the-replacement\""));
        // One value replaced: the policy names the hashes of the document served.
        assert_eq!(
            after.document.csp, before.document.csp,
            "the same bundle hashes the same, whatever validator carried it"
        );
        assert!(String::from_utf8(after.document.body.to_vec())
            .unwrap()
            .contains("https://app.example"));
    }

    /// A schedule fast enough to assert on, in real time.
    const BRISK: Schedule = Schedule {
        interval: Duration::from_millis(10),
        floor: Duration::from_millis(10),
    };

    /// A refresh that fails, one that finds nothing new, and one that
    /// replaces: the first two leave the served document as it is, and the
    /// loop reaches the third.
    #[tokio::test]
    async fn the_loop_survives_a_failed_refresh_and_replaces_on_a_later_one() {
        let distribution = Distribution::healthy().await;
        let state = bridge(&distribution).await;
        let before = state.callback.borrow().clone();

        // Answered in order, then the standing replacement.
        distribution.answers_next(Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Reply::artifact()
        });
        distribution.answers_next(Reply::artifact());
        distribution.now_serves(Reply::replacement());

        let mut published = state.callback.clone();
        let loop_task = tokio::spawn(refresh(state.clone(), BRISK));
        // Resolves on the first send, so nothing before it published.
        published.changed().await.expect("the loop publishes");
        // Stopped, though nothing below depends on how promptly it stops.
        loop_task.abort();

        let after = published.borrow_and_update().clone();
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.etag.as_deref(), Some("W/\"the-replacement\""));
        // Both queued answers were given before the replacement was reached.
        assert_eq!(distribution.still_queued(), 0);
        assert!(distribution.requests().len() >= 4);
    }

    /// A `3xx` is refused, not followed.
    #[tokio::test]
    async fn a_redirect_is_refused_rather_than_followed() {
        let distribution = Distribution::healthy().await;
        let state = bridge(&distribution).await;
        distribution.now_serves(Reply {
            status: StatusCode::FOUND,
            etag: None,
            ..Reply::artifact()
        });

        let refusal = revalidate(&state, &upstream(&distribution))
            .await
            .expect_err("a redirect is not an artifact");
        assert!(
            matches!(refusal, FetchError::Redirect(StatusCode::FOUND)),
            "{refusal}"
        );
        // One request, so nothing was followed.
        assert_eq!(distribution.requests().len(), 2);
    }

    /// A body over the bound is refused, with or without a `content-length`.
    #[tokio::test]
    async fn a_body_over_the_bound_is_refused() {
        let oversize = "x".repeat(scan::MAX_ARTIFACT_BYTES + 1);
        for chunked in [false, true] {
            let distribution = Distribution::serving(Reply {
                etag: None,
                body: oversize.clone(),
                chunked,
                ..Reply::artifact()
            })
            .await;
            let refusal = refused(
                upstream(&distribution),
                &format!("chunked={chunked}: an oversize body is refused"),
            )
            .await;
            assert!(
                matches!(refusal, FetchError::TooLarge),
                "chunked={chunked}: {refusal}"
            );
        }
    }

    /// A response that is not `text/html` is refused before scanning.
    #[tokio::test]
    async fn an_answer_that_is_not_html_is_refused() {
        for media in [
            "application/json",
            "text/plain",
            "text/htmlx",
            "text/html-fragment",
            "",
        ] {
            let distribution = Distribution::serving(Reply {
                media,
                etag: None,
                body: "{}".to_owned(),
                ..Reply::artifact()
            })
            .await;
            let refusal =
                refused(upstream(&distribution), "this is not the artifact").await;
            assert!(
                matches!(refusal, FetchError::Media(_)),
                "{media:?}: {refusal}"
            );
        }
    }

    /// Every spelling of `text/html` is admitted: the type is
    /// case-insensitive, and parameters begin after optional whitespace and a
    /// `;`.
    #[test]
    fn every_spelling_of_text_html_is_the_artifact() {
        for media in [
            "text/html",
            "text/html; charset=utf-8",
            "text/html;charset=utf-8",
            "TEXT/HTML",
            "Text/HTML; charset=UTF-8",
            "  text/html",
            "text/html ",
        ] {
            assert!(is_html(media), "{media:?} names the artifact");
        }
        for media in ["text/htmlx", "text/html-fragment", "application/json", ""] {
            assert!(!is_html(media), "{media:?} does not name the artifact");
        }
    }

    /// The request carries nothing a deployment did not configure.
    #[tokio::test]
    async fn the_request_carries_nothing_a_deployment_did_not_configure() {
        let distribution = Distribution::healthy().await;
        let state = bridge(&distribution).await;
        revalidate(&state, &upstream(&distribution)).await.unwrap();

        let requests = distribution.requests();
        let [first, second] = &requests[..] else {
            panic!("startup and one revalidation, got {}", requests.len())
        };
        for request in [first, second] {
            for absent in [
                header::COOKIE,
                header::AUTHORIZATION,
                header::REFERER,
                header::ORIGIN,
            ] {
                assert!(request.get(&absent).is_none(), "{absent} was sent");
            }
            assert_eq!(
                request.get(header::ACCEPT_ENCODING).unwrap(),
                "identity",
                "the artifact must arrive as the bytes that get hashed"
            );
        }
        // The first retrieval is unconditional; the second carries the
        // validator the first was published with.
        assert!(first.get(header::IF_NONE_MATCH).is_none());
        assert_eq!(
            second.get(header::IF_NONE_MATCH).unwrap(),
            "W/\"the-artifact\""
        );
    }

    /// A Distribution outlives the runtime that started it: the shared one is
    /// started by whichever test reaches it first, and that test's runtime is
    /// dropped when the test returns.
    #[test]
    fn a_distribution_outlives_the_runtime_that_started_it() {
        let runtime = || tokio::runtime::Runtime::new().unwrap();
        let distribution = runtime().block_on(Distribution::healthy());
        let published =
            runtime().block_on(upstream(&distribution).retrieve(&origins(), None));
        assert!(published.unwrap().is_some());
    }
    /// A peer presenting a certificate the compiled-in anchors do not carry is
    /// refused, and the refusal names the certificate.
    #[tokio::test]
    async fn an_untrusted_certificate_is_refused_as_a_certificate() {
        let origin = untrusted_tls_origin().await;
        let refusal = refused(
            Upstream::new(&origin).unwrap(),
            "an untrusted peer is not a Distribution",
        )
        .await;
        let detail = format!("{refusal}");
        assert!(
            detail.contains("certificate") && detail.contains("UnknownIssuer"),
            "the refusal must name the certificate, and this one says: {detail}"
        );
    }

    /// An origin this cannot dial is refused at startup.
    #[test]
    fn an_origin_that_cannot_be_dialled_is_refused_at_startup() {
        for spelling in [
            "not an origin",
            "https://",
            "file:///etc/passwd",
            // A special scheme with a known default port, which `Url` drops.
            "ftp://dist.example",
            "ws://dist.example",
        ] {
            assert!(
                Upstream::new(spelling).is_err(),
                "{spelling} must not parse into something dialable"
            );
        }
    }

    /// An encoded body is refused: the request admitted `identity` alone.
    #[tokio::test]
    async fn a_body_that_arrives_encoded_is_refused() {
        let distribution = Distribution::serving(Reply {
            etag: None,
            encoding: Some("br"),
            ..Reply::artifact()
        })
        .await;
        let refusal = refused(
            upstream(&distribution),
            "an encoded body is not the artifact this bridge would hash",
        )
        .await;
        assert!(matches!(refusal, FetchError::Encoded(_)), "{refusal}");
    }

    /// A `304` to a request that carried no validator is refused, and a
    /// deployment cannot start on it.
    #[tokio::test]
    async fn a_304_to_a_request_that_asked_nothing_is_refused() {
        let distribution = Distribution::serving(Reply {
            status: StatusCode::NOT_MODIFIED,
            etag: None,
            ..Reply::artifact()
        })
        .await;
        let refusal = refused(
            upstream(&distribution),
            "an unasked 304 leaves nothing to serve",
        )
        .await;
        assert!(
            matches!(refusal, FetchError::UnaskedNotModified),
            "{refusal}"
        );
        assert!(crate::build_state(&config(distribution.origin()))
            .await
            .is_err());
    }

    /// `Host` carries the port only when it is not the scheme's default.
    #[test]
    fn the_host_header_omits_a_default_port() {
        let authority = |origin| Upstream::new(origin).unwrap().authority;
        assert_eq!(authority("https://lib.id"), "lib.id");
        assert_eq!(authority("https://lib.id:443"), "lib.id");
        assert_eq!(authority("https://lib.id:8443"), "lib.id:8443");
        assert_eq!(authority("http://127.0.0.1:8787"), "127.0.0.1:8787");
        // An IPv6 literal is bracketed in the header and bare for the socket.
        let upstream = Upstream::new("http://[::1]:8787").unwrap();
        assert_eq!(upstream.authority, "[::1]:8787");
        assert_eq!(upstream.host, "::1");
    }
}
