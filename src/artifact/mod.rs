//! The callback document this bridge serves: the CCDP Distribution's artifact
//! with one unversioned list substituted into its one non-executable slot,
//! and a Content-Security-Policy computed here over the bytes served.

pub(crate) mod scan;

use axum::http::HeaderValue;
use base64::{
    engine::general_purpose::STANDARD,
    Engine,
};
use bytes::Bytes;
use sha2::{
    Digest,
    Sha256,
};

use scan::{
    ArtifactError,
    Layout,
};

/// The artifact compiled into this binary: a valid document that completes no
/// ceremony, served when no artifact is configured.
pub(crate) const EMBEDDED: &str = include_str!("callback.html");

/// What the deployment contributes to the document and its policy.
pub(crate) struct DeploymentInputs<'a> {
    /// The CCDP Distribution this bridge selects: in the inserted list, and
    /// the one origin the policy admits a frame from.
    pub(crate) ccdp_origin: &'a str,
    /// The effective admission set, which the Callback authenticates an
    /// application against. It contains the CCDP origin.
    pub(crate) allowed_origins: &'a [String],
}

/// Where the served artifact came from. It decides what is logged and nothing
/// else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// The compiled-in artifact.
    Embedded,
    /// A file this deployment supplied.
    Supplied,
}

/// The finished document: the exact bytes, and the policy they are served
/// under.
pub(crate) struct CallbackDocument {
    /// The document, composed once.
    pub(crate) body: Bytes,
    /// Its `Content-Security-Policy`, naming a hash for every script the body
    /// carries.
    pub(crate) csp: HeaderValue,
    /// Where the bytes came from.
    pub(crate) source: Source,
}

impl CallbackDocument {
    /// Configure one artifact and compose the response it is served as: the
    /// one constructor, where the policy is computed over the composed bytes.
    pub(crate) fn compose(
        html: &str,
        inputs: &DeploymentInputs<'_>,
        source: Source,
    ) -> Result<CallbackDocument, ArtifactError> {
        let layout = Layout::scan(html)?;
        // The slot holds exactly the marker, and the marker occurs nowhere
        // else.
        if html[layout.slot.clone()].trim() != scan::MARKER
            || html.matches(scan::MARKER).nth(1).is_some()
        {
            return Err(ArtifactError::Marker);
        }

        // One unversioned list: `[allowedOrigins, ccdpOrigin]`.
        let record = serde_json::json!([inputs.allowed_origins, inputs.ccdp_origin]);
        let mut body = String::with_capacity(html.len());
        body.push_str(&html[..layout.slot.start]);
        body.push_str(&json(&record));
        body.push_str(&html[layout.slot.end..]);

        // Substitution changes no executable byte: the scripts hash the same
        // before and after.
        let after = Layout::scan(&body)?;
        let before: Vec<String> = layout
            .executables
            .iter()
            .map(|r| hash_source(&html[r.clone()]))
            .collect();
        let hashes: Vec<String> = after
            .executables
            .iter()
            .map(|r| hash_source(&body[r.clone()]))
            .collect();
        if before != hashes {
            return Err(ArtifactError::SubstitutionMovedExecutableBytes);
        }

        let csp = policy(&hashes, inputs.ccdp_origin);
        let csp = HeaderValue::from_str(&csp)
            .map_err(|e| ArtifactError::Policy(format!("{csp:?}: {e}")))?;
        Ok(CallbackDocument {
            body: Bytes::from(body),
            csp,
            source,
        })
    }
}

/// The response policy, from the hashes of the scripts this document carries
/// and the one origin the deployment selects.
fn policy(hashes: &[String], ccdp_origin: &str) -> String {
    [
        "default-src 'none'".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'none'".to_owned(),
        "form-action 'none'".to_owned(),
        "frame-ancestors 'none'".to_owned(),
        // Hashes only; the artifact bundles its dependencies.
        format!("script-src {}", hashes.join(" ")),
        // The artifact's own inline styles.
        "style-src 'unsafe-inline'".to_owned(),
        // Callback may frame the Distribution it came from, and nothing else.
        format!("frame-src {ccdp_origin}"),
        "connect-src 'none'".to_owned(),
    ]
    .join("; ")
}

/// The CSP source for an inline script: the base64 SHA-256 of its exact text.
fn hash_source(script: &str) -> String {
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(script.as_bytes()))
    )
}

/// A JSON island, escaped so it cannot end the script element that carries
/// it: `<`, `>`, `&`, the line separators and every non-ASCII character leave
/// as `\uXXXX` escapes, so the inserted data is ASCII.
fn json(value: &serde_json::Value) -> String {
    use std::fmt::Write as _;

    let rendered = value.to_string();
    let mut out = String::with_capacity(rendered.len());
    for c in rendered.chars() {
        match c {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if c.is_ascii() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The effective admission set: the application origins with the CCDP
    /// origin joined.
    fn origins() -> Vec<String> {
        vec!["https://app.example".into(), "https://ccdp.example".into()]
    }

    fn composed(html: &str, origins: &[String]) -> CallbackDocument {
        CallbackDocument::compose(
            html,
            &DeploymentInputs {
                ccdp_origin: "https://ccdp.example",
                allowed_origins: origins,
            },
            Source::Embedded,
        )
        .expect("composes")
    }

    fn text(doc: &CallbackDocument) -> String {
        String::from_utf8(doc.body.to_vec()).unwrap()
    }

    /// The compiled-in artifact composes.
    #[test]
    fn the_compiled_in_artifact_composes() {
        let doc = composed(EMBEDDED, &origins());
        assert!(text(&doc).contains("https://app.example"));
    }

    /// The policy names the hash of the script the composed body carries.
    #[test]
    fn the_policy_names_the_hash_of_the_script_the_body_carries() {
        let doc = composed(EMBEDDED, &origins());
        let html = text(&doc);
        let csp = doc.csp.to_str().unwrap();

        let open = "<script type=\"module\">";
        assert_eq!(html.matches(open).count(), 1);
        let start = html.find(open).unwrap() + open.len();
        let end = start + html[start..].find("</script>").unwrap();
        assert!(
            csp.contains(&hash_source(&html[start..end])),
            "the policy must name the hash of the served script"
        );
    }

    /// The inserted record is one unversioned list: the allowlist, then the
    /// origin.
    #[test]
    fn the_inserted_record_is_one_unversioned_list() {
        let doc = composed(EMBEDDED, &origins());
        let html = text(&doc);
        let open = "<script id=\"libid-callback-config\" type=\"application/json\">";
        let start = html.find(open).unwrap() + open.len();
        let end = start + html[start..].find("</script>").unwrap();
        assert_eq!(
            &html[start..end],
            r#"[["https://app.example","https://ccdp.example"],"https://ccdp.example"]"#
        );
        assert!(!html.contains(scan::MARKER), "the marker is consumed");
    }

    /// Two insertions produce two documents with one `script-src`.
    #[test]
    fn substitution_does_not_move_the_bytes_the_browser_executes() {
        let one = composed(EMBEDDED, &origins());
        let many = composed(
            EMBEDDED,
            &["https://a.example".into(), "https://b.example".into()],
        );
        assert_ne!(text(&one), text(&many));
        let script_src = |d: &CallbackDocument| {
            d.csp
                .to_str()
                .unwrap()
                .split("; ")
                .find(|x| x.starts_with("script-src "))
                .unwrap()
                .to_owned()
        };
        assert_eq!(script_src(&one), script_src(&many));
    }

    /// Every non-ASCII character leaves as a `\uXXXX` escape, astral planes as
    /// a surrogate pair.
    #[test]
    fn the_inserted_data_is_always_ascii() {
        let escaped = json(&serde_json::json!("caf\u{e9} \u{1f512} \u{2028} <&>"));
        assert!(escaped.is_ascii(), "{escaped}");
        assert!(escaped.contains("\\u00e9"), "{escaped}");
        assert!(
            escaped.contains("\\ud83d") && escaped.contains("\\udd12"),
            "{escaped}"
        );
        assert!(escaped.contains("\\u2028"), "{escaped}");
        for e in ["\\u003c", "\\u0026", "\\u003e"] {
            assert!(escaped.contains(e), "{e} missing from {escaped}");
        }
    }

    /// An inserted value cannot end the script element that carries it.
    #[test]
    fn an_inserted_value_cannot_end_the_script_element() {
        let hostile = vec!["https://a.example/</script><script>x".to_owned()];
        let doc = composed(EMBEDDED, &hostile);
        let html = text(&doc);
        assert_eq!(html.matches("<script").count(), 2, "slot and module only");
        assert!(!html.contains("</script><script>x"));
    }

    /// A slot holding anything but the marker, or a marker occurring twice, is
    /// refused.
    #[test]
    fn a_slot_that_does_not_hold_exactly_the_marker_is_refused() {
        let filled = EMBEDDED.replace(scan::MARKER, "[]");
        assert!(matches!(
            CallbackDocument::compose(
                &filled,
                &DeploymentInputs {
                    ccdp_origin: "https://ccdp.example",
                    allowed_origins: &origins(),
                },
                Source::Embedded,
            ),
            Err(scan::ArtifactError::Marker)
        ));

        let twice = EMBEDDED.replace(
            "const query =",
            &format!("// {}\nconst query =", scan::MARKER),
        );
        assert!(matches!(
            CallbackDocument::compose(
                &twice,
                &DeploymentInputs {
                    ccdp_origin: "https://ccdp.example",
                    allowed_origins: &origins(),
                },
                Source::Embedded,
            ),
            Err(scan::ArtifactError::Marker)
        ));
    }
}
