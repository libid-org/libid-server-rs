//! The callback document this bridge serves, and how deployment data gets into
//! it.
//!
//! The bridge does not write this document. The CCDP Distribution builds one
//! self-contained artifact carrying every supported Callback implementation,
//! and this service configures and serves it at the registered redirect URI --
//! so browser code, version selection and failure UI all belong to the
//! distribution, and a compatible Callback change needs no bridge rebuild.
//!
//! What the bridge owns is narrow and does not vary by version: it substitutes
//! one unversioned list into one non-executable slot, computes the policy from
//! the bytes it is about to serve, and publishes the pair. The contract is
//! explicit that this is "a data-insertion contract, not a UI template or
//! renderer API".
//!
//! The hashes in that policy are computed HERE, over the served bytes, and
//! never copied from an upstream header -- the contract asks for "the artifact's
//! executable hashes with its own deployment-specific policy, not an upstream
//! policy permitting arbitrary sources", and a policy taken on trust from the
//! document it is supposed to constrain is not a constraint.

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

/// The artifact compiled into this binary.
///
/// A floor, and the reason the contract's "inert unavailable response" has no
/// representation in this service: there is always a valid document to serve,
/// so no request can arrive at a route that can answer nothing. It is not a
/// working Callback -- see the file itself -- and a deployment running on it
/// says so at startup.
pub(crate) const EMBEDDED: &str = include_str!("callback.html");

/// What the deployment contributes to the document and its policy.
pub(crate) struct DeploymentInputs<'a> {
    /// The CCDP Distribution this bridge selects. Travels in the inserted list
    /// and is the only origin the policy admits a frame from.
    pub(crate) ccdp_origin: &'a str,
    /// The bridge's effective admission set, which the Callback authenticates
    /// an application against. It contains the CCDP origin by construction.
    pub(crate) allowed_origins: &'a [String],
}

/// Where the served artifact came from. It decides what is logged and nothing
/// else: a supplied artifact is not more trusted than an embedded one -- both
/// are read, held to the same shape, and hashed by this service.
///
/// Stated by the caller, never inferred. A `const` is inlined at each use, so
/// two references to [`EMBEDDED`] need not share an address and a pointer
/// comparison would answer whatever the optimiser felt like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// The compiled-in floor: valid, and not a working Callback.
    Embedded,
    /// A file this deployment supplied.
    Supplied,
}

/// The finished document: the exact bytes, and the policy they are served
/// under.
pub(crate) struct CallbackDocument {
    /// The document, composed once. `Bytes`, so serving it is a reference count
    /// and not a copy.
    pub(crate) body: Bytes,
    /// Its `Content-Security-Policy`, naming a hash for every script the body
    /// actually carries. Parsed into a header value here, so no request pays
    /// for -- or can fail -- that parse.
    pub(crate) csp: HeaderValue,
    /// Where the bytes came from.
    pub(crate) source: Source,
}

impl CallbackDocument {
    /// Configure one artifact and compose the response it is served as.
    ///
    /// Private fields and this as the only constructor, because the property
    /// the whole document rests on -- the policy names the hash of the script
    /// the body carries -- is established here and nowhere else. A pair
    /// assembled anywhere else is a document a browser refuses to run, served
    /// `200`.
    pub(crate) fn compose(
        html: &str,
        inputs: &DeploymentInputs<'_>,
        source: Source,
    ) -> Result<CallbackDocument, ArtifactError> {
        let layout = Layout::scan(html)?;
        // The marker rule, which belongs to insertion rather than to reading a
        // document's shape: the slot must hold exactly the token, and the token
        // must occur nowhere else -- a second occurrence inside a bundled string
        // literal would make "repeated markers reject the artifact" depend on
        // which one a reader found first.
        // `nth(1)`, not `count() != 1`: the slot already holds one, so the
        // question is whether a SECOND exists, and that stops at the second
        // rather than walking a 4 MiB document to the end to report a number
        // nothing reads.
        if html[layout.slot.clone()].trim() != scan::MARKER
            || html.matches(scan::MARKER).nth(1).is_some()
        {
            return Err(ArtifactError::Marker);
        }

        // One unversioned list, derived from configuration this bridge has already
        // validated and published. The contract: "no version-keyed wrapper,
        // input-declaration block, or Bridge-side CCDP version list", and every
        // bundled implementation receives the same list.
        let record = serde_json::json!([inputs.allowed_origins, inputs.ccdp_origin]);
        let mut body = String::with_capacity(html.len());
        body.push_str(&html[..layout.slot.start]);
        body.push_str(&json(&record));
        body.push_str(&html[layout.slot.end..]);

        // "Data substitution does not change executable bytes." The slot is
        // `application/json` and nothing hashes it, so that is true by
        // construction -- and this turns "by construction" into something that
        // runs on every compose rather than an argument in a comment.
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
        // Hashes and nothing else. No external source at all: the artifact
        // bundles its dependencies rather than fetching them, so a document
        // that needed one would be a document this bridge should not serve.
        format!("script-src {}", hashes.join(" ")),
        // The package owns its markup, styles and inline logo, and there is no
        // stylesheet hash to configure any more -- a compatible UI change must
        // not need a bridge setting.
        "style-src 'unsafe-inline'".to_owned(),
        // Callback may frame the distribution it came from, and nothing else.
        format!("frame-src {ccdp_origin}"),
        // Only what a configured popup fallback would need. None is
        // configured, so nothing is.
        "connect-src 'none'".to_owned(),
    ]
    .join("; ")
}

/// The CSP source for an inline script: the base64 SHA-256 of its exact text.
///
/// Taken from the same `String` that goes into the document, so the two cannot
/// disagree. A hash computed anywhere else -- a build step, an upstream header
/// -- is a hash of a document nobody serves.
fn hash_source(script: &str) -> String {
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(script.as_bytes()))
    )
}

/// A JSON island, escaped so it cannot end the script element that carries it.
///
/// `</script>` inside a string literal closes the element for an HTML parser,
/// whatever JSON thinks. The line separators are escaped because they end a
/// statement in JavaScript but not in JSON, and every remaining non-ASCII byte
/// with them, which makes the inserted data ASCII and its encoding moot. The
/// contract asks only for `<`; this is a superset and stays one.
fn json(value: &serde_json::Value) -> String {
    use std::fmt::Write as _;

    let rendered = value.to_string();
    // Escaping only ever grows, so the rendered length is the floor.
    let mut out = String::with_capacity(rendered.len());
    for c in rendered.chars() {
        match c {
            // `write!` into the buffer rather than `push_str(&format!(..))`,
            // which allocated a `String` per escaped character.
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

    /// The effective admission set as `build_state` derives it: the configured
    /// application origins with the resolved CCDP origin joined. `compose` is
    /// handed the finished set rather than deriving it, so the fixture carries
    /// the shape the contract's own example shows.
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

    /// The checked-in floor composes for a real deployment. This is what keeps
    /// an unserveable `callback.html` out of `main`: the file is data, so
    /// nothing else would catch it.
    #[test]
    fn the_compiled_in_artifact_composes() {
        let doc = composed(EMBEDDED, &origins());
        assert!(text(&doc).contains("https://app.example"));
    }

    /// The one property the whole document rests on: the policy names the hash
    /// of the script the body actually carries -- computed here, over the
    /// composed bytes, never taken from the artifact.
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

    /// Exactly the contract's shape: one unversioned list, the allowlist then
    /// the origin, no wrapper and no version key.
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

    /// Substitution changes the slot and nothing the browser runs, which is
    /// what lets the hash be computed once. Asserted rather than argued.
    #[test]
    fn substitution_does_not_move_the_bytes_the_browser_executes() {
        let one = composed(EMBEDDED, &origins());
        let many = composed(
            EMBEDDED,
            &["https://a.example".into(), "https://b.example".into()],
        );
        // Two different insertions, two different documents, one hash.
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

    /// Every non-ASCII byte leaves as a `\uXXXX` escape, astral planes as the
    /// surrogate pair JavaScript reads them as -- which makes the inserted data
    /// ASCII and the document's declared encoding irrelevant to what it means.
    #[test]
    fn the_inserted_data_is_always_ascii() {
        let escaped = json(&serde_json::json!("caf\u{e9} \u{1f512} \u{2028} <&>"));
        assert!(escaped.is_ascii(), "{escaped}");
        assert!(escaped.contains("\\u00e9"), "{escaped}");
        // U+1F512 is outside the BMP: two escapes, not one.
        assert!(
            escaped.contains("\\ud83d") && escaped.contains("\\udd12"),
            "{escaped}"
        );
        // A line separator ends a statement in JavaScript and not in JSON.
        assert!(escaped.contains("\\u2028"), "{escaped}");
        // The contract names `<`; these are the superset this has always used.
        for e in ["\\u003c", "\\u0026", "\\u003e"] {
            assert!(escaped.contains(e), "{e} missing from {escaped}");
        }
    }

    /// A value that closed the script element would end the data block early
    /// and put whatever followed into the document as markup.
    #[test]
    fn an_inserted_value_cannot_end_the_script_element() {
        let hostile = vec!["https://a.example/</script><script>x".to_owned()];
        let doc = composed(EMBEDDED, &hostile);
        let html = text(&doc);
        assert_eq!(html.matches("<script").count(), 2, "slot and module only");
        assert!(!html.contains("</script><script>x"));
    }

    /// The marker rule belongs to insertion, and both halves of it bite.
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

        // A second occurrence anywhere, even inside the bundled code, makes
        // "repeated markers reject the artifact" depend on which one a reader
        // found first.
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
