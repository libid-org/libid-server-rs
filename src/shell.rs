//! The callback document this bridge generates.
//!
//! It is a security shell and nothing else: one inline module bootstrap and
//! one empty mount point, no application markup. The bootstrap copies the
//! provider's return, bounds it, clears it with `history.replaceState`, reads
//! the CCDP version out of the OAuth `state`, and imports that version's
//! Callback module from the configured CCDP origin. Everything after that is
//! the module's.
//!
//! It is rendered **once**, at startup, and served as frozen bytes. That is not
//! an optimisation. The contract says the response may not depend on the
//! request's `Origin`, `Referer`, query, fragment, platform or ceremony, and a
//! document built once cannot: there is no per-request code to review for a
//! way it might.

use base64::{
    engine::general_purpose::STANDARD,
    Engine,
};
use sha2::{
    Digest,
    Sha256,
};

use axum::http::HeaderValue;
use bytes::Bytes;

use crate::error::{
    Error,
    Result,
};

/// The bootstrap. `__CCDP_ORIGIN__`, `__ORIGINS__` and `__VERSIONS__` are
/// JSON islands; `__OVERRIDES__` is the per-version input override map.
const BOOTSTRAP: &str = include_str!("shells/callback.js");

/// The finished document: the exact bytes, and the policy they are served
/// under.
pub struct RenderedShell {
    /// The document, rendered once. `Bytes`, so serving it is a reference
    /// count and not a copy: the contract's "one document" is one allocation
    /// for the life of the process, not one per request.
    pub body: Bytes,
    /// Its `Content-Security-Policy`, carrying the hash of the bootstrap the
    /// body actually contains. Parsed into a header value once, here, so no
    /// request pays for -- or can fail -- that parse.
    pub csp: HeaderValue,
}

/// What the shell embeds.
pub struct ShellInputs<'a> {
    /// The CCDP Distribution whose Callback the shell imports.
    pub ccdp_origin: &'a str,
    /// The closed list of CCDP versions the shell may select.
    pub supported_versions: &'a [u16],
    /// The application origins the Callback authenticates against.
    pub allowed_app_origins: &'a [String],
    /// The package-published stylesheet hash, or empty.
    pub style_hash: &'a str,
}

/// Render the callback shell.
pub fn callback(inputs: &ShellInputs<'_>) -> Result<RenderedShell> {
    // Only version 1 exists and its default tuple serves it, so there is
    // nothing to override yet. The map is embedded empty rather than omitted
    // so the bootstrap's algorithm is already the one a second version needs.
    let overrides = serde_json::json!({});
    let script = BOOTSTRAP
        .replace(
            "__CCDP_ORIGIN__",
            &json(&serde_json::json!(inputs.ccdp_origin)),
        )
        .replace(
            "__ORIGINS__",
            &json(&serde_json::json!(inputs.allowed_app_origins)),
        )
        .replace(
            "__VERSIONS__",
            &json(&serde_json::json!(inputs.supported_versions)),
        )
        .replace("__OVERRIDES__", &json(&overrides));

    // Exact module URLs, one per supported version, and no directory prefix:
    // the contract admits "only the exact supported Callback implementation
    // URLs on the configured CCDP origin".
    let modules = inputs
        .supported_versions
        .iter()
        .map(|v| callback_module_url(inputs.ccdp_origin, *v))
        .collect::<Vec<_>>()
        .join(" ");

    let csp = [
        "default-src 'none'".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'none'".to_owned(),
        "form-action 'none'".to_owned(),
        "frame-ancestors 'none'".to_owned(),
        format!("script-src {} {modules}", hash_source(&script)),
        style_src(inputs.style_hash),
        // The Callback may frame the distribution it came from, and nothing
        // else.
        format!("frame-src {}", inputs.ccdp_origin),
        // Only what a configured popup fallback needs. None is configured —
        // the WebRTC carrier is out of scope — so nothing is.
        "connect-src 'none'".to_owned(),
    ]
    .join("; ");

    let csp = HeaderValue::from_str(&csp).map_err(|e| Error::Config {
        detail: format!("the callback shell's CSP is not a header value: {e}"),
    })?;
    Ok(RenderedShell {
        body: Bytes::from(document(&script)),
        csp,
    })
}

/// Where a CCDP version's Callback module lives on the distribution.
pub fn callback_module_url(ccdp_origin: &str, version: u16) -> String {
    format!("{ccdp_origin}/ccdp/v{version}/callback.js")
}

/// The CSP source for an inline script: the base64 SHA-256 of its exact text.
///
/// Taken from the same `String` that goes into the document, so the two cannot
/// disagree. A hash computed anywhere else — a build step, a second render —
/// is a hash of a document nobody serves.
fn hash_source(script: &str) -> String {
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(script.as_bytes()))
    )
}

/// `style-src` for a shell whose stylesheet hash the package has published,
/// or `'none'` for one it has not. Unstyled is the safe half of that choice.
fn style_src(hash: &str) -> String {
    if hash.is_empty() {
        "style-src 'none'".into()
    } else {
        format!("style-src '{hash}'")
    }
}

/// A JSON island, escaped so it cannot end the script element that carries it.
///
/// `</script>` inside a string literal closes the element for an HTML parser,
/// whatever JSON thinks. The line separators are escaped because they end a
/// statement in JavaScript but not in JSON, and every remaining non-ASCII byte
/// with them, which makes the whole document ASCII and its encoding moot.
fn json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    for c in value.to_string().chars() {
        match c {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if c.is_ascii() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out
}

/// The shell around the bootstrap: the semantic equivalent the contract
/// spells out, and nothing that loads.
fn document(script: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>libID</title></head>\
         <body><main id=\"libid-root\"></main>\
         <script type=\"module\">{script}</script></body></html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origins() -> Vec<String> {
        vec!["https://app.example".into()]
    }

    /// The rendered shell, with its bytes readable as text and its policy as
    /// the string the tests inspect.
    struct Rendered {
        body: String,
        csp: String,
    }

    fn render(origins: &[String], style_hash: &str) -> Rendered {
        let shell = callback(&ShellInputs {
            ccdp_origin: "https://ccdp.example",
            supported_versions: &[1],
            allowed_app_origins: origins,
            style_hash,
        })
        .unwrap();
        Rendered {
            body: String::from_utf8(shell.body.to_vec()).unwrap(),
            csp: shell.csp.to_str().unwrap().to_owned(),
        }
    }

    /// The one property the whole shell rests on: the CSP names the hash of
    /// the script the document actually carries. Written this way a second
    /// script element fails the test rather than quietly going unhashed.
    #[test]
    fn the_csp_hashes_the_script_the_document_carries() {
        let shell = render(&origins(), "");
        assert_eq!(shell.body.matches("<script").count(), 1);
        let open = "<script type=\"module\">";
        let start = shell.body.find(open).unwrap() + open.len();
        let end = shell.body.find("</script>").unwrap();
        assert!(
            shell.csp.contains(&hash_source(&shell.body[start..end])),
            "the CSP must name the hash of the served script"
        );
    }

    /// The shell imports one exact module per supported version, from the
    /// configured distribution, and admits nothing broader.
    #[test]
    fn script_src_names_exact_callback_modules_and_nothing_else() {
        let shell = render(&origins(), "");
        assert!(shell
            .csp
            .contains("https://ccdp.example/ccdp/v1/callback.js"));
        // Token-wise, not substring-wise: the exact module URL begins with
        // `https:`, and the source this must refuse is the bare scheme alone.
        let tokens: Vec<&str> = shell.csp.split([' ', ';']).collect();
        for forbidden in [
            "*",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "https:",
            "http:",
            "data:",
            "blob:",
        ] {
            assert!(!tokens.contains(&forbidden), "{forbidden} in {}", shell.csp);
        }
        assert!(shell.csp.contains("frame-src https://ccdp.example"));
        assert!(shell.csp.contains("connect-src 'none'"));
    }

    /// A value that closed the script element would end the document early
    /// and put whatever followed outside the hash.
    #[test]
    fn an_embedded_value_cannot_end_the_script() {
        let hostile = vec!["https://a.example/</script><script>x".to_owned()];
        let shell = render(&hostile, "");
        assert_eq!(shell.body.matches("<script").count(), 1);
        assert!(shell.body.is_ascii());
    }

    /// A stylesheet nobody can name is one no shell should admit.
    #[test]
    fn an_unpublished_stylesheet_hash_admits_no_stylesheet() {
        assert!(render(&origins(), "").csp.contains("style-src 'none'"));
        assert!(render(&origins(), "sha256-abc")
            .csp
            .contains("style-src 'sha256-abc'"));
    }

    /// Google's profile is `response_mode=fragment`, so its routing `state`
    /// never reaches the query. A bootstrap that searched only the query would
    /// fail every Google ceremony closed while the platform stayed admitted.
    #[test]
    fn the_bootstrap_looks_for_the_routing_state_in_both_halves() {
        let body = render(&origins(), "").body;
        assert!(body.contains("new URLSearchParams(query).getAll('state')"));
        assert!(
            body.contains(
                "new URLSearchParams(fragment.replace(/^#/, '')).getAll('state')"
            ),
            "the fragment carries the state for Google"
        );
    }

    /// The bootstrap sees the deployment's values and no request's.
    #[test]
    fn the_bootstrap_embeds_the_deployment_and_only_the_deployment() {
        let shell = render(&origins(), "");
        for needle in [
            "\"https://ccdp.example\"",
            "[\"https://app.example\"]",
            "[1]",
        ] {
            assert!(shell.body.contains(needle), "{needle} missing");
        }
    }
}
