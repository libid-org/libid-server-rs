//! Reading a Callback artifact well enough to serve it, and refusing anything
//! else: a tag-level tokenizer that finds the configuration slot and the byte
//! ranges the browser executes, and refuses any document where it cannot
//! determine both.

use std::ops::Range;

/// The marker the build leaves for deployment data, and the element that
/// carries it. Both are fixed by the artifact contract.
pub(crate) const MARKER: &str = "__LIBID_CALLBACK_CONFIG__";
const SLOT_OPEN: &str = "<script id=\"libid-callback-config\" type=\"application/json\">";
const MODULE_OPEN: &str = "<script type=\"module\">";
const SCRIPT_CLOSE: &str = "</script>";

/// The largest artifact this bridge will read.
pub(crate) const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// The most executable scripts a document may carry.
const MAX_EXECUTABLES: usize = 8;

/// Why an artifact was refused. Every variant is a refusal to serve, never a
/// repair.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ArtifactError {
    #[error("the artifact is {0} bytes, over the {MAX_ARTIFACT_BYTES}-byte bound")]
    TooLarge(usize),
    #[error("the artifact carries {0} at byte {1}, which this bridge will not read")]
    Forbidden(&'static str, usize),
    #[error("a tag at byte {0} is not in the canonical form this bridge reads")]
    Malformed(usize),
    #[error("a script at byte {0} is neither the config slot nor a plain module")]
    UnreadableScript(usize),
    #[error("the document carries {0} configuration slots, and must carry one")]
    Markers(usize),
    #[error("the configuration slot does not hold exactly the marker")]
    Marker,
    #[error("the document carries {0} executable scripts, and must carry 1 to 8")]
    Executables(usize),
    #[error("the document does not carry exactly one empty `<main id=\"libid-root\">`")]
    MountPoint,
    #[error("inserting the deployment data moved bytes the browser executes")]
    SubstitutionMovedExecutableBytes,
    #[error("the composed policy is not a header value: {0}")]
    Policy(String),
}

/// Where the slot is and what the browser will execute.
#[derive(Debug)]
pub(crate) struct Layout {
    /// The byte range of the marker itself, between the slot element's tags.
    pub(crate) slot: Range<usize>,
    /// The byte ranges the browser executes, in document order. Each is exactly
    /// the text between a `<script type="module">` and its `</script>`, which
    /// is the span a CSP hash covers.
    pub(crate) executables: Vec<Range<usize>>,
}

impl Layout {
    /// Read an artifact, or refuse it.
    pub(crate) fn scan(html: &str) -> Result<Layout, ArtifactError> {
        if html.len() > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::TooLarge(html.len()));
        }
        refuse_hostile_bytes(html)?;

        let bytes = html.as_bytes();
        let mut slots: Vec<Range<usize>> = Vec::new();
        let mut executables: Vec<Range<usize>> = Vec::new();
        let mut mounts = 0usize;
        let mut at = 0usize;

        while at < bytes.len() {
            let Some(next) = html[at..].find('<') else {
                break
            };
            let open = at + next;

            // A `<` in text that is not a tag start; a document writes `&lt;`.
            let rest = &html[open..];
            if rest.starts_with(SLOT_OPEN) {
                let text = open + SLOT_OPEN.len();
                let end = close_of(html, text)?;
                slots.push(text..end);
                at = end + SCRIPT_CLOSE.len();
            } else if rest.starts_with(MODULE_OPEN) {
                let text = open + MODULE_OPEN.len();
                let end = close_of(html, text)?;
                executables.push(text..end);
                at = end + SCRIPT_CLOSE.len();
            } else if let Some(after) = foreign_subtree(html, open)? {
                // Foreign content: an inline logo is stepped over.
                at = after;
            } else if rest
                .as_bytes()
                .get(1..7)
                .is_some_and(|t| t.eq_ignore_ascii_case(b"script"))
            {
                // Any other script element: a `src`, a nonce, a classic script, an
                // attribute in another order.
                return Err(ArtifactError::UnreadableScript(open));
            } else {
                if rest.starts_with("<main id=\"libid-root\"></main>") {
                    mounts += 1;
                }
                at = ordinary_tag(html, open)?;
            }
        }

        // Exactly one slot element. Whether it holds the marker is
        // [`super::compose`]'s rule: this runs on the composed document too.
        if slots.len() != 1 {
            return Err(ArtifactError::Markers(slots.len()));
        }
        let slot = slots.remove(0);
        if executables.is_empty() || executables.len() > MAX_EXECUTABLES {
            return Err(ArtifactError::Executables(executables.len()));
        }
        if mounts != 1 {
            return Err(ArtifactError::MountPoint);
        }
        Ok(Layout { slot, executables })
    }
}

/// Case-insensitive prefix test that allocates nothing.
fn starts_with_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(needle))
}

/// Case-insensitive search that allocates nothing, as a byte offset into
/// `haystack`. `needle` must be nonempty, which every caller's is a literal.
fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Bytes that make the rest of this reader unsound, refused before anything
/// else looks at the document.
fn refuse_hostile_bytes(html: &str) -> Result<(), ArtifactError> {
    // The HTML input stream normalises CR and CRLF to LF before tokenizing, so
    // a `\r` inside a script is hashed differently by the browser.
    if let Some(i) = html.find('\r') {
        return Err(ArtifactError::Forbidden("a carriage return", i));
    }
    // Inside script data `<!--` enters the escaped states, where `</script>`
    // does not necessarily end the element.
    if let Some(i) = html.find("<!--") {
        return Err(ArtifactError::Forbidden("an HTML comment", i));
    }
    // In foreign content `<script>` is parsed as markup rather than raw text.
    // `<svg` and `<math` are stepped over by `foreign_subtree` and refused
    // only if one holds a `<script`.
    if let Some(i) = html.find("<?") {
        return Err(ArtifactError::Forbidden("a processing instruction", i));
    }
    // `<![` needs no case folding; the word after it does.
    let mut from = 0;
    while let Some(k) = html[from..].find("<![") {
        let i = from + k;
        if starts_with_ci(&html.as_bytes()[i + 3..], b"cdata[") {
            return Err(ArtifactError::Forbidden("a CDATA section", i));
        }
        from = i + 3;
    }
    // Control bytes are not markup and not text a document needs.
    if let Some(i) = html
        .bytes()
        .position(|b| b.is_ascii_control() && b != b'\n' && b != b'\t')
    {
        return Err(ArtifactError::Forbidden("a control byte", i));
    }
    Ok(())
}

/// Skip an `<svg>` or `<math>` subtree, refusing one that contains a
/// `<script` (inside foreign content `<script>` is parsed as markup), or
/// return `None` if this tag opens neither.
fn foreign_subtree(html: &str, open: usize) -> Result<Option<usize>, ArtifactError> {
    let rest = &html[open..];
    let name = ["svg", "math"]
        .into_iter()
        // Compared as bytes: slicing `&str` at a fixed byte index panics inside
        // a multi-byte character.
        .find(|n| {
            rest.as_bytes()
                .get(1..=n.len())
                .is_some_and(|t| t.eq_ignore_ascii_case(n.as_bytes()))
                // The name ends there: `<math-field>` is a custom element, not
                // foreign content.
                && rest
                    .as_bytes()
                    .get(1 + n.len())
                    .is_none_or(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/')
        });
    let Some(name) = name else { return Ok(None) };

    // One open tag, which may close itself.
    let tag_end = end_of_tag(html, open, open + 1 + name.len())?;
    if html[open..tag_end].ends_with("/>") {
        return Ok(Some(tag_end));
    }

    // Otherwise walk to the matching close, counting nesting.
    let tail = &html.as_bytes()[tag_end..];
    let (o, c) = (format!("<{name}"), format!("</{name}"));
    let (o, c) = (o.as_bytes(), c.as_bytes());
    let (mut depth, mut i) = (1usize, 0usize);
    while depth > 0 {
        let next_open = find_ci(&tail[i..], o).map(|k| i + k);
        let Some(next_close) = find_ci(&tail[i..], c).map(|k| i + k) else {
            return Err(ArtifactError::Malformed(open));
        };
        match next_open {
            Some(n) if n < next_close => {
                depth += 1;
                i = n + o.len();
            }
            _ => {
                depth -= 1;
                i = next_close + c.len();
            }
        }
    }
    let end = end_of_tag(html, open, tag_end + i)?;
    if find_ci(&tail[..i], b"<script").is_some() {
        return Err(ArtifactError::Forbidden(
            "a script inside foreign content",
            open,
        ));
    }
    Ok(Some(end))
}

/// The end of a script element's text, requiring the exact `</script>`
/// terminator; `</script >` and `</script\n>` are refused.
fn close_of(html: &str, text_start: usize) -> Result<usize, ArtifactError> {
    let tail = &html[text_start..];
    match tail.find(SCRIPT_CLOSE) {
        // Nothing resembling a close before the real one, or the real one is
        // the first thing that resembles it.
        Some(i) => {
            let end = text_start + i;
            match find_ci(&tail.as_bytes()[..i], b"</script") {
                None => Ok(end),
                Some(j) => Err(ArtifactError::Malformed(text_start + j)),
            }
        }
        None => Err(ArtifactError::Malformed(text_start)),
    }
}

/// Step over one non-script tag, refusing any spelling this reader does not
/// fully understand. Inline handlers, `javascript:`, `<base>`, `<link>` and
/// `<iframe>` are left to the composed policy.
fn ordinary_tag(html: &str, open: usize) -> Result<usize, ArtifactError> {
    let bytes = html.as_bytes();
    let mut i = open + 1;
    if i >= bytes.len() {
        return Err(ArtifactError::Malformed(open));
    }
    // `<!doctype html>` is the one `<!` this reader admits; `<!--` was already
    // refused above.
    if bytes[i] == b'!' {
        if !starts_with_ci(&bytes[open..], b"<!doctype ") {
            return Err(ArtifactError::Malformed(open));
        }
        return end_of_tag(html, open, i);
    }
    if bytes[i] == b'/' {
        i += 1;
    }
    let name_start = i;
    while i < bytes.len() && bytes[i].is_ascii_lowercase() {
        i += 1;
    }
    if i == name_start {
        // A `<` that opens no lowercase tag name. In text that means a bare
        // `<`, which a document should have written `&lt;`.
        return Err(ArtifactError::Malformed(open));
    }
    end_of_tag(html, open, i)
}

/// Walk to the `>` of a tag. A double-quoted value is skipped whole, an
/// unquoted value cannot contain `>`, and a single-quoted value is refused.
fn end_of_tag(html: &str, open: usize, mut i: usize) -> Result<usize, ArtifactError> {
    let bytes = html.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'>' => return Ok(i + 1),
            b'"' => {
                let Some(j) = html[i + 1..].find('"') else {
                    return Err(ArtifactError::Malformed(open));
                };
                i = i + 1 + j + 1;
            }
            // A single-quoted value, or a `<` where a tag has not closed.
            b'\'' | b'<' => return Err(ArtifactError::Malformed(open)),
            _ => i += 1,
        }
    }
    Err(ArtifactError::Malformed(open))
}

#[cfg(test)]
mod tests {
    /// The CDATA rule: the spelling, the case folding, and a `<![` that begins
    /// no CDATA section.
    #[test]
    fn a_cdata_section_is_refused_however_it_is_spelled() {
        for body in ["<![CDATA[x]]>", "<![cdata[x]]>", "<![CdAtA[x]]>"] {
            assert!(
                matches!(
                    refuse_hostile_bytes(body),
                    Err(ArtifactError::Forbidden("a CDATA section", _))
                ),
                "{body} must be refused as CDATA"
            );
        }
    }

    /// A `<![` the scan steps over rather than stopping on, and one that
    /// follows it -- the loop must keep looking after a near miss.
    #[test]
    fn a_bracket_that_opens_no_cdata_does_not_stop_the_scan() {
        assert!(refuse_hostile_bytes("<![notcdata[x").is_ok());
        assert!(matches!(
            refuse_hostile_bytes("<![nope[ then <![CDATA[x"),
            Err(ArtifactError::Forbidden("a CDATA section", _))
        ));
    }

    /// A localised artifact scans: neither a panic nor a refusal.
    #[test]
    fn a_multi_byte_character_scans_rather_than_panicking() {
        for text in [
            "<p>\u{e9}</p>",
            "<b>\u{2014}</b>",
            "<em>\u{e9}</em>",
            "<h1>\u{e9}</h1>",
            "<p>abc\u{e9}</p>",
        ] {
            let html = doc(&format!("{text}<script type=\"module\">let a=1</script>"));
            let out = Layout::scan(&html);
            assert!(
                out.is_ok(),
                "a localised artifact must scan: {text} -> {out:?}"
            );
        }
    }

    use super::*;

    /// A document in the canonical shape, with one thing varied per test.
    fn doc(body: &str) -> String {
        format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">\
             <title>libID</title><body><main id=\"libid-root\"></main>\
             <script id=\"libid-callback-config\" type=\"application/json\">\
             {MARKER}</script>{body}</body></html>"
        )
    }

    fn module(code: &str) -> String {
        doc(&format!("<script type=\"module\">{code}</script>"))
    }

    #[test]
    fn the_compiled_in_artifact_is_readable() {
        let layout = Layout::scan(super::super::EMBEDDED).expect("the floor must scan");
        assert_eq!(super::super::EMBEDDED[layout.slot].trim(), MARKER);
        assert_eq!(layout.executables.len(), 1);
    }

    /// The hashed span is exactly the bytes between `>` and `</script>`.
    #[test]
    fn the_executable_span_is_the_script_text_exactly() {
        let html = module("let x = 1;");
        let layout = Layout::scan(&html).unwrap();
        assert_eq!(&html[layout.executables[0].clone()], "let x = 1;");
    }

    /// Three refusals about hash correctness.
    #[test]
    fn bytes_that_would_desynchronise_the_hash_are_refused() {
        // CR is normalised to LF by the HTML input stream before tokenizing.
        assert!(matches!(
            Layout::scan(&module("let x = 1;\r\n")),
            Err(ArtifactError::Forbidden("a carriage return", _))
        ));
        // `<!--` in script data enters the escaped states, where `</script>`
        // does not necessarily close the element.
        assert!(matches!(
            Layout::scan(&module("<!-- x -->")),
            Err(ArtifactError::Forbidden("an HTML comment", _))
        ));
        for hostile in ["<![CDATA[x]]>", "<?x?>"] {
            assert!(
                matches!(
                    Layout::scan(&doc(hostile)),
                    Err(ArtifactError::Forbidden(..))
                ),
                "accepted {hostile}"
            );
        }
        assert!(matches!(
            Layout::scan(&module("let x = 1;\u{0}")),
            Err(ArtifactError::Forbidden("a control byte", _))
        ));
    }

    /// Every script shape but the two this bridge reads is refused; foreign
    /// content is stepped over, and a `<script>` inside it is refused.
    #[test]
    fn foreign_content_is_stepped_over_and_a_script_inside_one_is_not() {
        for logo in [
            "<svg viewBox=\"0 0 8 8\"><path d=\"M0 0\"></path></svg>",
            "<svg><svg></svg></svg>",
            "<svg/>",
            "<math><mi>x</mi></math>",
            "<SVG></SVG>",
        ] {
            let html = doc(&format!(
                "{logo}<script type=\"module\">let x = 1;</script>"
            ));
            let layout =
                Layout::scan(&html).unwrap_or_else(|e| panic!("refused {logo}: {e}"));
            assert_eq!(&html[layout.executables[0].clone()], "let x = 1;");
        }

        // An element whose name merely starts with `svg` or `math` is not
        // foreign content.
        for ordinary in [
            "<math-field><script type=\"module\">let x = 1;</script></math-field>",
            "<svg-icon>logo</svg-icon><script type=\"module\">let x = 1;</script>",
        ] {
            let html = doc(ordinary);
            let layout =
                Layout::scan(&html).unwrap_or_else(|e| panic!("refused {ordinary}: {e}"));
            assert_eq!(
                &html[layout.executables[0].clone()],
                "let x = 1;",
                "{ordinary} carries an ordinary element, not foreign content"
            );
        }

        for hostile in [
            "<svg><script>x</script></svg>",
            "<math><script type=\"module\">x</script></math>",
        ] {
            let html = doc(&format!(
                "{hostile}<script type=\"module\">let x = 1;</script>"
            ));
            assert!(
                matches!(
                    Layout::scan(&html),
                    Err(ArtifactError::Forbidden(
                        "a script inside foreign content",
                        _
                    ))
                ),
                "accepted {hostile}"
            );
        }
    }

    #[test]
    fn a_script_this_reader_does_not_understand_is_refused() {
        for hostile in [
            "<script src=\"/x.js\"></script>",
            "<script></script>",
            "<script type=\"text/javascript\">x</script>",
            "<script type=\"module\" defer>x</script>",
            "<script nonce=\"abc\" type=\"module\">x</script>",
            "<SCRIPT TYPE=\"module\">x</SCRIPT>",
        ] {
            assert!(
                matches!(
                    Layout::scan(&doc(hostile)),
                    Err(ArtifactError::UnreadableScript(_))
                ),
                "accepted {hostile}"
            );
        }
    }

    /// `</script >` and `</script\n>` are refused.
    #[test]
    fn a_loose_close_inside_a_script_is_refused() {
        for hostile in ["</script >", "</script\n>", "</SCRIPT>"] {
            let html = module(&format!("let s = '{hostile}';"));
            assert!(
                matches!(Layout::scan(&html), Err(ArtifactError::Malformed(_))),
                "accepted {hostile}"
            );
        }
    }

    #[test]
    fn a_tag_this_reader_cannot_bound_is_refused() {
        // A single-quoted value and a bare `<` are refused; an unquoted value
        // is admitted.
        for hostile in ["<p class='x'>", "<p>a < b</p>"] {
            assert!(
                matches!(
                    Layout::scan(&doc(&format!(
                        "{hostile}<script type=\"module\">x</script>"
                    ))),
                    Err(ArtifactError::Malformed(_))
                ),
                "accepted {hostile}"
            );
        }
    }

    #[test]
    fn the_document_carries_one_slot_one_mount_and_some_code() {
        // Two slots.
        let two = doc(
            "<script id=\"libid-callback-config\" type=\"application/json\">x</script>\
             <script type=\"module\">x</script>",
        );
        assert!(matches!(Layout::scan(&two), Err(ArtifactError::Markers(2))));

        // No executable at all.
        assert!(matches!(
            Layout::scan(&doc("")),
            Err(ArtifactError::Executables(0))
        ));

        // More than the shape admits.
        let many: String = (0..MAX_EXECUTABLES + 1)
            .map(|_| "<script type=\"module\">x</script>")
            .collect();
        assert!(matches!(
            Layout::scan(&doc(&many)),
            Err(ArtifactError::Executables(_))
        ));

        // No mount point, and two.
        let no_mount = module("x").replace("<main id=\"libid-root\"></main>", "");
        assert!(matches!(
            Layout::scan(&no_mount),
            Err(ArtifactError::MountPoint)
        ));
        let two_mounts = module("x").replace(
            "<main id=\"libid-root\"></main>",
            "<main id=\"libid-root\"></main><main id=\"libid-root\"></main>",
        );
        assert!(matches!(
            Layout::scan(&two_mounts),
            Err(ArtifactError::MountPoint)
        ));
    }

    #[test]
    fn an_artifact_over_the_bound_is_refused_before_it_is_read() {
        let huge = "a".repeat(MAX_ARTIFACT_BYTES + 1);
        assert!(
            matches!(Layout::scan(&huge), Err(ArtifactError::TooLarge(n)) if n == huge.len())
        );
    }
}
