//! The email HTML renderer: a bounded markdown subset rendered to
//! inline-styled HTML that cannot carry active content.
//!
//! # Safety is structural, not a filter
//!
//! There is no sanitiser here and no denylist of dangerous tags. The renderer
//! emits a FIXED tag set — `h1`, `h2`, `p`, `a`, `hr` — and HTML-escapes every
//! character it did not emit itself, so a `<script>` in the source arrives as
//! `&lt;script&gt;` because escaping is the default and emission is the
//! exception. A filter can be evaded; an allowlist of emitted tags cannot be,
//! because nothing else has a code path that writes a `<`.
//!
//! Anchors are the one construct built from source text, so they carry their
//! own rule: only `http://` and `https://` URLs become an `href`, and a
//! `javascript:` URL is escaped as ordinary text instead. Both the label and
//! the URL are escaped before they are written.
//!
//! # No remote assets
//!
//! No `img`, no stylesheet link, no web font. Styling is inline, which is what
//! mail clients honour anyway, and a message that fetches nothing cannot leak
//! an open-tracking signal the sender did not intend.

/// Render markdown to inline-styled email HTML.
///
/// The subset is deliberate: `# ` and `## ` headings, `[label](url)` links,
/// and everything else as a paragraph. `footer_note` is the sending
/// application's own attribution line, rendered after a rule and escaped like
/// any other text.
#[must_use]
pub fn render_email_html(subject: &str, body_md: &str, footer_note: &str) -> String {
    let mut out = String::with_capacity(body_md.len() * 2 + 512);
    out.push_str(
        "<!doctype html><html><body style=\"font-family:-apple-system,Segoe UI,Roboto,\
         Helvetica,Arial,sans-serif;max-width:640px;margin:0 auto;color:#1a1a1a;\
         line-height:1.5\">",
    );
    render_blocks(&mut out, body_md, None);
    out.push_str(&format!(
        "<hr style=\"border:none;border-top:1px solid #eee;margin:24px 0\">\
         <p style=\"color:#999;font-size:12px\">{} — {}</p>",
        html_escape(subject),
        html_escape(footer_note)
    ));
    out.push_str("</body></html>");
    out
}

/// Render a broadcast email: the same bounded subset, with the two things a
/// message to a list needs and a transactional one does not.
///
/// `preheader` is the line a mail client shows after the subject. It is
/// written first and hidden, so the preview is the sender's sentence and not
/// whatever the body happens to open with.
///
/// `footer_md` is rendered line by line in small type after a rule, with links
/// allowed: it carries who sent the message and why, the postal address, the
/// preferences link and the unsubscribe link. `unsubscribe_href` is the one
/// link target that need not be an `http(s)` URL: the provider's placeholder
/// for the recipient's unsubscribe address (Postmark's
/// `{{{ pm:unsubscribe }}}`), admitted in the body and the footer when a link
/// names it exactly. It is escaped like every other target, so a placeholder
/// that could close an attribute cannot be smuggled in through it.
#[must_use]
pub fn render_broadcast_html(preheader: &str, body_md: &str, footer_md: &str, unsubscribe_href: &str) -> String {
    let mut out = String::with_capacity(body_md.len() * 2 + footer_md.len() * 2 + 768);
    out.push_str(
        "<!doctype html><html><body style=\"font-family:-apple-system,Segoe UI,Roboto,\
         Helvetica,Arial,sans-serif;max-width:640px;margin:0 auto;color:#1a1a1a;\
         line-height:1.5\">",
    );
    if !preheader.trim().is_empty() {
        out.push_str(&format!(
            "<div style=\"display:none;max-height:0;overflow:hidden;opacity:0;color:transparent\">{}</div>",
            html_escape(preheader.trim())
        ));
    }
    render_blocks(&mut out, body_md, Some(unsubscribe_href));
    out.push_str("<hr style=\"border:none;border-top:1px solid #eee;margin:24px 0\">");
    for raw_line in footer_md.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "<p style=\"color:#6b6b6b;font-size:12px;margin:4px 0\">{}</p>",
            render_inline(line, Some(unsubscribe_href))
        ));
    }
    out.push_str("</body></html>");
    out
}

/// The body: headings and paragraphs, one per non-empty line.
fn render_blocks(out: &mut String, body_md: &str, extra_href: Option<&str>) {
    for raw_line in body_md.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(h1) = line.strip_prefix("# ") {
            out.push_str(&format!(
                "<h1 style=\"font-size:22px;border-bottom:2px solid #eee;padding-bottom:8px\">{}</h1>",
                render_inline(h1, extra_href)
            ));
        } else if let Some(h2) = line.strip_prefix("## ") {
            out.push_str(&format!(
                "<h2 style=\"font-size:17px;margin-top:24px\">{}</h2>",
                render_inline(h2, extra_href)
            ));
        } else {
            out.push_str(&format!(
                "<p style=\"margin:8px 0\">{}</p>",
                render_inline(line, extra_href)
            ));
        }
    }
}

/// Render one line's inline markdown: `[label](url)` links, everything else
/// HTML-escaped. Untrusted content can never inject a tag. `extra_href` is one
/// exact link target admitted besides `http(s)` URLs.
fn render_inline(line: &str, extra_href: Option<&str>) -> String {
    let mut out = String::with_capacity(line.len() + 16);
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c == '[' {
            if let Some((text, url, next)) = parse_link(&chars, i) {
                // Only http(s) URLs and the one named target; escape both parts.
                if url.starts_with("https://") || url.starts_with("http://") || extra_href == Some(url.as_str()) {
                    out.push_str(&format!(
                        "<a href=\"{}\" style=\"color:#0645ad\">{}</a>",
                        html_escape(&url),
                        html_escape(&text)
                    ));
                    i = next;
                    continue;
                }
            }
        }
        push_escaped(&mut out, c);
        i += 1;
    }
    out
}

/// Parse `[text](url)` starting at `open` (`[`); returns the label, the URL and
/// the index past the closing paren, or `None`. Uses `.get()` throughout, so a
/// malformed construct is data rather than a panic.
fn parse_link(chars: &[char], open: usize) -> Option<(String, String, usize)> {
    let close_br = (open + 1..chars.len()).find(|&k| chars.get(k) == Some(&']'))?;
    if chars.get(close_br + 1) != Some(&'(') {
        return None;
    }
    let close_par = (close_br + 2..chars.len()).find(|&k| chars.get(k) == Some(&')'))?;
    let text: String = chars.get(open + 1..close_br)?.iter().collect();
    let url: String = chars.get(close_br + 2..close_par)?.iter().collect();
    Some((text, url, close_par + 1))
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '&' => out.push_str("&amp;"),
        '"' => out.push_str("&quot;"),
        _ => out.push(c),
    }
}

/// HTML-escape a string: the four characters that can leave text context.
#[must_use]
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        push_escaped(&mut out, c);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::{html_escape, render_broadcast_html, render_email_html};

    const NOTE: &str = "sent by the kit's test";

    #[test]
    fn markup_in_the_source_arrives_as_text() {
        let html = render_email_html(
            "Subject <x>",
            "# Heading\n\n## Section & \"quotes\"\n\nBody with <script>alert(1)</script>.\n",
            NOTE,
        );
        assert!(html.contains("<h1"));
        assert!(html.contains("<h2"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Subject &lt;x&gt;"));
    }

    #[test]
    fn only_http_urls_become_anchors() {
        let good = render_email_html("s", "See [the post](https://x.dev/p).", NOTE);
        assert!(good.contains("<a href=\"https://x.dev/p\""));
        assert!(good.contains(">the post</a>"));

        for hostile in [
            "[click](javascript:alert(1))",
            "[click](data:text/html;base64,PHNjcmlwdD4=)",
            "[click](vbscript:msgbox)",
        ] {
            let html = render_email_html("s", hostile, NOTE);
            assert!(!html.contains("<a href"), "an anchor was emitted: {html}");
        }
    }

    #[test]
    fn a_quote_in_a_url_cannot_close_the_href_attribute() {
        let html = render_email_html("s", "[x](https://x.dev/\" onload=\"alert(1))", NOTE);
        assert!(!html.contains("onload=\"alert"));
        assert!(html.contains("&quot;"));
    }

    #[test]
    fn a_malformed_link_is_text_not_a_panic() {
        for line in ["[unclosed", "[label](unclosed", "[]()", "[a]b(c)"] {
            let html = render_email_html("s", line, NOTE);
            assert!(!html.contains("<a href"));
        }
    }

    #[test]
    fn the_footer_note_is_escaped_like_any_other_text() {
        let html = render_email_html("s", "body", "<b>brand</b>");
        assert!(html.contains("&lt;b&gt;brand&lt;/b&gt;"));
        assert_eq!(html_escape("a<b>&\"c"), "a&lt;b&gt;&amp;&quot;c");
    }

    #[test]
    fn a_broadcast_carries_a_hidden_preheader_and_a_footer_with_links() {
        let html = render_broadcast_html(
            "What changed in <November>",
            "# News\nRead [the notes](https://docs.x/notes).",
            "Ferrite Cloud, 1 Main St\n[Email preferences](https://dash.x/prefs) or [unsubscribe]({{{ pm:unsubscribe }}})",
            "{{{ pm:unsubscribe }}}",
        );
        assert!(html.contains("<div style=\"display:none;max-height:0;overflow:hidden;opacity:0;color:transparent\">What changed in &lt;November&gt;</div>"));
        assert!(html.find("display:none").unwrap() < html.find("<h1").unwrap(), "the preheader comes first");
        assert!(html.contains("<a href=\"https://docs.x/notes\""));
        assert!(html.contains("<a href=\"https://dash.x/prefs\""));
        assert!(html.contains("<a href=\"{{{ pm:unsubscribe }}}\" style=\"color:#0645ad\">unsubscribe</a>"));
        assert!(html.contains("Ferrite Cloud, 1 Main St"));
        assert!(render_broadcast_html("", "body", "foot", "{{{ pm:unsubscribe }}}").find("display:none").is_none());
    }

    #[test]
    fn only_the_exact_unsubscribe_target_is_admitted_and_it_is_still_escaped() {
        let placeholder = "{{{ pm:unsubscribe }}}";
        for hostile in ["[x](javascript:alert(1))", "[x]({{{ pm:unsubscribe }}} )", "[x]({{{ pm:other }}})"] {
            let html = render_broadcast_html("p", hostile, hostile, placeholder);
            assert!(!html.contains("<a href"), "an anchor was emitted: {html}");
        }
        // A transactional email never admits it.
        assert!(!render_email_html("s", "[x]({{{ pm:unsubscribe }}})", NOTE).contains("<a href"));
        // A target that could close the attribute is escaped even when it is the named one.
        let html = render_broadcast_html("p", "[x](a\"b)", "", "a\"b");
        assert!(html.contains("href=\"a&quot;b\""));
    }
}
