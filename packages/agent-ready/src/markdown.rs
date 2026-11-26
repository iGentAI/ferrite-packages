//! Deterministic HTML → Markdown conversion for `.md` content twins.
//!
//! The single highest-leverage readability feature on the readiness
//! checklist is serving Markdown to agents instead of making them parse
//! HTML. The `.md` sibling URL is the primary mechanism: every content page
//! gets one (`/docs` → `/docs.md`), advertised in `llms.txt` and served by
//! the well-known router. A sibling URL is cacheable and linkable, which
//! header negotiation is not, so it stays primary even though
//! [`well_known::handle`](super::well_known::handle) also reads `Accept`
//! where the consuming app declares `forward_headers`. This module converts
//! the app's HTML to clean Markdown, so an
//! app authoring HTML pays nothing extra for the twin.
//!
//! The converter is intentionally a SUBSET: it handles the structural tags
//! a content page is made of (headings, paragraphs, lists, links, emphasis,
//! code, pre, blockquote, tables, hr, br) and strips everything else
//! (script/style/nav/svg dropped with their contents). Deterministic output
//! — same input, same bytes — because the scoring suite hashes it.

/// Convert an HTML document (or fragment) to Markdown.
pub fn to_markdown(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut chars = html.char_indices().peekable();
    let mut ctx = Ctx::default();
    while let Some((i, c)) = chars.next() {
        if c == '<' {
            let rest = &html[i + 1..];
            if let Some(comment) = rest.strip_prefix("!--") {
                let Some(end) = comment.find("-->") else { break };
                let after = i + 1 + 3 + end + 3;
                while chars.peek().is_some_and(|&(next_i, _)| next_i < after) {
                    chars.next();
                }
                continue;
            }
            let Some(end) = tag_end(rest) else { break };
            let tag_body = &rest[..end];
            // Advance the iterator past the tag by byte offset, not char count.
            let after = i + 1 + end + 1;
            while chars.peek().is_some_and(|&(next_i, _)| next_i < after) {
                chars.next();
            }
            handle_tag(tag_body, &mut out, &mut ctx);
        } else if !ctx.skip_depth_active() {
            push_text_char(c, &mut out, &mut ctx);
        }
    }
    normalize(&out)
}

#[derive(Default)]
struct Ctx {
    /// Depth inside tags whose CONTENT is dropped (script/style/head/nav/svg).
    skip_depth: usize,
    /// Current list nesting: each entry is (ordered, next_index).
    lists: Vec<(bool, usize)>,
    /// Inside a <pre> block.
    pre: bool,
    /// Link target captured from the last opening <a href="…">.
    link: Option<String>,
    /// Text captured while inside a link.
    link_text: String,
    /// Inside a table: current row's cells, and whether header row emitted.
    table: Option<TableCtx>,
    /// Blockquote depth.
    quote: usize,
}

#[derive(Default)]
struct TableCtx {
    row: Vec<String>,
    in_cell: bool,
    header_done: bool,
}

impl Ctx {
    fn skip_depth_active(&self) -> bool {
        self.skip_depth > 0
    }
}

/// The byte offset of the `>` closing a tag, skipping any inside a quoted
/// attribute value.
fn tag_end(rest: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in rest.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn attr(tag: &str, name: &str) -> Option<String> {
    // Minimal attribute scan: name="value" or name='value', where `name`
    // starts the attribute (so `data-href=` is not `href=`).
    let lower = tag.to_ascii_lowercase();
    let pat = format!("{name}=");
    let start = lower
        .match_indices(&pat)
        .map(|(at, _)| at)
        .find(|&at| at == 0 || lower.as_bytes()[at - 1].is_ascii_whitespace())?
        + pat.len();
    let rest = &tag[start..];
    let (quote, rest) = match rest.chars().next() {
        Some(q @ ('"' | '\'')) => (q, &rest[1..]),
        _ => return None,
    };
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn handle_tag(tag_body: &str, out: &mut String, ctx: &mut Ctx) {
    let body = tag_body.trim();
    if body.starts_with("!--") {
        return; // comment
    }
    let closing = body.starts_with('/');
    let name_part = body.trim_start_matches('/');
    let name: String = name_part
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();

    const SKIP: &[&str] = &[
        "script", "style", "head", "nav", "svg", "noscript", "template",
    ];
    if SKIP.contains(&name.as_str()) {
        if closing {
            ctx.skip_depth = ctx.skip_depth.saturating_sub(1);
        } else if !body.ends_with('/') {
            ctx.skip_depth += 1;
        }
        return;
    }
    if ctx.skip_depth_active() {
        return;
    }

    match (name.as_str(), closing) {
        ("h1", false) => out.push_str("\n\n# "),
        ("h2", false) => out.push_str("\n\n## "),
        ("h3", false) => out.push_str("\n\n### "),
        ("h4", false) => out.push_str("\n\n#### "),
        ("h5", false) => out.push_str("\n\n##### "),
        ("h6", false) => out.push_str("\n\n###### "),
        ("h1" | "h2" | "h3" | "h4" | "h5" | "h6", true) => out.push_str("\n\n"),
        ("p" | "div" | "section" | "article" | "header" | "footer" | "main", false) => {
            if ctx.quote > 0 {
                out.push_str("\n> ");
            } else {
                out.push_str("\n\n");
            }
        }
        ("p" | "div" | "section" | "article" | "header" | "footer" | "main", true) => {
            out.push('\n')
        }
        ("br", _) => out.push('\n'),
        ("hr", _) => out.push_str("\n\n---\n\n"),
        ("ul", false) => ctx.lists.push((false, 1)),
        ("ol", false) => ctx.lists.push((true, 1)),
        ("ul" | "ol", true) => {
            ctx.lists.pop();
            out.push('\n');
        }
        ("li", false) => {
            out.push('\n');
            let depth = ctx.lists.len().saturating_sub(1);
            for _ in 0..depth {
                out.push_str("  ");
            }
            match ctx.lists.last_mut() {
                Some((true, n)) => {
                    out.push_str(&format!("{n}. "));
                    *n += 1;
                }
                _ => out.push_str("- "),
            }
        }
        ("li", true) => {}
        ("a", false) => {
            ctx.link = attr(tag_body, "href");
            ctx.link_text.clear();
        }
        ("a", true) => {
            let text = ctx.link_text.trim().to_string();
            match ctx.link.take() {
                Some(href) if !text.is_empty() => {
                    out.push_str(&format!("[{text}]({href})"));
                }
                _ => out.push_str(&text),
            }
        }
        ("strong" | "b", _) => out.push_str("**"),
        ("em" | "i", _) => out.push('*'),
        ("code", _) if !ctx.pre => out.push('`'),
        ("pre", false) => {
            ctx.pre = true;
            out.push_str("\n\n```\n");
        }
        ("pre", true) => {
            ctx.pre = false;
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("```\n\n");
        }
        ("blockquote", false) => {
            ctx.quote += 1;
            out.push_str("\n\n> ");
        }
        ("blockquote", true) => {
            ctx.quote = ctx.quote.saturating_sub(1);
            out.push_str("\n\n");
        }
        ("table", false) => ctx.table = Some(TableCtx::default()),
        ("table", true) => {
            ctx.table = None;
            out.push('\n');
        }
        ("tr", false) => {
            if let Some(t) = ctx.table.as_mut() {
                t.row.clear();
            }
        }
        ("tr", true) => {
            if let Some(t) = ctx.table.as_mut() {
                if !t.row.is_empty() {
                    out.push_str("\n| ");
                    out.push_str(&t.row.join(" | "));
                    out.push_str(" |");
                    if !t.header_done {
                        out.push_str("\n|");
                        out.push_str(&" --- |".repeat(t.row.len()));
                        t.header_done = true;
                    }
                }
            }
        }
        ("th" | "td", false) => {
            if let Some(t) = ctx.table.as_mut() {
                t.in_cell = true;
                t.row.push(String::new());
            }
        }
        ("th" | "td", true) => {
            if let Some(t) = ctx.table.as_mut() {
                t.in_cell = false;
                if let Some(cell) = t.row.last_mut() {
                    *cell = cell.trim().to_string();
                }
            }
        }
        _ => {}
    }
}

fn push_text_char(c: char, out: &mut String, ctx: &mut Ctx) {
    // Route text into the innermost capture: table cell, link text, or out.
    let c = if !ctx.pre && (c == '\n' || c == '\t') {
        ' '
    } else {
        c
    };
    let pre = ctx.pre;
    let collapses = |s: &str| s.ends_with(' ') || s.ends_with('\n') || s.is_empty();
    if let Some(t) = ctx.table.as_mut() {
        if t.in_cell {
            if let Some(cell) = t.row.last_mut() {
                if !(c == ' ' && !pre && collapses(cell)) {
                    cell.push(c);
                }
            }
        }
        return;
    }
    if ctx.link.is_some() {
        if !(c == ' ' && !pre && collapses(&ctx.link_text)) {
            ctx.link_text.push(c);
        }
        return;
    }
    if c == ' ' && !pre && collapses(out) {
        return;
    }
    out.push(c);
}

/// Decode the small set of HTML entities content pages actually use.
fn decode_entities(s: &str) -> String {
    // `&amp;` last: decoding it first would turn `&amp;lt;` into `<`.
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut blank_run = 0usize;
    for line in s.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            blank_run += 1;
            if blank_run > 1 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        out.push_str(trimmed);
        out.push('\n');
    }
    let t = out.trim_start_matches('\n').trim_end().to_string();
    decode_entities(&t) + "\n"
}

#[cfg(test)]
mod tests {
    #[test]
    fn entities_decode_once_and_quoted_angles_stay_in_the_tag() {
        let md = super::to_markdown("<p>&amp;lt;script&amp;gt; and &amp;nbsp;</p>");
        assert!(md.contains("&lt;script&gt;"), "{md}");
        assert!(md.contains("&nbsp;"), "{md}");
        let md = super::to_markdown("<p><a title=\"a > b\" href=\"/x\">link</a></p>");
        assert!(!md.contains("b\""), "{md}");
        assert_eq!(super::attr("a data-href=\"/bad\" href=\"/good\"", "href").as_deref(), Some("/good"));
    }

    use super::to_markdown;

    #[test]
    fn multibyte_utf8_attributes_do_not_skip_following_text() {
        let html = r#"<p title="café — naïve — 日本語">Hello world</p>"#;
        assert_eq!(to_markdown(html), "Hello world\n");

        let link_html = r#"<p><a href="https://example.com/café" title="Übersicht">Link</a> tail</p>"#;
        assert_eq!(to_markdown(link_html), "[Link](https://example.com/café) tail\n");
    }

    #[test]
    fn html_comments_containing_gt_and_utf8_are_stripped_to_closing_delimiter() {
        let html = "<p>Before<!-- a > b and <div>café</div> -->After</p>";
        assert_eq!(to_markdown(html), "BeforeAfter\n");

        let script_comment = "<!-- <script> -->Visible<p>Done</p>";
        assert_eq!(to_markdown(script_comment), "Visible\n\nDone\n");
    }
}

