//! Content extraction for agents: plain text, markdown, links, and HTML
//! serialization from a parsed DOM.
//!
//! This is the part of the pipeline agents consume most: token-efficient
//! views of the page. Extraction skips non-content elements (`script`,
//! `style`, `head`, `template`) and normalizes whitespace so the output is
//! stable regardless of source formatting. `<noscript>` is content: the
//! parser already dropped it when scripting was on, and when scripting is
//! off a browser shows it.

use crate::browser_core::dom::{Document, NodeData, NodeId};
use crate::browser_core::html::is_void;

/// Elements whose subtree never contributes to extracted content. An
/// `iframe`'s (or `noembed`/`noframes`') raw-text child is fallback markup a
/// browser never shows, so it is no more "text" than a script body is.
fn skip_subtree(tag: &str) -> bool {
    matches!(
        tag,
        "script" | "style" | "head" | "template" | "iframe" | "noembed" | "noframes"
    )
}

/// Block-level elements that force paragraph breaks in text/markdown output.
fn is_block(tag: &str) -> bool {
    matches!(
        tag,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "body"
            | "div"
            | "dl"
            | "dd"
            | "dt"
            | "fieldset"
            | "figure"
            | "figcaption"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "tr"
            | "ul"
    )
}

/// Extract normalized plain text (like a terse `document.body.innerText`).
pub fn text(doc: &Document) -> String {
    text_with(doc, &|_| false)
}

/// Extract plain text, skipping any subtree for which `is_hidden` returns
/// true (the caller supplies CSS knowledge, e.g. `display: none`).
pub fn text_with(doc: &Document, is_hidden: &dyn Fn(NodeId) -> bool) -> String {
    text_with_visibility(doc, is_hidden, &|_| false)
}

/// [`text_with`] plus a per-element `is_invisible` predicate: an element
/// whose own text must not appear (`visibility: hidden`, `font-size: 0`)
/// while its descendants are still walked, because a child can set
/// `visibility: visible` again. `is_hidden` prunes the whole subtree.
pub fn text_with_visibility(
    doc: &Document,
    is_hidden: &dyn Fn(NodeId) -> bool,
    is_invisible: &dyn Fn(NodeId) -> bool,
) -> String {
    let root = doc.find_tag("body").unwrap_or(NodeId::DOCUMENT);
    let mut out = String::new();
    text_walk(doc, root, &mut out, false, is_invisible(root), is_hidden, is_invisible);
    normalize_blocks(&out)
}

#[allow(clippy::too_many_arguments)]
fn text_walk(
    doc: &Document,
    node: NodeId,
    out: &mut String,
    in_pre: bool,
    invisible: bool,
    is_hidden: &dyn Fn(NodeId) -> bool,
    is_invisible: &dyn Fn(NodeId) -> bool,
) {
    for child in doc.children(node) {
        match &doc.node(child).data {
            NodeData::Text(t) => {
                if invisible {
                    continue;
                }
                if in_pre {
                    out.push_str(t);
                } else {
                    let mut last_ws = out.ends_with([' ', '\n']);
                    for ch in t.chars() {
                        if ch.is_whitespace() {
                            if !last_ws {
                                out.push(' ');
                                last_ws = true;
                            }
                        } else {
                            out.push(ch);
                            last_ws = false;
                        }
                    }
                }
            }
            NodeData::Element(e) => {
                if skip_subtree(&e.tag) || is_hidden(child) {
                    continue;
                }
                let block = is_block(&e.tag);
                if block && !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                if e.tag == "br" && !invisible {
                    out.push('\n');
                }
                text_walk(
                    doc,
                    child,
                    out,
                    in_pre || e.tag == "pre",
                    is_invisible(child),
                    is_hidden,
                    is_invisible,
                );
                if block && !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
            }
            _ => {}
        }
    }
}

/// Collapse 3+ newlines to 2 and trim outer whitespace.
fn normalize_blocks(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut newlines = 0usize;
    let mut in_fence = false;
    for line in s.lines() {
        let line = line.trim_end();
        if line.trim_start().starts_with("```") {
            // Fenced code block boundary: keep verbatim, toggle state.
            if !out.is_empty() {
                out.push('\n');
                if newlines > 0 && !in_fence {
                    out.push('\n');
                }
            }
            out.push_str(line);
            newlines = 0;
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            // Inside a fence every line (even blank) is content, verbatim.
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(line);
            newlines = 0;
            continue;
        }
        if line.trim().is_empty() {
            newlines += 1;
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
            if newlines > 0 {
                out.push('\n');
            }
        }
        out.push_str(line.trim_start_matches(' '));
        newlines = 0;
    }
    out
}

/// Extract the document as markdown: headings, emphasis, lists, links,
/// images, code blocks, blockquotes, and tables (pipe form).
pub fn markdown(doc: &Document) -> String {
    markdown_with(doc, &MarkdownOptions::default())
}

/// Options for agent-grade ("clean") markdown extraction. The default is
/// byte-stable with the historical [`markdown`] output.
#[derive(Default)]
pub struct MarkdownOptions<'a> {
    /// Resolve relative hrefs / img srcs against this page URL.
    pub base_url: Option<&'a str>,
    /// Skip any subtree for which this returns true (the caller supplies
    /// CSS knowledge — `display:none` navs and menus stop leaking).
    pub is_hidden: Option<&'a dyn Fn(NodeId) -> bool>,
    /// Prepend a front-matter header: `# <title>` and a `> source:` line.
    pub front_matter: Option<FrontMatter<'a>>,
    /// Restrict extraction to the dominant content region: the first
    /// `<main>`, `<article>` or `#content`/`#main` element when present
    /// (falls back to the whole body).
    pub main_content: bool,
}

/// The provenance line for [`MarkdownOptions::front_matter`].
pub struct FrontMatter<'a> {
    pub title: &'a str,
    pub url: &'a str,
}

/// Extract markdown with [`MarkdownOptions`]: URL resolution, visibility
/// filtering, front-matter, and main-content isolation for agent use.
pub fn markdown_with(doc: &Document, opts: &MarkdownOptions) -> String {
    let mut root = doc.find_tag("body").unwrap_or(NodeId::DOCUMENT);
    if opts.main_content {
        if let Some(main) = find_main_content(doc, root) {
            root = main;
        }
    }
    let mut out = String::new();
    if let Some(fm) = &opts.front_matter {
        let title = fm.title.trim();
        if !title.is_empty() {
            out.push_str("# ");
            out.push_str(title);
            out.push('\n');
        }
        if !fm.url.is_empty() {
            out.push_str("> source: ");
            out.push_str(fm.url);
            out.push('\n');
        }
        out.push('\n');
    }
    let ctx = MdCtx::default();
    let walk_opts = MdOpts {
        base_url: opts.base_url,
        is_hidden: opts.is_hidden,
    };
    md_walk_with(doc, root, &mut out, &ctx, &walk_opts);
    normalize_blocks(&out)
}

/// The dominant content region: the first `<main>` or `<article>`, else an
/// element whose id is `content`/`main`. `None` keeps the whole body.
fn find_main_content(doc: &Document, root: NodeId) -> Option<NodeId> {
    for n in doc.descendants(root) {
        if let Some(e) = doc.get(n).and_then(|x| x.as_element()) {
            if e.tag == "main" || e.tag == "article" {
                return Some(n);
            }
        }
    }
    for n in doc.descendants(root) {
        if let Some(e) = doc.get(n).and_then(|x| x.as_element()) {
            if matches!(e.attr("id"), Some("content") | Some("main")) {
                return Some(n);
            }
        }
    }
    None
}

#[derive(Default, Clone, Copy)]
struct MdOpts<'a> {
    base_url: Option<&'a str>,
    is_hidden: Option<&'a dyn Fn(NodeId) -> bool>,
}

impl MdOpts<'_> {
    fn hidden(&self, n: NodeId) -> bool {
        self.is_hidden.map(|f| f(n)).unwrap_or(false)
    }
    fn resolve(&self, raw: &str) -> String {
        match self.base_url {
            Some(base) if !raw.is_empty() => {
                crate::browser_core::cdp::resolve_url(base, raw).unwrap_or_else(|| raw.to_string())
            }
            _ => raw.to_string(),
        }
    }
}

#[derive(Default, Clone)]
struct MdCtx {
    list_depth: usize,
    ordered: bool,
    index: usize,
    in_pre: bool,
}

fn md_walk_with(doc: &Document, node: NodeId, out: &mut String, ctx: &MdCtx, opts: &MdOpts) {
    let mut li_index = 0usize;
    for child in doc.children(node) {
        match &doc.node(child).data {
            NodeData::Text(t) => {
                if ctx.in_pre {
                    out.push_str(t);
                } else {
                    let collapsed: String = collapse_ws(t);
                    if !collapsed.is_empty() {
                        if out.ends_with('\n') {
                            out.push_str(collapsed.trim_start());
                        } else {
                            out.push_str(&collapsed);
                        }
                    }
                }
            }
            NodeData::Element(e) => {
                if skip_subtree(&e.tag) || opts.hidden(child) {
                    continue;
                }
                match e.tag.as_str() {
                    "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                        let level = e.tag.as_bytes()[1] - b'0';
                        ensure_blank(out);
                        for _ in 0..level {
                            out.push('#');
                        }
                        out.push(' ');
                        md_walk_with(doc, child, out, ctx, opts);
                        out.push('\n');
                    }
                    "p" => {
                        ensure_blank(out);
                        md_walk_with(doc, child, out, ctx, opts);
                        out.push('\n');
                    }
                    "strong" | "b" => {
                        out.push_str("**");
                        md_walk_with(doc, child, out, ctx, opts);
                        out.push_str("**");
                    }
                    "em" | "i" => {
                        out.push('*');
                        md_walk_with(doc, child, out, ctx, opts);
                        out.push('*');
                    }
                    "code" if !ctx.in_pre => {
                        out.push('`');
                        md_walk_with(doc, child, out, ctx, opts);
                        out.push('`');
                    }
                    "pre" => {
                        ensure_blank(out);
                        out.push_str("```\n");
                        let inner = MdCtx {
                            in_pre: true,
                            ..ctx.clone()
                        };
                        md_walk_with(doc, child, out, &inner, opts);
                        if !out.ends_with('\n') {
                            out.push('\n');
                        }
                        out.push_str("```\n");
                    }
                    "a" => {
                        let href = opts.resolve(e.attr("href").unwrap_or(""));
                        out.push('[');
                        md_walk_with(doc, child, out, ctx, opts);
                        out.push_str("](");
                        out.push_str(&href);
                        out.push(')');
                    }
                    "img" => {
                        let alt = e.attr("alt").unwrap_or("");
                        let src = opts.resolve(e.attr("src").unwrap_or(""));
                        out.push_str("![");
                        out.push_str(alt);
                        out.push_str("](");
                        out.push_str(&src);
                        out.push(')');
                    }
                    "ul" | "ol" => {
                        ensure_blank(out);
                        let inner = MdCtx {
                            list_depth: ctx.list_depth + 1,
                            ordered: e.tag == "ol",
                            index: 0,
                            in_pre: ctx.in_pre,
                        };
                        md_walk_with(doc, child, out, &inner, opts);
                    }
                    "li" => {
                        li_index += 1;
                        if !out.ends_with('\n') && !out.is_empty() {
                            out.push('\n');
                        }
                        for _ in 1..ctx.list_depth {
                            out.push_str("  ");
                        }
                        if ctx.ordered {
                            out.push_str(&format!("{}. ", li_index.max(ctx.index + li_index)));
                        } else {
                            out.push_str("- ");
                        }
                        md_walk_with(doc, child, out, ctx, opts);
                    }
                    "blockquote" => {
                        ensure_blank(out);
                        let mut inner = String::new();
                        md_walk_with(doc, child, &mut inner, ctx, opts);
                        for line in normalize_blocks(&inner).lines() {
                            out.push_str("> ");
                            out.push_str(line);
                            out.push('\n');
                        }
                    }
                    "br" => out.push('\n'),
                    "hr" => {
                        ensure_blank(out);
                        out.push_str("---\n");
                    }
                    "table" => {
                        ensure_blank(out);
                        md_table_with(doc, child, out, opts);
                    }
                    _ => {
                        if is_block(&e.tag) {
                            ensure_blank(out);
                            md_walk_with(doc, child, out, ctx, opts);
                            if !out.ends_with('\n') {
                                out.push('\n');
                            }
                        } else {
                            md_walk_with(doc, child, out, ctx, opts);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn collapse_ws(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    let mut ws = false;
    for ch in t.chars() {
        if ch.is_whitespace() {
            ws = true;
        } else {
            if ws {
                s.push(' ');
            }
            s.push(ch);
            ws = false;
        }
    }
    if ws {
        s.push(' ');
    }
    s
}

fn ensure_blank(out: &mut String) {
    if out.is_empty() {
        return;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.ends_with("\n\n") {
        out.push('\n');
    }
}

/// Pipe-markdown table with [`MdOpts`]: hidden rows/cells are skipped and a
/// `colspan="n"` cell is flattened into `n` columns (its text in the first,
/// the rest empty) so column alignment survives. `rowspan` is approximated:
/// the cell occupies only its own row.
fn md_table_with(doc: &Document, table: NodeId, out: &mut String, opts: &MdOpts) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut header_cells = 0usize;
    collect_rows_with(doc, table, &mut rows, &mut header_cells, opts);
    if rows.is_empty() {
        return;
    }
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    for (i, row) in rows.iter().enumerate() {
        out.push('|');
        for c in 0..cols {
            out.push(' ');
            out.push_str(row.get(c).map(String::as_str).unwrap_or(""));
            out.push_str(" |");
        }
        out.push('\n');
        if i == 0 {
            out.push('|');
            for _ in 0..cols {
                out.push_str(" --- |");
            }
            out.push('\n');
        }
    }
}

fn collect_rows_with(
    doc: &Document,
    node: NodeId,
    rows: &mut Vec<Vec<String>>,
    header_cells: &mut usize,
    opts: &MdOpts,
) {
    for child in doc.children(node) {
        if let Some(e) = doc.node(child).as_element() {
            if opts.hidden(child) {
                continue;
            }
            match e.tag.as_str() {
                "tr" => {
                    let mut row = Vec::new();
                    for cell in doc.children(child) {
                        if let Some(ce) = doc.node(cell).as_element() {
                            if ce.tag == "td" || ce.tag == "th" {
                                if opts.hidden(cell) {
                                    continue;
                                }
                                let mut s = String::new();
                                let ctx = MdCtx::default();
                                md_walk_with(doc, cell, &mut s, &ctx, opts);
                                row.push(normalize_blocks(&s).replace('\n', " "));
                                if ce.tag == "th" {
                                    *header_cells += 1;
                                }
                                // colspan: pad with empty cells so later
                                // columns keep their position.
                                let span = ce
                                    .attr("colspan")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                                    .unwrap_or(1)
                                    .clamp(1, 64);
                                for _ in 1..span {
                                    row.push(String::new());
                                }
                            }
                        }
                    }
                    if !row.is_empty() {
                        rows.push(row);
                    }
                }
                "thead" | "tbody" | "tfoot" => {
                    collect_rows_with(doc, child, rows, header_cells, opts)
                }
                _ => {}
            }
        }
    }
}

/// A hyperlink found in the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub href: String,
    pub text: String,
}

/// All `<a href>` links with their visible text, in document order.
pub fn links(doc: &Document) -> Vec<Link> {
    let mut out = Vec::new();
    for n in doc.descendants(NodeId::DOCUMENT) {
        if let Some(e) = doc.node(n).as_element() {
            if e.tag == "a" {
                if let Some(href) = e.attr("href") {
                    let text = collapse_ws(&doc.text_content(n)).trim().to_string();
                    out.push(Link {
                        href: href.to_string(),
                        text,
                    });
                }
            }
        }
    }
    out
}

/// Serialize a subtree back to HTML (like `outerHTML` of the root's children).
pub fn serialize_html(doc: &Document, root: NodeId) -> String {
    let mut out = String::new();
    serialize_children(doc, root, &mut out);
    out
}

/// `innerHTML` view of a node: its children serialized, without the node's
/// own tag. Used by the JS DOM bindings.
pub fn inner_html(doc: &Document, node: NodeId) -> String {
    let mut out = String::new();
    serialize_children(doc, node, &mut out);
    out
}

/// `outerHTML` view of a node: the node itself serialized, tag included.
/// Used by the JS DOM bindings.
pub fn outer_html(doc: &Document, node: NodeId) -> String {
    let mut out = String::new();
    serialize_node(doc, node, &mut out);
    out
}

fn serialize_children(doc: &Document, node: NodeId, out: &mut String) {
    for child in doc.children(node) {
        serialize_node(doc, child, out);
    }
}

fn serialize_node(doc: &Document, node: NodeId, out: &mut String) {
    match &doc.node(node).data {
        NodeData::Document => serialize_children(doc, node, out),
        NodeData::Doctype { name } => {
            out.push_str("<!DOCTYPE ");
            out.push_str(name);
            out.push('>');
        }
        NodeData::Comment(c) => {
            out.push_str("<!--");
            out.push_str(c);
            out.push_str("-->");
        }
        NodeData::Text(t) => {
            // Raw text inside script/style; escaped elsewhere.
            let parent_tag = doc
                .node(node)
                .parent
                .and_then(|p| doc.node(p).as_element().map(|e| e.tag.clone()));
            if matches!(parent_tag.as_deref(), Some("script") | Some("style")) {
                out.push_str(t);
            } else {
                out.push_str(&escape_text(t));
            }
        }
        NodeData::Element(e) => {
            out.push('<');
            out.push_str(&e.tag);
            for (name, value) in &e.attrs {
                out.push(' ');
                out.push_str(name);
                out.push_str("=\"");
                out.push_str(&escape_attr(value));
                out.push('"');
            }
            out.push('>');
            if !is_void(&e.tag) {
                serialize_children(doc, node, out);
                out.push_str("</");
                out.push_str(&e.tag);
                out.push('>');
            }
        }
    }
}

fn escape_text(t: &str) -> String {
    t.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(t: &str) -> String {
    escape_text(t).replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_core::html;

    #[test]
    fn text_extraction_skips_script_and_normalizes() {
        let doc = html::parse(
            "<html><head><script>var x=1;</script><style>p{}</style></head>\
             <body><h1>Title</h1><p>Hello   <b>world</b>.</p></body></html>",
        );
        let t = text(&doc);
        assert!(t.contains("Title"));
        assert!(t.contains("Hello world."));
        assert!(!t.contains("var x"));
        assert!(!t.contains("p{}"));
    }

    #[test]
    fn markdown_headings_lists_links() {
        let doc = html::parse(
            "<body><h2>Head</h2><ul><li>one</li><li>two</li></ul>\
             <p>See <a href=\"https://x.y\">link</a> and <b>bold</b></p></body>",
        );
        let md = markdown(&doc);
        assert!(md.contains("## Head"), "md was: {md}");
        assert!(md.contains("- one"), "md was: {md}");
        assert!(md.contains("- two"), "md was: {md}");
        assert!(md.contains("[link](https://x.y)"), "md was: {md}");
        assert!(md.contains("**bold**"), "md was: {md}");
    }

    #[test]
    fn markdown_table_and_pre() {
        let doc = html::parse(
            "<body><table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>\
             <pre>code  here</pre></body>",
        );
        let md = markdown(&doc);
        assert!(md.contains("| A | B |"), "md was: {md}");
        assert!(md.contains("| --- | --- |"), "md was: {md}");
        assert!(md.contains("| 1 | 2 |"), "md was: {md}");
        assert!(md.contains("```\ncode  here\n```"), "md was: {md}");
    }

    #[test]
    fn links_collects_hrefs() {
        let doc = html::parse(
            "<body><a href=\"/a\">first</a><div><a href=\"/b\">second link</a></div>\
             <a>no href</a></body>",
        );
        let ls = links(&doc);
        assert_eq!(ls.len(), 2);
        assert_eq!(ls[0].href, "/a");
        assert_eq!(ls[0].text, "first");
        assert_eq!(ls[1].href, "/b");
        assert_eq!(ls[1].text, "second link");
    }

    #[test]
    fn serialize_roundtrip_basics() {
        let doc = html::parse("<body><p class=\"x\">hi &amp; bye</p><br></body>");
        let out = serialize_html(&doc, crate::browser_core::dom::NodeId::DOCUMENT);
        assert!(
            out.contains("<p class=\"x\">hi &amp; bye</p>"),
            "got: {out}"
        );
        assert!(out.contains("<br>"), "got: {out}");
        assert!(!out.contains("<br></br>"), "got: {out}");
    }

    #[test]
    fn empty_and_hostile_inputs() {
        assert_eq!(text(&html::parse("")), "");
        assert_eq!(markdown(&html::parse("")), "");
        assert!(links(&html::parse("")).is_empty());
        // binary garbage must not panic
        let garbage = "\u{0}\u{1}<<<>>>&&&#x;<a href";
        let _ = text(&html::parse(garbage));
        let _ = markdown(&html::parse(garbage));
    }
}
