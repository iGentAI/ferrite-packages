//! HTML parsing: a robust, infallible HTML5 tokenizer + tree constructor.
//!
//! This is not a byte-for-byte WHATWG state machine, but it implements the
//! behaviors that matter for real-world documents and the HTML rendering
//! tests: doctype, comments (including bogus comments), attributes in every
//! quoting style, character references (named + numeric), RAWTEXT/RCDATA
//! elements (`script`, `style`, `title`, `textarea`), void elements, implied
//! `<html>/<head>/<body>`, auto-closing (`p`, `li`, `dt/dd`, `option`,
//! `tr/td/th`, `thead/tbody/tfoot`), and mis-nested end tags. Any input —
//! truncated, hostile, or binary garbage — produces a best-effort tree and
//! never a panic.

use crate::browser_core::dom::{Document, NodeData, NodeId};

/// Elements that never have children (WHATWG "void elements").
pub const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Elements whose content is raw text (no markup, no character references
/// except in RCDATA).
const RAWTEXT_ELEMENTS: &[&str] = &["script", "style", "xmp", "iframe", "noembed", "noframes"];
/// RCDATA: raw text but character references are decoded.
const RCDATA_ELEMENTS: &[&str] = &["title", "textarea"];

pub fn is_void(tag: &str) -> bool {
    VOID_ELEMENTS.contains(&tag)
}

/// Parse an HTML document into a DOM tree. Infallible. Every document —
/// including the empty one — gets the full implied html/head/body
/// scaffolding, per the WHATWG tree-construction rules.
pub fn parse(input: &str) -> Document {
    parse_with_scripting(input, false)
}

/// Parse with the document's scripting flag set. `<noscript>` is the one
/// element whose parse depends on it (HTML §13.2.6.4.4): with scripting
/// DISABLED its children are ordinary markup and render — what a no-script
/// Chrome shows, and what 263 of the 512 sites in the Chrome-referenced
/// corpus carry ("JavaScript is not activated" notices, tracking pixels,
/// fallback navigation); with scripting ENABLED its content is raw text
/// that never renders, so it is dropped here. [`parse`] is the no-script
/// document; embedders that run page scripts pass `true`.
pub fn parse_with_scripting(input: &str, scripting: bool) -> Document {
    let mut p = Parser::new(input);
    p.scripting = scripting;
    p.run();
    // Implied scaffolding even for empty/whitespace-only input.
    p.ensure_head();
    p.ensure_body();
    p.doc
}

/// The `href` values of `<link rel="stylesheet">` elements in document
/// order. Used by embedders (e.g. the agent-browser service) to fetch external
/// CSS through their own scoped network channel and feed it to
/// `Page::load_with_stylesheets`.
pub fn stylesheet_links(input: &str) -> Vec<String> {
    let doc = parse(input);
    let mut out = Vec::new();
    for n in doc.descendants(NodeId::DOCUMENT) {
        let Some(el) = doc.node(n).as_element() else {
            continue;
        };
        if el.tag == "link"
            && el
                .attr("rel")
                .is_some_and(|r| r.eq_ignore_ascii_case("stylesheet"))
        {
            if let Some(href) = el.attr("href") {
                if !href.is_empty() {
                    out.push(href.to_string());
                }
            }
        }
    }
    out
}

/// Parse an HTML fragment: children are appended under a synthetic root
/// context without implied html/head/body.
pub fn parse_fragment(input: &str) -> Document {
    let mut p = Parser::new(input);
    p.fragment = true;
    p.run();
    p.doc
}

/// Parse an HTML fragment and graft its top-level nodes under `parent` in an
/// EXISTING document (the `innerHTML` setter). The fragment is parsed into a
/// scratch document and its subtree is copied node by node; the scratch
/// arena is dropped, so handles in `doc` stay stable.
pub fn parse_fragment_into(doc: &mut Document, parent: NodeId, input: &str) {
    let frag = parse_fragment(input);
    for top in frag.children(NodeId::DOCUMENT).collect::<Vec<_>>() {
        graft(doc, parent, &frag, top);
    }
}

/// Deep-copy `src_node` (and subtree) from `src` under `dst_parent` in `dst`.
fn graft(dst: &mut Document, dst_parent: NodeId, src: &Document, src_node: NodeId) {
    let Some(n) = src.get(src_node) else {
        return;
    };
    let new_id = dst.create_node(n.data.clone());
    dst.append_child(dst_parent, new_id);
    for child in src.children(src_node).collect::<Vec<_>>() {
        graft(dst, new_id, src, child);
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    doc: Document,
    /// Open element stack (indices into the arena).
    stack: Vec<NodeId>,
    fragment: bool,
    /// Set once <html>, <head>, <body> exist (document mode).
    html: Option<NodeId>,
    head: Option<NodeId>,
    body: Option<NodeId>,
    /// True after </head> or once body content starts.
    in_body: bool,
    pending_text: String,
    /// The scripting flag: decides whether `<noscript>` content is markup
    /// (false) or discarded raw text (true).
    scripting: bool,
}

#[derive(Debug, PartialEq)]
enum Token {
    Doctype(String),
    StartTag {
        name: String,
        attrs: Vec<(String, String)>,
        self_closing: bool,
    },
    EndTag(String),
    Text(String),
    Comment(String),
    Eof,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Parser {
            bytes: input.as_bytes(),
            pos: 0,
            doc: Document::new(),
            stack: vec![NodeId::DOCUMENT],
            fragment: false,
            html: None,
            head: None,
            body: None,
            in_body: false,
            pending_text: String::new(),
            scripting: false,
        }
    }

    fn run(&mut self) {
        loop {
            let tok = self.next_token();
            match tok {
                Token::Eof => break,
                Token::Doctype(name) => {
                    self.flush_text();
                    let n = self.doc.create_node(NodeData::Doctype { name });
                    self.doc.append_child(NodeId::DOCUMENT, n);
                }
                Token::Comment(text) => {
                    self.flush_text();
                    let n = self.doc.create_node(NodeData::Comment(text));
                    let parent = self.insertion_parent_for_comment();
                    self.doc.append_child(parent, n);
                }
                Token::Text(t) => {
                    self.pending_text.push_str(&t);
                }
                Token::StartTag {
                    name,
                    attrs,
                    self_closing,
                } => {
                    self.flush_text();
                    self.handle_start_tag(name, attrs, self_closing);
                }
                Token::EndTag(name) => {
                    self.flush_text();
                    self.handle_end_tag(&name);
                }
            }
        }
        self.flush_text();
    }

    fn current(&self) -> NodeId {
        *self.stack.last().unwrap_or(&NodeId::DOCUMENT)
    }

    fn insertion_parent_for_comment(&self) -> NodeId {
        self.current()
    }

    fn current_tag(&self) -> Option<&str> {
        self.doc
            .node(self.current())
            .as_element()
            .map(|e| e.tag.as_str())
    }

    /// Ensure the html/head/body scaffolding exists (document mode only).
    fn ensure_body(&mut self) {
        if self.fragment {
            return;
        }
        // WHATWG: an implied document always carries a <head>, even when
        // content jumps straight to body.
        self.ensure_html_and_head();
        if self.body.is_none() {
            let body = self.doc.create_element("body");
            let html = self.html.unwrap_or(NodeId::DOCUMENT);
            self.doc.append_child(html, body);
            self.body = Some(body);
            // Stack: document, html, body
            self.stack.truncate(2);
            self.stack.push(body);
        }
        self.in_body = true;
    }

    fn ensure_head(&mut self) -> NodeId {
        if self.fragment {
            return self.current();
        }
        self.ensure_html_and_head();
        self.head.unwrap_or(NodeId::DOCUMENT)
    }

    fn ensure_html_and_head(&mut self) {
        if self.html.is_none() {
            let html = self.doc.create_element("html");
            self.doc.append_child(NodeId::DOCUMENT, html);
            self.html = Some(html);
            self.stack = vec![NodeId::DOCUMENT, html];
        }
        if self.head.is_none() {
            let head = self.doc.create_element("head");
            let html = self.html.unwrap_or(NodeId::DOCUMENT);
            self.doc.append_child(html, head);
            self.head = Some(head);
        }
    }

    fn flush_text(&mut self) {
        if self.pending_text.is_empty() {
            return;
        }
        let text = std::mem::take(&mut self.pending_text);
        // Whitespace-only text before <body> is dropped (spec: ignored in
        // "before head"/"before html" insertion modes).
        let ws_only = text.chars().all(|c| c.is_ascii_whitespace());
        if !self.fragment && !self.in_body && ws_only {
            return;
        }
        if !self.fragment && !self.in_body {
            // Real text forces body open unless we're inside head metadata
            // (title/script/style handle their own text via rawtext paths).
            let in_head_element = self.head.map(|h| self.stack.contains(&h)).unwrap_or(false);
            if !in_head_element {
                self.ensure_body();
            }
        }
        let n = self.doc.create_text(text);
        let cur = self.current();
        self.doc.append_child(cur, n);
    }

    fn handle_start_tag(&mut self, name: String, attrs: Vec<(String, String)>, self_closing: bool) {
        if !self.fragment {
            match name.as_str() {
                "html" => {
                    if self.html.is_none() {
                        let html = self.doc.create_element("html");
                        if let NodeData::Element(e) = &mut self.doc.node_mut(html).data {
                            e.attrs = attrs;
                        }
                        self.doc.append_child(NodeId::DOCUMENT, html);
                        self.html = Some(html);
                        self.stack = vec![NodeId::DOCUMENT, html];
                    }
                    return;
                }
                "head" => {
                    let head = self.ensure_head();
                    if let NodeData::Element(e) = &mut self.doc.node_mut(head).data {
                        if e.attrs.is_empty() {
                            e.attrs = attrs;
                        }
                    }
                    self.stack.push(head);
                    return;
                }
                "body" => {
                    self.ensure_body();
                    if let Some(body) = self.body {
                        if let NodeData::Element(e) = &mut self.doc.node_mut(body).data {
                            if e.attrs.is_empty() {
                                e.attrs = attrs;
                            }
                        }
                    }
                    return;
                }
                // Head-only metadata: goes into <head> until body opens.
                "base" | "link" | "meta" | "title" | "style" | "script" | "noscript"
                    if !self.in_body =>
                {
                    let head = self.ensure_head();
                    let el = self.doc.create_element(name.clone());
                    if let NodeData::Element(e) = &mut self.doc.node_mut(el).data {
                        e.attrs = attrs;
                    }
                    self.doc.append_child(head, el);
                    // The self-closing flag is acknowledged on VOID elements
                    // only (HTML §13.2.6.4); on anything else (`<iframe />`,
                    // `<script />`) it is a parse error and ignored, so the
                    // element opens and, for raw-text elements, swallows
                    // everything to its end tag. Chrome renders such pages
                    // blank, and so must a conformant engine.
                    if is_void(&name) {
                        return;
                    }
                    let _ = self_closing;
                    if self.consume_special_content(&name, el) {
                        return;
                    }
                    self.stack.push(el);
                    return;
                }
                _ => {
                    self.ensure_body();
                }
            }
        }

        // Auto-closing of open elements (`p`, `li`, table cells, ...).
        self.auto_close_for(&name);

        let el = self.doc.create_element(name.clone());
        if let NodeData::Element(e) = &mut self.doc.node_mut(el).data {
            e.attrs = attrs;
        }
        let cur = self.current();
        self.doc.append_child(cur, el);

        // The self-closing flag only closes void elements (and foreign
        // content, which this parser does not distinguish: an inline
        // `<svg/>`/`<path/>` is the one place `/>` is honoured on a non-void
        // name, so SVG children are kept self-closing to avoid swallowing
        // the rest of the document into a `<path>`).
        if is_void(&name) || (self_closing && self.in_foreign_content()) {
            return;
        }
        if self.consume_special_content(&name, el) {
            return;
        }
        self.stack.push(el);
    }

    /// Consume the content of an element the tokenizer reads verbatim up to
    /// its end tag; true when `name` is such an element.
    fn consume_special_content(&mut self, name: &str, el: NodeId) -> bool {
        if name == "noscript" && self.scripting {
            // Scripting on: the content is raw text that never renders; it is
            // consumed and dropped.
            let _ = self.consume_rawtext(name, false);
            return true;
        }
        let rcdata = RCDATA_ELEMENTS.contains(&name);
        if !rcdata && !RAWTEXT_ELEMENTS.contains(&name) {
            return false;
        }
        let text = self.consume_rawtext(name, rcdata);
        if !text.is_empty() {
            let t = self.doc.create_text(text);
            self.doc.append_child(el, t);
        }
        true
    }

    /// Whether the current insertion point is inside inline SVG or MathML
    /// (foreign content), where `/>` genuinely self-closes any element.
    /// An HTML integration point (`foreignObject`, SVG `desc`/`title`,
    /// MathML `annotation-xml`) switches back to HTML rules for its
    /// subtree, so the walk stops there (HTML §13.2.6.5).
    fn in_foreign_content(&self) -> bool {
        for &id in self.stack.iter().rev() {
            let Some(e) = self.doc.node(id).as_element() else {
                continue;
            };
            match e.tag.as_str() {
                "svg" | "math" => return true,
                "foreignobject" | "desc" | "annotation-xml" => return false,
                // SVG <title> is an integration point; the HTML <title> is
                // RCDATA and never on the stack, so the name is unambiguous.
                "title" => return false,
                _ => {}
            }
        }
        false
    }

    /// Close elements that a new start tag implicitly terminates.
    fn auto_close_for(&mut self, name: &str) {
        // <p> is closed by block-level starters.
        const P_CLOSERS: &[&str] = &[
            "address",
            "article",
            "aside",
            "blockquote",
            "details",
            "div",
            "dl",
            "fieldset",
            "figcaption",
            "figure",
            "footer",
            "form",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "header",
            "hr",
            "main",
            "menu",
            "nav",
            "ol",
            "p",
            "pre",
            "section",
            "table",
            "ul",
        ];
        if P_CLOSERS.contains(&name) {
            self.close_if_open("p");
        }
        match name {
            "li" => self.close_in_scope("li", &["ul", "ol"]),
            "dt" | "dd" => {
                self.close_in_scope("dt", &["dl"]);
                self.close_in_scope("dd", &["dl"]);
            }
            "option" => self.close_if_current("option"),
            "optgroup" => {
                self.close_if_current("option");
                self.close_if_current("optgroup");
            }
            "tr" => {
                self.close_in_scope("td", &["table"]);
                self.close_in_scope("th", &["table"]);
                self.close_in_scope("tr", &["table"]);
            }
            "td" | "th" => {
                self.close_in_scope("td", &["table"]);
                self.close_in_scope("th", &["table"]);
            }
            "thead" | "tbody" | "tfoot" => {
                self.close_in_scope("td", &["table"]);
                self.close_in_scope("th", &["table"]);
                self.close_in_scope("tr", &["table"]);
                self.close_in_scope("thead", &["table"]);
                self.close_in_scope("tbody", &["table"]);
                self.close_in_scope("tfoot", &["table"]);
            }
            "col" => self.close_if_current("col"),
            "caption" | "colgroup" => {}
            _ => {}
        }
    }

    /// Close `tag` if it is the current (innermost) open element.
    fn close_if_current(&mut self, tag: &str) {
        if self.current_tag() == Some(tag) {
            self.stack.pop();
        }
    }

    /// Close `tag` if open anywhere above the nearest scope boundary.
    fn close_in_scope(&mut self, tag: &str, boundaries: &[&str]) {
        let mut idx = None;
        for (i, &id) in self.stack.iter().enumerate().rev() {
            if let Some(e) = self.doc.node(id).as_element() {
                if e.tag == tag {
                    idx = Some(i);
                    break;
                }
                if boundaries.contains(&e.tag.as_str()) {
                    break;
                }
            }
        }
        if let Some(i) = idx {
            self.stack.truncate(i);
        }
    }

    /// Close `tag` if open anywhere in the stack (used for `p`).
    fn close_if_open(&mut self, tag: &str) {
        // <p> cannot cross block boundaries in practice; searching the whole
        // stack is fine because a new <p>-closer implies we are in flow.
        let mut idx = None;
        for (i, &id) in self.stack.iter().enumerate().rev() {
            if let Some(e) = self.doc.node(id).as_element() {
                if e.tag == tag {
                    idx = Some(i);
                    break;
                }
                // Don't cross these boundaries looking for a p to close.
                if matches!(
                    e.tag.as_str(),
                    "body" | "html" | "table" | "td" | "th" | "caption"
                ) {
                    break;
                }
            }
        }
        if let Some(i) = idx {
            self.stack.truncate(i);
        }
    }

    fn handle_end_tag(&mut self, name: &str) {
        match name {
            "html" | "body" if !self.fragment => {
                // Ignore: they close implicitly at EOF.
                return;
            }
            "head" if !self.fragment => {
                // Pop head if we're inside it.
                if let Some(head) = self.head {
                    if let Some(i) = self.stack.iter().rposition(|&n| n == head) {
                        self.stack.truncate(i);
                    }
                }
                return;
            }
            "p" => {
                // </p> with no open p creates an empty p (spec behavior).
                let open = self
                    .stack
                    .iter()
                    .any(|&id| self.doc.node(id).as_element().map(|e| e.tag == "p") == Some(true));
                if !open {
                    self.ensure_body();
                    let el = self.doc.create_element("p");
                    let cur = self.current();
                    self.doc.append_child(cur, el);
                    return;
                }
            }
            "br" => {
                // </br> is treated as <br>.
                self.ensure_body();
                let el = self.doc.create_element("br");
                let cur = self.current();
                self.doc.append_child(cur, el);
                return;
            }
            _ => {}
        }
        // Find the matching open element; if found, pop through it.
        // Mis-nested end tags close everything above the match.
        if let Some(i) = self
            .stack
            .iter()
            .rposition(|&id| self.doc.node(id).as_element().map(|e| e.tag == name) == Some(true))
        {
            self.stack.truncate(i);
        }
        // Unmatched end tag: ignored.
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, off: usize) -> Option<u8> {
        self.bytes.get(self.pos + off).copied()
    }

    fn starts_with_ci(&self, s: &str) -> bool {
        let end = self.pos + s.len();
        if end > self.bytes.len() {
            return false;
        }
        self.bytes[self.pos..end].eq_ignore_ascii_case(s.as_bytes())
    }

    fn next_token(&mut self) -> Token {
        if self.pos >= self.bytes.len() {
            return Token::Eof;
        }
        if self.peek() == Some(b'<') {
            match self.peek_at(1) {
                Some(b'!') => return self.consume_markup_declaration(),
                Some(b'/') => return self.consume_end_tag(),
                Some(b'?') => return self.consume_bogus_comment(2),
                Some(c) if c.is_ascii_alphabetic() => return self.consume_start_tag(),
                _ => {
                    // Literal '<' as text.
                    self.pos += 1;
                    return Token::Text("<".to_string());
                }
            }
        }
        // Text run until next '<'.
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos] != b'<' {
            self.pos += 1;
        }
        let raw = &self.bytes[start..self.pos];
        let text = String::from_utf8_lossy(raw);
        Token::Text(decode_entities(&text))
    }

    fn consume_markup_declaration(&mut self) -> Token {
        // self.pos at '<', pos+1 at '!'
        if self.starts_with_ci("<!--") {
            self.pos += 4;
            let start = self.pos;
            let mut end = self.bytes.len();
            let mut close_len = 0;
            let mut i = self.pos;
            while i < self.bytes.len() {
                if self.bytes[i] == b'-' && self.bytes.get(i + 1) == Some(&b'-') {
                    if self.bytes.get(i + 2) == Some(&b'>') {
                        end = i;
                        close_len = 3;
                        break;
                    }
                    // --!> also closes (spec: incorrectly closed comment)
                    if self.bytes.get(i + 2) == Some(&b'!') && self.bytes.get(i + 3) == Some(&b'>')
                    {
                        end = i;
                        close_len = 4;
                        break;
                    }
                }
                i += 1;
            }
            let text = String::from_utf8_lossy(&self.bytes[start..end]).into_owned();
            self.pos = (end + close_len).min(self.bytes.len());
            return Token::Comment(text);
        }
        if self.starts_with_ci("<!doctype") {
            self.pos += 9;
            // Skip whitespace, read name until '>' (ignore public/system ids).
            while matches!(self.peek(), Some(c) if c.is_ascii_whitespace()) {
                self.pos += 1;
            }
            let start = self.pos;
            while self.pos < self.bytes.len() && self.bytes[self.pos] != b'>' {
                self.pos += 1;
            }
            let raw = String::from_utf8_lossy(&self.bytes[start..self.pos]);
            let name = raw
                .split_ascii_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if self.peek() == Some(b'>') {
                self.pos += 1;
            }
            return Token::Doctype(name);
        }
        if self.starts_with_ci("<![CDATA[") {
            // In HTML documents CDATA is a bogus comment.
            return self.consume_bogus_comment(2);
        }
        self.consume_bogus_comment(2)
    }

    fn consume_bogus_comment(&mut self, skip: usize) -> Token {
        self.pos += skip;
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos] != b'>' {
            self.pos += 1;
        }
        let text = String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
        if self.peek() == Some(b'>') {
            self.pos += 1;
        }
        Token::Comment(text)
    }

    fn consume_end_tag(&mut self) -> Token {
        // at '</'
        self.pos += 2;
        if !matches!(self.peek(), Some(c) if c.is_ascii_alphabetic()) {
            // "</>" or "</ " -> bogus comment / ignored
            return self.consume_bogus_comment(0);
        }
        let start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'-' || c == b':')
        {
            self.pos += 1;
        }
        let name = String::from_utf8_lossy(&self.bytes[start..self.pos]).to_ascii_lowercase();
        // Skip to '>'.
        while self.pos < self.bytes.len() && self.bytes[self.pos] != b'>' {
            self.pos += 1;
        }
        if self.peek() == Some(b'>') {
            self.pos += 1;
        }
        Token::EndTag(name)
    }

    fn consume_start_tag(&mut self) -> Token {
        // at '<'
        self.pos += 1;
        let start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'-' || c == b':')
        {
            self.pos += 1;
        }
        let name = String::from_utf8_lossy(&self.bytes[start..self.pos]).to_ascii_lowercase();
        let mut attrs: Vec<(String, String)> = Vec::new();
        let mut self_closing = false;
        loop {
            // Skip whitespace.
            while matches!(self.peek(), Some(c) if c.is_ascii_whitespace()) {
                self.pos += 1;
            }
            match self.peek() {
                None => break,
                Some(b'>') => {
                    self.pos += 1;
                    break;
                }
                Some(b'/') => {
                    self.pos += 1;
                    if self.peek() == Some(b'>') {
                        self.pos += 1;
                        self_closing = true;
                        break;
                    }
                    // stray '/', ignore
                }
                Some(_) => {
                    // Attribute name.
                    let astart = self.pos;
                    while let Some(c) = self.peek() {
                        if c.is_ascii_whitespace() || c == b'=' || c == b'>' || c == b'/' {
                            break;
                        }
                        self.pos += 1;
                    }
                    if self.pos == astart {
                        // Defensive: didn't advance (e.g. '=' first) — skip one.
                        self.pos += 1;
                        continue;
                    }
                    let aname =
                        String::from_utf8_lossy(&self.bytes[astart..self.pos]).to_ascii_lowercase();
                    // Skip whitespace before '='.
                    while matches!(self.peek(), Some(c) if c.is_ascii_whitespace()) {
                        self.pos += 1;
                    }
                    let value = if self.peek() == Some(b'=') {
                        self.pos += 1;
                        while matches!(self.peek(), Some(c) if c.is_ascii_whitespace()) {
                            self.pos += 1;
                        }
                        match self.peek() {
                            Some(q @ (b'"' | b'\'')) => {
                                self.pos += 1;
                                let vstart = self.pos;
                                while self.pos < self.bytes.len() && self.bytes[self.pos] != q {
                                    self.pos += 1;
                                }
                                let v = String::from_utf8_lossy(&self.bytes[vstart..self.pos])
                                    .into_owned();
                                if self.peek() == Some(q) {
                                    self.pos += 1;
                                }
                                decode_entities(&v)
                            }
                            _ => {
                                let vstart = self.pos;
                                while let Some(c) = self.peek() {
                                    if c.is_ascii_whitespace() || c == b'>' {
                                        break;
                                    }
                                    self.pos += 1;
                                }
                                let v = String::from_utf8_lossy(&self.bytes[vstart..self.pos])
                                    .into_owned();
                                decode_entities(&v)
                            }
                        }
                    } else {
                        String::new()
                    };
                    // First declaration of an attribute wins (spec).
                    if !attrs.iter().any(|(n, _)| *n == aname) {
                        attrs.push((aname, value));
                    }
                }
            }
        }
        Token::StartTag {
            name,
            attrs,
            self_closing,
        }
    }

    /// Consume raw text until `</name` (case-insensitive). Returns the text.
    fn consume_rawtext(&mut self, name: &str, rcdata: bool) -> String {
        let start = self.pos;
        let closer = format!("</{name}");
        let mut end = self.bytes.len();
        let mut i = self.pos;
        while i < self.bytes.len() {
            if self.bytes[i] == b'<'
                && self.bytes.len() - i >= closer.len()
                && self.bytes[i..i + closer.len()].eq_ignore_ascii_case(closer.as_bytes())
            {
                // Must be followed by whitespace, '/', '>' or EOF to count.
                match self.bytes.get(i + closer.len()) {
                    None | Some(b'>') | Some(b'/') => {
                        end = i;
                        break;
                    }
                    Some(c) if c.is_ascii_whitespace() => {
                        end = i;
                        break;
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        let raw = String::from_utf8_lossy(&self.bytes[start..end]).into_owned();
        // Skip past the close tag.
        self.pos = end;
        if end < self.bytes.len() {
            self.pos += closer.len();
            while self.pos < self.bytes.len() && self.bytes[self.pos] != b'>' {
                self.pos += 1;
            }
            if self.peek() == Some(b'>') {
                self.pos += 1;
            }
        }
        if rcdata {
            decode_entities(&raw)
        } else {
            raw
        }
    }
}

/// Decode HTML character references (named, decimal, hex). Unknown or
/// malformed references are passed through literally, per spec error handling.
pub fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            // Copy one UTF-8 scalar.
            let ch_len = utf8_len(bytes[i]);
            let end = (i + ch_len).min(bytes.len());
            out.push_str(&String::from_utf8_lossy(&bytes[i..end]));
            i = end;
            continue;
        }
        // Try numeric: &#123; or &#x1F600;
        if bytes.get(i + 1) == Some(&b'#') {
            let (hex, mut j) = match bytes.get(i + 2) {
                Some(b'x') | Some(b'X') => (true, i + 3),
                _ => (false, i + 2),
            };
            let dstart = j;
            while j < bytes.len()
                && ((hex && bytes[j].is_ascii_hexdigit()) || (!hex && bytes[j].is_ascii_digit()))
            {
                j += 1;
            }
            if j > dstart {
                let digits = std::str::from_utf8(&bytes[dstart..j]).unwrap_or("");
                let code = u32::from_str_radix(digits, if hex { 16 } else { 10 }).unwrap_or(0xFFFD);
                let ch = decode_numeric(code);
                out.push(ch);
                if bytes.get(j) == Some(&b';') {
                    j += 1;
                }
                i = j;
                continue;
            }
            out.push('&');
            i += 1;
            continue;
        }
        // Named entity: longest match wins, with and without semicolon.
        let mut j = i + 1;
        while j < bytes.len() && j - i <= 32 && (bytes[j].is_ascii_alphanumeric()) {
            j += 1;
        }
        let has_semi = bytes.get(j) == Some(&b';');
        let name = std::str::from_utf8(&bytes[i + 1..j]).unwrap_or("");
        if let Some(rep) = lookup_entity(name, has_semi) {
            out.push_str(rep);
            i = j + if has_semi { 1 } else { 0 };
            continue;
        }
        out.push('&');
        i += 1;
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

/// Map a numeric character reference, applying the WHATWG replacement rules
/// for C1 controls and invalid code points.
fn decode_numeric(code: u32) -> char {
    // Windows-1252 mappings for the C1 range, per spec.
    const C1_MAP: [u32; 32] = [
        0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160,
        0x2039, 0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
        0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
    ];
    let mapped = if (0x80..=0x9F).contains(&code) {
        C1_MAP[(code - 0x80) as usize]
    } else if code == 0 || code > 0x10FFFF || (0xD800..=0xDFFF).contains(&code) {
        0xFFFD
    } else {
        code
    };
    char::from_u32(mapped).unwrap_or('\u{FFFD}')
}

/// Common named entities. `bare` entities (no semicolon) are the legacy set.
fn lookup_entity(name: &str, has_semi: bool) -> Option<&'static str> {
    // Legacy entities that work without a semicolon.
    let bare: Option<&'static str> = match name {
        "amp" => Some("&"),
        "lt" => Some("<"),
        "gt" => Some(">"),
        "quot" => Some("\""),
        "nbsp" => Some("\u{00A0}"),
        "copy" => Some("\u{00A9}"),
        "reg" => Some("\u{00AE}"),
        _ => None,
    };
    if let Some(b) = bare {
        return Some(b);
    }
    if !has_semi {
        return None;
    }
    let v = match name {
        "apos" => "'",
        "mdash" => "\u{2014}",
        "ndash" => "\u{2013}",
        "lsquo" => "\u{2018}",
        "rsquo" => "\u{2019}",
        "ldquo" => "\u{201C}",
        "rdquo" => "\u{201D}",
        "hellip" => "\u{2026}",
        "bull" => "\u{2022}",
        "middot" => "\u{00B7}",
        "sect" => "\u{00A7}",
        "para" => "\u{00B6}",
        "deg" => "\u{00B0}",
        "plusmn" => "\u{00B1}",
        "times" => "\u{00D7}",
        "divide" => "\u{00F7}",
        "frac12" => "\u{00BD}",
        "frac14" => "\u{00BC}",
        "frac34" => "\u{00BE}",
        "sup1" => "\u{00B9}",
        "sup2" => "\u{00B2}",
        "sup3" => "\u{00B3}",
        "micro" => "\u{00B5}",
        "laquo" => "\u{00AB}",
        "raquo" => "\u{00BB}",
        "iexcl" => "\u{00A1}",
        "iquest" => "\u{00BF}",
        "cent" => "\u{00A2}",
        "pound" => "\u{00A3}",
        "yen" => "\u{00A5}",
        "euro" => "\u{20AC}",
        "curren" => "\u{00A4}",
        "trade" => "\u{2122}",
        "dagger" => "\u{2020}",
        "Dagger" => "\u{2021}",
        "permil" => "\u{2030}",
        "prime" => "\u{2032}",
        "Prime" => "\u{2033}",
        "infin" => "\u{221E}",
        "ne" => "\u{2260}",
        "le" => "\u{2264}",
        "ge" => "\u{2265}",
        "minus" => "\u{2212}",
        "lowast" => "\u{2217}",
        "radic" => "\u{221A}",
        "prop" => "\u{221D}",
        "sum" => "\u{2211}",
        "prod" => "\u{220F}",
        "int" => "\u{222B}",
        "asymp" => "\u{2248}",
        "equiv" => "\u{2261}",
        "forall" => "\u{2200}",
        "exist" => "\u{2203}",
        "empty" => "\u{2205}",
        "nabla" => "\u{2207}",
        "isin" => "\u{2208}",
        "notin" => "\u{2209}",
        "ni" => "\u{220B}",
        "cap" => "\u{2229}",
        "cup" => "\u{222A}",
        "sub" => "\u{2282}",
        "sup" => "\u{2283}",
        "sube" => "\u{2286}",
        "supe" => "\u{2287}",
        "and" => "\u{2227}",
        "or" => "\u{2228}",
        "not" => "\u{00AC}",
        "there4" => "\u{2234}",
        "because" => "\u{2235}",
        "larr" => "\u{2190}",
        "uarr" => "\u{2191}",
        "rarr" => "\u{2192}",
        "darr" => "\u{2193}",
        "harr" => "\u{2194}",
        "lArr" => "\u{21D0}",
        "rArr" => "\u{21D2}",
        "hArr" => "\u{21D4}",
        "spades" => "\u{2660}",
        "clubs" => "\u{2663}",
        "hearts" => "\u{2665}",
        "diams" => "\u{2666}",
        "alpha" => "\u{03B1}",
        "beta" => "\u{03B2}",
        "gamma" => "\u{03B3}",
        "delta" => "\u{03B4}",
        "epsilon" => "\u{03B5}",
        "zeta" => "\u{03B6}",
        "eta" => "\u{03B7}",
        "theta" => "\u{03B8}",
        "iota" => "\u{03B9}",
        "kappa" => "\u{03BA}",
        "lambda" => "\u{03BB}",
        "mu" => "\u{03BC}",
        "nu" => "\u{03BD}",
        "xi" => "\u{03BE}",
        "omicron" => "\u{03BF}",
        "pi" => "\u{03C0}",
        "rho" => "\u{03C1}",
        "sigma" => "\u{03C3}",
        "tau" => "\u{03C4}",
        "upsilon" => "\u{03C5}",
        "phi" => "\u{03C6}",
        "chi" => "\u{03C7}",
        "psi" => "\u{03C8}",
        "omega" => "\u{03C9}",
        "Alpha" => "\u{0391}",
        "Beta" => "\u{0392}",
        "Gamma" => "\u{0393}",
        "Delta" => "\u{0394}",
        "Epsilon" => "\u{0395}",
        "Zeta" => "\u{0396}",
        "Eta" => "\u{0397}",
        "Theta" => "\u{0398}",
        "Iota" => "\u{0399}",
        "Kappa" => "\u{039A}",
        "Lambda" => "\u{039B}",
        "Mu" => "\u{039C}",
        "Nu" => "\u{039D}",
        "Xi" => "\u{039E}",
        "Omicron" => "\u{039F}",
        "Pi" => "\u{03A0}",
        "Rho" => "\u{03A1}",
        "Sigma" => "\u{03A3}",
        "Tau" => "\u{03A4}",
        "Upsilon" => "\u{03A5}",
        "Phi" => "\u{03A6}",
        "Chi" => "\u{03A7}",
        "Psi" => "\u{03A8}",
        "Omega" => "\u{03A9}",
        "sigmaf" => "\u{03C2}",
        "thinsp" => "\u{2009}",
        "ensp" => "\u{2002}",
        "emsp" => "\u{2003}",
        "zwnj" => "\u{200C}",
        "zwj" => "\u{200D}",
        "lrm" => "\u{200E}",
        "rlm" => "\u{200F}",
        "shy" => "\u{00AD}",
        "oline" => "\u{203E}",
        "frasl" => "\u{2044}",
        "weierp" => "\u{2118}",
        "image" => "\u{2111}",
        "real" => "\u{211C}",
        "alefsym" => "\u{2135}",
        "crarr" => "\u{21B5}",
        "lceil" => "\u{2308}",
        "rceil" => "\u{2309}",
        "lfloor" => "\u{230A}",
        "rfloor" => "\u{230B}",
        "lang" => "\u{2329}",
        "rang" => "\u{232A}",
        "loz" => "\u{25CA}",
        "oplus" => "\u{2295}",
        "otimes" => "\u{2297}",
        "perp" => "\u{22A5}",
        "sdot" => "\u{22C5}",
        "AElig" => "\u{00C6}",
        "aelig" => "\u{00E6}",
        "OElig" => "\u{0152}",
        "oelig" => "\u{0153}",
        "Aring" => "\u{00C5}",
        "aring" => "\u{00E5}",
        "Oslash" => "\u{00D8}",
        "oslash" => "\u{00F8}",
        "Ccedil" => "\u{00C7}",
        "ccedil" => "\u{00E7}",
        "szlig" => "\u{00DF}",
        "Ntilde" => "\u{00D1}",
        "ntilde" => "\u{00F1}",
        _ => {
            // Accented latin: generic forms like &eacute; &Uuml; &agrave;
            return lookup_latin_entity(name);
        }
    };
    Some(v)
}

/// Latin-1 accented letters expressed as `<letter><accent>` names, e.g.
/// `eacute`, `Agrave`, `ocirc`, `uuml`, `atilde`.
fn lookup_latin_entity(name: &str) -> Option<&'static str> {
    const TABLE: &[(&str, &str)] = &[
        ("Agrave", "\u{00C0}"),
        ("Aacute", "\u{00C1}"),
        ("Acirc", "\u{00C2}"),
        ("Atilde", "\u{00C3}"),
        ("Auml", "\u{00C4}"),
        ("Egrave", "\u{00C8}"),
        ("Eacute", "\u{00C9}"),
        ("Ecirc", "\u{00CA}"),
        ("Euml", "\u{00CB}"),
        ("Igrave", "\u{00CC}"),
        ("Iacute", "\u{00CD}"),
        ("Icirc", "\u{00CE}"),
        ("Iuml", "\u{00CF}"),
        ("Ograve", "\u{00D2}"),
        ("Oacute", "\u{00D3}"),
        ("Ocirc", "\u{00D4}"),
        ("Otilde", "\u{00D5}"),
        ("Ouml", "\u{00D6}"),
        ("Ugrave", "\u{00D9}"),
        ("Uacute", "\u{00DA}"),
        ("Ucirc", "\u{00DB}"),
        ("Uuml", "\u{00DC}"),
        ("Yacute", "\u{00DD}"),
        ("agrave", "\u{00E0}"),
        ("aacute", "\u{00E1}"),
        ("acirc", "\u{00E2}"),
        ("atilde", "\u{00E3}"),
        ("auml", "\u{00E4}"),
        ("egrave", "\u{00E8}"),
        ("eacute", "\u{00E9}"),
        ("ecirc", "\u{00EA}"),
        ("euml", "\u{00EB}"),
        ("igrave", "\u{00EC}"),
        ("iacute", "\u{00ED}"),
        ("icirc", "\u{00EE}"),
        ("iuml", "\u{00EF}"),
        ("ograve", "\u{00F2}"),
        ("oacute", "\u{00F3}"),
        ("ocirc", "\u{00F4}"),
        ("otilde", "\u{00F5}"),
        ("ouml", "\u{00F6}"),
        ("ugrave", "\u{00F9}"),
        ("uacute", "\u{00FA}"),
        ("ucirc", "\u{00FB}"),
        ("uuml", "\u{00FC}"),
        ("yacute", "\u{00FD}"),
        ("yuml", "\u{00FF}"),
        ("ETH", "\u{00D0}"),
        ("eth", "\u{00F0}"),
        ("THORN", "\u{00DE}"),
        ("thorn", "\u{00FE}"),
        ("acute", "\u{00B4}"),
        ("cedil", "\u{00B8}"),
        ("uml", "\u{00A8}"),
        ("macr", "\u{00AF}"),
        ("ordf", "\u{00AA}"),
        ("ordm", "\u{00BA}"),
        ("brvbar", "\u{00A6}"),
    ];
    TABLE.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_core::dom::NodeId;

    fn body_of(doc: &Document) -> NodeId {
        doc.descendants(NodeId::DOCUMENT)
            .find(|&n| doc.node(n).as_element().map(|e| e.tag == "body") == Some(true))
            .expect("body")
    }

    #[test]
    fn basic_document() {
        let doc = parse(
            "<!DOCTYPE html><html><head><title>T</title></head><body><p>Hi</p></body></html>",
        );
        let body = body_of(&doc);
        let p = doc.children(body).next().unwrap();
        assert_eq!(doc.node(p).as_element().unwrap().tag, "p");
        assert_eq!(doc.text_content(p), "Hi");
        // title text present
        let title = doc.find_tag("title").unwrap();
        assert_eq!(doc.text_content(title), "T");
    }

    #[test]
    fn implied_scaffolding() {
        let doc = parse("Hello <b>world</b>");
        let body = body_of(&doc);
        assert_eq!(doc.text_content(body), "Hello world");
        let b = doc.find_tag("b").unwrap();
        assert_eq!(doc.text_content(b), "world");
    }

    #[test]
    fn void_and_self_closing() {
        let doc = parse("<body><br><img src=x><hr/><p>after</p></body>");
        let body = body_of(&doc);
        let tags: Vec<String> = doc
            .children(body)
            .filter_map(|n| doc.node(n).as_element().map(|e| e.tag.clone()))
            .collect();
        assert_eq!(tags, vec!["br", "img", "hr", "p"]);
    }

    #[test]
    fn p_auto_close() {
        let doc = parse("<p>one<p>two<div>three</div>");
        let body = body_of(&doc);
        let tags: Vec<String> = doc
            .children(body)
            .filter_map(|n| doc.node(n).as_element().map(|e| e.tag.clone()))
            .collect();
        assert_eq!(tags, vec!["p", "p", "div"]);
    }

    #[test]
    fn li_auto_close_nested_lists() {
        let doc = parse("<ul><li>a<li>b<ul><li>c</li></ul></ul>");
        let ul = doc.find_tag("ul").unwrap();
        let lis: Vec<NodeId> = doc
            .children(ul)
            .filter(|&n| doc.node(n).as_element().map(|e| e.tag == "li") == Some(true))
            .collect();
        assert_eq!(lis.len(), 2);
        // nested ul lives under second li
        let nested = doc
            .descendants(lis[1])
            .find(|&n| doc.node(n).as_element().map(|e| e.tag == "ul") == Some(true));
        assert!(nested.is_some());
    }

    #[test]
    fn table_cells_auto_close() {
        let doc = parse("<table><tr><td>1<td>2<tr><td>3</table>");
        let table = doc.find_tag("table").unwrap();
        let trs: Vec<NodeId> = doc
            .descendants(table)
            .filter(|&n| doc.node(n).as_element().map(|e| e.tag == "tr") == Some(true))
            .collect();
        assert_eq!(trs.len(), 2);
        let tds0: Vec<NodeId> = doc
            .children(trs[0])
            .filter(|&n| doc.node(n).as_element().map(|e| e.tag == "td") == Some(true))
            .collect();
        assert_eq!(tds0.len(), 2);
    }

    #[test]
    fn rawtext_script_not_parsed() {
        let doc =
            parse("<body><script>if (a < b) { x = \"<p>not a tag</p>\"; }</script><p>real</p>");
        let script = doc.find_tag("script").unwrap();
        assert!(doc.text_content(script).contains("<p>not a tag</p>"));
        // Only one real p element
        let ps: Vec<NodeId> = doc
            .descendants(NodeId::DOCUMENT)
            .filter(|&n| doc.node(n).as_element().map(|e| e.tag == "p") == Some(true))
            .collect();
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn rcdata_title_decodes_entities() {
        let doc = parse("<title>Fish &amp; Chips</title>");
        let title = doc.find_tag("title").unwrap();
        assert_eq!(doc.text_content(title), "Fish & Chips");
    }

    #[test]
    fn entities() {
        assert_eq!(decode_entities("&amp;&lt;&gt;&quot;&apos;"), "&<>\"'");
        assert_eq!(decode_entities("&#65;&#x42;&#X43;"), "ABC");
        assert_eq!(decode_entities("&eacute;&Uuml;"), "\u{00E9}\u{00DC}");
        assert_eq!(decode_entities("&nbsp"), "\u{00A0}"); // legacy, no semi
        assert_eq!(decode_entities("&unknown;"), "&unknown;");
        assert_eq!(decode_entities("a & b"), "a & b");
        assert_eq!(decode_entities("&#0;"), "\u{FFFD}");
        assert_eq!(decode_entities("&#x80;"), "\u{20AC}"); // C1 remap
    }

    #[test]
    fn comments_and_doctype() {
        let doc = parse("<!-- hello --><!DOCTYPE html><p>x</p>");
        let mut saw_comment = false;
        let mut saw_doctype = false;
        for n in doc.descendants(NodeId::DOCUMENT) {
            match &doc.node(n).data {
                NodeData::Comment(c) => {
                    saw_comment = true;
                    assert_eq!(c, " hello ");
                }
                NodeData::Doctype { name } => {
                    saw_doctype = true;
                    assert_eq!(name, "html");
                }
                _ => {}
            }
        }
        assert!(saw_comment && saw_doctype);
    }

    #[test]
    fn attributes_all_quoting_styles() {
        let doc = parse(r#"<div id=main class="a b" data-x='y' checked>t</div>"#);
        let div = doc.find_tag("div").unwrap();
        let e = doc.node(div).as_element().unwrap();
        assert_eq!(e.attr("id"), Some("main"));
        assert_eq!(e.attr("class"), Some("a b"));
        assert_eq!(e.attr("data-x"), Some("y"));
        assert_eq!(e.attr("checked"), Some(""));
    }

    #[test]
    fn hostile_input_never_panics() {
        let cases = [
            "",
            "<",
            "</",
            "<!",
            "<!-",
            "<!--",
            "<x",
            "<x a",
            "<x a=",
            "<x a='",
            "</p>",
            "<><><>",
            "&#xD800;",
            "&#999999999;",
            "<p><b></p></b>",
            "<table><td>orphan",
            "\u{0000}\u{FFFF}",
            "<script>",
            "<title>never closed",
        ];
        for c in cases {
            let _ = parse(c);
        }
    }

    #[test]
    fn misnested_end_tags() {
        // </b> closes b even though i is open; i is force-closed too
        // (simplified adoption: everything above the match pops).
        let doc = parse("<b>bold<i>both</b>italic</i>");
        let body = body_of(&doc);
        assert_eq!(doc.text_content(body), "boldbothitalic");
    }

    #[test]
    fn end_tag_br_becomes_element() {
        let doc = parse("a</br>b");
        assert!(doc.find_tag("br").is_some());
    }

    #[test]
    fn self_closing_flag_only_closes_void_elements() {
        // warnerbros.com (Chrome-referenced corpus) ships
        // `<noscript><iframe src=… /></noscript>` in its head. In Chrome
        // the `/>` on a non-void element is a parse error and ignored, so
        // the iframe's raw text runs to `</iframe>` — never written — and
        // the whole body is swallowed: Chrome shows a blank page. The old
        // parser honoured `/>` and rendered content Chrome never shows.
        let doc = parse("<head><noscript><iframe src=x /></noscript></head><body><p>gone</p></body>");
        assert!(doc.find_tag("p").is_none(), "the <p> was swallowed as iframe raw text");
        let iframe = doc.find_tag("iframe").expect("iframe element");
        assert!(doc.text_content(iframe).contains("<p>gone</p>"), "raw text lives inside the iframe");
        // A self-closing non-void in the body also stays open.
        let doc = parse("<body><div id=a /><p>inside</p></body>");
        let mut d = doc.clone();
        let a = d.get_element_by_id("a").unwrap();
        assert!(doc.find_tag("p").map(|p| doc.node(p).parent == Some(a)).unwrap_or(false));
        // Inside inline SVG, `/>` self-closes (foreign content)…
        let doc = parse("<body><svg><path d=M0 /><circle r=1 /></svg><p>after</p></body>");
        let svg = doc.find_tag("svg").unwrap();
        let kids: Vec<String> = doc
            .children(svg)
            .filter_map(|n| doc.node(n).as_element().map(|e| e.tag.clone()))
            .collect();
        assert_eq!(kids, vec!["path", "circle"]);
        let p = doc.find_tag("p").unwrap();
        assert_eq!(doc.node(p).parent, Some(body_of(&doc)));
        // …but not inside a foreignObject, which is HTML again.
        let doc = parse("<body><svg><foreignObject><div id=f /><b>in</b></foreignObject></svg></body>");
        let mut d = doc.clone();
        let f = d.get_element_by_id("f").unwrap();
        let b = doc.find_tag("b").unwrap();
        assert_eq!(doc.node(b).parent, Some(f));
    }

    #[test]
    fn noscript_follows_the_scripting_flag() {
        let src = "<head><noscript><link rel=stylesheet href=a.css></noscript></head>\
                   <body><noscript><p>Please enable JavaScript</p></noscript><p>main</p></body>";
        // Scripting off (the no-script render and Chrome with JS disabled):
        // noscript children are real markup.
        let off = parse_with_scripting(src, false);
        assert!(off.find_tag("link").is_some(), "head noscript link is an element");
        assert!(off.text_content(body_of(&off)).contains("Please enable JavaScript"));
        // Scripting on: the content is raw text that never renders.
        let on = parse_with_scripting(src, true);
        assert!(on.find_tag("link").is_none());
        let text = on.text_content(body_of(&on));
        assert!(!text.contains("Please enable"), "{text}");
        assert!(text.contains("main"));
    }
}
