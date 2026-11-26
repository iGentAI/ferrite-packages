//! The HTML layer: an escape-safe tree/builder with ONE normative escaper
//! (template-v1 §6 — the same escaper serves text and attribute contexts,
//! so a context mix-up can never under-escape), a URL-attribute policy,
//! an ACTIVE-SINK policy, and the void-element table. The template
//! compiler emits calls into exactly this API; there is no other
//! rendering path.
//!
//! ## What "escape-safe construction" does and does not mean
//!
//! Escaping makes a value inert in PASSIVE contexts (text, quoted
//! attribute values). It does nothing for ACTIVE sinks, because the
//! browser decodes entities before handing the value to another
//! interpreter: an `onclick` attribute is JavaScript source, a `srcdoc`
//! attribute is a nested HTML document, a `<script>` body is raw text
//! where `&lt;` never becomes `<`. Escaping those is not a defense.
//!
//! So the builder refuses them (adversarial review ALY-HTML-001/002):
//! [`el`] admits only passive elements, and [`Element::attr`] refuses
//! event handlers and `srcdoc`. Framework-generated active markup (the
//! island script tag, metadata `<link>`/`<meta>`) goes through
//! [`trusted_el`], which is for STATIC, framework-authored tag names —
//! never a runtime value.

use std::fmt::Display;
use std::fmt::Write as _;

/// The one normative escaper (template-v1 §6): `&` `<` `>` `"` `'`.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Void elements (template-v1 §2): no children, no closing tag.
const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
    "track", "wbr",
];

/// Elements the generic [`el`] builder refuses: script hosts, nested
/// browsing contexts, document-base rewriters, raw-text elements whose
/// content is NOT HTML-escapable, and foreign-content roots whose
/// attribute grammar differs from HTML's.
const ACTIVE_TAGS: &[&str] = &[
    "script", "style", "iframe", "object", "embed", "base", "svg", "math",
    "template", "noscript", "frame", "frameset", "applet", "portal", "xmp",
];

/// Whether an attribute makes an otherwise-ordinary element active.
///
/// `meta` and `link` are NOT refused as tags: a real document needs
/// `<meta charset>`, `<meta name=viewport>` and `<link rel=stylesheet>`,
/// and refusing the element would push every author to a raw-HTML
/// escape hatch — which is strictly worse. What is refused is the
/// specific attribute that turns them into a navigation or a script
/// loader: `http-equiv` (refresh, and CSP weakening) and the `rel`
/// values that execute JavaScript.
fn is_active_for_tag(tag: &str, name: &str, value: &str) -> bool {
    match tag {
        "meta" => name == "http-equiv",
        "link" => {
            name == "rel"
                && value.split_whitespace().any(|token| {
                    matches!(
                        token.to_ascii_lowercase().as_str(),
                        "import" | "modulepreload"
                    )
                })
        }
        _ => false,
    }
}

/// Attributes whose values carry URLs and take the scheme policy.
const URL_ATTRS: &[&str] = &[
    "href", "src", "action", "formaction", "poster", "ping", "data", "xlink:href",
];

/// Attributes carrying a comma-separated URL list (each candidate's
/// first token is a URL).
const URL_LIST_ATTRS: &[&str] = &["srcset", "imagesrcset"];

/// Attributes the generic builder refuses outright: every `on*` event
/// handler (JavaScript source), `srcdoc` (a nested HTML document), and
/// `style` (a CSS parser whose escape syntax can hide `url(` from any
/// substring check). `style` has a purpose-built door instead:
/// [`Element::style_attr`].
fn is_active_attr(name: &str) -> bool {
    name.starts_with("on") || name == "srcdoc" || name == "style"
}

/// The URL a refused scheme renders as.
const REFUSED_URL: &str = "#refused";

/// `data:` media types that cannot execute script. SVG is deliberately
/// ABSENT: `data:image/svg+xml` is an executable document (ALY-HTML-003).
const SAFE_DATA_PREFIXES: &[&str] = &[
    "data:image/png",
    "data:image/jpeg",
    "data:image/jpg",
    "data:image/gif",
    "data:image/webp",
    "data:image/avif",
];

/// Schemes that are never admitted in a URL attribute.
const REFUSED_SCHEMES: &[&str] = &["javascript", "vbscript", "livescript", "mocha", "about"];

/// A valid element name per the template grammar: `[a-z][a-z0-9-]*`
/// (checked after ASCII lowercasing).
fn valid_tag(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
}

/// A valid attribute name: `[a-z][a-z0-9_.:-]*` after lowercasing — a
/// closed token syntax, so a name can never carry markup, spaces, or an
/// embedded value.
fn valid_attr_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '.' | ':' | '-'))
}

/// Scheme policy (template-v1 §3). A URL is refused when, after
/// stripping ASCII whitespace and control characters and lowercasing:
/// its scheme is in [`REFUSED_SCHEMES`], or it is a `data:` URL outside
/// the passive-raster allowlist. Control characters anywhere in the
/// value also refuse it outright rather than being rendered through.
pub fn url_is_refused(value: &str) -> bool {
    if value.chars().any(|c| c.is_ascii_control()) {
        return true;
    }
    let compact: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let Some((scheme, _)) = compact.split_once(':') else {
        return false; // relative or scheme-less: not this policy's concern
    };
    // A "scheme" containing a path separator is not a scheme at all
    // (e.g. "/a:b" or "?x=a:b").
    if scheme.contains('/') || scheme.contains('?') || scheme.contains('#') {
        return false;
    }
    if REFUSED_SCHEMES.contains(&scheme) {
        return true;
    }
    if scheme == "data" {
        return !SAFE_DATA_PREFIXES
            .iter()
            .any(|p| compact.starts_with(p) && compact[p.len()..].starts_with([';', ',']));
    }
    false
}

/// A literal, NON-AUTHORITATIVE check for the obvious CSS sinks. CSS
/// escapes (`\75 rl`, `u\72 l`) and comment splitting can hide these
/// tokens, so this is a mistake-catcher, never a boundary: the boundary
/// is that untrusted data never reaches an inline style at all (the
/// generic [`Element::attr`] refuses `style` outright).
fn style_is_refused(value: &str) -> bool {
    let compact: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect();
    compact.contains("url(")
        || compact.contains("expression(")
        || compact.contains("javascript:")
        || compact.contains("@import")
}

/// Every candidate in a `srcset`-style list must pass the URL policy.
fn url_list_is_refused(value: &str) -> bool {
    value.split(',').any(|candidate| {
        let url = candidate.split_whitespace().next().unwrap_or("");
        !url.is_empty() && url_is_refused(url)
    })
}

/// Note a neutralized inline style. Kept as a hook rather than a hard
/// dependency so `html` stays free of the runtime's logging surface.
fn tracing_note_refused_style() {
    #[cfg(debug_assertions)]
    {
        // Visible in dev without adding a logging dependency to the
        // rendering layer.
        eprintln!("rsx: neutralized an inline style value that named a CSS sink");
    }
}

/// A rendered HTML fragment. Construction is the safety boundary for
/// PASSIVE contexts: `text` escapes, `raw` is the single explicit
/// unescaped door (the `RawHtml` builtin), elements are built through
/// [`Element`], and active sinks are refused rather than escaped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Html(String);

impl Html {
    /// The empty fragment.
    pub fn empty() -> Self {
        Self(String::new())
    }

    /// An escaped text fragment (any `Display` value).
    pub fn text(value: impl Display) -> Self {
        Self(escape(&value.to_string()))
    }

    /// Verbatim markup — the ONLY unescaped interpolation (the compiler
    /// emits this solely for `<RawHtml>`, which requires the template's
    /// `allow_raw = true` opt-in; review every hand-written use).
    pub fn raw(markup: impl Into<String>) -> Self {
        Self(markup.into())
    }

    /// Append another fragment.
    pub fn push(&mut self, other: Html) {
        self.0.push_str(&other.0);
    }

    /// Concatenate fragments in order.
    pub fn concat(parts: impl IntoIterator<Item = Html>) -> Self {
        let mut out = Html::empty();
        for p in parts {
            out.push(p);
        }
        out
    }

    /// The rendered bytes as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The rendered string.
    pub fn into_string(self) -> String {
        self.0
    }

    /// The rendered length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this fragment is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn refused_element(original: &str, marker: &str) -> Element {
    let mut e = Element {
        tag: "div".to_string(),
        attrs: String::new(),
        children: String::new(),
        void: false,
    };
    let _ = write!(e.attrs, " {}=\"{}\"", marker, escape(original));
    e
}

/// Start an element builder for a PASSIVE element.
///
/// The tag must satisfy the template grammar (`[a-z][a-z0-9-]*` after
/// lowercasing) and must not be an [`ACTIVE_TAGS`] member. A refused tag
/// renders as a `div` carrying `data-rsx-invalid-tag` or
/// `data-rsx-refused-tag` with the escaped original — visible in the
/// output, never executable, never a construction panic. Framework code
/// that legitimately needs an active element uses [`trusted_el`].
pub fn el(tag: &str) -> Element {
    let lowered = tag.to_ascii_lowercase();
    if !valid_tag(&lowered) {
        return refused_element(tag, "data-rsx-invalid-tag");
    }
    if ACTIVE_TAGS.contains(&lowered.as_str()) {
        return refused_element(tag, "data-rsx-refused-tag");
    }
    Element {
        void: VOID.contains(&lowered.as_str()),
        tag: lowered,
        attrs: String::new(),
        children: String::new(),
    }
}

/// The closed vocabulary of ACTIVE elements the framework itself emits.
///
/// There is deliberately no `trusted_el(&str)`: a runtime string would
/// be exactly the escape hatch the active-tag policy exists to close
/// (adversarial review ALY-HTML-002). Adding a variant here is a
/// reviewable change to the framework, not something request data can
/// reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedTag {
    /// The island loader / hydration bootstrap.
    Script,
    /// The aggregated app stylesheet.
    Style,
    /// Document metadata.
    Meta,
    /// Stylesheet, preload and icon links.
    Link,
    /// A no-JS fallback region.
    NoScript,
}

impl TrustedTag {
    fn as_str(self) -> &'static str {
        match self {
            TrustedTag::Script => "script",
            TrustedTag::Style => "style",
            TrustedTag::Meta => "meta",
            TrustedTag::Link => "link",
            TrustedTag::NoScript => "noscript",
        }
    }
}

/// Start an element builder for an active element the FRAMEWORK owns.
///
/// The tag comes from the closed [`TrustedTag`] vocabulary, so no
/// request value can select one. Content still needs the right
/// treatment for the element: `script` and `style` are RAW TEXT, where
/// HTML escaping is meaningless, so their children must be
/// framework-generated [`Html::raw`].
pub fn trusted_el(tag: TrustedTag) -> Element {
    let name = tag.as_str();
    Element {
        void: VOID.contains(&name),
        tag: name.to_string(),
        attrs: String::new(),
        children: String::new(),
    }
}

/// A component: a value carrying its props, rendered with its children.
///
/// `<Card title={t}>body</Card>` compiles to
/// `component(Card { title: (t) }, <body>)`, so props are NAMED and
/// order-independent, and rustc type-checks each one.
pub trait Component {
    /// Render this component around `children`.
    fn render(self, children: Html) -> Html;
}

/// Render a component (the function the compiler emits).
pub fn component<C: Component>(c: C, children: Html) -> Html {
    c.render(children)
}

/// Prefix a document root with the doctype.
pub fn document(root: Html) -> Html {
    let mut s = String::with_capacity(root.0.len() + 16);
    s.push_str("<!doctype html>");
    s.push_str(&root.0);
    Html(s)
}

/// Why an attribute was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrRefusal {
    /// The name is not a valid attribute token.
    InvalidName,
    /// The name is an active sink (`on*`, `srcdoc`).
    ActiveSink,
}

/// An element under construction. Attribute and child order is emission
/// order (template-v1 §3).
#[derive(Debug, Clone)]
pub struct Element {
    tag: String,
    attrs: String,
    children: String,
    void: bool,
}

impl Element {
    fn admit_name(name: &str) -> Result<String, AttrRefusal> {
        let lowered = name.to_ascii_lowercase();
        if !valid_attr_name(&lowered) {
            return Err(AttrRefusal::InvalidName);
        }
        if is_active_attr(&lowered) {
            return Err(AttrRefusal::ActiveSink);
        }
        Ok(lowered)
    }

    fn policy_value(name: &str, rendered: String) -> String {
        let refused = (URL_ATTRS.contains(&name) && url_is_refused(&rendered))
            || (URL_LIST_ATTRS.contains(&name) && url_list_is_refused(&rendered));
        if refused {
            REFUSED_URL.to_string()
        } else {
            rendered
        }
    }

    fn write_attr(&mut self, name: &str, value: &str) {
        let _ = write!(self.attrs, " {}=\"{}\"", name, escape(value));
    }

    /// An attribute with an escaped `Display` value, refusing invalid
    /// names and active sinks (`on*`, `srcdoc`, `style`), plus the
    /// attributes that would make a head element active.
    pub fn try_attr(mut self, name: &str, value: impl Display) -> Result<Self, AttrRefusal> {
        let name = Self::admit_name(name)?;
        let value = Self::policy_value(&name, value.to_string());
        if is_active_for_tag(&self.tag, &name, &value) {
            return Err(AttrRefusal::ActiveSink);
        }
        self.write_attr(&name, &value);
        Ok(self)
    }

    /// An attribute with an escaped `Display` value.
    ///
    /// Refused (dropped whole, value included) when: the name is not a
    /// valid attribute token, or it is an ACTIVE SINK — any `on*` event
    /// handler, `srcdoc`, or `style`. Escaping cannot make those safe,
    /// so the builder does not pretend otherwise; interactivity uses
    /// islands and `data-rsx-*` directives, and CSS uses scoped style
    /// blocks or [`Element::style_attr`].
    ///
    /// URL-valued names additionally take the scheme policy (a refused
    /// scheme renders as `#refused`) and `srcset`-style lists are
    /// checked candidate by candidate.
    pub fn attr(mut self, name: &str, value: impl Display) -> Self {
        match Self::admit_name(name) {
            Ok(name) => {
                let value = Self::policy_value(&name, value.to_string());
                if is_active_for_tag(&self.tag, &name, &value) {
                    return self;
                }
                self.write_attr(&name, &value);
                self
            }
            Err(_) => self,
        }
    }

    /// The TRUSTED inline-style door — an escape hatch, not a boundary.
    ///
    /// CSS is its own language with its own escape syntax (`\75 rl(...)`
    /// is `url(...)`), so no substring check can police it and this API
    /// does not claim to: the caller vouches for the value. Pass only
    /// DEVELOPER- or FRAMEWORK-authored declarations. Untrusted data
    /// belongs in a class name plus a scoped style block, never here.
    ///
    /// The cheap literal filter below is defense in depth against an
    /// obvious mistake — it is deliberately NOT the security argument.
    pub fn trusted_style_attr(mut self, declarations: impl Display) -> Self {
        let value = declarations.to_string();
        let value = if style_is_refused(&value) {
            tracing_note_refused_style();
            String::new()
        } else {
            value
        };
        self.write_attr("style", &value);
        self
    }

    /// A boolean attribute: present bare when `on`, absent otherwise.
    /// Invalid names and active sinks are dropped.
    pub fn bool_attr(mut self, name: &str, on: bool) -> Self {
        if !on {
            return self;
        }
        match Self::admit_name(name) {
            Ok(name) => {
                let _ = write!(self.attrs, " {name}");
                self
            }
            Err(_) => self,
        }
    }

    /// A bare (valueless) attribute. Invalid names and active sinks are
    /// dropped.
    pub fn bare_attr(mut self, name: &str) -> Self {
        match Self::admit_name(name) {
            Ok(name) => {
                let _ = write!(self.attrs, " {name}");
                self
            }
            Err(_) => self,
        }
    }

    /// Append a child fragment (ignored on void elements, which take no
    /// children by the template grammar — the compiler refuses them
    /// earlier).
    pub fn child(mut self, child: Html) -> Self {
        if !self.void {
            self.children.push_str(child.as_str());
        }
        self
    }

    /// Append escaped text (convenience for `child(Html::text(..))`).
    pub fn text(self, value: impl Display) -> Self {
        let t = Html::text(value);
        self.child(t)
    }

    /// Render the element.
    pub fn build(self) -> Html {
        let mut out =
            String::with_capacity(self.tag.len() * 2 + self.attrs.len() + self.children.len() + 5);
        out.push('<');
        out.push_str(&self.tag);
        out.push_str(&self.attrs);
        out.push('>');
        if !self.void {
            out.push_str(&self.children);
            out.push_str("</");
            out.push_str(&self.tag);
            out.push('>');
        }
        Html(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_elements_are_allowed_but_their_active_attributes_are_not() {
        // A real document needs these, so the ELEMENTS are ordinary.
        assert_eq!(
            el("meta").attr("charset", "utf-8").build().as_str(),
            "<meta charset=\"utf-8\">"
        );
        assert_eq!(
            el("link")
                .attr("rel", "stylesheet")
                .attr("href", "/app.css")
                .build()
                .as_str(),
            "<link rel=\"stylesheet\" href=\"/app.css\">"
        );
        assert!(el("meta")
            .attr("name", "viewport")
            .build()
            .as_str()
            .contains("viewport"));

        // What is refused is the attribute that navigates or executes.
        let refresh = el("meta")
            .attr("http-equiv", "refresh")
            .attr("content", "0;url=https://evil.example")
            .build();
        assert!(
            !refresh.as_str().contains("http-equiv"),
            "a meta refresh is a navigation: {}",
            refresh.as_str()
        );
        for rel in ["import", "modulepreload", "stylesheet import"] {
            let link = el("link").attr("rel", rel).build();
            assert!(
                !link.as_str().contains("rel="),
                "rel={rel} loads code: {}",
                link.as_str()
            );
        }
        assert_eq!(
            el("meta").try_attr("http-equiv", "refresh").err(),
            Some(AttrRefusal::ActiveSink)
        );
        // The scheme policy still applies to a link's href.
        assert!(el("link")
            .attr("rel", "stylesheet")
            .attr("href", "javascript:alert(1)")
            .build()
            .as_str()
            .contains("#refused"));
    }

    #[test]
    fn the_escaper_matches_the_normative_table() {
        assert_eq!(
            escape("Rsx & Friends <notes>"),
            "Rsx &amp; Friends &lt;notes&gt;"
        );
        assert_eq!(
            escape("\"><script>alert(1)</script>"),
            "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape("a'b"), "a&#39;b");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn text_interpolation_escapes_and_raw_does_not() {
        assert_eq!(Html::text("<b>x</b>").as_str(), "&lt;b&gt;x&lt;/b&gt;");
        assert_eq!(Html::raw("<b>x</b>").as_str(), "<b>x</b>");
        assert_eq!(Html::text(7 * 6).as_str(), "42");
    }

    #[test]
    fn elements_render_attrs_in_order_and_escape_values() {
        let h = el("a")
            .attr("rel", "nofollow")
            .attr("href", "/blog?page=2&sort=asc")
            .attr("class", "x")
            .text("n")
            .build();
        assert_eq!(
            h.as_str(),
            "<a rel=\"nofollow\" href=\"/blog?page=2&amp;sort=asc\" class=\"x\">n</a>"
        );
        let attack = el("input")
            .attr("value", "\"><script>alert(1)</script>")
            .build();
        assert_eq!(
            attack.as_str(),
            "<input value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\">"
        );
    }

    #[test]
    fn boolean_and_bare_attributes() {
        assert_eq!(
            el("button")
                .bool_attr("disabled", true)
                .text("Go")
                .build()
                .as_str(),
            "<button disabled>Go</button>"
        );
        assert_eq!(
            el("button")
                .bool_attr("disabled", false)
                .text("Go")
                .build()
                .as_str(),
            "<button>Go</button>"
        );
        assert_eq!(
            el("input").bare_attr("required").build().as_str(),
            "<input required>"
        );
    }

    #[test]
    fn void_elements_take_no_children_and_no_close() {
        assert_eq!(el("br").build().as_str(), "<br>");
        assert_eq!(
            el("hr").attr("class", "rule").build().as_str(),
            "<hr class=\"rule\">"
        );
        assert_eq!(el("img").child(Html::text("x")).build().as_str(), "<img>");
    }

    #[test]
    fn url_scheme_policy_refuses_the_documented_shapes() {
        assert_eq!(
            el("a").attr("href", "JavaScript:alert(1)").build().as_str(),
            "<a href=\"#refused\"></a>"
        );
        assert_eq!(
            el("a")
                .attr("href", " java\tscript:alert(1)")
                .build()
                .as_str(),
            "<a href=\"#refused\"></a>"
        );
        assert_eq!(
            el("a").attr("href", "data:text/html,x").build().as_str(),
            "<a href=\"#refused\"></a>"
        );
        assert_eq!(
            el("img")
                .attr("src", "data:image/png;base64,AA==")
                .build()
                .as_str(),
            "<img src=\"data:image/png;base64,AA==\">"
        );
        assert_eq!(
            el("a")
                .attr("href", "/blog?page=2&sort=asc")
                .build()
                .as_str(),
            "<a href=\"/blog?page=2&amp;sort=asc\"></a>"
        );
        assert_eq!(
            el("div")
                .attr("title", "javascript:notaurl")
                .build()
                .as_str(),
            "<div title=\"javascript:notaurl\"></div>"
        );
    }

    /// ALY-HTML-003: the adversarial URL matrix.
    #[test]
    fn the_url_policy_refuses_the_adversarial_matrix() {
        for hostile in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "vbscript:msgbox(1)",
            "livescript:x",
            "java\nscript:alert(1)",
            "java\0script:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            // the executable image type — SVG is a document, not a raster
            "data:image/svg+xml,%3Csvg onload%3Dalert(1)%3E",
            "data:image/svg+xml;base64,PHN2Zz4=",
            // a prefix that only LOOKS like an allowlisted type
            "data:image/png-evil,x",
        ] {
            assert!(
                url_is_refused(hostile),
                "must refuse {hostile:?}"
            );
        }
        for ok in [
            "/relative/path",
            "https://example.com/x",
            "mailto:a@b.c",
            "data:image/png;base64,AA==",
            "data:image/webp,x",
            "?query=only",
            "#fragment",
            "/a:b",
        ] {
            assert!(!url_is_refused(ok), "must admit {ok:?}");
        }
    }

    /// ALY-HTML-001: event handlers and `srcdoc` are refused, not escaped.
    #[test]
    fn active_attributes_are_refused_not_escaped() {
        assert_eq!(
            el("button").try_attr("onclick", "alert(1)").unwrap_err(),
            AttrRefusal::ActiveSink
        );
        assert_eq!(
            el("img").try_attr("ONERROR", "alert(1)").unwrap_err(),
            AttrRefusal::ActiveSink
        );
        assert_eq!(
            el("iframe")
                .try_attr("srcdoc", "<script>alert(1)</script>")
                .unwrap_err(),
            AttrRefusal::ActiveSink
        );
        assert_eq!(
            el("div").try_attr("style", "position:fixed;inset:0").unwrap_err(),
            AttrRefusal::ActiveSink
        );
        // the infallible API drops them entirely
        assert_eq!(
            el("button").attr("onclick", "alert(1)").text("x").build().as_str(),
            "<button>x</button>"
        );
        // a JS-string breakout cannot even be constructed
        let user = "');alert(1);//";
        assert_eq!(
            el("button")
                .attr("onclick", format!("run('{user}')"))
                .build()
                .as_str(),
            "<button></button>"
        );
        // but a data-* hook (the sanctioned directive path) is fine
        assert_eq!(
            el("button").attr("data-rsx-on", "toggle").build().as_str(),
            "<button data-rsx-on=\"toggle\"></button>"
        );
    }

    /// ALY-HTML-002: dynamic active tags cannot be created through `el`.
    #[test]
    fn active_tags_are_refused_by_the_generic_builder() {
        for tag in [
            "script", "SCRIPT", "iframe", "object", "embed", "base", "svg",
            "math", "style", "template", "noscript", "frameset",
        ] {
            let rendered = el(tag).text("alert(1)").build();
            assert!(
                rendered.as_str().starts_with("<div data-rsx-refused-tag="),
                "{tag} must be refused, got {}",
                rendered.as_str()
            );
            assert!(!rendered.as_str().contains(&format!("<{}", tag.to_ascii_lowercase())));
        }
        // passive tags still work, uppercase normalizes
        assert_eq!(el("DIV").text("x").build().as_str(), "<div>x</div>");
        assert_eq!(el("section").build().as_str(), "<section></section>");
    }

    /// The framework door stays open for its own static markup — through
    /// a CLOSED vocabulary, never a runtime string.
    #[test]
    fn trusted_el_admits_framework_owned_active_tags() {
        assert_eq!(
            trusted_el(TrustedTag::Script)
                .attr("type", "module")
                .child(Html::raw("import '/x.js';"))
                .build()
                .as_str(),
            "<script type=\"module\">import '/x.js';</script>"
        );
        assert_eq!(
            trusted_el(TrustedTag::Meta)
                .attr("name", "description")
                .attr("content", "hi")
                .build()
                .as_str(),
            "<meta name=\"description\" content=\"hi\">"
        );
        assert_eq!(
            trusted_el(TrustedTag::Link)
                .attr("rel", "stylesheet")
                .attr("href", "/_assets/app.css")
                .build()
                .as_str(),
            "<link rel=\"stylesheet\" href=\"/_assets/app.css\">"
        );
    }

    #[test]
    fn url_lists_and_style_values_take_their_own_policies() {
        assert_eq!(
            el("img")
                .attr("srcset", "/a.png 1x, javascript:alert(1) 2x")
                .build()
                .as_str(),
            "<img srcset=\"#refused\">"
        );
        assert_eq!(
            el("img")
                .attr("srcset", "/a.png 1x, /b.png 2x")
                .build()
                .as_str(),
            "<img srcset=\"/a.png 1x, /b.png 2x\">"
        );
        // `style` is refused by the GENERIC surface entirely
        assert_eq!(
            el("div").try_attr("style", "width:50%").unwrap_err(),
            AttrRefusal::ActiveSink
        );
        assert_eq!(
            el("div").attr("style", "width:50%").build().as_str(),
            "<div></div>"
        );
        // the TRUSTED door renders it (caller vouches for the value)
        assert_eq!(
            el("div").trusted_style_attr("width:50%").build().as_str(),
            "<div style=\"width:50%\"></div>"
        );
        // the literal filter catches the obvious mistakes
        for obvious in [
            "background:url(//evil.com/x)",
            "background:URL('//evil.com/x')",
            "width:expression(alert(1))",
            "@import 'evil.css'",
            "background:javascript:alert(1)",
        ] {
            assert_eq!(
                el("div").trusted_style_attr(obvious).build().as_str(),
                "<div style=\"\"></div>",
                "must neutralize {obvious:?}"
            );
        }
        // … and does NOT catch CSS-escaped spellings. This assertion
        // pins the DOCUMENTED limit of the trusted door: the filter is a
        // mistake-catcher, and the real boundary is that untrusted data
        // never reaches it (the generic `attr` refusal above).
        let escaped = el("div")
            .trusted_style_attr("background:\\75 rl(//evil.com/x)")
            .build();
        assert!(
            escaped.as_str().contains("75 rl"),
            "the filter is not a CSS parser and does not claim to be: {}",
            escaped.as_str()
        );
        // formaction and ping are URL sinks too
        assert_eq!(
            el("button")
                .attr("formaction", "javascript:alert(1)")
                .build()
                .as_str(),
            "<button formaction=\"#refused\"></button>"
        );
    }

    #[test]
    fn document_prefixes_the_doctype() {
        let d = document(el("html").child(el("body").text("x").build()).build());
        assert_eq!(d.as_str(), "<!doctype html><html><body>x</body></html>");
    }

    #[test]
    fn invalid_tag_names_cannot_inject_markup() {
        let h = el("div><script").text("x").build();
        assert_eq!(
            h.as_str(),
            "<div data-rsx-invalid-tag=\"div&gt;&lt;script\">x</div>"
        );
        assert!(!h.as_str().contains("<script"), "no tag injection: {}", h.as_str());
    }

    #[test]
    fn invalid_attribute_names_are_dropped_wholesale() {
        let h = el("div").attr("x onclick=alert(1) y", "v").build();
        assert_eq!(h.as_str(), "<div></div>", "name and value both dropped");
        let h = el("div").bare_attr("x onclick=alert(1)").build();
        assert_eq!(h.as_str(), "<div></div>");
        let h = el("div").bool_attr("a b", true).build();
        assert_eq!(h.as_str(), "<div></div>");
        assert_eq!(
            el("div").attr("data-rsx-key", 7).build().as_str(),
            "<div data-rsx-key=\"7\"></div>"
        );
    }

    #[test]
    fn concat_preserves_order() {
        let h = Html::concat([Html::text("a"), Html::raw("<b>"), Html::text("c")]);
        assert_eq!(h.as_str(), "a<b>c");
    }
}
