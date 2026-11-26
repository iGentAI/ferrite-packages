//! Document assembly: turning a build-time React shell into a per-request
//! HTML document, in Rust, without rendering React.
//!
//! # The mechanism
//!
//! A build step may prerender each route's body on the developer machine.
//! The application supplies those bodies through its
//! [`AlloyApp`](crate::alloy::app::AlloyApp) implementation, and one shared
//! shell carries two required markers plus an optional route-body marker:
//!
//! ```html
//! <!--__alloy_head-->
//! <div id="root"><!--__alloy_body--></div>
//! <script id="__alloy_data" type="application/json"></script>
//! ```
//!
//! For a document request the app optionally fills the route body, replaces
//! the head marker with the route's metadata, and fills the data script with
//! the loader payload. This is **byte substitution into a cached template**,
//! not a render, and it is why a crawler sees complete HTML while the browser
//! hydrates with no fetch waterfall.
//!
//! # Why the escaping here is load-bearing
//!
//! Loader data is application data — a drop title, a user's display name —
//! and it lands inside a `<script>` element. HTML does not parse that element
//! as JSON: the tokenizer looks for `</script` and for `<!--` regardless of
//! what the content means. A title containing `</script><img onerror=…>`
//! would therefore close the block and execute. JSON escaping alone does NOT
//! prevent this, because `/` and `<` are legal literal characters in a JSON
//! string.
//!
//! [`escape_json_for_script`] closes that hole with `\u003c`, which is the
//! same string to `JSON.parse` and inert to the HTML tokenizer.

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;

use crate::alloy::error::{AlloyError, Result};

/// The marker the route's `<head>` metadata replaces.
pub const HEAD_MARKER: &str = "<!--__alloy_head-->";

/// The marker a route-specific prerendered body replaces.
///
/// Unlike [`HEAD_MARKER`] and [`DATA_SCRIPT_EMPTY`], this marker is optional:
/// shells written before route-specific prerendering remain valid. When an
/// [`AlloyApp`](crate::alloy::app::AlloyApp) supplies a body, the runtime
/// requires exactly one copy between the head and data markers before it
/// performs the substitution.
pub const BODY_MARKER: &str = "<!--__alloy_body-->";

/// The id of the script element the loader payload lands in.
pub const DATA_SCRIPT_ID: &str = "__alloy_data";

/// The empty data script as the shell builder emits it.
pub const DATA_SCRIPT_EMPTY: &str =
    "<script id=\"__alloy_data\" type=\"application/json\"></script>";

/// One `<meta>`-level fact about a route.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct Metadata {
    /// The document title.
    pub title: Option<String>,
    /// The template a CHILD's title is formatted through (`%s` is the
    /// child's title). Never applied to the level that declared it.
    #[serde(default)]
    pub title_template: Option<String>,
    /// The title served when no child supplies one.
    #[serde(default)]
    pub title_default: Option<String>,
    /// The meta description.
    pub description: Option<String>,
    /// The canonical URL.
    pub canonical: Option<String>,
    /// The viewport declaration.
    #[serde(default)]
    pub viewport: Option<String>,
    /// The theme color, for browsers honouring no colour scheme or light.
    #[serde(default)]
    pub theme_color: Option<String>,
    /// The dark-scheme theme color, emitted with a `media` attribute.
    #[serde(default)]
    pub theme_color_dark: Option<String>,
    /// The favicon href.
    #[serde(default)]
    pub icon: Option<String>,
    /// The apple-touch-icon href.
    #[serde(default)]
    pub apple_icon: Option<String>,
    /// `keywords`, joined with commas at render.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// The document author.
    #[serde(default)]
    pub author: Option<String>,
    /// `og:*` properties, in declaration order.
    pub open_graph: Vec<(String, String)>,
    /// `twitter:*` properties.
    pub twitter: Vec<(String, String)>,
    /// `robots` directives, for example `noindex, nofollow`.
    pub robots: Option<String>,
    /// JSON-LD documents embedded as `application/ld+json`.
    pub json_ld: Vec<serde_json::Value>,
}

impl Metadata {
    /// Empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the title.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the template a child's title is formatted through.
    ///
    /// `%s` stands for the child's title. The template applies to LOWER
    /// levels only: a layout that declares `"%s | Acme"` and a title in one
    /// breath is asking its pages to be suffixed, not itself.
    pub fn title_template(mut self, template: impl Into<String>) -> Self {
        self.title_template = Some(template.into());
        self
    }

    /// Set the title served when no child supplies one.
    pub fn title_default(mut self, default: impl Into<String>) -> Self {
        self.title_default = Some(default.into());
        self
    }

    /// Set the viewport declaration.
    pub fn viewport(mut self, viewport: impl Into<String>) -> Self {
        self.viewport = Some(viewport.into());
        self
    }

    /// Set the theme color.
    pub fn theme_color(mut self, color: impl Into<String>) -> Self {
        self.theme_color = Some(color.into());
        self
    }

    /// Set the dark-scheme theme color.
    pub fn theme_color_dark(mut self, color: impl Into<String>) -> Self {
        self.theme_color_dark = Some(color.into());
        self
    }

    /// Set the favicon href.
    pub fn icon(mut self, href: impl Into<String>) -> Self {
        self.icon = Some(href.into());
        self
    }

    /// Set the apple-touch-icon href.
    pub fn apple_icon(mut self, href: impl Into<String>) -> Self {
        self.apple_icon = Some(href.into());
        self
    }

    /// Set the robots directives.
    pub fn robots(mut self, robots: impl Into<String>) -> Self {
        self.robots = Some(robots.into());
        self
    }

    /// Set the keywords.
    pub fn keywords(mut self, keywords: Vec<String>) -> Self {
        self.keywords = keywords;
        self
    }

    /// Set the author.
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Set the description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the canonical URL.
    pub fn canonical(mut self, url: impl Into<String>) -> Self {
        self.canonical = Some(url.into());
        self
    }

    /// Add an Open Graph property, supplying the `og:` prefix when the
    /// caller wrote a bare name.
    ///
    /// A name that ALREADY carries a vocabulary prefix keeps it. The Open
    /// Graph namespace is not the only one rendered through `<meta
    /// property=…>`: an article shares `article:author` and `article:tag`,
    /// a profile shares `profile:username`, a book shares `book:isbn`, and
    /// all of them are siblings of `og:` rather than members of it.
    ///
    /// Prefixing unconditionally would emit `og:article:tag`, which is a
    /// property no crawler reads — and the failure is doubly silent,
    /// because [`REPEATABLE_PROPERTIES`] names `article:tag`, so the
    /// mangled form also falls out of the repeatable set and a page's tags
    /// then REPLACE its layout's instead of joining them.
    pub fn og(mut self, property: &str, content: impl Into<String>) -> Self {
        self.open_graph
            .push((qualify_property(property), content.into()));
        self
    }

    /// Add a Twitter card property (the `twitter:` prefix is added if absent).
    pub fn twitter(mut self, name: &str, content: impl Into<String>) -> Self {
        let name = if name.starts_with("twitter:") {
            name.to_string()
        } else {
            format!("twitter:{name}")
        };
        self.twitter.push((name, content.into()));
        self
    }

    /// Add a JSON-LD document.
    pub fn json_ld(mut self, doc: serde_json::Value) -> Self {
        self.json_ld.push(doc);
        self
    }

    /// Merge `child` over `self`: a route's metadata layering over its
    /// layout's.
    ///
    /// A child's scalar wins when present. For the property LISTS the rule
    /// is per-property rather than per-list, because Open Graph itself is
    /// two different things in one vocabulary:
    ///
    /// - **Single-valued properties replace.** `og:title` names one title.
    ///   Appending a page's title to its layout's would emit the document
    ///   with two, and a crawler takes whichever it meets first — so a
    ///   layout that sets a site-wide title would silently win over every
    ///   page beneath it. That is the shape of the defect: not a crash, not
    ///   a failing test, just every share card on the site showing the same
    ///   wrong words.
    /// - **Repeatable properties append.** `og:image` is explicitly
    ///   multi-valued in the Open Graph protocol — a page offering several
    ///   images is normal, and collapsing them to the last one declared
    ///   would be its own defect.
    ///
    /// JSON-LD always appends: a document may carry any number of
    /// independent linked-data blocks, and they do not overwrite each other.
    ///
    /// # The title template chain
    ///
    /// A child's title is formatted through the NEAREST parent template —
    /// which after a pairwise fold is exactly `self.title_template`, because
    /// a child that declares its own template REPLACES the inherited one for
    /// everything below it. The template never applies to the level that
    /// declared it: a layout writing `"%s | Acme"` is addressing its pages,
    /// not suffixing itself, so the child's OWN template plays no part in
    /// formatting the child's own title.
    pub fn merge(mut self, child: &Metadata) -> Self {
        if let Some(title) = &child.title {
            self.title = Some(match &self.title_template {
                Some(template) => template.replacen("%s", title, 1),
                None => title.clone(),
            });
        }
        // The child's template resets the chain for ITS children; a child
        // declaring none inherits the parent's, which is what lets a
        // template skip an intermediate layout that has nothing to say.
        if child.title_template.is_some() {
            self.title_template = child.title_template.clone();
        }
        if child.title_default.is_some() {
            self.title_default = child.title_default.clone();
        }
        if child.description.is_some() {
            self.description = child.description.clone();
        }
        if child.canonical.is_some() {
            self.canonical = child.canonical.clone();
        }
        if child.viewport.is_some() {
            self.viewport = child.viewport.clone();
        }
        if child.theme_color.is_some() {
            self.theme_color = child.theme_color.clone();
        }
        if child.theme_color_dark.is_some() {
            self.theme_color_dark = child.theme_color_dark.clone();
        }
        if child.icon.is_some() {
            self.icon = child.icon.clone();
        }
        if child.apple_icon.is_some() {
            self.apple_icon = child.apple_icon.clone();
        }
        // Keywords replace as a WHOLE list, matching Next's shallow merge:
        // a page naming its own keywords is curating the set, and a union
        // would let a layout's generic words dilute every page beneath it.
        if !child.keywords.is_empty() {
            self.keywords = child.keywords.clone();
        }
        if child.author.is_some() {
            self.author = child.author.clone();
        }
        if child.robots.is_some() {
            self.robots = child.robots.clone();
        }
        merge_properties(&mut self.open_graph, &child.open_graph);
        merge_properties(&mut self.twitter, &child.twitter);
        self.json_ld.extend(child.json_ld.iter().cloned());
        self
    }

    /// Render as the `<head>` fragment that replaces [`HEAD_MARKER`].
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(256);
        // The default steps in only when no level of the chain supplied a
        // title, and it is served VERBATIM: the template belongs to the
        // children of the level that declared it, and the default is that
        // same level speaking for itself.
        if let Some(t) = self.title.as_ref().or(self.title_default.as_ref()) {
            out.push_str("<title>");
            out.push_str(&escape_html_text(t));
            out.push_str("</title>");
        }
        if let Some(v) = &self.viewport {
            out.push_str(&meta_named("viewport", v));
        }
        if let Some(d) = &self.description {
            out.push_str(&meta_named("description", d));
        }
        if let Some(r) = &self.robots {
            out.push_str(&meta_named("robots", r));
        }
        if !self.keywords.is_empty() {
            out.push_str(&meta_named("keywords", &self.keywords.join(",")));
        }
        if let Some(a) = &self.author {
            out.push_str(&meta_named("author", a));
        }
        // A light/dark PAIR carries `media` attributes so the browser picks
        // by scheme; a single colour carries none, because a media-scoped
        // lone value would leave the other scheme with no colour at all.
        match (&self.theme_color, &self.theme_color_dark) {
            (Some(light), Some(dark)) => {
                out.push_str(&theme_color_meta(
                    light,
                    Some("(prefers-color-scheme: light)"),
                ));
                out.push_str(&theme_color_meta(
                    dark,
                    Some("(prefers-color-scheme: dark)"),
                ));
            }
            (Some(only), None) => out.push_str(&theme_color_meta(only, None)),
            (None, Some(dark)) => {
                out.push_str(&theme_color_meta(
                    dark,
                    Some("(prefers-color-scheme: dark)"),
                ));
            }
            (None, None) => {}
        }
        if let Some(href) = &self.icon {
            out.push_str("<link rel=\"icon\" href=\"");
            out.push_str(&escape_html_attr(href));
            out.push_str("\">");
        }
        if let Some(href) = &self.apple_icon {
            out.push_str("<link rel=\"apple-touch-icon\" href=\"");
            out.push_str(&escape_html_attr(href));
            out.push_str("\">");
        }
        if let Some(c) = &self.canonical {
            out.push_str("<link rel=\"canonical\" href=\"");
            out.push_str(&escape_html_attr(c));
            out.push_str("\">");
        }
        for (property, content) in &self.open_graph {
            out.push_str("<meta property=\"");
            out.push_str(&escape_html_attr(property));
            out.push_str("\" content=\"");
            out.push_str(&escape_html_attr(content));
            out.push_str("\">");
        }
        for (name, content) in &self.twitter {
            out.push_str(&meta_named(name, content));
        }
        for doc in &self.json_ld {
            out.push_str("<script type=\"application/ld+json\">");
            out.push_str(&escape_json_for_script(&doc.to_string()));
            out.push_str("</script>");
        }
        out
    }
}

/// The Open Graph properties that may legitimately appear more than once.
///
/// Everything outside this set is single-valued, so a child's declaration
/// REPLACES its layout's rather than joining it. The list is deliberately
/// short and explicit: guessing from the property name — treating anything
/// plural-looking as repeatable — would make the rule unpredictable to an
/// author, and the failure mode is invisible in the rendered page.
///
/// `og:image` carries structured sub-properties (`og:image:width` and the
/// rest) that describe the image preceding them, so those repeat with it;
/// the prefix match is what keeps a multi-image document coherent.
const REPEATABLE_PROPERTIES: &[&str] = &[
    "og:image",
    "og:video",
    "og:audio",
    "og:locale:alternate",
    "article:tag",
    "article:author",
];

/// The vocabularies that render through `<meta property=…>` alongside
/// Open Graph, and therefore must not be nested under an `og:` prefix.
///
/// Each is a namespace the Open Graph protocol defines for a specific
/// `og:type`: an `article` carries `article:*`, a `profile` carries
/// `profile:*`, a `book` carries `book:*`, and a `music`/`video` object
/// carries its own. They are siblings of `og:`, never children.
const PROPERTY_VOCABULARIES: &[&str] = &[
    "og:", "article:", "profile:", "book:", "music:", "video:", "fb:",
];

/// Qualify a property name written by an author.
///
/// A bare name is an Open Graph property and gains `og:`; a name already
/// carrying a recognised vocabulary prefix is left exactly as written.
fn qualify_property(property: &str) -> String {
    if PROPERTY_VOCABULARIES
        .iter()
        .any(|prefix| property.starts_with(prefix))
    {
        property.to_string()
    } else {
        format!("og:{property}")
    }
}

/// Whether `property` may appear more than once in one document.
fn is_repeatable(property: &str) -> bool {
    REPEATABLE_PROPERTIES
        .iter()
        .any(|p| property == *p || property.starts_with(&format!("{p}:")))
}

/// Layer `child`'s properties over `parent`'s in place.
///
/// A replacing property drops every parent entry of the same name before
/// the child's are appended, so the child's own ORDER among its properties
/// survives and no stale value is left behind for a crawler to find.
fn merge_properties(parent: &mut Vec<(String, String)>, child: &[(String, String)]) {
    for (name, _) in child {
        if !is_repeatable(name) {
            parent.retain(|(existing, _)| existing != name);
        }
    }
    parent.extend(child.iter().cloned());
}

fn meta_named(name: &str, content: &str) -> String {
    format!(
        "<meta name=\"{}\" content=\"{}\">",
        escape_html_attr(name),
        escape_html_attr(content)
    )
}

/// A `theme-color` meta tag, media-scoped when the colour is scheme-bound.
fn theme_color_meta(color: &str, media: Option<&str>) -> String {
    match media {
        Some(media) => format!(
            "<meta name=\"theme-color\" media=\"{}\" content=\"{}\">",
            escape_html_attr(media),
            escape_html_attr(color)
        ),
        None => meta_named("theme-color", color),
    }
}

/// Escape text for an HTML text node.
pub fn escape_html_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape text for a double-quoted HTML attribute.
pub fn escape_html_attr(s: &str) -> String {
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

/// Make a JSON document safe to embed inside a `<script>` element.
///
/// Only three sequences can end or reinterpret the element — `</`, `<!--`,
/// and (inside a module/HTML comment context) `-->`. Escaping every `<` as
/// `\u003c` neutralises all of them at once, and `JSON.parse` sees exactly
/// the same string, so the payload is unchanged. `&` is left alone: a script
/// element's content is raw text, so entities are not decoded there.
///
/// U+2028 and U+2029 are also escaped: they terminate a line in JavaScript's
/// grammar though they are legal inside a JSON string, so an unescaped one in
/// a data payload can produce a syntax error.
pub fn escape_json_for_script(json: &str) -> String {
    let mut out = String::with_capacity(json.len() + 16);
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(c),
        }
    }
    out
}

/// The payload the client runtime reads before React mounts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct LoaderPayload {
    /// The matched route id.
    pub route: String,
    /// The route parameters, as matched.
    pub params: serde_json::Value,
    /// The loader's typed result.
    pub data: serde_json::Value,
    /// The build this document was served by, so a client holding a stale
    /// bundle can detect skew and reload.
    pub build: String,
    /// Tag epochs observed while assembling the payload, so the client seeds
    /// its query cache with the same invalidation basis the server used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub epochs: Vec<(String, u64)>,
}

impl LoaderPayload {
    /// Serialize for embedding.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| AlloyError::internal(e.to_string()))
    }
}

/// Convert a loader's typed result into the payload value, refusing a
/// non-finite number and propagating a serialization failure.
///
/// # The two silent failures this closes
///
/// The obvious spelling of this conversion is
/// `serde_json::to_value(&view).unwrap_or_default()`, and it loses data twice.
///
/// **A non-finite float becomes `null`.** JSON has no `NaN` and no
/// `Infinity`, so `serde_json` renders both as `null` and reports SUCCESS. A
/// loader that averages an empty set therefore ships `null` where the
/// contract promised a number: the server logs nothing, a REQUIRED `f64`
/// field arrives as `null` in violation of its own declared type, and the
/// client cannot tell "missing" from "computed wrongly". Checking the
/// resulting [`serde_json::Value`] cannot help — `serde_json::Number` is
/// incapable of holding a non-finite value, so by then the evidence is gone.
/// The check has to inspect the TYPED value, which is what [`ensure_finite`]
/// does.
///
/// **A failed conversion becomes `null`.** `unwrap_or_default()` turns any
/// serialization error into `Value::Null`, so a view that cannot encode is
/// served as a 200 carrying no data at all.
pub fn loader_value<T>(view: &T) -> Result<serde_json::Value>
where
    T: ferrite_app::serde::Serialize,
{
    ensure_finite(view)?;
    serde_json::to_value(view).map_err(|e| AlloyError::internal(e.to_string()))
}

/// Refuse a value carrying a non-finite float, naming the field.
///
/// This walks the value through serde WITHOUT building anything, so it costs
/// a traversal and no allocation of the encoded form. It runs before
/// `to_value`, because `to_value` is exactly where the information is
/// destroyed.
pub fn ensure_finite<T>(view: &T) -> Result<()>
where
    T: ferrite_app::serde::Serialize + ?Sized,
{
    let path = core::cell::RefCell::new(Vec::<String>::new());
    view.serialize(FiniteCheck { path: &path })
        .map_err(|e| AlloyError::internal(e.0))
}

/// The failure a [`FiniteCheck`] reports.
struct CheckFailed(String);

impl core::fmt::Display for CheckFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::fmt::Debug for CheckFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CheckFailed {}

impl ferrite_app::serde::ser::Error for CheckFailed {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        CheckFailed(msg.to_string())
    }
}

/// A serializer that builds nothing and only asks whether every float is
/// finite.
///
/// Implementing `Serializer` rather than inspecting the encoded output is
/// what makes this exact: the encoded output no longer distinguishes a
/// `null` that was written as null from a `null` that WAS a number.
#[derive(Clone, Copy)]
struct FiniteCheck<'a> {
    path: &'a core::cell::RefCell<Vec<String>>,
}

impl<'a> FiniteCheck<'a> {
    fn here(&self) -> String {
        let parts = self.path.borrow();
        if parts.is_empty() {
            "the loader payload".to_string()
        } else {
            parts.join(".")
        }
    }

    fn check(&self, finite: bool, value: &str) -> core::result::Result<(), CheckFailed> {
        if finite {
            return Ok(());
        }
        Err(CheckFailed(format!(
            "'{}' is {value}, which JSON cannot represent; serializing it would \
             write null and lose the value with no error",
            self.here()
        )))
    }

    fn nested<T>(&self, key: &str, value: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.path.borrow_mut().push(key.to_string());
        let outcome = value.serialize(*self);
        self.path.borrow_mut().pop();
        outcome
    }
}

impl<'a> ferrite_app::serde::Serializer for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    // Non-float scalars can never be non-finite; each passthrough is written
    // out verbatim because the constrained-app code gate treats app-defined
    // `macro_rules!` as opaque and refuses the source.
    fn serialize_bool(self, _v: bool) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_i8(self, _v: i8) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_i16(self, _v: i16) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_i32(self, _v: i32) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_i64(self, _v: i64) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_u8(self, _v: u8) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_u16(self, _v: u16) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_u32(self, _v: u32) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_u64(self, _v: u64) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_char(self, _v: char) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_str(self, _v: &str) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
    fn serialize_bytes(self, _v: &[u8]) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> core::result::Result<(), CheckFailed> {
        self.check(v.is_finite(), &v.to_string())
    }

    fn serialize_f64(self, v: f64) -> core::result::Result<(), CheckFailed> {
        self.check(v.is_finite(), &v.to_string())
    }

    fn serialize_none(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }

    fn serialize_some<T>(self, value: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }

    fn serialize_unit_struct(self, _: &'static str) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }

    fn serialize_newtype_struct<T>(
        self,
        _: &'static str,
        value: &T,
    ) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested(variant, value)
    }

    fn serialize_seq(self, _: Option<usize>) -> core::result::Result<Self, CheckFailed> {
        Ok(self)
    }

    fn serialize_tuple(self, _: usize) -> core::result::Result<Self, CheckFailed> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> core::result::Result<Self, CheckFailed> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> core::result::Result<Self, CheckFailed> {
        Ok(self)
    }

    fn serialize_map(self, _: Option<usize>) -> core::result::Result<Self, CheckFailed> {
        Ok(self)
    }

    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> core::result::Result<Self, CheckFailed> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> core::result::Result<Self, CheckFailed> {
        Ok(self)
    }
}

impl<'a> ferrite_app::serde::ser::SerializeSeq for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;

    fn serialize_element<T>(&mut self, value: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested("[]", value)
    }

    fn end(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
}

impl<'a> ferrite_app::serde::ser::SerializeTuple for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;

    fn serialize_element<T>(&mut self, value: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested("[]", value)
    }

    fn end(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
}

impl<'a> ferrite_app::serde::ser::SerializeTupleStruct for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;

    fn serialize_field<T>(&mut self, value: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested("[]", value)
    }

    fn end(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
}

impl<'a> ferrite_app::serde::ser::SerializeTupleVariant for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;

    fn serialize_field<T>(&mut self, value: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested("[]", value)
    }

    fn end(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
}

impl<'a> ferrite_app::serde::ser::SerializeMap for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;

    fn serialize_key<T>(&mut self, key: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        // A JSON object key is a string, but the RUST key type need not be:
        // a map may be keyed by a newtype, a tuple, or anything else whose
        // `Serialize` reaches a float. `serde_json` would reject such a key
        // later with its own error, so skipping it here would leave the
        // traversal claiming to be complete while quietly relying on a
        // downstream failure to say something less specific.
        self.nested("$key", key)
    }

    fn serialize_value<T>(&mut self, value: &T) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested("*", value)
    }

    fn end(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
}

impl<'a> ferrite_app::serde::ser::SerializeStruct for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;

    fn serialize_field<T>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested(key, value)
    }

    fn end(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
}

impl<'a> ferrite_app::serde::ser::SerializeStructVariant for FiniteCheck<'a> {
    type Ok = ();
    type Error = CheckFailed;

    fn serialize_field<T>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> core::result::Result<(), CheckFailed>
    where
        T: ferrite_app::serde::Serialize + ?Sized,
    {
        self.nested(key, value)
    }

    fn end(self) -> core::result::Result<(), CheckFailed> {
        Ok(())
    }
}

/// A prerendered shell, parsed once and reused for every request.
///
/// The split is computed at construction so a request costs two copies rather
/// than a scan.
#[derive(Debug, Clone)]
pub struct Shell {
    head_before: String,
    head_after_to_data: String,
    data_after: String,
    digest: String,
}

impl Shell {
    /// Parse a prerendered shell.
    ///
    /// Both markers are required: a shell missing one would silently serve
    /// documents with no metadata or no payload, which is a defect that only
    /// shows up as bad SEO or a hydration waterfall in production.
    pub fn parse(html: &str, digest: impl Into<String>) -> Result<Self> {
        let head_at = html.find(HEAD_MARKER).ok_or_else(|| {
            AlloyError::internal(format!(
                "the prerendered shell carries no {HEAD_MARKER} marker"
            ))
        })?;
        let data_at = html.find(DATA_SCRIPT_EMPTY).ok_or_else(|| {
            AlloyError::internal(
                "the prerendered shell carries no empty __alloy_data script element",
            )
        })?;
        if data_at < head_at {
            return Err(AlloyError::internal(
                "the __alloy_data script precedes the head marker; the payload must be \
                 injected after the metadata so the document parses in order",
            ));
        }
        let head_end = head_at + HEAD_MARKER.len();
        // The data script is rebuilt around the payload, so the opening tag
        // is kept and the closing tag follows the injected JSON.
        let open_tag_len = DATA_SCRIPT_EMPTY.len() - "</script>".len();
        Ok(Self {
            head_before: html[..head_at].to_string(),
            head_after_to_data: html[head_end..data_at + open_tag_len].to_string(),
            data_after: html[data_at + open_tag_len..].to_string(),
            digest: digest.into(),
        })
    }

    /// The shell's content digest — its blob key and its ETag.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Assemble a document: metadata into the head marker, payload into the
    /// data script.
    pub fn render(&self, metadata: &Metadata, payload: &LoaderPayload) -> Result<String> {
        let head = metadata.render();
        let json = escape_json_for_script(&payload.to_json()?);
        let mut out = String::with_capacity(
            self.head_before.len()
                + head.len()
                + self.head_after_to_data.len()
                + json.len()
                + self.data_after.len(),
        );
        out.push_str(&self.head_before);
        out.push_str(&head);
        out.push_str(&self.head_after_to_data);
        out.push_str(&json);
        out.push_str(&self.data_after);
        Ok(out)
    }

    /// [`render`](Self::render), stamping `nonce="…"` on the data script and
    /// on every `<script>` tag of the SHELL.
    ///
    /// Only the shell's own parts are stamped, and that restriction is the
    /// security property: the loader payload escapes every `<` and the
    /// metadata escapes its text and attributes, so neither can contain a
    /// live `<script` for the stamping to find — application data therefore
    /// CANNOT acquire a nonce, however hostile. Stamping the assembled
    /// document instead would hand a nonce to any content that smuggled a
    /// script tag past a future escaping bug, converting an injection the
    /// CSP would have blocked into one it licenses.
    pub fn render_with_nonce(
        &self,
        metadata: &Metadata,
        payload: &LoaderPayload,
        nonce: &str,
    ) -> Result<String> {
        // The nonce lands inside a double-quoted attribute, so a value that
        // could close the quote is refused outright. The nonce is app-made
        // (random bytes, encoded), so anything outside a token charset is a
        // caller bug, not an input to accommodate.
        if nonce.is_empty()
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
        {
            return Err(AlloyError::internal(
                "a CSP nonce must be non-empty base64 text; anything else could \
                 escape the attribute it is stamped into",
            ));
        }
        let head = metadata.render();
        let json = escape_json_for_script(&payload.to_json()?);
        let mut out = String::with_capacity(
            self.head_before.len()
                + head.len()
                + self.head_after_to_data.len()
                + json.len()
                + self.data_after.len()
                + 64,
        );
        out.push_str(&stamp_nonce(&self.head_before, nonce));
        out.push_str(&head);
        out.push_str(&stamp_nonce(&self.head_after_to_data, nonce));
        out.push_str(&json);
        out.push_str(&stamp_nonce(&self.data_after, nonce));
        Ok(out)
    }
}

/// Stamp `nonce="…"` onto every `<script` tag opening in `html`.
///
/// Both spellings are covered — `<script ` and a bare `<script>` — and
/// nothing else is: `<scription` or a `<script` inside ordinary text is not
/// a tag opening and stays untouched.
fn stamp_nonce(html: &str, nonce: &str) -> String {
    let mut out = String::with_capacity(html.len() + 64);
    // Tag names are ASCII case-insensitive, and any HTML whitespace, `/` or `>`
    // ends one (`<SCRIPT`, `<script\n type=...>`). ASCII lowercasing keeps offsets.
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find("<script") {
        let after = from + found + "<script".len();
        out.push_str(&html[from..after]);
        if matches!(html.as_bytes().get(after), Some(b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'/' | b'>')) {
            out.push_str(&format!(" nonce=\"{nonce}\""));
        }
        from = after;
    }
    out.push_str(&html[from..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_html() -> String {
        format!(
            "<!doctype html><html><head>{HEAD_MARKER}</head><body><div id=\"root\"></div>{DATA_SCRIPT_EMPTY}<script src=\"/a.js\"></script></body></html>"
        )
    }

    fn payload(data: serde_json::Value) -> LoaderPayload {
        LoaderPayload {
            route: "drop".into(),
            params: serde_json::json!({ "id": "42" }),
            data,
            build: "b1".into(),
            epochs: Vec::new(),
        }
    }

    #[test]
    fn a_shell_renders_metadata_and_payload_in_place() {
        let shell = Shell::parse(&shell_html(), "deadbeef").unwrap();
        let meta = Metadata::new().title("Drop 42").description("A drop");
        let html = shell
            .render(&meta, &payload(serde_json::json!({ "title": "Hi" })))
            .unwrap();
        assert!(html.contains("<title>Drop 42</title>"));
        assert!(html.contains("<meta name=\"description\" content=\"A drop\">"));
        assert!(html.contains("\"title\":\"Hi\""));
        assert!(!html.contains(HEAD_MARKER));
        // The document still closes correctly and keeps the bundle script.
        assert!(html.contains("</script><script src=\"/a.js\"></script></body></html>"));
        assert_eq!(shell.digest(), "deadbeef");
    }

    #[test]
    fn a_payload_cannot_break_out_of_its_script_element() {
        // The attack: application data closes the script and opens a new one.
        let hostile = serde_json::json!({
            "title": "</script><script>alert(1)</script>",
            "note": "<!--<script>",
        });
        let shell = Shell::parse(&shell_html(), "d").unwrap();
        let html = shell.render(&Metadata::new(), &payload(hostile)).unwrap();
        // Exactly two script elements survive: the data script and the bundle.
        assert_eq!(html.matches("</script>").count(), 2);
        assert!(!html.contains("<script>alert(1)"));
        assert!(!html.contains("<!--<script>"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }

    #[test]
    fn escaped_json_is_still_the_same_json() {
        // The escaping must be transparent to JSON.parse: \u003c IS '<'.
        let value = serde_json::json!({ "a": "<b>&'\"", "n": 1 });
        let escaped = escape_json_for_script(&value.to_string());
        let back: serde_json::Value = serde_json::from_str(&escaped).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn line_separators_are_escaped_because_javascript_ends_a_line_on_them() {
        let value = serde_json::json!({ "a": "x\u{2028}y\u{2029}z" });
        let escaped = escape_json_for_script(&value.to_string());
        assert!(!escaped.contains('\u{2028}'));
        assert!(!escaped.contains('\u{2029}'));
        let back: serde_json::Value = serde_json::from_str(&escaped).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn metadata_escapes_hostile_titles_and_attributes() {
        let meta = Metadata::new()
            .title("</title><script>alert(1)</script>")
            .og("image", "\" onload=\"alert(1)")
            .canonical("https://x.test/?a=1&b=2");
        let rendered = meta.render();
        assert!(!rendered.contains("<script>"));
        assert!(rendered.contains("&lt;/title&gt;"));
        assert!(rendered.contains("&quot; onload=&quot;"));
        assert!(rendered.contains("a=1&amp;b=2"));
    }

    #[test]
    fn og_and_twitter_prefixes_are_added_once() {
        let meta = Metadata::new().og("title", "t").og("og:type", "article");
        let rendered = meta.render();
        assert!(rendered.contains("property=\"og:title\""));
        assert!(rendered.contains("property=\"og:type\""));
        assert!(!rendered.contains("og:og:"));
    }

    #[test]
    fn a_sibling_vocabulary_is_never_nested_under_the_og_prefix() {
        // `article:*` is a SIBLING of `og:*`, not a member. Prefixing it
        // unconditionally emits `og:article:tag` — a property no crawler
        // reads — and the failure is doubly silent, because the mangled
        // name also drops out of REPEATABLE_PROPERTIES, so a page's tags
        // then replace its layout's instead of joining them.
        let meta = Metadata::new()
            .og("type", "article")
            .og("article:author", "ana")
            .og("article:tag", "rust")
            .og("profile:username", "ferrite");
        let rendered = meta.render();
        assert!(
            rendered.contains("property=\"article:author\""),
            "{rendered}"
        );
        assert!(rendered.contains("property=\"article:tag\""));
        assert!(rendered.contains("property=\"profile:username\""));
        assert!(!rendered.contains("og:article:"), "a vocabulary was nested");
        assert!(!rendered.contains("og:profile:"));
        // …and a bare name is still an Open Graph property.
        assert!(rendered.contains("property=\"og:type\""));
    }

    #[test]
    fn article_authors_accumulate_because_the_protocol_says_they_may() {
        // An article with three authors renders three tags. This is the
        // rule the `og:` mangling silently defeated: the repeatable set
        // names `article:author`, and `og:article:author` is not in it.
        let parent = Metadata::new().og("article:author", "ana");
        let child = Metadata::new()
            .og("article:author", "raj")
            .og("article:author", "mei");
        let merged = parent.merge(&child);

        let authors: Vec<&str> = merged
            .open_graph
            .iter()
            .filter(|(p, _)| p == "article:author")
            .map(|(_, c)| c.as_str())
            .collect();
        assert_eq!(authors, vec!["ana", "raj", "mei"]);
        assert_eq!(
            merged
                .render()
                .matches("property=\"article:author\"")
                .count(),
            3
        );

        // A single-valued member of the same vocabulary still replaces.
        let parent = Metadata::new().og("article:published_time", "2026-01-01");
        let child = Metadata::new().og("article:published_time", "2026-08-21");
        let merged = parent.merge(&child);
        assert_eq!(
            merged
                .open_graph
                .iter()
                .filter(|(p, _)| p == "article:published_time")
                .count(),
            1
        );
    }

    #[test]
    fn every_repeatable_name_is_reachable_from_the_builder() {
        // REPEATABLE_PROPERTIES is only meaningful if `og(..)` can actually
        // produce the names in it. When the builder mangled `article:tag`
        // into `og:article:tag`, two entries in this list were dead code
        // and nothing said so.
        for name in REPEATABLE_PROPERTIES {
            let produced = qualify_property(name);
            assert_eq!(
                &produced, name,
                "the builder cannot produce the repeatable property '{name}'"
            );
            assert!(is_repeatable(&produced));
        }
    }

    #[test]
    fn child_metadata_overrides_scalars_and_appends_lists() {
        let parent = Metadata::new()
            .title("Site")
            .description("D")
            .og("site", "s");
        let child = Metadata::new().title("Page").og("title", "p");
        let merged = parent.merge(&child);
        assert_eq!(merged.title.as_deref(), Some("Page"));
        assert_eq!(merged.description.as_deref(), Some("D"));
        // Two DIFFERENT properties, so both survive.
        assert_eq!(merged.open_graph.len(), 2);
    }

    #[test]
    fn a_child_replaces_its_layouts_single_valued_property() {
        // The defect this prevents is silent: appending leaves the document
        // carrying two `og:title` tags, a crawler reads the FIRST, and every
        // share card on the site shows the layout's site-wide title instead
        // of the page's. Nothing fails; the words are just wrong everywhere.
        let parent = Metadata::new().og("title", "Site").og("type", "website");
        let child = Metadata::new().og("title", "The page");
        let merged = parent.merge(&child);

        let titles: Vec<&str> = merged
            .open_graph
            .iter()
            .filter(|(p, _)| p == "og:title")
            .map(|(_, c)| c.as_str())
            .collect();
        assert_eq!(titles, vec!["The page"], "got {:?}", merged.open_graph);
        // A property the child did not mention is inherited untouched.
        assert!(merged
            .open_graph
            .iter()
            .any(|(p, c)| p == "og:type" && c == "website"));

        // …and the rendered document carries exactly one of them.
        let rendered = merged.render();
        assert_eq!(rendered.matches("property=\"og:title\"").count(), 1);
    }

    #[test]
    fn repeatable_properties_still_accumulate_across_a_merge() {
        // `og:image` is multi-valued by protocol: a page offering several
        // images is normal, and collapsing them to the last would be its own
        // defect. Its structured sub-properties travel with it.
        let parent = Metadata::new().og("image", "/a.png");
        let child = Metadata::new()
            .og("image", "/b.png")
            .og("image:width", "1200");
        let merged = parent.merge(&child);

        let images: Vec<&str> = merged
            .open_graph
            .iter()
            .filter(|(p, _)| p == "og:image")
            .map(|(_, c)| c.as_str())
            .collect();
        assert_eq!(images, vec!["/a.png", "/b.png"]);
        assert!(merged.open_graph.iter().any(|(p, _)| p == "og:image:width"));
    }

    #[test]
    fn a_twitter_card_property_is_single_valued() {
        // Twitter's vocabulary has no repeatable member at all, so a child
        // always wins outright.
        let parent = Metadata::new().twitter("card", "summary");
        let child = Metadata::new().twitter("card", "summary_large_image");
        let merged = parent.merge(&child);
        assert_eq!(merged.twitter.len(), 1);
        assert_eq!(merged.twitter[0].1, "summary_large_image");
    }

    #[test]
    fn no_twitter_property_can_be_treated_as_repeatable() {
        // `is_repeatable` is shared by both vocabularies, which is safe
        // only because every repeatable name is `og:`- or `article:`-
        // prefixed and a Twitter property never is. That is a property of
        // the LIST rather than of the function, so adding a bare name to
        // it later could silently make Twitter properties accumulate —
        // and the symptom would be two `twitter:card` tags, not a failure.
        for (property, _) in [("twitter:card", ""), ("twitter:image", "")] {
            assert!(
                !is_repeatable(property),
                "'{property}' must be single-valued"
            );
        }
        for name in REPEATABLE_PROPERTIES {
            assert!(
                name.starts_with("og:") || name.starts_with("article:"),
                "'{name}' is neither an Open Graph nor an article property, so it \
                 could collide with another vocabulary"
            );
        }
    }

    #[test]
    fn merging_is_associative_over_three_layers() {
        // A layout, a nested layout and a page. The deepest declaration must
        // win however the merges are grouped, or metadata would depend on
        // the order a framework happened to fold the tree.
        let root = Metadata::new().og("title", "Root").og("site_name", "S");
        let section = Metadata::new().og("title", "Section");
        let page = Metadata::new().og("title", "Page");

        let left = root.clone().merge(&section).merge(&page);
        let right = root.merge(&section.merge(&page));

        for merged in [left, right] {
            let titles: Vec<&str> = merged
                .open_graph
                .iter()
                .filter(|(p, _)| p == "og:title")
                .map(|(_, c)| c.as_str())
                .collect();
            assert_eq!(titles, vec!["Page"]);
            assert!(merged
                .open_graph
                .iter()
                .any(|(p, c)| p == "og:site_name" && c == "S"));
        }
    }

    #[test]
    fn json_ld_blocks_never_replace_one_another() {
        // A document may carry any number of independent linked-data blocks;
        // they describe different things and do not overwrite each other.
        let parent = Metadata::new().json_ld(serde_json::json!({ "@type": "Organization" }));
        let child = Metadata::new().json_ld(serde_json::json!({ "@type": "Article" }));
        assert_eq!(parent.merge(&child).json_ld.len(), 2);
    }

    #[test]
    fn json_ld_is_embedded_and_escaped() {
        let meta = Metadata::new().json_ld(serde_json::json!({
            "@type": "Article",
            "headline": "</script><script>",
        }));
        let rendered = meta.render();
        assert!(rendered.contains("application/ld+json"));
        assert_eq!(rendered.matches("</script>").count(), 1);
    }

    #[test]
    fn a_non_finite_number_is_refused_rather_than_shipped_as_null() {
        // JSON has no NaN and no Infinity, so `serde_json` writes `null`
        // and reports SUCCESS. A loader that averages an empty set would
        // therefore ship `null` where its own contract promised a number:
        // a REQUIRED f64 arrives null, the server logs nothing, and the
        // client cannot tell "absent" from "computed wrongly".
        #[derive(ferrite_app::serde::Serialize)]
        #[serde(crate = "ferrite_app::serde")]
        struct Report {
            name: String,
            average: f64,
        }

        // This is the silent corruption, demonstrated: the encoder is happy.
        let corrupt = serde_json::to_value(Report {
            name: "q3".into(),
            average: f64::NAN,
        })
        .expect("serde_json accepts it");
        assert_eq!(
            corrupt["average"],
            serde_json::Value::Null,
            "this is the defect being closed: NaN became null with no error"
        );

        // …and this is the refusal.
        let err = loader_value(&Report {
            name: "q3".into(),
            average: f64::NAN,
        })
        .expect_err("a non-finite number must be refused");
        assert_eq!(err.status(), 500);

        for bad in [f64::INFINITY, f64::NEG_INFINITY] {
            assert!(loader_value(&Report {
                name: "q3".into(),
                average: bad,
            })
            .is_err());
        }

        // An ordinary value is untouched, including the legitimate edges.
        for good in [0.0, -0.0, 1.5, f64::MIN, f64::MAX] {
            let value = loader_value(&Report {
                name: "q3".into(),
                average: good,
            })
            .expect("a finite number serializes");
            assert_eq!(value["name"], "q3");
        }
    }

    #[test]
    fn the_finite_check_reaches_every_nesting_position() {
        #[derive(ferrite_app::serde::Serialize)]
        #[serde(crate = "ferrite_app::serde")]
        struct Inner {
            ratio: f32,
        }
        #[derive(ferrite_app::serde::Serialize)]
        #[serde(crate = "ferrite_app::serde")]
        struct Outer {
            rows: Vec<Inner>,
        }

        assert!(ensure_finite(&Outer {
            rows: vec![Inner { ratio: f32::NAN }],
        })
        .is_err());
        assert!(ensure_finite(&vec![1.0f64, f64::NAN]).is_err());
        assert!(ensure_finite(&Some(f64::NAN)).is_err());
        assert!(ensure_finite(&(1.0f64, f64::INFINITY)).is_err());
        let mut map = std::collections::BTreeMap::new();
        map.insert("k".to_string(), f64::NAN);
        assert!(ensure_finite(&map).is_err());
        // …and a payload with no float at all is cheap and clean.
        assert!(ensure_finite(&serde_json::json!({ "a": "b", "n": 1 })).is_ok());
    }

    #[test]
    fn a_loader_value_propagates_a_failure_instead_of_serving_null() {
        // The obvious spelling is `to_value(..).unwrap_or_default()`, which
        // turns any encoding failure into `Value::Null` — a 200 carrying no
        // data. `loader_value` returns the error instead.
        struct Unencodable;
        impl ferrite_app::serde::Serialize for Unencodable {
            fn serialize<S: ferrite_app::serde::Serializer>(
                &self,
                _: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                use ferrite_app::serde::ser::Error as _;
                Err(S::Error::custom("this value cannot be encoded"))
            }
        }
        let err = loader_value(&Unencodable).expect_err("must propagate");
        assert_eq!(err.status(), 500);
    }

    #[test]
    fn a_shell_without_its_markers_is_refused() {
        assert!(Shell::parse("<html><head></head></html>", "d").is_err());
        assert!(Shell::parse(&format!("<html>{HEAD_MARKER}</html>"), "d").is_err());
        // Payload before metadata would parse out of order.
        let inverted = format!("<html>{DATA_SCRIPT_EMPTY}{HEAD_MARKER}</html>");
        assert!(Shell::parse(&inverted, "d").is_err());
    }

    #[test]
    fn a_payload_round_trips_through_the_document() {
        let shell = Shell::parse(&shell_html(), "d").unwrap();
        let p = payload(serde_json::json!({ "rows": [1, 2, 3] }));
        let html = shell.render(&Metadata::new(), &p).unwrap();
        let open = html.find("<script id=\"__alloy_data\"").unwrap();
        let start = html[open..].find('>').unwrap() + open + 1;
        let end = html[start..].find("</script>").unwrap() + start;
        let back: LoaderPayload = serde_json::from_str(&html[start..end]).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn a_child_title_is_formatted_through_the_nearest_parent_template() {
        // The template belongs to the level's CHILDREN: the layout's own
        // title is never suffixed by its own template.
        let layout = Metadata::new().title("Acme").title_template("%s | Acme");
        assert_eq!(layout.clone().render(), "<title>Acme</title>");

        let page = Metadata::new().title("Pricing");
        let merged = layout.merge(&page);
        assert_eq!(merged.title.as_deref(), Some("Pricing | Acme"));
        assert!(merged.render().contains("<title>Pricing | Acme</title>"));
    }

    #[test]
    fn a_child_template_resets_the_chain_for_its_own_children() {
        // Level 1 declares "%s | Acme"; level 2 declares its own template
        // AND a title. Level 2's title formats through LEVEL 1's template
        // (never its own), and level 3 formats through level 2's — the
        // nearest — not through both.
        let root = Metadata::new().title_template("%s | Acme");
        let section = Metadata::new().title("Docs").title_template("%s – Docs");
        let page = Metadata::new().title("Install");

        let two = root.merge(&section);
        assert_eq!(two.title.as_deref(), Some("Docs | Acme"));

        let three = two.merge(&page);
        assert_eq!(
            three.title.as_deref(),
            Some("Install – Docs"),
            "the nearest template must win, and exactly once"
        );
    }

    #[test]
    fn a_template_skips_a_level_that_declares_no_title() {
        // An intermediate layout with nothing to say passes the chain
        // through: the root's template still reaches the page.
        let root = Metadata::new().title_template("%s | Acme");
        let quiet = Metadata::new().description("a quiet layout");
        let page = Metadata::new().title("About");
        let merged = root.merge(&quiet).merge(&page);
        assert_eq!(merged.title.as_deref(), Some("About | Acme"));
    }

    #[test]
    fn the_default_title_steps_in_only_when_the_chain_produced_none() {
        let layout = Metadata::new()
            .title_default("Acme")
            .title_template("%s | Acme");
        // No child title anywhere: the default serves, verbatim.
        assert!(layout.clone().render().contains("<title>Acme</title>"));
        assert!(!layout.clone().render().contains("| Acme</title>"));
        // A child title exists: the default is silent.
        let merged = layout.merge(&Metadata::new().title("Pricing"));
        let rendered = merged.render();
        assert_eq!(rendered.matches("<title>").count(), 1);
        assert!(rendered.contains("<title>Pricing | Acme</title>"));
    }

    #[test]
    fn a_hostile_title_cannot_smuggle_markup_through_the_template() {
        // The template formats BEFORE escaping, so the composed string is
        // escaped as one unit and a title carrying markup stays text.
        let layout = Metadata::new().title_template("%s | <Acme>");
        let merged = layout.merge(&Metadata::new().title("</title><script>alert(1)</script>"));
        let rendered = merged.render();
        assert!(!rendered.contains("<script>"), "{rendered}");
        assert!(rendered.contains("&lt;/title&gt;"));
        assert!(rendered.contains("&lt;Acme&gt;"));
    }

    #[test]
    fn the_v2_scalars_merge_shallowly_and_keywords_replace_whole() {
        let parent = Metadata::new()
            .viewport("width=device-width, initial-scale=1")
            .theme_color("#ffffff")
            .icon("/favicon.ico")
            .author("ferrite")
            .keywords(vec!["rust".into(), "framework".into()]);
        let child = Metadata::new()
            .theme_color("#111111")
            .apple_icon("/apple.png")
            .keywords(vec!["alloy".into()]);
        let merged = parent.merge(&child);

        // A child field set wins; a field it left unset is inherited.
        assert_eq!(merged.theme_color.as_deref(), Some("#111111"));
        assert_eq!(
            merged.viewport.as_deref(),
            Some("width=device-width, initial-scale=1")
        );
        assert_eq!(merged.icon.as_deref(), Some("/favicon.ico"));
        assert_eq!(merged.apple_icon.as_deref(), Some("/apple.png"));
        assert_eq!(merged.author.as_deref(), Some("ferrite"));
        // Keywords replace as a whole list, not a union.
        assert_eq!(merged.keywords, vec!["alloy".to_string()]);
    }

    #[test]
    fn theme_colors_carry_media_attributes_only_as_a_pair() {
        // A lone colour is unscoped — media-scoping it would leave the
        // other scheme with no colour at all.
        let lone = Metadata::new().theme_color("#fff").render();
        assert!(lone.contains("<meta name=\"theme-color\" content=\"#fff\">"));
        assert!(!lone.contains("media="));

        // A pair is scoped per scheme.
        let pair = Metadata::new()
            .theme_color("#fff")
            .theme_color_dark("#000")
            .render();
        assert!(pair.contains(
            "<meta name=\"theme-color\" media=\"(prefers-color-scheme: light)\" content=\"#fff\">"
        ));
        assert!(pair.contains(
            "<meta name=\"theme-color\" media=\"(prefers-color-scheme: dark)\" content=\"#000\">"
        ));
    }

    #[test]
    fn the_v2_fields_render_their_tags_and_escape_their_values() {
        // Every new field is application data landing in an attribute, so
        // every one is escaped — a quote in any of them is the attribute
        // breakout this closes.
        let meta = Metadata::new()
            .viewport("width=device-width\" onload=\"alert(1)")
            .theme_color("#fff\"><script>alert(1)</script>")
            .icon("/i.png\" onerror=\"alert(1)")
            .apple_icon("/a.png\"><img src=x>")
            .author("<b>ana</b>")
            .keywords(vec!["a\"b".into(), "c<d".into()])
            .robots("noindex");
        let rendered = meta.render();
        assert!(!rendered.contains("<script>"), "{rendered}");
        assert!(!rendered.contains("<img"), "{rendered}");
        assert!(!rendered.contains("onload=\"alert"));
        assert!(!rendered.contains("onerror=\"alert"));
        // The tags themselves are present.
        assert!(rendered.contains("<meta name=\"viewport\""));
        assert!(rendered.contains("<meta name=\"author\""));
        assert!(rendered.contains("<meta name=\"keywords\""));
        assert!(rendered.contains("<link rel=\"icon\""));
        assert!(rendered.contains("<link rel=\"apple-touch-icon\""));
        // Keywords join with commas, escaped as one attribute value.
        assert!(rendered.contains("content=\"a&quot;b,c&lt;d\""));
    }

    #[test]
    fn a_nonce_lands_on_the_data_script_and_every_shell_script() {
        let shell = Shell::parse(&shell_html(), "d").unwrap();
        let html = shell
            .render_with_nonce(&Metadata::new(), &payload(serde_json::json!({})), "abc123")
            .unwrap();
        // The data script and the bundle script both carry it.
        assert!(html.contains("<script nonce=\"abc123\" id=\"__alloy_data\""));
        assert!(html.contains("<script nonce=\"abc123\" src=\"/a.js\">"));
        // Exactly the shell's two scripts were stamped.
        assert_eq!(html.matches("nonce=\"abc123\"").count(), 2);
        // …and the un-nonced render is unchanged by the feature existing.
        let plain = shell
            .render(&Metadata::new(), &payload(serde_json::json!({})))
            .unwrap();
        assert!(!plain.contains("nonce="));
    }

    #[test]
    fn hostile_content_cannot_acquire_a_nonce() {
        // The attack: application data carries a `<script` hoping the
        // stamping pass hands it a licence the CSP would otherwise refuse.
        // Escaping means the stamper never sees a live `<script` in data.
        let shell = Shell::parse(&shell_html(), "d").unwrap();
        let hostile_payload = payload(serde_json::json!({
            "title": "<script src=\"https://evil.example/x.js\"></script>",
            "note": "<script>steal()</script>",
        }));
        let hostile_meta = Metadata::new()
            .title("<script>alert(1)</script>")
            .og("image", "\"><script>alert(2)</script>");
        let html = shell
            .render_with_nonce(&hostile_meta, &hostile_payload, "abc123")
            .unwrap();
        // Still exactly the shell's own two nonces.
        assert_eq!(html.matches("nonce=\"abc123\"").count(), 2);
        assert!(!html.contains("<script nonce=\"abc123\" src=\"https://evil.example"));
        // No live hostile script exists at all, nonced or not.
        assert!(!html.contains("<script>steal"));
    }

    #[test]
    fn a_nonce_that_could_escape_its_attribute_is_refused() {
        // The nonce is caller-made, so a bad one is a bug — but the failure
        // must be a refusal, not a document whose CSP attribute closed
        // early and licensed what follows.
        let shell = Shell::parse(&shell_html(), "d").unwrap();
        for bad in ["", "abc\" onload=\"alert(1)", "a b", "a>b", "ab\u{2028}"] {
            assert!(
                shell
                    .render_with_nonce(&Metadata::new(), &payload(serde_json::json!({})), bad)
                    .is_err(),
                "'{bad}' was accepted as a nonce"
            );
        }
        // The base64 alphabets (standard and URL-safe) all pass.
        for good in ["abc123", "a+b/c=", "a-b_c"] {
            assert!(shell
                .render_with_nonce(&Metadata::new(), &payload(serde_json::json!({})), good)
                .is_ok());
        }
    }
}
