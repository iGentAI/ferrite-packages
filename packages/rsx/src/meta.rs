//! Page metadata: the head a document needs and a crawler reads.
//!
//! Metadata is DATA, not markup: a page declares it, the runtime
//! renders it into `<head>` for a document and carries the same values
//! in the soft-navigation payload so a client can update the tab title
//! and the canonical link without a reload. One source, two surfaces —
//! which is what stops the two from drifting apart.

use ferrite_app::serde_json;

use super::html::{el, escape, Html};
use super::nav;

/// A page's metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    /// The document title.
    pub title: Option<String>,
    /// The description meta tag.
    pub description: Option<String>,
    /// The canonical URL.
    pub canonical: Option<String>,
    /// The robots directive (`noindex`, `index,follow`, …).
    pub robots: Option<String>,
    /// Open Graph properties, without the `og:` prefix.
    pub og: Vec<(String, String)>,
    /// Arbitrary `name`/`content` meta tags.
    pub meta: Vec<(String, String)>,
    /// A JSON-LD document, already serialized.
    pub json_ld: Option<String>,
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

    /// Set the robots directive.
    pub fn robots(mut self, directive: impl Into<String>) -> Self {
        self.robots = Some(directive.into());
        self
    }

    /// Add an Open Graph property (without the `og:` prefix).
    pub fn og(mut self, property: impl Into<String>, content: impl Into<String>) -> Self {
        self.og.push((property.into(), content.into()));
        self
    }

    /// Add a `name`/`content` meta tag.
    pub fn tag(mut self, name: impl Into<String>, content: impl Into<String>) -> Self {
        self.meta.push((name.into(), content.into()));
        self
    }

    /// Attach a JSON-LD document.
    pub fn json_ld<T: ferrite_app::serde::Serialize>(mut self, value: &T) -> Self {
        if let Ok(text) = serde_json::to_string(value) {
            self.json_ld = Some(text);
        }
        self
    }

    /// Whether anything at all was declared.
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.description.is_none()
            && self.canonical.is_none()
            && self.robots.is_none()
            && self.og.is_empty()
            && self.meta.is_empty()
            && self.json_ld.is_none()
    }

    /// Render the head markup.
    pub fn head(&self) -> Html {
        let mut parts: Vec<Html> = Vec::new();
        if let Some(title) = &self.title {
            // `title` holds TEXT, not markup: the escaper is what keeps
            // a page title from closing its own element.
            parts.push(Html::raw(format!("<title>{}</title>", escape(title))));
        }
        if let Some(description) = &self.description {
            parts.push(
                el("meta")
                    .attr("name", "description")
                    .attr("content", description)
                    .build(),
            );
        }
        if let Some(robots) = &self.robots {
            parts.push(
                el("meta")
                    .attr("name", "robots")
                    .attr("content", robots)
                    .build(),
            );
        }
        for (property, content) in &self.og {
            parts.push(
                el("meta")
                    .attr("property", format!("og:{property}"))
                    .attr("content", content)
                    .build(),
            );
        }
        for (name, content) in &self.meta {
            parts.push(el("meta").attr("name", name).attr("content", content).build());
        }
        if let Some(canonical) = &self.canonical {
            parts.push(
                el("link")
                    .attr("rel", "canonical")
                    .attr("href", canonical)
                    .build(),
            );
        }
        if let Some(json_ld) = &self.json_ld {
            // A script element is ACTIVE markup, so its content is
            // neutralized the same way the boot state is: `<` cannot
            // appear, therefore the element cannot be closed early.
            let safe = json_ld
                .replace('&', "\\u0026")
                .replace('<', "\\u003c")
                .replace('>', "\\u003e");
            parts.push(Html::raw(format!(
                "<script type=\"application/ld+json\">{safe}</script>"
            )));
        }
        Html::concat(parts)
    }

    /// The payload head a soft navigation carries.
    ///
    /// Everything a client can APPLY without a reload: the title, the
    /// meta tags (description, robots, Open Graph, custom) and the
    /// canonical link. JSON-LD is deliberately absent — it is consumed
    /// by crawlers, which fetch documents rather than navigating
    /// softly, so shipping it on every navigation would be weight
    /// nobody reads.
    pub fn payload_head(&self) -> nav::Head {
        let mut head = nav::Head {
            title: self.title.clone(),
            meta: Vec::new(),
            links: Vec::new(),
        };
        if let Some(description) = &self.description {
            head.meta.push(vec![
                "name".to_string(),
                "description".to_string(),
                description.clone(),
            ]);
        }
        if let Some(robots) = &self.robots {
            head.meta.push(vec![
                "name".to_string(),
                "robots".to_string(),
                robots.clone(),
            ]);
        }
        for (property, content) in &self.og {
            head.meta.push(vec![
                "property".to_string(),
                format!("og:{property}"),
                content.clone(),
            ]);
        }
        for (name, content) in &self.meta {
            head.meta
                .push(vec!["name".to_string(), name.clone(), content.clone()]);
        }
        if let Some(canonical) = &self.canonical {
            head.links
                .push(vec!["canonical".to_string(), canonical.clone()]);
        }
        head
    }
}

/// Remove the document title — and ONLY that.
///
/// The search is bounded by `</head>`, because `<title>` is a valid
/// element inside SVG too (`<svg><title>Play</title></svg>` is how an
/// icon gets an accessible name). A global search would delete that,
/// silently removing accessibility content while "fixing" the head.
/// A fragment with no head has no document title, so nothing is
/// removed.
fn remove_head_title(document: &str) -> String {
    let Some(head_end) = document.find("</head>") else {
        return document.to_string();
    };
    let head = &document[..head_end];
    let Some(start) = head.find("<title>") else {
        return document.to_string();
    };
    let Some(end_rel) = head[start..].find("</title>") else {
        return document.to_string();
    };
    let end = start + end_rel + "</title>".len();
    let mut out = String::with_capacity(document.len());
    out.push_str(&document[..start]);
    out.push_str(&document[end..]);
    out
}

/// Insert head markup into a rendered document.
///
/// Before `</head>` when the document has one; otherwise the markup is
/// prepended, so a fragment still carries its metadata rather than
/// losing it silently.
///
/// A declared title REPLACES the layout's. Two `<title>` elements in one
/// head is invalid HTML and a browser silently uses the FIRST one — so
/// appending would let a layout's fallback quietly beat the page's own
/// declaration, which is exactly backwards.
pub fn inject_head(document: &str, head: &str) -> String {
    if head.is_empty() {
        return document.to_string();
    }
    let document = if head.contains("<title>") {
        remove_head_title(document)
    } else {
        document.to_string()
    };
    match document.find("</head>") {
        Some(at) => {
            let mut out = String::with_capacity(document.len() + head.len());
            out.push_str(&document[..at]);
            out.push_str(head);
            out.push_str(&document[at..]);
            out
        }
        None => format!("{head}{document}"),
    }
}

/// Render `robots.txt` for a site.
///
/// `disallow` names paths crawlers should skip; the framework's own
/// routes are always excluded because they are protocol, not content.
pub fn robots_txt(sitemap_url: Option<&str>, disallow: &[String]) -> String {
    let mut out = String::from("User-agent: *\n");
    for path in ["/_rsx/", "/_live/"] {
        out.push_str(&format!("Disallow: {path}\n"));
    }
    for path in disallow {
        // A newline in a path would forge a directive.
        if path.contains(['\n', '\r']) {
            continue;
        }
        out.push_str(&format!("Disallow: {path}\n"));
    }
    out.push_str("Allow: /\n");
    if let Some(url) = sitemap_url {
        // The same rule as a disallowed path: a newline here would
        // forge whatever directive followed it.
        if !url.contains(['\n', '\r']) {
            out.push_str(&format!("Sitemap: {url}\n"));
        }
    }
    out
}

/// Render `sitemap.xml` from a list of URLs.
///
/// Only STATIC routes can be listed: a dynamic pattern names a shape,
/// not a page, and inventing URLs for it would advertise pages that do
/// not exist.
pub fn sitemap_xml(base_url: &str, paths: &[String]) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    let base = base_url.trim_end_matches('/');
    for path in paths {
        out.push_str(&format!(
            "  <url><loc>{}</loc></url>\n",
            escape(&format!("{base}{path}"))
        ));
    }
    out.push_str("</urlset>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_head_renders_every_declared_value() {
        let head = Metadata::new()
            .title("Blog")
            .description("Posts about Rust")
            .canonical("https://example.com/blog")
            .robots("index,follow")
            .og("type", "website")
            .tag("theme-color", "#101010")
            .head()
            .into_string();
        assert!(head.contains("<title>Blog</title>"), "{head}");
        assert!(head.contains("name=\"description\" content=\"Posts about Rust\""));
        assert!(head.contains("property=\"og:type\" content=\"website\""));
        assert!(head.contains("name=\"theme-color\""));
        assert!(head.contains("rel=\"canonical\" href=\"https://example.com/blog\""));
        assert!(head.contains("name=\"robots\" content=\"index,follow\""));
    }

    #[test]
    fn a_title_cannot_close_its_own_element() {
        let head = Metadata::new()
            .title("</title><script>alert(1)</script>")
            .head()
            .into_string();
        assert!(!head.contains("<script>alert(1)"), "{head}");
        assert!(head.contains("&lt;/title&gt;"), "{head}");
    }

    #[test]
    fn json_ld_cannot_close_its_script_element() {
        let head = Metadata::new()
            .json_ld(&serde_json::json!({ "x": "</script><script>alert(1)</script>" }))
            .head()
            .into_string();
        assert!(head.contains("application/ld+json"), "{head}");
        assert!(!head.contains("</script><script>alert(1)"), "{head}");
        assert!(head.contains("\\u003c/script"), "{head}");
    }

    #[test]
    fn the_payload_head_carries_the_same_values() {
        let head = Metadata::new()
            .title("Blog")
            .description("Posts")
            .robots("noindex")
            .canonical("/blog")
            .og("image", "/cover.png")
            .payload_head();
        assert_eq!(head.title.as_deref(), Some("Blog"));
        assert!(head
            .meta
            .iter()
            .any(|m| m == &vec!["name".to_string(), "description".to_string(), "Posts".to_string()]));
        assert!(
            head.meta.iter().any(|m| m[1] == "robots" && m[2] == "noindex"),
            "a navigation must be able to change the robots directive: {:?}",
            head.meta
        );
        assert!(head.meta.iter().any(|m| m[1] == "og:image"));
        assert_eq!(head.links[0][0], "canonical");
    }

    #[test]
    fn head_injection_lands_inside_the_head() {
        let doc = "<html><head><meta charset=\"utf-8\"></head><body>x</body></html>";
        let out = inject_head(doc, "<title>T</title>");
        assert!(out.contains("<meta charset=\"utf-8\"><title>T</title></head>"), "{out}");
        // A fragment keeps its metadata rather than losing it.
        assert!(inject_head("<p>x</p>", "<title>T</title>").starts_with("<title>T</title>"));
        assert_eq!(inject_head(doc, ""), doc);
    }

    /// A browser uses the FIRST title, so appending a second would make
    /// the layout's fallback beat the page's declaration.
    #[test]
    fn a_declared_title_replaces_the_layouts_title() {
        let doc = "<html><head><title>Layout</title></head><body>x</body></html>";
        let out = inject_head(doc, "<title>Page</title>");
        assert_eq!(out.matches("<title>").count(), 1, "exactly one title: {out}");
        assert!(out.contains("<title>Page</title>"), "{out}");
        assert!(!out.contains("Layout"), "{out}");

        // Metadata WITHOUT a title leaves the layout's alone.
        let kept = inject_head(doc, "<meta name=\"robots\" content=\"noindex\">");
        assert!(kept.contains("<title>Layout</title>"), "{kept}");
        assert_eq!(kept.matches("<title>").count(), 1);
    }

    /// `<title>` is also a valid SVG element — it is how an icon gets an
    /// accessible name. Replacing the DOCUMENT title must never reach
    /// into the body and delete one.
    #[test]
    fn an_svg_title_in_the_body_survives_metadata_injection() {
        let doc = "<html><head><title>Layout</title></head>\
<body><svg><title>Play</title></svg></body></html>";
        let out = inject_head(doc, "<title>Page</title>");
        assert!(
            out.contains("<svg><title>Play</title></svg>"),
            "the accessible name is untouched: {out}"
        );
        assert!(out.contains("<title>Page</title></head>"), "{out}");
        assert!(!out.contains(">Layout<"), "{out}");

        // A document with NO head title and an SVG one keeps the SVG's.
        let no_head_title =
            "<html><head><meta charset=\"utf-8\"></head><body><svg><title>Play</title></svg></body></html>";
        let out = inject_head(no_head_title, "<title>Page</title>");
        assert!(out.contains("<svg><title>Play</title></svg>"), "{out}");
        assert!(out.contains("<title>Page</title></head>"), "{out}");
    }

    #[test]
    fn robots_excludes_the_framework_routes_and_refuses_forged_directives() {
        let txt = robots_txt(Some("https://example.com/sitemap.xml"), &["/admin".to_string()]);
        assert!(txt.contains("Disallow: /_rsx/"));
        assert!(txt.contains("Disallow: /_live/"));
        assert!(txt.contains("Disallow: /admin"));
        assert!(txt.contains("Sitemap: https://example.com/sitemap.xml"));

        let forged = robots_txt(None, &["/x\nAllow: /secret".to_string()]);
        assert!(
            !forged.contains("Allow: /secret"),
            "a newline in a path must not forge a directive: {forged}"
        );
        let forged_sitemap = robots_txt(Some("https://x/s.xml\nAllow: /secret"), &[]);
        assert!(
            !forged_sitemap.contains("Allow: /secret"),
            "nor in the sitemap URL: {forged_sitemap}"
        );
    }

    #[test]
    fn the_sitemap_lists_absolute_urls() {
        let xml = sitemap_xml(
            "https://example.com/",
            &["/".to_string(), "/blog".to_string()],
        );
        assert!(xml.contains("<loc>https://example.com/</loc>"), "{xml}");
        assert!(xml.contains("<loc>https://example.com/blog</loc>"), "{xml}");
        assert!(xml.starts_with("<?xml"));
    }
}
