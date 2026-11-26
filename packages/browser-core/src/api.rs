//! The top-level page API — the agent-facing façade over the pipeline.
//!
//! Mirrors the Kitesurf "quick action" surface: load HTML, then ask for a
//! screenshot, the extracted text, markdown, title, or serialized HTML.
//! Every operation is infallible: hostile input degrades, it never panics.

use crate::browser_core::cdp::resolve_url;
use crate::browser_core::css::{self, Stylesheet};
use crate::browser_core::dom::{Document, NodeId};
use crate::browser_core::extract;
use crate::browser_core::html;
use crate::browser_core::layout::{self, LayoutTree};
use crate::browser_core::paint;
use crate::browser_core::png;
use crate::browser_core::style;

/// Options for loading a page.
#[derive(Debug, Clone)]
pub struct PageOptions {
    /// Viewport width in CSS px (default 1280).
    pub viewport_width: f32,
    /// Viewport height in CSS px (default 720, the height the Chrome
    /// reference captures use). Layout does not depend on it; `@media`
    /// height features, `vh` units' reference and `<link media>` queries
    /// do.
    pub viewport_height: f32,
    /// Device scale factor for screenshots (default 1.0).
    pub scale: f32,
    /// Cap on the rasterized page height in CSS px (default 8192): a
    /// screenshot of an arbitrarily long page stays memory-bounded, the
    /// same cost-control trade Kitesurf makes. Extraction (text/markdown/
    /// html/links) always covers the full document regardless of this cap.
    pub max_screenshot_height: f32,
}

impl Default for PageOptions {
    fn default() -> Self {
        PageOptions {
            viewport_width: 1280.0,
            viewport_height: 720.0,
            scale: 1.0,
            max_screenshot_height: 8192.0,
        }
    }
}

/// A loaded page: parsed DOM, collected stylesheets, computed layout.
pub struct Page {
    pub doc: Document,
    pub stylesheets: Vec<Stylesheet>,
    pub layout: LayoutTree,
    styles: std::collections::HashMap<NodeId, style::ComputedStyle>,
    /// Render options (public so embedders can compute projected raster
    /// cost — scale, height cap — BEFORE asking for pixels).
    pub options: PageOptions,
}

impl Page {
    /// Parse and lay out an HTML document. Infallible.
    pub fn load(html_src: &str) -> Page {
        Page::load_with(html_src, PageOptions::default())
    }

    /// Parse and lay out with explicit options and extra author stylesheets
    /// (e.g. fetched `<link rel=stylesheet>` CSS supplied by the embedder,
    /// which owns network access). Extra sheets cascade after in-document
    /// `<style>` blocks, matching their source order after the inline ones.
    pub fn load_with_stylesheets(html_src: &str, options: PageOptions, extra_css: &[&str]) -> Page {
        let doc = html::parse(html_src);
        let env = media_env(&options);
        let mut stylesheets = collect_stylesheets(&doc, env);
        for src in extra_css {
            stylesheets.push(css::parse_stylesheet_with_env(src, env));
        }
        Page::finish(doc, stylesheets, options, &std::collections::HashMap::new())
    }

    /// Parse and lay out with explicit options.
    pub fn load_with(html_src: &str, options: PageOptions) -> Page {
        let doc = html::parse(html_src);
        let stylesheets = collect_stylesheets(&doc, media_env(&options));
        Page::finish(doc, stylesheets, options, &std::collections::HashMap::new())
    }

    /// Lay out an ALREADY-BUILT document — the path for JS-executed pages,
    /// where scripts have mutated the DOM before layout. Extra stylesheets
    /// and decoded images (keyed by raw `src` attribute value) come from the
    /// embedder, which owns network access.
    pub fn from_document(
        doc: Document,
        options: PageOptions,
        extra_css: &[&str],
        images: &std::collections::HashMap<
            String,
            std::rc::Rc<crate::browser_core::image::DecodedImage>,
        >,
    ) -> Page {
        let env = media_env(&options);
        let mut stylesheets = collect_stylesheets(&doc, env);
        for src in extra_css {
            stylesheets.push(css::parse_stylesheet_with_env(src, env));
        }
        Page::finish(doc, stylesheets, options, images)
    }

    /// Lay out an already-built document with the embedder's fetched
    /// `<link rel=stylesheet>` sheets cascading AT THEIR LINK'S POSITION
    /// among the document's own `<style>` blocks — the author-sheet order
    /// Chrome uses. [`Page::from_document`] appends every extra sheet after
    /// the inline blocks, which inverts the cascade on a page whose
    /// external sheet precedes an inline `<style>` (the Chrome-referenced
    /// corpus renders the same captured bytes Chrome did, so the order
    /// must match too).
    ///
    /// `sheets` is `(href, css)` in the order the embedder wants them
    /// cascaded: each `<link>`'s sheet preceded by the sheets it `@import`s.
    /// A link claims the first unclaimed entry whose `href` equals the
    /// link's `href` exactly (as written, or resolved against `base_url`);
    /// every unclaimed entry BEFORE it is taken as that link's imports.
    /// Entries no link claims cascade last, in their given order. When a
    /// link's own sheet is missing from `sheets` (a fetch that failed) the
    /// entries between it and the next claimed link cascade at the next
    /// link's position — still in document order relative to the links,
    /// but after any `<style>` block between the two.
    pub fn from_document_with_sheets(
        doc: Document,
        options: PageOptions,
        base_url: Option<&str>,
        sheets: &[(&str, &str)],
        images: &std::collections::HashMap<
            String,
            std::rc::Rc<crate::browser_core::image::DecodedImage>,
        >,
    ) -> Page {
        let env = media_env(&options);
        let stylesheets = collect_stylesheets_interleaved(&doc, base_url, sheets, env);
        Page::finish(doc, stylesheets, options, images)
    }

    fn finish(
        doc: Document,
        stylesheets: Vec<Stylesheet>,
        options: PageOptions,
        images: &std::collections::HashMap<
            String,
            std::rc::Rc<crate::browser_core::image::DecodedImage>,
        >,
    ) -> Page {
        let styles = style::compute_styles(&doc, &stylesheets);
        let layout = layout::layout_tree_with_images(&doc, &styles, options.viewport_width, images);
        Page {
            doc,
            stylesheets,
            layout,
            styles,
            options,
        }
    }

    /// The document title (empty string when absent).
    pub fn title(&self) -> String {
        self.doc
            .find_tag("title")
            .map(|t| normalize_ws(&self.doc.text_content(t)))
            .unwrap_or_default()
    }

    /// Visible text content, block-aware and CSS-aware, like Chrome's
    /// `innerText`: a subtree is excluded when it is `display: none`, when
    /// its text is `visibility: hidden` (a descendant may turn visibility
    /// back on, so this is per element, not per subtree), when its font
    /// size is zero, or when it is an `overflow: hidden` box with an
    /// explicit zero height (the collapsed mega-menu idiom). The corpus
    /// showed the engine extracting whole hidden navigations Chrome's
    /// `innerText` drops; those rules are what Chrome applies.
    pub fn text(&self) -> String {
        extract::text_with_visibility(
            &self.doc,
            &|n| self.is_css_hidden(n),
            &|n| {
                self.styles
                    .get(&n)
                    .map(|s| !s.visible || s.font_size < 0.5)
                    .unwrap_or(false)
            },
        )
    }

    fn is_css_hidden(&self, n: NodeId) -> bool {
        self.styles
            .get(&n)
            .map(|s| {
                s.display == style::Display::None
                    || (s.overflow_y_clips
                        && (matches!(s.height, style::Length::Px(h) if h <= 0.0)
                            || matches!(s.max_height, style::Length::Px(h) if h <= 0.0)))
                    || (s.overflow_x_clips
                        && matches!(s.width, style::Length::Px(w) if w <= 0.0))
            })
            .unwrap_or(false)
    }

    /// Markdown rendering of the document (headings, lists, links, tables).
    pub fn markdown(&self) -> String {
        extract::markdown(&self.doc)
    }

    /// Agent-grade ("clean") markdown: relative hrefs/srcs resolved against
    /// `page_url`, CSS-hidden subtrees excluded (the same `display:none` /
    /// clipped-overflow rules as [`Page::text`]), a `# title` + `> source:`
    /// front-matter header, and optional main-content isolation.
    pub fn markdown_clean(&self, page_url: Option<&str>, main_content: bool) -> String {
        let hidden = |n: NodeId| self.is_css_hidden(n);
        let title = self.title();
        let fm = page_url.map(|u| extract::FrontMatter {
            title: &title,
            url: u,
        });
        extract::markdown_with(
            &self.doc,
            &extract::MarkdownOptions {
                base_url: page_url,
                is_hidden: Some(&hidden),
                front_matter: fm,
                main_content,
            },
        )
    }

    /// Serialize the (parsed, normalized) DOM back to HTML.
    pub fn html(&self) -> String {
        extract::serialize_html(&self.doc, NodeId::DOCUMENT)
    }

    /// Rasterize the page and encode as PNG. The rendered height is capped
    /// at `options.max_screenshot_height` CSS px (Kitesurf-style cost
    /// control): agents almost never need a 100k-px-tall capture, and the
    /// cap keeps the pixel buffer bounded and predictable.
    ///
    /// MEMORY: the canvas (the single largest allocation of a screenshot
    /// request) is dropped BEFORE the PNG output vec is returned; peak is
    /// canvas + output only inside `png::encode`, and the canvas is freed
    /// the moment encoding finishes rather than living until the reply is
    /// serialized.
    pub fn screenshot_png(&self) -> Vec<u8> {
        let canvas = self.rasterize();
        let png = png::encode(canvas.width, canvas.height, &canvas.pixels);
        drop(canvas);
        png
    }

    /// The computed style of a node (default style when uncomputed).
    pub fn style_of(&self, node: NodeId) -> style::ComputedStyle {
        self.styles.get(&node).cloned().unwrap_or_default()
    }

    /// The first layout box belonging to `node`, if the node produced one.
    pub fn box_of(&self, node: NodeId) -> Option<&layout::LayoutBox> {
        self.layout.boxes.iter().find(|b| b.node == Some(node))
    }

    /// Rasterize and return the raw RGBA canvas (for tests/diffing),
    /// height-capped like [`Page::screenshot_png`].
    pub fn rasterize(&self) -> paint::Canvas {
        let mut tree = self.layout.clone();
        if tree.page_height > self.options.max_screenshot_height {
            tree.page_height = self.options.max_screenshot_height.max(1.0);
        }
        paint::rasterize_scaled(&tree, self.options.scale)
    }

    /// All links: href + visible text, in document order.
    pub fn links(&self) -> Vec<extract::Link> {
        extract::links(&self.doc)
    }
}

/// The media environment a render evaluates `@media` and `<link media>`
/// against: the page's own viewport width and height. Every author sheet
/// — inline, linked, or supplied by the embedder — parses against this
/// ONE environment, so a nested `@media (max-width: 600px)` block
/// resolves the same way on a 500 px render whichever sheet it sits in,
/// and a `(min-height: 900px)` block does not match a 720 px viewport.
fn media_env(options: &PageOptions) -> css::MediaEnv {
    css::MediaEnv {
        width: options.viewport_width,
        height: options.viewport_height,
    }
}

/// Gather `<style>` blocks (in document order), parsed against `env`.
/// `<link rel=stylesheet>` needs network access, which is the consumer
/// app's job: fetched CSS is supplied by the embedder via
/// [`Page::load_with_stylesheets`], or by using the lower-level pipeline
/// functions directly.
fn collect_stylesheets(doc: &Document, env: css::MediaEnv) -> Vec<Stylesheet> {
    let mut sheets = Vec::new();
    for n in doc.descendants(NodeId::DOCUMENT) {
        let Some(el) = doc.node(n).as_element() else {
            continue;
        };
        if el.tag == "style" {
            sheets.push(css::parse_stylesheet_with_env(&doc.text_content(n), env));
        }
    }
    sheets
}

/// The document's author sheets in cascade order: `<style>` blocks parsed in
/// place, and each `<link rel=stylesheet>` replaced by the fetched sheet
/// (plus its imports) the embedder supplied for it. See
/// [`Page::from_document_with_sheets`] for the matching rule.
fn collect_stylesheets_interleaved(
    doc: &Document,
    base_url: Option<&str>,
    linked: &[(&str, &str)],
    env: css::MediaEnv,
) -> Vec<Stylesheet> {
    let mut out = Vec::new();
    let mut next = 0usize;
    for n in doc.descendants(NodeId::DOCUMENT) {
        let Some(el) = doc.node(n).as_element() else {
            continue;
        };
        if el.tag == "style" {
            out.push(css::parse_stylesheet_with_env(&doc.text_content(n), env));
            continue;
        }
        let is_link = el.tag == "link"
            && el
                .attr("rel")
                .map(|r| r.split_whitespace().any(|w| w.eq_ignore_ascii_case("stylesheet")))
                .unwrap_or(false);
        if !is_link {
            continue;
        }
        let Some(href) = el.attr("href").map(str::trim).filter(|h| !h.is_empty()) else {
            continue;
        };
        // A `<link media=…>` whose query does not match the render's own
        // viewport (`media="print"` on 34 of the 1024 corpus sites, a
        // `(max-width: 600px)` sheet on a 1280 px render) does not apply:
        // its rules are consumed from the list but dropped, exactly as
        // Chrome leaves a non-matching link out of the screen cascade.
        // wetter.com's print sheet ends with `div, form, input, button,
        // select { display: none }`, which blanked the whole page when it
        // cascaded as screen CSS.
        let media_applies = el
            .attr("media")
            .map(|m| css::media_query_matches(m, env))
            .unwrap_or(true);
        let abs = base_url.and_then(|b| resolve_url(b, href));
        let Some(rest) = linked.get(next..) else {
            break;
        };
        // Exact matches only: a suffix guess would let `css/site.css` claim
        // another origin's `/css/site.css`.
        let claimed = rest
            .iter()
            .position(|(h, _)| *h == href || abs.as_deref() == Some(*h));
        if let Some(pos) = claimed {
            // The entries before this link's sheet are its @imports, placed
            // there by the embedder; they cascade ahead of it, here.
            if let Some(run) = rest.get(..=pos) {
                for (_, css_text) in run {
                    if media_applies {
                        out.push(css::parse_stylesheet_with_env(css_text, env));
                    }
                }
            }
            next = next.saturating_add(pos).saturating_add(1);
        }
    }
    if let Some(tail) = linked.get(next..) {
        for (_, css_text) in tail {
            out.push(css::parse_stylesheet_with_env(css_text, env));
        }
    }
    out
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_pipeline_smoke() {
        let page = Page::load(
            "<!DOCTYPE html><html><head><title>Hi  there</title>\
             <style>body { background: white; } h1 { color: red; }</style></head>\
             <body><h1>Hello</h1><p>World <a href=\"/x\">link</a></p></body></html>",
        );
        assert_eq!(page.title(), "Hi there");
        let text = page.text();
        assert!(text.contains("Hello") && text.contains("World"));
        assert_eq!(page.links().len(), 1);
        assert_eq!(page.links()[0].href, "/x");
        assert_eq!(page.links()[0].text, "link");
        let png = page.screenshot_png();
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert!(page.layout.page_height > 0.0);
    }

    #[test]
    fn linked_sheets_cascade_at_their_link_position() {
        // <link> before <style>: the inline block is later in source order,
        // so at equal specificity it wins — exactly what Chrome does, and the
        // inverse of appending the fetched sheet after every inline block.
        let doc = html::parse(
            "<head><link rel=stylesheet href=/a.css><style>p { color: #00ff00 }</style>\
             <link rel=stylesheet href=b.css></head><body><p id=p>x</p></body>",
        );
        let images = std::collections::HashMap::new();
        let page = Page::from_document_with_sheets(
            doc,
            PageOptions::default(),
            Some("https://s.test/dir/index.html"),
            &[
                // a.css's @import rides ahead of it; b.css is matched by its
                // base-resolved URL.
                ("https://s.test/imported.css", "p { margin: 0; font-weight: bold }"),
                ("https://s.test/a.css", "p { color: #ff0000 }"),
                ("https://s.test/dir/b.css", "p { font-size: 40px }"),
            ],
            &images,
        );
        let mut d = page.doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        let s = page.style_of(p);
        // a.css (red) lost to the later inline <style> (green) …
        assert_eq!(s.color, css::Color::rgb(0, 255, 0));
        // … while b.css, after the inline block, still applies, as does the
        // import that rode ahead of a.css.
        assert_eq!(s.font_size, 40.0);
        assert!(s.font_weight.is_bold());
        // The legacy path appends: the same sheets then beat the inline one.
        let doc = html::parse("<head><style>p { color: #00ff00 }</style></head><body><p id=p>x</p></body>");
        let page = Page::from_document(doc, PageOptions::default(), &["p { color: #ff0000 }"], &images);
        let mut d = page.doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        assert_eq!(page.style_of(p).color, css::Color::rgb(255, 0, 0));
        // An unmatched href claims nothing (no suffix guessing): the sheet
        // cascades last instead.
        let doc = html::parse(
            "<head><link rel=stylesheet href=css/site.css><style>p { color: #00ff00 }</style></head><body><p id=p>x</p></body>",
        );
        let page = Page::from_document_with_sheets(
            doc,
            PageOptions::default(),
            None,
            &[("https://other.test/css/site.css", "p { color: #ff0000 }")],
            &images,
        );
        let mut d = page.doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        assert_eq!(page.style_of(p).color, css::Color::rgb(255, 0, 0));
        // A `<link media=print>` sheet is left out of the screen cascade, and
        // a width query is judged against the PAGE's viewport, not a default.
        let doc = html::parse(
            "<head><link rel=stylesheet href=p.css media=print>\
             <link rel=stylesheet href=n.css media=\"(max-width: 600px)\">\
             <link rel=stylesheet href=w.css media=\"screen and (min-width: 400px)\"></head>\
             <body><p id=p>x</p></body>",
        );
        let page = Page::from_document_with_sheets(
            doc,
            PageOptions {
                viewport_width: 500.0,
                ..PageOptions::default()
            },
            None,
            &[
                ("p.css", "p { display: none }"),
                ("n.css", "p { color: #0000ff }"),
                ("w.css", "p { font-size: 33px }"),
            ],
            &images,
        );
        let mut d = page.doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        let s = page.style_of(p);
        assert_ne!(s.display, style::Display::None, "print sheet must not cascade");
        assert_eq!(s.color, css::Color::rgb(0, 0, 255), "500px viewport matches max-width: 600px");
        assert_eq!(s.font_size, 33.0);
    }

    #[test]
    fn media_queries_use_the_render_viewport_height_in_every_sheet() {
        // A height feature inside an INLINE block, a LINKED sheet and an
        // embedder-supplied sheet all resolve against the PageOptions
        // height, not the default environment's: a 900 px `min-height`
        // matches a 1000 px render and not a 720 px one.
        let src = "<head><style>@media (min-height: 900px) { p { color: #ff0000 } }</style>\
             <link rel=stylesheet href=h.css></head><body><p id=p>x</p></body>";
        let images = std::collections::HashMap::new();
        let tall = PageOptions {
            viewport_height: 1000.0,
            ..PageOptions::default()
        };
        let page = Page::from_document_with_sheets(
            html::parse(src),
            tall.clone(),
            None,
            &[("h.css", "@media (min-height: 900px) { p { font-size: 44px } }")],
            &images,
        );
        let mut d = page.doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        let s = page.style_of(p);
        assert_eq!(s.color, css::Color::rgb(255, 0, 0), "inline @media height matches a 1000px render");
        assert_eq!(s.font_size, 44.0, "linked @media height matches a 1000px render");
        let page = Page::from_document_with_sheets(
            html::parse(src),
            PageOptions::default(),
            None,
            &[("h.css", "@media (min-height: 900px) { p { font-size: 44px } }")],
            &images,
        );
        let mut d = page.doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        let s = page.style_of(p);
        assert_ne!(s.color, css::Color::rgb(255, 0, 0), "720px render must not match min-height: 900px");
        assert_ne!(s.font_size, 44.0);
        // The embedder-supplied path (`load_with_stylesheets`) sees the
        // same environment.
        let page = Page::load_with_stylesheets(
            "<body><p id=p>x</p></body>",
            tall,
            &["@media (max-height: 800px) { p { display: none } }"],
        );
        let mut d = page.doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        assert_ne!(page.style_of(p).display, style::Display::None, "1000px render is not max-height: 800px");
    }

    #[test]
    fn hostile_input_never_panics() {
        for garbage in [
            "",
            "<",
            "</",
            "<!--",
            "<div",
            "<a href='",
            "\u{0}\u{fffd}<b><i></b></i>",
            "<table><tr><td><table>",
            "<style>@media {</style>",
        ] {
            let page = Page::load(garbage);
            let _ = page.text();
            let _ = page.markdown();
            let _ = page.html();
            let _ = page.screenshot_png();
        }
    }
}
