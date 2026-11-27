//! HTML serialisation of a [`Document`] tree.
//!
//! Text is escaped (`&`, `<`, `>`) everywhere except directly inside
//! `script` and `style`, whose content HTML reads as raw text. Attribute
//! values are escaped the same way and additionally for `"`, and every
//! attribute is written double-quoted. Void elements are written without an
//! end tag and without their children.

use super::tree::{Document, NodeData, NodeId};

/// Elements that never have children (WHATWG "void elements").
pub const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// True when `tag` names a void element. The tag is compared as written, so
/// a caller passes the lowercase name an HTML tree stores.
pub fn is_void(tag: &str) -> bool {
    VOID_ELEMENTS.contains(&tag)
}

/// Serialize a subtree back to HTML (like `outerHTML` of the root's children).
pub fn serialize_html(doc: &Document, root: NodeId) -> String {
    let mut out = String::new();
    serialize_children(doc, root, &mut out);
    out
}

/// `innerHTML` view of a node: its children serialized, without the node's
/// own tag.
pub fn inner_html(doc: &Document, node: NodeId) -> String {
    let mut out = String::new();
    serialize_children(doc, node, &mut out);
    out
}

/// `outerHTML` view of a node: the node itself serialized, tag included.
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

    fn element(doc: &mut Document, parent: NodeId, tag: &str) -> NodeId {
        let node = doc.create_element(tag);
        doc.append_child(parent, node);
        node
    }

    fn text(doc: &mut Document, parent: NodeId, value: &str) {
        let node = doc.create_text(value);
        doc.append_child(parent, node);
    }

    #[test]
    fn text_and_attribute_values_are_escaped() {
        let mut doc = Document::new();
        let p = element(&mut doc, NodeId::DOCUMENT, "p");
        doc.set_attr(p, "title", "a \"quoted\" <b> & more");
        text(&mut doc, p, "1 < 2 & 3 > 2 <img src=x onerror=alert(1)>");
        assert_eq!(
            serialize_html(&doc, NodeId::DOCUMENT),
            "<p title=\"a &quot;quoted&quot; &lt;b&gt; &amp; more\">\
             1 &lt; 2 &amp; 3 &gt; 2 &lt;img src=x onerror=alert(1)&gt;</p>"
        );
    }

    #[test]
    fn void_elements_take_no_end_tag() {
        let mut doc = Document::new();
        let body = element(&mut doc, NodeId::DOCUMENT, "body");
        let br = element(&mut doc, body, "br");
        // A child the tree allows but HTML does not is left out.
        text(&mut doc, br, "ignored");
        let meta = element(&mut doc, body, "meta");
        doc.set_attr(meta, "charset", "utf-8");
        assert_eq!(
            serialize_html(&doc, NodeId::DOCUMENT),
            "<body><br><meta charset=\"utf-8\"></body>"
        );
        assert!(is_void("img") && !is_void("p"));
    }

    #[test]
    fn script_and_style_text_is_written_raw() {
        let mut doc = Document::new();
        let style = element(&mut doc, NodeId::DOCUMENT, "style");
        text(&mut doc, style, "a > b { color: red }");
        let script = element(&mut doc, NodeId::DOCUMENT, "script");
        text(&mut doc, script, "if (a < b && c) {}");
        assert_eq!(
            serialize_html(&doc, NodeId::DOCUMENT),
            "<style>a > b { color: red }</style><script>if (a < b && c) {}</script>"
        );
    }

    #[test]
    fn doctype_and_comment_nodes_are_written() {
        let mut doc = Document::new();
        let doctype = doc.create_node(NodeData::Doctype {
            name: "html".into(),
        });
        doc.append_child(NodeId::DOCUMENT, doctype);
        let comment = doc.create_node(NodeData::Comment(" note ".into()));
        doc.append_child(NodeId::DOCUMENT, comment);
        assert_eq!(
            serialize_html(&doc, NodeId::DOCUMENT),
            "<!DOCTYPE html><!-- note -->"
        );
    }

    #[test]
    fn inner_and_outer_views_differ_by_the_node_itself() {
        let mut doc = Document::new();
        let div = element(&mut doc, NodeId::DOCUMENT, "div");
        let span = element(&mut doc, div, "span");
        text(&mut doc, span, "x");
        assert_eq!(inner_html(&doc, div), "<span>x</span>");
        assert_eq!(outer_html(&doc, div), "<div><span>x</span></div>");
        assert_eq!(serialize_html(&doc, div), inner_html(&doc, div));
    }
}
