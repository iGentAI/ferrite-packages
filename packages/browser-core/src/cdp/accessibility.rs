//! The Accessibility domain: the full accessibility tree.

use super::super::dom::Document;
use super::super::dom::NodeId;
use super::{CdpBrowser, CdpCommand, CdpError, JsonValue, method_not_found, node_to_cdp};

impl CdpBrowser {
    pub(super) fn accessibility_command(
        &mut self,
        cmd: &CdpCommand,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Accessibility.enable" | "Accessibility.disable" => Ok(JsonValue::obj(vec![])),
            "Accessibility.getFullAXTree" => {
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                let mut nodes: Vec<JsonValue> = Vec::new();
                for n in doc.descendants(NodeId::DOCUMENT) {
                    let Some(el) = doc.get(n).and_then(|x| x.as_element()) else {
                        continue;
                    };
                    let role = ax_role(el);
                    if role.is_empty() {
                        continue;
                    }
                    let name = ax_name(&doc, n, el);
                    nodes.push(JsonValue::obj(vec![
                        ("nodeId", JsonValue::str(format!("ax-{}", n.index()))),
                        ("backendDOMNodeId", JsonValue::Num(node_to_cdp(n))),
                        ("ignored", JsonValue::Bool(false)),
                        (
                            "role",
                            JsonValue::obj(vec![
                                ("type", JsonValue::str("role")),
                                ("value", JsonValue::str(role)),
                            ]),
                        ),
                        (
                            "name",
                            JsonValue::obj(vec![
                                ("type", JsonValue::str("computedString")),
                                ("value", JsonValue::str(name)),
                            ]),
                        ),
                    ]));
                }
                Ok(JsonValue::obj(vec![("nodes", JsonValue::Arr(nodes))]))
            }
            other => Err(method_not_found(other)),
        }
    }
}

/// The computed accessibility role for an element (HTML-AAM defaults).
fn ax_role(el: &super::super::dom::ElementData) -> &'static str {
    match el.tag.as_str() {
        "a" => {
            if el.attr("href").is_some() {
                "link"
            } else {
                "generic"
            }
        }
        "button" => "button",
        "input" => match el.attr("type").unwrap_or("text").to_ascii_lowercase().as_str() {
            "button" | "submit" | "reset" | "image" => "button",
            "checkbox" => "checkbox",
            "radio" => "radio",
            "range" => "slider",
            "hidden" => "",
            _ => "textbox",
        },
        "textarea" => "textbox",
        "select" => "combobox",
        "option" => "option",
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => "heading",
        "img" => "image",
        "ul" | "ol" => "list",
        "li" => "listitem",
        "table" => "table",
        "tr" => "row",
        "td" | "th" => "cell",
        "form" => "form",
        "nav" => "navigation",
        "main" => "main",
        "header" => "banner",
        "footer" => "contentinfo",
        "aside" => "complementary",
        "p" => "paragraph",
        "label" => "generic",
        "div" | "span" | "body" | "html" | "section" | "article" => "generic",
        _ => "",
    }
}

/// The accessible name: aria-label, alt, value/placeholder, or visible text.
fn ax_name(doc: &Document, n: NodeId, el: &super::super::dom::ElementData) -> String {
    if let Some(label) = el.attr("aria-label") {
        return label.to_string();
    }
    if let Some(alt) = el.attr("alt") {
        return alt.to_string();
    }
    if el.tag == "input" {
        if let Some(v) = el.attr("value").or_else(|| el.attr("placeholder")) {
            return v.to_string();
        }
    }
    let text = doc.text_content(n);
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(128).collect()
}
