//! Reads and writes of DOM properties, including style and dataset facets.

use std::rc::Rc;
use super::super::interp::Interp;
use super::super::super::dom::Document;
use super::super::super::dom::NodeData;
use super::super::super::dom::NodeId;
use super::super::super::html;
use super::super::value::Facet;
use super::super::value::JsObject;
use super::super::value::JsValue;
use super::super::value::NativeFn;
use super::super::value::ObjKind;
use super::super::value::ObjRef;
use super::{define_method, dom_list, node_id, wrap_node};
use super::scripts::{backward_node};

/// Read a DOM-backed property. Returns None when `key` is not DOM-special
/// (caller falls back to ordinary object properties).
pub fn get_dom_property(
    interp: &mut Interp,
    handle: usize,
    key: &str,
) -> Result<Option<JsValue>, JsValue> {
    let Some(dom_rc) = interp.dom.clone() else {
        return Ok(None);
    };
    let id = node_id(handle);
    let out = match key {
        "tagName" | "nodeName" => {
            let doc = dom_rc.borrow();
            doc.get(id)
                .and_then(|n| n.as_element().map(|e| e.tag.to_uppercase()))
                .map(JsValue::str)
        }
        "id" => {
            let doc = dom_rc.borrow();
            Some(JsValue::str(
                doc.get(id)
                    .and_then(|n| n.as_element().and_then(|e| e.attr("id")))
                    .unwrap_or("")
                    .to_string(),
            ))
        }
        "className" => {
            let doc = dom_rc.borrow();
            Some(JsValue::str(
                doc.get(id)
                    .and_then(|n| n.as_element().and_then(|e| e.attr("class")))
                    .unwrap_or("")
                    .to_string(),
            ))
        }
        "textContent" | "innerText" => {
            let doc = dom_rc.borrow();
            Some(JsValue::str(collect_text(&doc, id)))
        }
        "innerHTML" => {
            let doc = dom_rc.borrow();
            Some(JsValue::str(super::super::super::extract::inner_html(&doc, id)))
        }
        "outerHTML" => {
            let doc = dom_rc.borrow();
            Some(JsValue::str(super::super::super::extract::outer_html(&doc, id)))
        }
        "value" => {
            let doc = dom_rc.borrow();
            let el = doc.get(id).and_then(|n| n.as_element());
            // A <textarea>'s value is its text content; form controls read
            // the `value` attribute (which input/insertText writes).
            if el.map(|e| e.tag == "textarea").unwrap_or(false) && el.and_then(|e| e.attr("value")).is_none() {
                return Ok(Some(JsValue::str(collect_text(&doc, id))));
            }
            el.and_then(|e| e.attr("value"))
                .map(|v| JsValue::str(v.to_string()))
                .or(Some(JsValue::str(String::new())))
        }
        "checked" | "disabled" | "selected" | "readOnly" | "required" | "hidden" => {
            let doc = dom_rc.borrow();
            let attr = if key == "readOnly" { "readonly" } else { key };
            Some(JsValue::Bool(
                doc.get(id)
                    .and_then(|n| n.as_element().map(|e| e.attr(attr).is_some()))
                    .unwrap_or(false),
            ))
        }
        "title" if handle == 0 => {
            // `document.title`: the <title> text, whitespace-collapsed.
            let doc = dom_rc.borrow();
            Some(JsValue::str(
                doc.find_tag("title")
                    .map(|t| {
                        doc.text_content(t)
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default(),
            ))
        }
        "href" | "src" | "name" | "type" | "placeholder" | "action" | "method" | "alt"
        | "title" | "role" | "lang" | "target" | "rel" | "htmlFor" | "tabIndex" => {
            let doc = dom_rc.borrow();
            let Some(el) = doc.get(id).and_then(|n| n.as_element()) else {
                return Ok(None);
            };
            let attr = match key {
                "htmlFor" => "for",
                "tabIndex" => "tabindex",
                other => other,
            };
            if key == "tabIndex" {
                return Ok(Some(JsValue::Num(
                    el.attr(attr).and_then(|v| v.trim().parse::<f64>().ok()).unwrap_or(-1.0),
                )));
            }
            if key == "type" && el.tag == "input" {
                return Ok(Some(JsValue::str(
                    el.attr("type").unwrap_or("text").to_ascii_lowercase(),
                )));
            }
            Some(JsValue::str(el.attr(attr).unwrap_or("").to_string()))
        }
        "classList" => {
            let handle_c = handle;
            let list = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            let classes: Vec<String> = {
                let doc = dom_rc.borrow();
                doc.get(id)
                    .and_then(|n| n.as_element())
                    .map(|e| e.classes().map(str::to_string).collect())
                    .unwrap_or_default()
            };
            list.borrow_mut()
                .set_prop("length", JsValue::Num(classes.len() as f64), false);
            let add: NativeFn = Rc::new(move |interp, _this, args| {
                mutate_classes(interp, handle_c, |set| {
                    for a in args {
                        let c = a.to_js_string();
                        if !c.is_empty() && !set.contains(&c) {
                            set.push(c);
                        }
                    }
                    false
                })
            });
            define_method(interp, &list, "add", add);
            let remove: NativeFn = Rc::new(move |interp, _this, args| {
                mutate_classes(interp, handle_c, |set| {
                    for a in args {
                        let c = a.to_js_string();
                        set.retain(|x| x != &c);
                    }
                    false
                })
            });
            define_method(interp, &list, "remove", remove);
            let toggle: NativeFn = Rc::new(move |interp, _this, args| {
                let c = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                let force = args.get(1).map(|v| v.truthy());
                mutate_classes(interp, handle_c, |set| {
                    let has = set.contains(&c);
                    let want = force.unwrap_or(!has);
                    if want && !has {
                        set.push(c.clone());
                    } else if !want && has {
                        set.retain(|x| x != &c);
                    }
                    want
                })
            });
            define_method(interp, &list, "toggle", toggle);
            let contains: NativeFn = Rc::new(move |interp, _this, args| {
                let c = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                let Some(dom) = interp.dom.clone() else {
                    return Ok(JsValue::Bool(false));
                };
                let doc = dom.borrow();
                Ok(JsValue::Bool(
                    doc.get(node_id(handle_c))
                        .and_then(|n| n.as_element().map(|e| e.has_class(&c)))
                        .unwrap_or(false),
                ))
            });
            define_method(interp, &list, "contains", contains);
            Some(JsValue::Object(list))
        }
        "dataset" => {
            // A LIVE facet: reads walk the `data-*` attributes, writes land
            // on them (`el.dataset.foo = 1` is `data-foo="1"`).
            let obj = JsObject::new(
                ObjKind::DomFacet {
                    handle,
                    facet: Facet::Dataset,
                },
                Some(interp.object_proto.clone()),
            );
            Some(JsValue::Object(obj))
        }
        "activeElement" => {
            // Only meaningful on `document`; other nodes fall through.
            if handle != 0 {
                return Ok(None);
            }
            let focused = interp.focused;
            Some(match focused {
                Some(h) => wrap_node(interp, h),
                None => {
                    let body = dom_rc.borrow().find_tag("body");
                    match body {
                        Some(b) => wrap_node(interp, b.index()),
                        None => JsValue::Null,
                    }
                }
            })
        }
        "ownerDocument" => Some(wrap_node(interp, 0)),
        "lastChild" | "lastElementChild" => {
            let doc = dom_rc.borrow();
            let cur = backward_node(
                &doc,
                doc.get(id).and_then(|n| n.last_child),
                key == "lastElementChild",
            );
            drop(doc);
            Some(match cur {
                Some(c) => wrap_node(interp, c.index()),
                None => JsValue::Null,
            })
        }
        "previousSibling" | "previousElementSibling" => {
            let doc = dom_rc.borrow();
            let cur = backward_node(
                &doc,
                doc.get(id).and_then(|n| n.prev_sibling),
                key == "previousElementSibling",
            );
            drop(doc);
            Some(match cur {
                Some(c) => wrap_node(interp, c.index()),
                None => JsValue::Null,
            })
        }
        "childElementCount" => {
            let doc = dom_rc.borrow();
            let n = doc
                .children(id)
                .filter(|c| matches!(doc.get(*c).map(|n| &n.data), Some(NodeData::Element(_))))
                .count();
            Some(JsValue::Num(n as f64))
        }
        "nodeValue" | "data" => {
            let doc = dom_rc.borrow();
            Some(match doc.get(id).map(|n| &n.data) {
                Some(NodeData::Text(t)) => JsValue::str(t.clone()),
                Some(NodeData::Comment(c)) => JsValue::str(c.clone()),
                _ => JsValue::Null,
            })
        }
        "localName" => {
            let doc = dom_rc.borrow();
            doc.get(id)
                .and_then(|n| n.as_element().map(|e| e.tag.clone()))
                .map(JsValue::str)
        }
        "attributes" => {
            // A NamedNodeMap: the Attr nodes by index AND by name
            // (`el.attributes.onsubmit`, `el.attributes["data-x"]`), each
            // carrying `specified` and `expando` the way Chrome's Attr does
            // (jQuery 1.x's event-bubbling probe reads
            // `d.attributes[c].expando === false`).
            let doc = dom_rc.borrow();
            let mut items = Vec::new();
            let mut named: Vec<(String, JsValue)> = Vec::new();
            if let Some(el) = doc.get(id).and_then(|n| n.as_element()) {
                for (k, v) in &el.attrs {
                    let a = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                    {
                        let mut b = a.borrow_mut();
                        b.class_name = "Attr";
                        b.set_prop("name", JsValue::str(k.clone()), true);
                        b.set_prop("localName", JsValue::str(k.clone()), true);
                        b.set_prop("nodeName", JsValue::str(k.clone()), true);
                        b.set_prop("value", JsValue::str(v.clone()), true);
                        b.set_prop("nodeValue", JsValue::str(v.clone()), true);
                        b.set_prop("nodeType", JsValue::Num(2.0), true);
                        b.set_prop("specified", JsValue::Bool(true), true);
                        b.set_prop("expando", JsValue::Bool(false), true);
                    }
                    let av = JsValue::Object(a);
                    named.push((k.clone(), av.clone()));
                    items.push(av);
                }
            }
            drop(doc);
            let arr = interp.new_array(items);
            if let JsValue::Object(ao) = &arr {
                let mut b = ao.borrow_mut();
                b.class_name = "NamedNodeMap";
                for (k, v) in named {
                    // Name keys are non-enumerable so `for...in` and
                    // `Array.from` see the indices only.
                    if b.own(&k).is_none() {
                        b.set_prop(&k, v, false);
                    }
                }
            }
            let get_named: NativeFn = Rc::new(|interp, this, args| {
                let k = args.first().map(|v| v.to_js_string()).unwrap_or_default().to_ascii_lowercase();
                let v = interp.get_property(&this, &k)?;
                Ok(if v.is_nullish() { JsValue::Null } else { v })
            });
            if let JsValue::Object(ao) = &arr {
                define_method(interp, ao, "getNamedItem", get_named.clone());
                let item: NativeFn = Rc::new(|interp, this, args| {
                    let i = interp.number_arg(args.first(), f64::NAN)?;
                    if !i.is_finite() || i < 0.0 {
                        return Ok(JsValue::Null);
                    }
                    let v = interp.get_property(&this, &(i as usize).to_string())?;
                    Ok(if v.is_nullish() { JsValue::Null } else { v })
                });
                define_method(interp, ao, "item", item);
            }
            Some(arr)
        }
        "URL" | "documentURI" => {
            if handle != 0 {
                return Ok(None);
            }
            let href = interp
                .global_object
                .borrow()
                .get_prop("location")
                .and_then(|l| match l {
                    JsValue::Object(o) => o.borrow().get_prop("href"),
                    _ => None,
                })
                .unwrap_or(JsValue::str("about:blank"));
            Some(href)
        }
        "location" => {
            // `document.location` IS `window.location` (the same object):
            // `document.location.protocol` / `.hostname` / `.href` are how
            // analytics loaders and legacy pages read the page URL.
            if handle != 0 {
                return Ok(None);
            }
            interp.global_object.borrow().get_prop("location")
        }
        "parentNode" | "parentElement" => {
            let parent = dom_rc.borrow().get(id).and_then(|n| n.parent);
            Some(match parent {
                Some(p) => wrap_node(interp, p.index()),
                None => JsValue::Null,
            })
        }
        "children" | "childNodes" => {
            let doc = dom_rc.borrow();
            let elements_only = key == "children";
            let mut out = Vec::new();
            let mut cur = doc.get(id).and_then(|n| n.first_child);
            while let Some(c) = cur {
                let keep = match doc.get(c).map(|n| &n.data) {
                    Some(NodeData::Element(_)) => true,
                    Some(NodeData::Text(_)) | Some(NodeData::Comment(_)) => !elements_only,
                    _ => false,
                };
                if keep {
                    out.push(c.index());
                }
                cur = doc.get(c).and_then(|n| n.next_sibling);
            }
            drop(doc);
            Some(dom_list(interp, out))
        }
        "firstChild" | "firstElementChild" => {
            let doc = dom_rc.borrow();
            let mut cur = doc.get(id).and_then(|n| n.first_child);
            if key == "firstElementChild" {
                while let Some(c) = cur {
                    if matches!(doc.get(c).map(|n| &n.data), Some(NodeData::Element(_))) {
                        break;
                    }
                    cur = doc.get(c).and_then(|n| n.next_sibling);
                }
            }
            drop(doc);
            Some(match cur {
                Some(c) => wrap_node(interp, c.index()),
                None => JsValue::Null,
            })
        }
        "nextSibling" | "nextElementSibling" => {
            let doc = dom_rc.borrow();
            let mut cur = doc.get(id).and_then(|n| n.next_sibling);
            if key == "nextElementSibling" {
                while let Some(c) = cur {
                    if matches!(doc.get(c).map(|n| &n.data), Some(NodeData::Element(_))) {
                        break;
                    }
                    cur = doc.get(c).and_then(|n| n.next_sibling);
                }
            }
            Some(match cur {
                Some(c) => wrap_node(interp, c.index()),
                None => JsValue::Null,
            })
        }
        "style" => {
            // A LIVE `CSSStyleDeclaration` facet over the `style` attribute:
            // `el.style.color = "red"` rewrites the attribute, `el.style
            // .color` parses it, `cssText` round-trips the whole string, and
            // `setProperty` / `getPropertyValue` / `removeProperty` take the
            // hyphenated names. jQuery's `.css()` and every framework's
            // inline-style binding write through here.
            let obj = JsObject::new(
                ObjKind::DomFacet {
                    handle,
                    facet: Facet::Style,
                },
                Some(interp.object_proto.clone()),
            );
            let set_property: NativeFn = Rc::new(move |interp, _this, args| {
                let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                let value = args.get(1).map(|v| v.to_js_string()).unwrap_or_default();
                style_write(interp, handle, name.trim(), &value);
                Ok(JsValue::Undefined)
            });
            define_method(interp, &obj, "setProperty", set_property);
            let remove_property: NativeFn = Rc::new(move |interp, _this, args| {
                let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                let old = style_read(interp, handle, name.trim());
                style_write(interp, handle, name.trim(), "");
                Ok(JsValue::str(old))
            });
            define_method(interp, &obj, "removeProperty", remove_property);
            let get_property_value: NativeFn = Rc::new(move |interp, _this, args| {
                let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                Ok(JsValue::str(style_read(interp, handle, name.trim())))
            });
            define_method(interp, &obj, "getPropertyValue", get_property_value);
            let get_priority: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::str("")));
            define_method(interp, &obj, "getPropertyPriority", get_priority);
            Some(JsValue::Object(obj))
        }
        "nodeType" => {
            let doc = dom_rc.borrow();
            Some(JsValue::Num(match doc.get(id).map(|n| &n.data) {
                Some(NodeData::Element(_)) => 1.0,
                Some(NodeData::Text(_)) => 3.0,
                Some(NodeData::Comment(_)) => 8.0,
                Some(NodeData::Document) => 9.0,
                _ => 0.0,
            }))
        }
        "body" | "head" | "documentElement" => {
            // Resolved against the RECEIVER's root, not the page: a scratch
            // document from `document.implementation.createHTMLDocument()`
            // lives detached in the same arena, and jQuery's feature tests
            // write `<form></form>` into ITS body. Resolving through the page
            // root would wipe the real page's body instead.
            let doc = dom_rc.borrow();
            let mut root = id;
            while let Some(p) = doc.get(root).and_then(|n| n.parent) {
                root = p;
            }
            let tag_under = |root: NodeId, tag: &str| -> Option<NodeId> {
                if root == NodeId::DOCUMENT {
                    return doc.find_tag(tag);
                }
                doc.descendants(root)
                    .find(|n| doc.get(*n).and_then(|x| x.as_element()).map(|e| e.tag == tag).unwrap_or(false))
            };
            let found = match key {
                "body" => tag_under(root, "body"),
                "head" => tag_under(root, "head"),
                _ => {
                    if root == NodeId::DOCUMENT {
                        doc.document_element()
                    } else {
                        doc.children(root)
                            .find(|c| doc.get(*c).and_then(|n| n.as_element()).is_some())
                    }
                }
            };
            drop(doc);
            Some(match found {
                Some(n) => wrap_node(interp, n.index()),
                None => JsValue::Null,
            })
        }
        _ => None,
    };
    Ok(out)
}

/// Write a DOM-backed property. Returns Ok(true) when the write was handled.
pub fn set_dom_property(
    interp: &mut Interp,
    obj: &ObjRef,
    key: &str,
    value: &JsValue,
) -> Result<bool, JsValue> {
    let handle = match &obj.borrow().kind {
        ObjKind::DomNode(h) => *h,
        _ => return Ok(false),
    };
    let Some(dom_rc) = interp.dom.clone() else {
        return Ok(false);
    };
    let id = node_id(handle);
    match key {
        "textContent" | "innerText" => {
            let text = value.to_js_string();
            let mut doc = dom_rc.borrow_mut();
            doc.remove_children(id);
            let t = doc.create_text(&text);
            doc.append_child(id, t);
            Ok(true)
        }
        "innerHTML" => {
            let src = value.to_js_string();
            let mut doc = dom_rc.borrow_mut();
            doc.remove_children(id);
            html::parse_fragment_into(&mut doc, id, &src);
            Ok(true)
        }
        "id" | "className" | "value" | "href" | "src" | "name" | "type" | "placeholder"
        | "action" | "method" | "alt" | "title" | "role" | "htmlFor" | "tabIndex" => {
            let attr = match key {
                "className" => "class",
                "htmlFor" => "for",
                "tabIndex" => "tabindex",
                other => other,
            };
            let v = value.to_js_string();
            let mut doc = dom_rc.borrow_mut();
            if key == "title" && !matches!(doc.get(id).map(|n| &n.data), Some(NodeData::Element(_))) {
                // document.title = "..." writes the <title> text.
                let title = match doc.find_tag("title") {
                    Some(t) => t,
                    None => {
                        let head = doc.find_tag("head").unwrap_or(NodeId::DOCUMENT);
                        let t = doc.create_element("title");
                        doc.append_child(head, t);
                        t
                    }
                };
                doc.remove_children(title);
                let text = doc.create_text(&v);
                doc.append_child(title, text);
                return Ok(true);
            }
            doc.set_attr(id, attr, &v);
            Ok(true)
        }
        "checked" | "disabled" | "selected" | "readOnly" | "required" | "hidden" => {
            let attr = if key == "readOnly" { "readonly" } else { key };
            let mut doc = dom_rc.borrow_mut();
            if value.truthy() {
                doc.set_attr(id, attr, "");
            } else if let Some(NodeData::Element(e)) = doc.get(id).map(|n| &n.data).cloned() {
                let mut e = e;
                e.attrs.retain(|(n, _)| n != attr);
                doc.node_mut(id).data = NodeData::Element(e);
            }
            Ok(true)
        }
        "nodeValue" | "data" => {
            let v = value.to_js_string();
            let mut doc = dom_rc.borrow_mut();
            match &mut doc.node_mut(id).data {
                NodeData::Text(t) => *t = v,
                NodeData::Comment(c) => *c = v,
                _ => {}
            }
            Ok(true)
        }
        _ if key.starts_with("on") && key.len() > 2 => {
            // `el.onclick = fn` — a single replaceable handler slot, fired
            // before addEventListener callbacks at the same node.
            let event = key.get(2..).unwrap_or("").to_string();
            let slot = (handle, format!("__on:{event}"));
            match value {
                JsValue::Object(_) => {
                    interp.node_listeners.insert(slot, vec![value.clone()]);
                }
                _ => {
                    interp.node_listeners.remove(&slot);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Apply `f` to the element's class list, writing the result back to the
/// `class` attribute; returns `f`'s boolean as a JS value.
fn mutate_classes(
    interp: &mut Interp,
    handle: usize,
    f: impl FnOnce(&mut Vec<String>) -> bool,
) -> Result<JsValue, JsValue> {
    let Some(dom) = interp.dom.clone() else {
        return Ok(JsValue::Bool(false));
    };
    let mut doc = dom.borrow_mut();
    let id = node_id(handle);
    let mut set: Vec<String> = doc
        .get(id)
        .and_then(|n| n.as_element())
        .map(|e| e.classes().map(str::to_string).collect())
        .unwrap_or_default();
    let out = f(&mut set);
    if doc.get(id).and_then(|n| n.as_element()).is_some() {
        doc.set_attr(id, "class", &set.join(" "));
    }
    Ok(JsValue::Bool(out))
}

/// Whether `el` matches any selector in `sel` (element.matches semantics).
/// An invalid selector list is a `SyntaxError`, as in Chrome.
pub(super) fn element_matches(doc: &Document, el: NodeId, sel: &str) -> Result<bool, JsValue> {
    let sels = super::super::super::css::parse_selector_list_strict(sel)
        .map_err(|m| Interp::throw(format!("SyntaxError: {m}")))?;
    Ok(sels
        .iter()
        .any(|s| super::super::super::css::matches_scoped(doc, el, s, Some(el))))
}

/// Whole-subtree text (like `textContent`).
pub(super) fn collect_text(doc: &Document, id: NodeId) -> String {
    let mut out = String::new();
    collect_text_into(doc, id, &mut out);
    out
}

fn collect_text_into(doc: &Document, id: NodeId, out: &mut String) {
    if let Some(t) = doc.get(id).and_then(|n| n.as_text()) {
        out.push_str(t);
    }
    let mut cur = doc.get(id).and_then(|n| n.first_child);
    while let Some(c) = cur {
        collect_text_into(doc, c, out);
        cur = doc.get(c).and_then(|n| n.next_sibling);
    }
}

/// The inline `style` attribute of `handle` as (name, value) declarations
/// in source order (hyphenated names, trimmed values).
fn style_decls(interp: &Interp, handle: usize) -> Vec<(String, String)> {
    let Some(dom) = interp.dom.clone() else {
        return Vec::new();
    };
    let doc = dom.borrow();
    let Some(style) = doc
        .get(node_id(handle))
        .and_then(|n| n.as_element().and_then(|e| e.attr("style")))
    else {
        return Vec::new();
    };
    super::super::super::css::parse_declarations(style)
        .into_iter()
        .map(|d| {
            let v = if d.important {
                format!("{} !important", d.value)
            } else {
                d.value
            };
            (d.name, v)
        })
        .collect()
}

/// Read one inline style property (hyphenated or camelCase name).
fn style_read(interp: &Interp, handle: usize, name: &str) -> String {
    let key = camel_to_css(name);
    style_decls(interp, handle)
        .into_iter()
        .rev()
        .find(|(n, _)| *n == key)
        .map(|(_, v)| v)
        .unwrap_or_default()
}

/// Write one inline style property back to the `style` attribute; an
/// empty value removes the declaration. The attribute is re-serialised in
/// declaration order, the way Chrome's `cssText` reads back.
fn style_write(interp: &Interp, handle: usize, name: &str, value: &str) {
    let key = camel_to_css(name);
    if key.is_empty() {
        return;
    }
    let mut decls = style_decls(interp, handle);
    decls.retain(|(n, _)| *n != key);
    let value = value.trim();
    if !value.is_empty() {
        decls.push((key, value.to_string()));
    }
    let text = decls
        .iter()
        .map(|(n, v)| format!("{n}: {v};"))
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(dom) = interp.dom.clone() {
        let mut doc = dom.borrow_mut();
        if doc.get(node_id(handle)).and_then(|n| n.as_element()).is_some() {
            if text.is_empty() {
                if let NodeData::Element(e) = &mut doc.node_mut(node_id(handle)).data {
                    e.attrs.retain(|(n, _)| n != "style");
                }
            } else {
                doc.set_attr(node_id(handle), "style", &text);
            }
        }
    }
}

/// Serialise the inline style as `cssText`.
fn style_css_text(interp: &Interp, handle: usize) -> String {
    style_decls(interp, handle)
        .iter()
        .map(|(n, v)| format!("{n}: {v};"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Read a live facet property (`el.style.x`, `el.dataset.x`). `None` when
/// the key is not facet-backed (methods and expandos fall through).
pub fn get_facet_property(
    interp: &mut Interp,
    handle: usize,
    facet: Facet,
    key: &str,
) -> Option<JsValue> {
    match facet {
        Facet::Style => match key {
            "cssText" => Some(JsValue::str(style_css_text(interp, handle))),
            "length" => Some(JsValue::Num(style_decls(interp, handle).len() as f64)),
            "setProperty" | "removeProperty" | "getPropertyValue" | "getPropertyPriority"
            | "constructor" | "toString" | "hasOwnProperty" | "valueOf" => None,
            k => {
                if let Ok(i) = k.parse::<usize>() {
                    return Some(
                        style_decls(interp, handle)
                            .get(i)
                            .map(|(n, _)| JsValue::str(n.clone()))
                            .unwrap_or(JsValue::Undefined),
                    );
                }
                Some(JsValue::str(style_read(interp, handle, k)))
            }
        },
        Facet::Dataset => {
            if matches!(key, "constructor" | "toString" | "hasOwnProperty" | "valueOf") {
                return None;
            }
            let attr = format!("data-{}", camel_to_css(key));
            let dom = interp.dom.clone()?;
            let doc = dom.borrow();
            Some(
                doc.get(node_id(handle))
                    .and_then(|n| n.as_element().and_then(|e| e.attr(&attr)))
                    .map(|v| JsValue::str(v.to_string()))
                    .unwrap_or(JsValue::Undefined),
            )
        }
        Facet::ClassList => None,
    }
}

/// Write a live facet property. Returns true when the write was absorbed
/// by the attribute.
pub fn set_facet_property(
    interp: &mut Interp,
    handle: usize,
    facet: Facet,
    key: &str,
    value: &JsValue,
) -> bool {
    match facet {
        Facet::Style => {
            if key == "cssText" {
                let text = value.to_js_string();
                if let Some(dom) = interp.dom.clone() {
                    let mut doc = dom.borrow_mut();
                    if doc.get(node_id(handle)).and_then(|n| n.as_element()).is_some() {
                        doc.set_attr(node_id(handle), "style", text.trim());
                    }
                }
                return true;
            }
            if key == "length" || key.parse::<usize>().is_ok() {
                return true;
            }
            // `el.style.x = null` / undefined clears, like Chrome.
            let v = if value.is_nullish() {
                String::new()
            } else {
                value.to_js_string()
            };
            style_write(interp, handle, key, &v);
            true
        }
        Facet::Dataset => {
            let attr = format!("data-{}", camel_to_css(key));
            if let Some(dom) = interp.dom.clone() {
                dom.borrow_mut()
                    .set_attr(node_id(handle), &attr, &value.to_js_string());
            }
            true
        }
        Facet::ClassList => false,
    }
}

/// The own enumerable keys a facet exposes (for `Object.keys(el.dataset)`
/// and `for...in` over `el.style`).
pub fn facet_keys(interp: &Interp, handle: usize, facet: Facet) -> Vec<String> {
    match facet {
        Facet::Style => style_decls(interp, handle)
            .iter()
            .map(|(n, _)| css_to_camel(n))
            .collect(),
        Facet::Dataset => {
            let Some(dom) = interp.dom.clone() else {
                return Vec::new();
            };
            let doc = dom.borrow();
            doc.get(node_id(handle))
                .and_then(|n| n.as_element())
                .map(|e| {
                    e.attrs
                        .iter()
                        .filter_map(|(k, _)| k.strip_prefix("data-").map(css_to_camel))
                        .collect()
                })
                .unwrap_or_default()
        }
        Facet::ClassList => Vec::new(),
    }
}

/// `backgroundColor` → `background-color`; hyphenated input passes
/// through; `cssFloat` is the `float` property.
fn camel_to_css(name: &str) -> String {
    if name == "cssFloat" {
        return "float".to_string();
    }
    if name.contains('-') || name.starts_with("--") {
        return name.to_ascii_lowercase();
    }
    let mut out = String::with_capacity(name.len() + 4);
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            out.push('-');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    // `webkitTransform` → `-webkit-transform`.
    if out.starts_with("webkit-") || out.starts_with("moz-") || out.starts_with("ms-") {
        out.insert(0, '-');
    }
    out
}

/// `background-color` → `backgroundColor`.
pub(super) fn css_to_camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '-' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}
