//! The DOM domain: node queries, attribute and tree edits, searches and box models.

use super::super::dom::Document;
use super::super::dom::NodeData;
use super::super::dom::NodeId;
use super::super::extract;
use super::super::html;
use super::super::js::dom_bindings;
use super::super::js::value::JsValue as JsVal;
use super::super::js::value::ObjKind;
use super::{CdpBrowser, CdpCommand, CdpError, CdpEvent, CdpHost, JsonValue, cdp_to_node, hit_test, invalid, method_not_found, node_to_cdp, remote_object};

impl CdpBrowser {
    pub(super) fn dom_command(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "DOM.enable" | "DOM.disable" => Ok(JsonValue::obj(vec![])),
            "DOM.getDocument" => {
                let depth = cmd
                    .params
                    .get("depth")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                // CDP: depth -1 means the whole tree.
                let depth = if depth < 0.0 {
                    usize::MAX >> 1
                } else {
                    depth as usize
                };
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                Ok(JsonValue::obj(vec![(
                    "root",
                    dom_node_json(&doc, NodeId::DOCUMENT, depth),
                )]))
            }
            "DOM.querySelector" => {
                let sel = cmd
                    .params
                    .get("selector")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("selector required"))?;
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                let root = cdp_to_node(node_id);
                let hits = super::super::css::query_selector_all(&doc, root, sel);
                let id = hits.first().map(|n| node_to_cdp(*n)).unwrap_or(0.0);
                Ok(JsonValue::obj(vec![("nodeId", JsonValue::Num(id))]))
            }
            "DOM.querySelectorAll" => {
                let sel = cmd
                    .params
                    .get("selector")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("selector required"))?;
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                let root = cdp_to_node(node_id);
                let hits = super::super::css::query_selector_all(&doc, root, sel);
                Ok(JsonValue::obj(vec![(
                    "nodeIds",
                    JsonValue::Arr(
                        hits.iter()
                            .map(|n| JsonValue::Num(node_to_cdp(*n)))
                            .collect(),
                    ),
                )]))
            }
            "DOM.getOuterHTML" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                let html_out = extract::outer_html(&doc, cdp_to_node(node_id));
                Ok(JsonValue::obj(vec![(
                    "outerHTML",
                    JsonValue::str(html_out),
                )]))
            }
            "DOM.getAttributes" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(0.0);
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                let mut flat: Vec<JsonValue> = Vec::new();
                if let Some(el) = doc.get(cdp_to_node(node_id)).and_then(|n| n.as_element()) {
                    for (k, v) in &el.attrs {
                        flat.push(JsonValue::str(k.clone()));
                        flat.push(JsonValue::str(v.clone()));
                    }
                }
                Ok(JsonValue::obj(vec![("attributes", JsonValue::Arr(flat))]))
            }
            "DOM.setAttributeValue" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(0.0);
                let name = cmd
                    .params
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("name required"))?
                    .to_string();
                let value = cmd
                    .params
                    .get("value")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                let session = self.session_for(cmd)?;
                session
                    .doc
                    .borrow_mut()
                    .set_attr(cdp_to_node(node_id), &name, &value);
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.describeNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                let depth = cmd
                    .params
                    .get("depth")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                let depth = if depth < 0.0 {
                    usize::MAX >> 1
                } else {
                    depth as usize
                };
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                Ok(JsonValue::obj(vec![(
                    "node",
                    dom_node_json(&doc, cdp_to_node(node_id), depth),
                )]))
            }
            "DOM.resolveNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                {
                    let session = self.session_for(cmd)?;
                    if session.doc.borrow().get(cdp_to_node(node_id)).is_none() {
                        return Err(invalid("no such node"));
                    }
                }
                let handle = cdp_to_node(node_id).index();
                let outcome = self.with_session_interp(cmd, host, |interp| {
                    Ok(dom_bindings::wrap_node(interp, handle))
                })?;
                let session = self.session_for(cmd)?;
                match outcome {
                    Ok(wrapper) => Ok(JsonValue::obj(vec![(
                        "object",
                        remote_object(session, &wrapper),
                    )])),
                    Err(e) => Err(CdpError {
                        code: -32000,
                        message: e,
                    }),
                }
            }
            "DOM.requestNode" => {
                let object_id = cmd
                    .params
                    .get("objectId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("objectId required"))?
                    .to_string();
                let session = self.session_for(cmd)?;
                let handle = session.remote_objects.get(&object_id).and_then(|v| match v {
                    JsVal::Object(o) => match &o.borrow().kind {
                        ObjKind::DomNode(h) => Some(*h),
                        _ => None,
                    },
                    _ => None,
                });
                match handle {
                    Some(h) => Ok(JsonValue::obj(vec![(
                        "nodeId",
                        JsonValue::Num(node_to_cdp(NodeId(h as u32))),
                    )])),
                    None => Err(invalid("object is not a DOM node")),
                }
            }
            "DOM.getBoxModel" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let page = self.page_for(cmd)?;
                let node = cdp_to_node(node_id);
                let Some(b) = page.box_of(node) else {
                    return Err(CdpError {
                        code: -32000,
                        message: "Could not compute box model: node has no layout box"
                            .to_string(),
                    });
                };
                let (bx, by, bw, bh) = (
                    b.rect.x as f64,
                    b.rect.y as f64,
                    b.rect.width as f64,
                    b.rect.height as f64,
                );
                let quad = |x: f64, y: f64, w: f64, h: f64| {
                    JsonValue::Arr(vec![
                        JsonValue::Num(x),
                        JsonValue::Num(y),
                        JsonValue::Num(x + w),
                        JsonValue::Num(y),
                        JsonValue::Num(x + w),
                        JsonValue::Num(y + h),
                        JsonValue::Num(x),
                        JsonValue::Num(y + h),
                    ])
                };
                let border = quad(bx, by, bw, bh);
                // The engine's rect is the border box; the content quad insets
                // the border edges (padding is folded into content geometry).
                let (bl, bt, br2, bb) = (
                    b.border.left as f64,
                    b.border.top as f64,
                    b.border.right as f64,
                    b.border.bottom as f64,
                );
                let content = quad(
                    bx + bl,
                    by + bt,
                    (bw - bl - br2).max(0.0),
                    (bh - bt - bb).max(0.0),
                );
                Ok(JsonValue::obj(vec![(
                    "model",
                    JsonValue::obj(vec![
                        ("content", content.clone()),
                        ("padding", content),
                        ("border", border.clone()),
                        ("margin", border),
                        ("width", JsonValue::Num(bw)),
                        ("height", JsonValue::Num(bh)),
                    ]),
                )]))
            }
            "DOM.getNodeForLocation" => {
                let x = cmd
                    .params
                    .get("x")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("x required"))?;
                let y = cmd
                    .params
                    .get("y")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("y required"))?;
                let tid = {
                    let session = self.session_for(cmd)?;
                    session.target_id.clone()
                };
                let page = self.page_for(cmd)?;
                match hit_test(&page, x as f32, y as f32) {
                    Some(n) => Ok(JsonValue::obj(vec![
                        ("nodeId", JsonValue::Num(node_to_cdp(n))),
                        ("backendNodeId", JsonValue::Num(node_to_cdp(n))),
                        ("frameId", JsonValue::str(tid)),
                    ])),
                    None => Err(CdpError {
                        code: -32000,
                        message: "no node at the given location".to_string(),
                    }),
                }
            }
            "DOM.setOuterHTML" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let html_src = cmd
                    .params
                    .get("outerHTML")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("outerHTML required"))?
                    .to_string();
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let target = cdp_to_node(node_id);
                if doc.get(target).and_then(|n| n.parent).is_none() {
                    return Err(invalid("cannot replace a node without a parent"));
                }
                // Parse into a detached holder, then splice the new nodes in
                // front of the old node so document position is preserved.
                let holder = doc.create_element("template");
                html::parse_fragment_into(&mut doc, holder, &html_src);
                let kids: Vec<NodeId> = doc.children(holder).collect();
                for k in kids {
                    doc.detach(k);
                    doc.insert_before(target, k);
                }
                doc.detach(target);
                doc.detach(holder);
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.removeNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let session = self.session_for(cmd)?;
                session.doc.borrow_mut().detach(cdp_to_node(node_id));
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.setNodeValue" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let value = cmd
                    .params
                    .get("value")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let id = cdp_to_node(node_id);
                if doc.get(id).is_none() {
                    return Err(invalid("no such node"));
                }
                match &mut doc.node_mut(id).data {
                    NodeData::Text(t) => *t = value,
                    NodeData::Comment(c) => *c = value,
                    _ => return Err(invalid("node is not a text or comment node")),
                }
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.focus" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let handle = cdp_to_node(node_id).index();
                // A throwing focus/blur listener is page behaviour, reported
                // through Runtime.exceptionThrown by with_session_interp; the
                // command itself still succeeds, as in Chrome.
                let _listener_outcome = self.with_session_interp(cmd, host, |interp| {
                    dom_bindings::focus_node(interp, handle)
                })?;
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.removeAttribute" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let name = cmd
                    .params
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("name required"))?
                    .to_ascii_lowercase();
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let id = cdp_to_node(node_id);
                if doc.get(id).is_none() {
                    return Err(invalid("no such node"));
                }
                match &mut doc.node_mut(id).data {
                    NodeData::Element(e) => e.attrs.retain(|(k, _)| k != &name),
                    _ => return Err(invalid("node is not an element")),
                }
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.setAttributesAsText" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let text = cmd
                    .params
                    .get("text")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("text required"))?
                    .to_string();
                let replaced = cmd
                    .params
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .map(|s| s.to_ascii_lowercase());
                // Parse the attribute text through the HTML tokenizer: a
                // `<x ...>` start tag carries exactly the attribute grammar.
                let parsed = html::parse(&format!("<x {text}>"));
                let attrs: Vec<(String, String)> = parsed
                    .find_tag("x")
                    .and_then(|n| parsed.get(n).and_then(|x| x.as_element()))
                    .map(|e| e.attrs.clone())
                    .unwrap_or_default();
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let id = cdp_to_node(node_id);
                if doc.get(id).is_none() {
                    return Err(invalid("no such node"));
                }
                match &mut doc.node_mut(id).data {
                    NodeData::Element(e) => {
                        if let Some(old) = &replaced {
                            e.attrs.retain(|(k, _)| k != old);
                        }
                        for (k, v) in attrs {
                            e.attrs.retain(|(ek, _)| ek != &k);
                            e.attrs.push((k, v));
                        }
                    }
                    _ => return Err(invalid("node is not an element")),
                }
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.setNodeName" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let name = cmd
                    .params
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("name required"))?
                    .to_ascii_lowercase();
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let id = cdp_to_node(node_id);
                if doc.get(id).is_none() {
                    return Err(invalid("no such node"));
                }
                match &mut doc.node_mut(id).data {
                    NodeData::Element(e) => e.tag = name,
                    _ => return Err(invalid("node is not an element")),
                }
                // The node keeps its identity (and id) in this arena.
                Ok(JsonValue::obj(vec![("nodeId", JsonValue::Num(node_id))]))
            }
            "DOM.moveTo" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let target = cmd
                    .params
                    .get("targetNodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("targetNodeId required"))?;
                let before = cmd
                    .params
                    .get("insertBeforeNodeId")
                    .and_then(JsonValue::as_f64)
                    .filter(|n| *n >= 1.0)
                    .map(cdp_to_node);
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let (node, parent) = (cdp_to_node(node_id), cdp_to_node(target));
                if doc.get(node).is_none() || doc.get(parent).is_none() {
                    return Err(invalid("no such node"));
                }
                // Moving a node into its own subtree would create a cycle.
                let mut cur = Some(parent);
                while let Some(c) = cur {
                    if c == node {
                        return Err(invalid("cannot move a node into its own subtree"));
                    }
                    cur = doc.get(c).and_then(|n| n.parent);
                }
                doc.detach(node);
                match before {
                    Some(b) if doc.get(b).and_then(|n| n.parent) == Some(parent) => {
                        doc.insert_before(b, node)
                    }
                    _ => doc.append_child(parent, node),
                }
                Ok(JsonValue::obj(vec![("nodeId", JsonValue::Num(node_id))]))
            }
            "DOM.requestChildNodes" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let depth = cmd
                    .params
                    .get("depth")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                let depth = if depth < 0.0 {
                    usize::MAX >> 1
                } else {
                    depth as usize
                };
                let sid = cmd.session_id.clone();
                let session = self.session_for(cmd)?;
                let id = cdp_to_node(node_id);
                let kids: Vec<JsonValue> = {
                    let doc = session.doc.borrow();
                    if doc.get(id).is_none() {
                        return Err(invalid("no such node"));
                    }
                    doc.children(id)
                        .map(|c| dom_node_json(&doc, c, depth.saturating_sub(1)))
                        .collect()
                };
                self.events.push(CdpEvent {
                    method: "DOM.setChildNodes".to_string(),
                    params: JsonValue::obj(vec![
                        ("parentId", JsonValue::Num(node_id)),
                        ("nodes", JsonValue::Arr(kids)),
                    ]),
                    session_id: sid,
                });
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.performSearch" => {
                let query = cmd
                    .params
                    .get("query")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("query required"))?
                    .to_string();
                let session = self.session_for(cmd)?;
                let hits: Vec<NodeId> = {
                    let doc = session.doc.borrow();
                    // Selector first; otherwise a case-insensitive substring
                    // match on tag names, attributes and text (Chrome's
                    // plain-text search).
                    let by_selector = super::super::css::query_selector_all(&doc, NodeId::DOCUMENT, &query);
                    if !by_selector.is_empty() {
                        by_selector
                    } else {
                        let needle = query.to_ascii_lowercase();
                        doc.descendants(NodeId::DOCUMENT)
                            .filter(|n| match doc.get(*n).map(|x| &x.data) {
                                Some(NodeData::Element(e)) => {
                                    e.tag.contains(&needle)
                                        || e.attrs.iter().any(|(k, v)| {
                                            k.contains(&needle)
                                                || v.to_ascii_lowercase().contains(&needle)
                                        })
                                }
                                Some(NodeData::Text(t)) => {
                                    t.to_ascii_lowercase().contains(&needle)
                                }
                                _ => false,
                            })
                            .collect()
                    }
                };
                let id = format!("search-{}", session.next_search_id);
                session.next_search_id = session.next_search_id.wrapping_add(1);
                let count = hits.len();
                session.searches.push((id.clone(), hits));
                Ok(JsonValue::obj(vec![
                    ("searchId", JsonValue::str(id)),
                    ("resultCount", JsonValue::Num(count as f64)),
                ]))
            }
            "DOM.getSearchResults" => {
                let id = cmd
                    .params
                    .get("searchId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("searchId required"))?;
                let from = cmd
                    .params
                    .get("fromIndex")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(0.0)
                    .max(0.0) as usize;
                let to = cmd
                    .params
                    .get("toIndex")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(f64::MAX)
                    .max(0.0);
                let session = self.session_for(cmd)?;
                let Some((_, hits)) = session.searches.iter().find(|(s, _)| s == id) else {
                    return Err(invalid("no such search"));
                };
                let to = if to >= hits.len() as f64 {
                    hits.len()
                } else {
                    to as usize
                };
                let slice = hits.get(from..to.max(from)).unwrap_or(&[]);
                Ok(JsonValue::obj(vec![(
                    "nodeIds",
                    JsonValue::Arr(slice.iter().map(|n| JsonValue::Num(node_to_cdp(*n))).collect()),
                )]))
            }
            "DOM.discardSearchResults" => {
                let id = cmd
                    .params
                    .get("searchId")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                let session = self.session_for(cmd)?;
                session.searches.retain(|(s, _)| s != &id);
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.setFileInputFiles" => {
                let files: Vec<String> = match cmd.params.get("files") {
                    Some(JsonValue::Arr(a)) => a
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .map(str::to_string)
                        .collect(),
                    _ => return Err(invalid("files required")),
                };
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let id = cdp_to_node(node_id);
                let is_file = doc
                    .get(id)
                    .and_then(|n| n.as_element())
                    .map(|e| {
                        e.tag == "input"
                            && e.attr("type").map(|t| t.eq_ignore_ascii_case("file")).unwrap_or(false)
                    })
                    .unwrap_or(false);
                if !is_file {
                    return Err(invalid("node is not a file input"));
                }
                // The engine has no filesystem: the selection is recorded on
                // the element (`data-files`) and mirrored into `value` the way
                // a browser exposes the first file's fake path.
                doc.set_attr(id, "data-files", &files.join("\n"));
                let first = files
                    .first()
                    .map(|f| format!("C:\\fakepath\\{}", f.rsplit('/').next().unwrap_or(f)))
                    .unwrap_or_default();
                doc.set_attr(id, "value", &first);
                Ok(JsonValue::obj(vec![]))
            }
            "DOM.scrollIntoViewIfNeeded" | "DOM.hideHighlight" | "DOM.highlightNode"
            | "DOM.highlightRect" | "DOM.markUndoableState" | "DOM.undo" | "DOM.redo" => {
                // Scrolling has no meaning for a whole-page layout, and the
                // engine paints no inspector overlay; these are accepted so
                // clients' prelude sequences do not fail.
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            other => Err(method_not_found(other)),
        }
    }
}

/// Serialize a DOM node the CDP way (children included to `depth`).
fn dom_node_json(doc: &Document, id: NodeId, depth: usize) -> JsonValue {
    let node = doc.get(id);
    let (node_type, node_name, node_value) = match node.map(|n| &n.data) {
        Some(NodeData::Document) => (9.0, "#document".to_string(), String::new()),
        Some(NodeData::Doctype { name }) => (10.0, name.clone(), String::new()),
        Some(NodeData::Element(e)) => (1.0, e.tag.to_uppercase(), String::new()),
        Some(NodeData::Text(t)) => (3.0, "#text".to_string(), t.clone()),
        Some(NodeData::Comment(c)) => (8.0, "#comment".to_string(), c.clone()),
        None => (0.0, String::new(), String::new()),
    };
    let mut entries: Vec<(String, JsonValue)> = vec![
        ("nodeId".to_string(), JsonValue::Num(node_to_cdp(id))),
        ("backendNodeId".to_string(), JsonValue::Num(node_to_cdp(id))),
        ("nodeType".to_string(), JsonValue::Num(node_type)),
        ("nodeName".to_string(), JsonValue::Str(node_name)),
        ("localName".to_string(), JsonValue::Str(String::new())),
        ("nodeValue".to_string(), JsonValue::Str(node_value)),
    ];
    if let Some(el) = node.and_then(|n| n.as_element()) {
        let mut flat = Vec::new();
        for (k, v) in &el.attrs {
            flat.push(JsonValue::Str(k.clone()));
            flat.push(JsonValue::Str(v.clone()));
        }
        entries.push(("attributes".to_string(), JsonValue::Arr(flat)));
    }
    if depth > 0 {
        let children: Vec<JsonValue> = doc
            .children(id)
            .map(|c| dom_node_json(doc, c, depth - 1))
            .collect();
        entries.push((
            "childNodeCount".to_string(),
            JsonValue::Num(children.len() as f64),
        ));
        entries.push(("children".to_string(), JsonValue::Arr(children)));
    }
    JsonValue::Obj(entries)
}
