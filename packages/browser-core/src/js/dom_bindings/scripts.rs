//! Script elements inserted by script: the dynamic load task and its fetch.

use std::rc::Rc;
use super::super::interp::Interp;
use super::super::super::dom::Document;
use super::super::super::dom::NodeData;
use super::super::super::dom::NodeId;
use super::super::value::JsObject;
use super::super::value::JsValue;
use super::super::value::NativeFn;
use super::super::value::ObjKind;
use super::{MAX_DYNAMIC_SCRIPTS, node_id};
use super::custom_elements::{connect_custom_elements};
use super::properties::{collect_text};

/// HTML §4.12.1 "prepare the script element", for a `<script>` that a
/// script inserted into the connected tree: a classic script that has not
/// already started is fetched (the embedder's pre-fetched map first, then
/// the host's `fetch`) and queued to run as a TASK on the virtual clock,
/// the way a browser's fetch completes on a later turn of the event loop.
/// `load` fires on the element after it ran, `error` when the fetch failed
/// or the source was refused, so chunk loaders (`__webpack_require__.l`,
/// Turbopack's `loadChunk`) settle their promises. Inline scripts run the
/// same way (a later task), which is how Chrome orders them relative to
/// the inserting script's remaining synchronous work.
pub fn script_inserted(interp: &mut Interp, handle: usize) {
    let Some(dom) = interp.dom.clone() else {
        return;
    };
    let id = node_id(handle);
    // Only scripts that actually landed in the document (not in a
    // detached fragment or a scratch document) start.
    let (connected, stype, src, inline) = {
        let doc = dom.borrow();
        let Some(el) = doc.get(id).and_then(|n| n.as_element()) else {
            return;
        };
        if el.tag != "script" {
            return;
        }
        let mut root = id;
        while let Some(p) = doc.get(root).and_then(|n| n.parent) {
            root = p;
        }
        let stype = el.attr("type").unwrap_or("").trim().to_ascii_lowercase();
        let src = el.attr("src").map(str::to_string).filter(|s| !s.trim().is_empty());
        let inline = collect_text(&doc, id);
        (root == NodeId::DOCUMENT, stype, src, inline)
    };
    if !connected {
        return;
    }
    if !(stype.is_empty() || stype == "text/javascript" || stype == "application/javascript") {
        return;
    }
    if interp.started_scripts.contains(&handle) {
        return;
    }
    if src.is_none() && inline.trim().is_empty() {
        return;
    }
    // The cap is checked BEFORE the element is marked started: a script
    // refused for capacity is not "already started", so the warning is
    // honest and the same element can start later if it is re-inserted
    // once other work has settled.
    if interp.dynamic_scripts >= MAX_DYNAMIC_SCRIPTS {
        interp.hooks.console(
            "warn",
            &format!("dynamic script limit ({MAX_DYNAMIC_SCRIPTS}) reached; <script> not started"),
        );
        return;
    }
    interp.started_scripts.insert(handle);
    interp.dynamic_scripts = interp.dynamic_scripts.saturating_add(1);
    // Queue the whole load as a task: the FETCH happens when the task runs
    // (a later turn of the event loop), not inside the inserting script's
    // `appendChild`, so the inserting script's remaining synchronous work
    // runs first, exactly as a browser orders it. The task carries what it
    // needs: the raw `src` (resolved against `location` at fetch time) or
    // the inline text.
    let request = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
    match &src {
        Some(raw) => request.borrow_mut().set_prop("src", JsValue::str(raw.clone()), false),
        None => request.borrow_mut().set_prop("inline", JsValue::str(inline), false),
    }
    let run: NativeFn = Rc::new(move |interp, _this, args| {
        let (Some(JsValue::Num(h)), Some(JsValue::Object(request))) = (args.first(), args.get(1)) else {
            return Ok(JsValue::Undefined);
        };
        let handle = *h as usize;
        let (raw_src, inline) = {
            let b = request.borrow();
            (b.get_prop("src"), b.get_prop("inline"))
        };
        let source: Result<String, String> = match (raw_src, inline) {
            (None, Some(text)) => Ok(text.to_js_string()),
            (Some(raw), _) => fetch_dynamic_source(interp, &raw.to_js_string()),
            _ => return Ok(JsValue::Undefined),
        };
        // A script removed before its task ran still runs (HTML: the
        // element need not be connected at execution time).
        match source {
            Ok(src) => {
                let ok = interp.run_dynamic_script(handle, &src);
                if ok {
                    interp.dynamic_scripts_ok = interp.dynamic_scripts_ok.saturating_add(1);
                }
                let event = if ok { "load" } else { "error" };
                interp.dispatch_node_event(handle, event, false, &[])?;
            }
            Err(e) => {
                interp
                    .hooks
                    .console("error", &format!("dynamic script failed to load: {e}"));
                interp.dispatch_node_event(handle, "error", false, &[])?;
            }
        }
        Ok(JsValue::Undefined)
    });
    let f = interp.native(run);
    interp.set_timer(
        f,
        0.0,
        vec![JsValue::Num(handle as f64), JsValue::Object(request)],
        false,
    );
}

/// `start`, or with `elements_only` the nearest element at or before it among
/// its siblings.
pub(super) fn backward_node(doc: &Document, start: Option<NodeId>, elements_only: bool) -> Option<NodeId> {
    let mut cur = start;
    if elements_only {
        while let Some(c) = cur {
            if matches!(doc.get(c).map(|n| &n.data), Some(NodeData::Element(_))) {
                break;
            }
            cur = doc.get(c).and_then(|n| n.prev_sibling);
        }
    }
    cur
}

/// The source of a dynamically inserted external script: the embedder's
/// pre-fetched map first (by raw `src`, by absolute URL, or by URL minus
/// its fragment — the replay harness keys captures by URL), then the
/// host's `fetch` through the same scoped egress every other page fetch
/// uses. A 4xx/5xx is a load failure, as it is for a browser's `<script>`.
fn fetch_dynamic_source(interp: &mut Interp, raw: &str) -> Result<String, String> {
    let base = interp
        .global_object
        .borrow()
        .get_prop("location")
        .and_then(|l| match l {
            JsValue::Object(o) => o.borrow().get_prop("href"),
            _ => None,
        })
        .map(|v| v.to_js_string())
        .unwrap_or_default();
    let abs = super::super::super::cdp::resolve_url(&base, raw).unwrap_or_else(|| raw.to_string());
    let strip = |u: &str| u.split('#').next().unwrap_or(u).to_string();
    let want = strip(&abs);
    let pre = interp
        .external_scripts
        .get(raw)
        .or_else(|| interp.external_scripts.get(&abs))
        .cloned()
        .or_else(|| {
            interp
                .external_scripts
                .iter()
                .find(|(u, _)| strip(u) == want)
                .map(|(_, s)| s.clone())
        });
    match pre {
        Some(s) => Ok(s),
        None => interp
            .hooks
            .fetch(&abs, "GET", &[], None)
            .and_then(|(status, _, body)| {
                if status >= 400 {
                    Err(format!("script {abs}: origin returned {status}"))
                } else {
                    Ok(String::from_utf8_lossy(&body).into_owned())
                }
            }),
    }
}

/// Every `<script>` element in the subtree rooted at `node` (the node
/// itself included), for the insertion paths to start.
fn scripts_in(doc: &Document, node: NodeId) -> Vec<usize> {
    let mut out = Vec::new();
    // `descendants` starts at the first child: the inserted node itself
    // (the common `appendChild(script)` case) is checked here.
    let is_script = |n: NodeId| {
        doc.get(n).and_then(|x| x.as_element()).map(|e| e.tag == "script").unwrap_or(false)
    };
    if is_script(node) {
        out.push(node.index());
    }
    for n in doc.descendants(node) {
        if doc.get(n).and_then(|x| x.as_element()).map(|e| e.tag == "script").unwrap_or(false) {
            out.push(n.index());
        }
    }
    out
}

/// After `nodes` were inserted into the tree: start every script among
/// them and their descendants (innerHTML-parsed scripts do NOT run, as in
/// browsers; this is only for node-insertion APIs).
pub(super) fn start_inserted_scripts(interp: &mut Interp, nodes: &[NodeId]) {
    let Some(dom) = interp.dom.clone() else {
        return;
    };
    let handles: Vec<usize> = {
        let doc = dom.borrow();
        nodes.iter().flat_map(|n| scripts_in(&doc, *n)).collect()
    };
    for h in handles {
        script_inserted(interp, h);
    }
    // Custom elements among the inserted nodes (the roots and their
    // descendants) are upgraded if their name is defined and their
    // `connectedCallback` runs once they are in the connected tree.
    connect_custom_elements(interp, nodes);
}
