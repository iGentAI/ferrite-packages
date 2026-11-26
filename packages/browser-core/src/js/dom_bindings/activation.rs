//! Focus, activation behaviour and form submission.

use super::super::interp::Interp;
use super::super::super::dom::Document;
use super::super::super::dom::NodeData;
use super::super::super::dom::NodeId;
use super::super::value::JsValue;
use super::{node_id};
use super::properties::{collect_text};

/// Move focus to `handle`: `blur` the previous element, set
/// `document.activeElement`, fire `focus` (non-bubbling) then `focusin`.
pub fn focus_node(interp: &mut Interp, handle: usize) -> Result<(), JsValue> {
    if interp.focused == Some(handle) {
        return Ok(());
    }
    if let Some(prev) = interp.focused.take() {
        interp.dispatch_node_event(prev, "blur", false, &[])?;
        interp.dispatch_node_event(prev, "focusout", true, &[])?;
    }
    interp.focused = Some(handle);
    interp.dispatch_node_event(handle, "focus", false, &[])?;
    interp.dispatch_node_event(handle, "focusin", true, &[])?;
    Ok(())
}

/// The activation behaviour for a click at `handle`: focus (when focusable),
/// a bubbling `click`, then the default action unless a listener prevented
/// it — checkbox/radio toggle, label → control forwarding, and submit
/// buttons submitting their form. Link/form navigation is recorded as the
/// hidden global `__pendingNavigation` for the embedder (it owns network).
pub fn activate(interp: &mut Interp, handle: usize) -> Result<bool, JsValue> {
    activate_with(interp, handle, &[])
}

/// [`activate`] with extra properties on the `click` event — the pointer
/// coordinates (`clientX`, `clientY`, `pageX`, `pageY`) a real mouse click
/// carries, supplied by the embedder's Input dispatch.
pub fn activate_with(
    interp: &mut Interp,
    handle: usize,
    extra: &[(&str, JsValue)],
) -> Result<bool, JsValue> {
    let Some(dom) = interp.dom.clone() else {
        return Ok(true);
    };
    let (tag, input_type, disabled) = {
        let doc = dom.borrow();
        match doc.get(node_id(handle)).and_then(|n| n.as_element()) {
            Some(e) => (
                e.tag.clone(),
                e.attr("type").unwrap_or("").to_ascii_lowercase(),
                e.attr("disabled").is_some(),
            ),
            None => (String::new(), String::new(), false),
        }
    };
    if disabled {
        return Ok(false);
    }
    if matches!(tag.as_str(), "input" | "textarea" | "select" | "button" | "a") {
        focus_node(interp, handle)?;
    }
    // `click` fires after the button is released, so no button is down
    // (`buttons` is 0); `button` still names the primary button.
    let mut props: Vec<(&str, JsValue)> = vec![
        ("button", JsValue::Num(0.0)),
        ("buttons", JsValue::Num(0.0)),
        ("detail", JsValue::Num(1.0)),
    ];
    props.extend(extra.iter().map(|(k, v)| (*k, v.clone())));
    let proceed = interp.dispatch_node_event(handle, "click", true, &props)?;
    if !proceed {
        return Ok(false);
    }
    // Default actions.
    if tag == "input" && input_type == "checkbox" {
        let now_checked = {
            let mut doc = dom.borrow_mut();
            let id = node_id(handle);
            let checked = doc
                .get(id)
                .and_then(|n| n.as_element().map(|e| e.attr("checked").is_some()))
                .unwrap_or(false);
            if checked {
                if let NodeData::Element(e) = &mut doc.node_mut(id).data {
                    e.attrs.retain(|(n, _)| n != "checked");
                }
            } else {
                doc.set_attr(id, "checked", "");
            }
            !checked
        };
        let _ = now_checked;
        interp.dispatch_node_event(handle, "input", true, &[])?;
        interp.dispatch_node_event(handle, "change", true, &[])?;
        return Ok(true);
    }
    if tag == "input" && input_type == "radio" {
        // A radio group is the same-named radios sharing a FORM OWNER (or,
        // without a form, the same-named form-less radios in the tree).
        let group: Vec<NodeId> = {
            let doc = dom.borrow();
            let name = doc
                .get(node_id(handle))
                .and_then(|n| n.as_element().and_then(|e| e.attr("name")))
                .map(str::to_string);
            let owner = form_owner(&doc, node_id(handle));
            doc.descendants(NodeId::DOCUMENT)
                .filter(|n| form_owner(&doc, *n) == owner)
                .filter(|n| {
                    doc.get(*n)
                        .and_then(|x| x.as_element())
                        .map(|e| {
                            e.tag == "input"
                                && e.attr("type").map(|t| t.eq_ignore_ascii_case("radio")).unwrap_or(false)
                                && e.attr("name").map(str::to_string) == name
                        })
                        .unwrap_or(false)
                })
                .collect()
        };
        {
            let mut doc = dom.borrow_mut();
            for n in group {
                if let NodeData::Element(e) = &mut doc.node_mut(n).data {
                    e.attrs.retain(|(k, _)| k != "checked");
                }
            }
            doc.set_attr(node_id(handle), "checked", "");
        }
        interp.dispatch_node_event(handle, "input", true, &[])?;
        interp.dispatch_node_event(handle, "change", true, &[])?;
        return Ok(true);
    }
    if tag == "label" {
        // Forward the activation to the labelled control.
        let control = {
            let doc = dom.borrow();
            let for_id = doc
                .get(node_id(handle))
                .and_then(|n| n.as_element().and_then(|e| e.attr("for")))
                .map(str::to_string);
            match for_id {
                Some(id) => doc.get_element_by_id_ref(&id),
                None => doc.descendants(node_id(handle)).find(|n| {
                    doc.get(*n)
                        .and_then(|x| x.as_element())
                        .map(|e| matches!(e.tag.as_str(), "input" | "textarea" | "select" | "button"))
                        .unwrap_or(false)
                }),
            }
        };
        if let Some(c) = control {
            return activate(interp, c.index());
        }
        return Ok(true);
    }
    let is_submit = (tag == "button" && (input_type.is_empty() || input_type == "submit"))
        || (tag == "input" && matches!(input_type.as_str(), "submit" | "image"));
    if is_submit {
        let form = {
            let doc = dom.borrow();
            form_owner(&doc, node_id(handle))
        };
        if let Some(f) = form {
            return submit_form(interp, f.index());
        }
        return Ok(true);
    }
    if tag == "a" {
        let href = {
            let doc = dom.borrow();
            doc.get(node_id(handle))
                .and_then(|n| n.as_element().and_then(|e| e.attr("href")))
                .map(str::to_string)
        };
        if let Some(href) = href {
            if !href.trim_start().starts_with("javascript:") && !href.starts_with('#') {
                interp
                    .global_object
                    .borrow_mut()
                    .set_prop("__pendingNavigation", JsValue::str(href), false);
            }
        }
    }
    Ok(true)
}

/// Submit `form`: fire a cancelable `submit`; unless prevented, record the
/// navigation (`action` + url-encoded GET fields, or the action alone for
/// POST, with the encoded body under `__pendingNavigationBody`) for the
/// embedder, which owns network access.
pub fn submit_form(interp: &mut Interp, form: usize) -> Result<bool, JsValue> {
    submit_form_steps(interp, form, true)
}

/// The submission steps behind both entry points. `fire_event` distinguishes
/// `requestSubmit()` / user activation (cancelable `submit` fires first) from
/// the legacy `form.submit()` API, which skips the event entirely
/// (HTML §4.10.21.3: "submitted from submit() method" sets the flag that
/// suppresses the event).
pub fn submit_form_steps(
    interp: &mut Interp,
    form: usize,
    fire_event: bool,
) -> Result<bool, JsValue> {
    if fire_event {
        let proceed = interp.dispatch_node_event(form, "submit", true, &[])?;
        if !proceed {
            return Ok(false);
        }
    }
    let Some(dom) = interp.dom.clone() else {
        return Ok(true);
    };
    let (action, method, body) = {
        let doc = dom.borrow();
        let el = doc.get(node_id(form)).and_then(|n| n.as_element());
        let action = el.and_then(|e| e.attr("action")).unwrap_or("").to_string();
        let method = el
            .and_then(|e| e.attr("method"))
            .unwrap_or("get")
            .to_ascii_lowercase();
        let mut pairs: Vec<String> = Vec::new();
        for n in doc.descendants(node_id(form)) {
            let Some(e) = doc.get(n).and_then(|x| x.as_element()) else {
                continue;
            };
            let Some(name) = e.attr("name") else {
                continue;
            };
            if e.attr("disabled").is_some() {
                continue;
            }
            let ty = e.attr("type").unwrap_or("text").to_ascii_lowercase();
            let value: Option<String> = match e.tag.as_str() {
                "input" => match ty.as_str() {
                    "checkbox" | "radio" => e
                        .attr("checked")
                        .map(|_| e.attr("value").unwrap_or("on").to_string()),
                    "submit" | "button" | "reset" | "image" | "file" => None,
                    _ => Some(e.attr("value").unwrap_or("").to_string()),
                },
                "textarea" => Some(
                    e.attr("value")
                        .map(str::to_string)
                        .unwrap_or_else(|| collect_text(&doc, n)),
                ),
                "select" => {
                    let mut chosen: Option<String> = None;
                    let mut first: Option<String> = None;
                    for o in doc.descendants(n) {
                        if let Some(oe) = doc.get(o).and_then(|x| x.as_element()) {
                            if oe.tag == "option" {
                                let v = oe
                                    .attr("value")
                                    .map(str::to_string)
                                    .unwrap_or_else(|| collect_text(&doc, o).trim().to_string());
                                if first.is_none() {
                                    first = Some(v.clone());
                                }
                                if oe.attr("selected").is_some() && chosen.is_none() {
                                    chosen = Some(v);
                                }
                            }
                        }
                    }
                    chosen.or(first)
                }
                _ => None,
            };
            if let Some(v) = value {
                pairs.push(format!("{}={}", form_encode(name), form_encode(&v)));
            }
        }
        (action, method, pairs.join("&"))
    };
    let mut g = interp.global_object.borrow_mut();
    if method == "post" {
        g.set_prop("__pendingNavigation", JsValue::str(action), false);
        g.set_prop("__pendingNavigationMethod", JsValue::str("POST"), false);
        g.set_prop("__pendingNavigationBody", JsValue::str(body), false);
    } else {
        // GET: the form data set REPLACES the action's query (HTML §4.10.21.3
        // "Mutate action URL"); the fragment is dropped.
        let base = action
            .split('#')
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("")
            .to_string();
        let url = format!("{base}?{body}");
        g.set_prop("__pendingNavigation", JsValue::str(url), false);
        g.set_prop("__pendingNavigationMethod", JsValue::str("GET"), false);
        g.set_prop("__pendingNavigationBody", JsValue::str(""), false);
    }
    Ok(true)
}

/// The form owner of a control: its `form="id"` attribute's form when
/// present, else the nearest `<form>` ancestor.
pub fn form_owner(doc: &Document, node: NodeId) -> Option<NodeId> {
    if let Some(fid) = doc
        .get(node)
        .and_then(|n| n.as_element())
        .and_then(|e| e.attr("form"))
    {
        if let Some(f) = doc.get_element_by_id_ref(fid) {
            if doc.get(f).and_then(|x| x.as_element()).map(|e| e.tag == "form").unwrap_or(false) {
                return Some(f);
            }
        }
    }
    let mut cur = doc.get(node).and_then(|n| n.parent);
    while let Some(p) = cur {
        if doc
            .get(p)
            .and_then(|x| x.as_element())
            .map(|e| e.tag == "form")
            .unwrap_or(false)
        {
            return Some(p);
        }
        cur = doc.get(p).and_then(|x| x.parent);
    }
    None
}

/// application/x-www-form-urlencoded encoding of one field name or value.
fn form_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
