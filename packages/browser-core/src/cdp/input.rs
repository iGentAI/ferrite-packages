//! The Input domain: synthesised mouse, keyboard and touch events.

use super::super::dom::NodeId;
use super::super::js::dom_bindings;
use super::super::js::interp::Interp;
use super::super::js::value::JsValue as JsVal;
use super::{CdpBrowser, CdpCommand, CdpError, CdpHost, JsonValue, hit_test, invalid, method_not_found};

impl CdpBrowser {
    pub(super) fn input_command(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Input.dispatchMouseEvent" => {
                let ty = cmd
                    .params
                    .get("type")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("type required"))?
                    .to_string();
                let x = cmd
                    .params
                    .get("x")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(0.0);
                let y = cmd
                    .params
                    .get("y")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(0.0);
                let button = cmd
                    .params
                    .get("button")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("none")
                    .to_string();
                let click_count = cmd
                    .params
                    .get("clickCount")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(0.0);
                let event_name = match ty.as_str() {
                    "mousePressed" => "mousedown",
                    "mouseReleased" => "mouseup",
                    "mouseMoved" => "mousemove",
                    _ => return Err(invalid("unsupported mouse event type")),
                };
                if self.session_for(cmd)?.ignore_input {
                    return Ok(JsonValue::obj(vec![]));
                }
                let page = self.page_for(cmd)?;
                let hit = hit_test(&page, x as f32, y as f32);
                drop(page);
                let button_num = match button.as_str() {
                    "middle" => 1.0,
                    "right" => 2.0,
                    _ => 0.0,
                };
                // A click is a press and a release on the SAME element: record
                // the pressed node, and activate on release only when it
                // matches (Chrome semantics; a stray release does nothing).
                let activates = {
                    let session = self.session_for(cmd)?;
                    match event_name {
                        "mousedown" if button == "left" => {
                            session.pressed = hit;
                            false
                        }
                        "mouseup" => {
                            let pressed = session.pressed.take();
                            button == "left"
                                && click_count >= 1.0
                                && pressed.is_some()
                                && pressed == hit
                        }
                        _ => false,
                    }
                };
                // Listener exceptions surface as Runtime.exceptionThrown; the
                // input command succeeds regardless (Chrome semantics).
                let _listener_outcome = self.with_session_interp(cmd, host, |interp| {
                    let target = hit.map(|n| n.index()).or_else(|| {
                        interp
                            .dom
                            .clone()
                            .and_then(|d| d.borrow().find_tag("body").map(|n| n.index()))
                    });
                    let Some(target) = target else {
                        return Ok(());
                    };
                    interp.dispatch_node_event(
                        target,
                        event_name,
                        true,
                        &[
                            ("clientX", JsVal::Num(x)),
                            ("clientY", JsVal::Num(y)),
                            ("pageX", JsVal::Num(x)),
                            ("pageY", JsVal::Num(y)),
                            ("button", JsVal::Num(button_num)),
                            ("detail", JsVal::Num(click_count)),
                        ],
                    )?;
                    // A completed left click activates the element (click
                    // event + default action), like a real browser.
                    if activates {
                        dom_bindings::activate_with(
                            interp,
                            target,
                            &[
                                ("clientX", JsVal::Num(x)),
                                ("clientY", JsVal::Num(y)),
                                ("pageX", JsVal::Num(x)),
                                ("pageY", JsVal::Num(y)),
                            ],
                        )?;
                    }
                    Ok(())
                })?;
                Ok(JsonValue::obj(vec![]))
            }
            "Input.dispatchKeyEvent" => {
                let ty = cmd
                    .params
                    .get("type")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("type required"))?
                    .to_string();
                let key = cmd
                    .params
                    .get("key")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("")
                    .to_string();
                let text = cmd
                    .params
                    .get("text")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("")
                    .to_string();
                if self.session_for(cmd)?.ignore_input {
                    return Ok(JsonValue::obj(vec![]));
                }
                let _listener_outcome = self.with_session_interp(cmd, host, |interp| {
                    let target = interp
                        .focused
                        .or_else(|| {
                            interp
                                .dom
                                .clone()
                                .and_then(|d| d.borrow().find_tag("body").map(|n| n.index()))
                        })
                        .unwrap_or(0);
                    match ty.as_str() {
                        "keyDown" | "rawKeyDown" => {
                            let proceed = interp.dispatch_node_event(
                                target,
                                "keydown",
                                true,
                                &[("key", JsVal::str(key.clone()))],
                            )?;
                            if proceed && !text.is_empty() {
                                insert_text_at(interp, target, &text)?;
                            }
                            // Enter in a form input triggers implicit submission.
                            if proceed && key == "Enter" {
                                let form = interp.dom.clone().and_then(|d| {
                                    let doc = d.borrow();
                                    let id = NodeId(target as u32);
                                    let is_input = doc
                                        .get(id)
                                        .and_then(|n| n.as_element())
                                        .map(|e| e.tag == "input")
                                        .unwrap_or(false);
                                    if is_input {
                                        dom_bindings::form_owner(&doc, id)
                                    } else {
                                        None
                                    }
                                });
                                if let Some(f) = form {
                                    dom_bindings::submit_form(interp, f.index())?;
                                }
                            }
                        }
                        "keyUp" => {
                            interp.dispatch_node_event(
                                target,
                                "keyup",
                                true,
                                &[("key", JsVal::str(key.clone()))],
                            )?;
                        }
                        "char" => {
                            if !text.is_empty() {
                                insert_text_at(interp, target, &text)?;
                            }
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
                Ok(JsonValue::obj(vec![]))
            }
            "Input.insertText" => {
                let text = cmd
                    .params
                    .get("text")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("text required"))?
                    .to_string();
                if self.session_for(cmd)?.ignore_input {
                    return Ok(JsonValue::obj(vec![]));
                }
                let _listener_outcome = self.with_session_interp(cmd, host, |interp| {
                    let Some(target) = interp.focused else {
                        return Ok(());
                    };
                    insert_text_at(interp, target, &text)
                })?;
                Ok(JsonValue::obj(vec![]))
            }
            "Input.setIgnoreInputEvents" => {
                let ignore = cmd
                    .params
                    .get("ignore")
                    .and_then(JsonValue::as_bool)
                    .ok_or_else(|| invalid("ignore required"))?;
                let session = self.session_for(cmd)?;
                session.ignore_input = ignore;
                Ok(JsonValue::obj(vec![]))
            }
            "Input.dispatchTouchEvent" => {
                let ty = cmd
                    .params
                    .get("type")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("type required"))?
                    .to_string();
                let points = match cmd.params.get("touchPoints") {
                    Some(JsonValue::Arr(a)) => a.clone(),
                    _ => return Err(invalid("touchPoints required")),
                };
                let event_name = match ty.as_str() {
                    "touchStart" => "touchstart",
                    "touchEnd" => "touchend",
                    "touchMove" => "touchmove",
                    "touchCancel" => "touchcancel",
                    _ => return Err(invalid("unsupported touch event type")),
                };
                if self.session_for(cmd)?.ignore_input {
                    return Ok(JsonValue::obj(vec![]));
                }
                let first = points.first().cloned();
                let (x, y) = first
                    .as_ref()
                    .map(|p| {
                        (
                            p.get("x").and_then(JsonValue::as_f64).unwrap_or(0.0),
                            p.get("y").and_then(JsonValue::as_f64).unwrap_or(0.0),
                        )
                    })
                    .unwrap_or((0.0, 0.0));
                let page = self.page_for(cmd)?;
                let hit = hit_test(&page, x as f32, y as f32);
                drop(page);
                // A touch start + end on one element is a tap: the click
                // activation runs on touchEnd, as a browser synthesizes it.
                let activates = {
                    let session = self.session_for(cmd)?;
                    match event_name {
                        "touchstart" => {
                            session.pressed = hit;
                            false
                        }
                        "touchend" => {
                            let pressed = session.pressed.take();
                            pressed.is_some() && pressed == hit
                        }
                        "touchcancel" => {
                            session.pressed = None;
                            false
                        }
                        _ => false,
                    }
                };
                let _listener_outcome = self.with_session_interp(cmd, host, |interp| {
                    let target = hit.map(|n| n.index()).or_else(|| {
                        interp
                            .dom
                            .clone()
                            .and_then(|d| d.borrow().find_tag("body").map(|n| n.index()))
                    });
                    let Some(target) = target else {
                        return Ok(());
                    };
                    interp.dispatch_node_event(
                        target,
                        event_name,
                        true,
                        &[
                            ("clientX", JsVal::Num(x)),
                            ("clientY", JsVal::Num(y)),
                            ("touches", JsVal::Num(points.len() as f64)),
                        ],
                    )?;
                    if activates {
                        dom_bindings::activate_with(
                            interp,
                            target,
                            &[("clientX", JsVal::Num(x)), ("clientY", JsVal::Num(y))],
                        )?;
                    }
                    Ok(())
                })?;
                Ok(JsonValue::obj(vec![]))
            }
            "Input.cancelDragging" => {
                let session = self.session_for(cmd)?;
                session.pressed = None;
                Ok(JsonValue::obj(vec![]))
            }
            other => Err(method_not_found(other)),
        }
    }
}

/// Append `text` to a focused form control's value (input/textarea) and fire
/// the `input` event, the way typing does.
fn insert_text_at(
    interp: &mut Interp<'_>,
    handle: usize,
    text: &str,
) -> Result<(), JsVal> {
    let Some(dom) = interp.dom.clone() else {
        return Ok(());
    };
    let id = NodeId(handle as u32);
    let editable = {
        let doc = dom.borrow();
        doc.get(id)
            .and_then(|n| n.as_element())
            .map(|e| matches!(e.tag.as_str(), "input" | "textarea"))
            .unwrap_or(false)
    };
    if !editable {
        return Ok(());
    }
    {
        let mut doc = dom.borrow_mut();
        let existing = doc
            .get(id)
            .and_then(|n| n.as_element())
            .and_then(|e| e.attr("value"))
            .unwrap_or("")
            .to_string();
        doc.set_attr(id, "value", &format!("{existing}{text}"));
    }
    interp.dispatch_node_event(handle, "input", true, &[])?;
    Ok(())
}
