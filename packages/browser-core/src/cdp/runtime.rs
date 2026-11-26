//! The Runtime domain: evaluation, remote objects and bindings.

use std::rc::Rc;
use super::super::js::interp::Interp;
use super::super::js::parser;
use super::super::js::value::JsObject;
use super::super::js::value::JsValue as JsVal;
use super::super::js::value::ObjKind;
use super::super::js::value::Prop;
use super::{CdpBrowser, CdpCommand, CdpError, CdpHost, ConsoleTap, JsonValue, Session, eval_in_realm, exception_event, invalid, js_to_json, method_not_found, remote_object};

impl CdpBrowser {
    pub(super) fn runtime_command(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Runtime.enable" | "Runtime.disable" => Ok(JsonValue::obj(vec![])),
            "Runtime.evaluate" => {
                let expr = cmd
                    .params
                    .get("expression")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("expression required"))?
                    .to_string();
                let return_by_value = cmd
                    .params
                    .get("returnByValue")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                // Evaluate in the session's PERSISTENT realm: globals,
                // listeners and focus survive across commands — standard CDP
                // session semantics. Navigation resets the realm.
                let (doc, mut realm) = {
                    let session = self.session_for(cmd)?;
                    (session.doc.clone(), core::mem::take(&mut session.realm))
                };
                let mut tap = ConsoleTap {
                    inner: host.hooks(),
                    lines: Vec::new(),
                };
                let outcome = eval_in_realm(doc, &mut realm, &expr, &mut tap);
                let lines = tap.lines;
                for (level, text) in &lines {
                    self.emit_console(cmd, level, text);
                }
                if let Err(e) = &outcome {
                    self.events.push(exception_event(e, cmd.session_id.clone()));
                }
                let session = self.session_for(cmd)?;
                session.realm = realm;
                match outcome {
                    Ok(value) => {
                        let result = if return_by_value {
                            JsonValue::obj(vec![
                                ("type", JsonValue::str(value.type_of())),
                                ("value", js_to_json(&value, 0)),
                                ("description", JsonValue::str(value.to_js_string())),
                            ])
                        } else {
                            remote_object(session, &value)
                        };
                        Ok(JsonValue::obj(vec![("result", result)]))
                    }
                    Err(e) => Ok(JsonValue::obj(vec![
                        (
                            "result",
                            JsonValue::obj(vec![
                                ("type", JsonValue::str("undefined")),
                                ("value", JsonValue::Null),
                                ("description", JsonValue::str("")),
                            ]),
                        ),
                        (
                            "exceptionDetails",
                            JsonValue::obj(vec![
                                ("text", JsonValue::str(e)),
                                ("exceptionId", JsonValue::Num(1.0)),
                                ("columnNumber", JsonValue::Num(0.0)),
                                ("lineNumber", JsonValue::Num(0.0)),
                            ]),
                        ),
                    ])),
                }
            }
            "Runtime.discardConsoleEntries" | "Runtime.releaseObjectGroup" => {
                Ok(JsonValue::obj(vec![]))
            }
            "Runtime.callFunctionOn" => {
                let decl = cmd
                    .params
                    .get("functionDeclaration")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("functionDeclaration required"))?
                    .to_string();
                let return_by_value = cmd
                    .params
                    .get("returnByValue")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                let args_json: Vec<JsonValue> = match cmd.params.get("arguments") {
                    Some(JsonValue::Arr(a)) => a.clone(),
                    _ => Vec::new(),
                };
                let object_id = cmd
                    .params
                    .get("objectId")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string);
                let (this_val, arg_refs) = {
                    let session = self.session_for(cmd)?;
                    let this_val = object_id
                        .as_ref()
                        .and_then(|id| session.remote_objects.get(id.as_str()).cloned());
                    let arg_refs: Vec<Option<JsVal>> = args_json
                        .iter()
                        .map(|a| {
                            a.get("objectId")
                                .and_then(JsonValue::as_str)
                                .and_then(|id| session.remote_objects.get(id).cloned())
                        })
                        .collect();
                    (this_val, arg_refs)
                };
                let outcome = self.with_session_interp(cmd, host, |interp| {
                    let src = format!("({decl})");
                    let prog = parser::parse(&src)
                        .map_err(|e| JsVal::str(format!("SyntaxError: {}", e.message)))?;
                    let f = interp.run_program(&prog)?;
                    let mut args: Vec<JsVal> = Vec::new();
                    for (a, r) in args_json.iter().zip(arg_refs.iter()) {
                        match r {
                            Some(v) => args.push(v.clone()),
                            None => {
                                let jv =
                                    json_to_js(interp, a.get("value").unwrap_or(&JsonValue::Null));
                                args.push(jv);
                            }
                        }
                    }
                    let this = this_val
                        .clone()
                        .unwrap_or(JsVal::Object(interp.global_object.clone()));
                    interp.call(f, this, &args)
                })?;
                let session = self.session_for(cmd)?;
                match outcome {
                    Ok(value) => {
                        let result = if return_by_value {
                            JsonValue::obj(vec![
                                ("type", JsonValue::str(value.type_of())),
                                ("value", js_to_json(&value, 0)),
                                ("description", JsonValue::str(value.to_js_string())),
                            ])
                        } else {
                            remote_object(session, &value)
                        };
                        Ok(JsonValue::obj(vec![("result", result)]))
                    }
                    Err(e) => Ok(JsonValue::obj(vec![
                        (
                            "result",
                            JsonValue::obj(vec![
                                ("type", JsonValue::str("undefined")),
                                ("value", JsonValue::Null),
                                ("description", JsonValue::str("")),
                            ]),
                        ),
                        (
                            "exceptionDetails",
                            JsonValue::obj(vec![
                                ("text", JsonValue::str(e)),
                                ("exceptionId", JsonValue::Num(1.0)),
                                ("columnNumber", JsonValue::Num(0.0)),
                                ("lineNumber", JsonValue::Num(0.0)),
                            ]),
                        ),
                    ])),
                }
            }
            "Runtime.getProperties" => {
                let object_id = cmd
                    .params
                    .get("objectId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("objectId required"))?
                    .to_string();
                let session = self.session_for(cmd)?;
                let Some(v) = session.remote_objects.get(&object_id).cloned() else {
                    return Err(invalid("no such object"));
                };
                let mut props: Vec<(String, JsVal)> = Vec::new();
                if let JsVal::Object(o) = &v {
                    let b = o.borrow();
                    if matches!(b.kind, ObjKind::Array) {
                        for (i, e) in b.elems.iter().enumerate() {
                            if let Some(e) = e {
                                props.push((i.to_string(), e.clone()));
                            }
                        }
                        props.push(("length".to_string(), JsVal::Num(b.array_length() as f64)));
                    }
                    for (k, p) in &b.props {
                        if let Prop::Value {
                            value,
                            enumerable: true,
                        } = p
                        {
                            props.push((k.clone(), value.clone()));
                        }
                    }
                }
                let result: Vec<JsonValue> = props
                    .into_iter()
                    .map(|(k, val)| {
                        JsonValue::obj(vec![
                            ("name", JsonValue::str(k)),
                            ("value", remote_object(session, &val)),
                            ("writable", JsonValue::Bool(true)),
                            ("configurable", JsonValue::Bool(true)),
                            ("enumerable", JsonValue::Bool(true)),
                            ("isOwn", JsonValue::Bool(true)),
                        ])
                    })
                    .collect();
                Ok(JsonValue::obj(vec![("result", JsonValue::Arr(result))]))
            }
            "Runtime.releaseObject" => {
                let object_id = cmd
                    .params
                    .get("objectId")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                let session = self.session_for(cmd)?;
                session.remote_objects.remove(&object_id);
                Ok(JsonValue::obj(vec![]))
            }
            "Runtime.compileScript" => {
                let expr = cmd
                    .params
                    .get("expression")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("expression required"))?
                    .to_string();
                let persist = cmd
                    .params
                    .get("persistScript")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                // A parse failure is exceptionDetails, as in Chrome.
                if let Err(e) = parser::parse(&expr) {
                    return Ok(JsonValue::obj(vec![(
                        "exceptionDetails",
                        JsonValue::obj(vec![
                            ("text", JsonValue::str(format!("SyntaxError: {}", e.message))),
                            ("exceptionId", JsonValue::Num(1.0)),
                            ("lineNumber", JsonValue::Num(0.0)),
                            ("columnNumber", JsonValue::Num(0.0)),
                        ]),
                    )]));
                }
                if !persist {
                    return Ok(JsonValue::obj(vec![]));
                }
                let session = self.session_for(cmd)?;
                let id = format!("compiled-{}", session.next_compiled_id);
                session.next_compiled_id = session.next_compiled_id.wrapping_add(1);
                session.compiled.push((id.clone(), expr));
                Ok(JsonValue::obj(vec![("scriptId", JsonValue::str(id))]))
            }
            "Runtime.runScript" => {
                let script_id = cmd
                    .params
                    .get("scriptId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("scriptId required"))?
                    .to_string();
                let return_by_value = cmd
                    .params
                    .get("returnByValue")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                let source = {
                    let session = self.session_for(cmd)?;
                    session
                        .compiled
                        .iter()
                        .find(|(id, _)| id == &script_id)
                        .map(|(_, s)| s.clone())
                        .ok_or_else(|| invalid("no such script"))?
                };
                let outcome = self.with_session_interp(cmd, host, |interp| {
                    let prog = parser::parse(&source)
                        .map_err(|e| JsVal::str(format!("SyntaxError: {}", e.message)))?;
                    interp.run_program(&prog)
                })?;
                let session = self.session_for(cmd)?;
                Ok(eval_result_json(session, outcome, return_by_value))
            }
            "Runtime.awaitPromise" => {
                let object_id = cmd
                    .params
                    .get("promiseObjectId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("promiseObjectId required"))?
                    .to_string();
                let return_by_value = cmd
                    .params
                    .get("returnByValue")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                let target = {
                    let session = self.session_for(cmd)?;
                    session
                        .remote_objects
                        .get(&object_id)
                        .cloned()
                        .ok_or_else(|| invalid("no such object"))?
                };
                let outcome = self.with_session_interp(cmd, host, |interp| match &target {
                    JsVal::Object(o) if matches!(o.borrow().kind, ObjKind::Promise(_)) => {
                        interp.await_promise(o)
                    }
                    other => Ok(other.clone()),
                })?;
                let session = self.session_for(cmd)?;
                Ok(eval_result_json(session, outcome, return_by_value))
            }
            "Runtime.addBinding" => {
                let name = cmd
                    .params
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("name required"))?
                    .to_string();
                {
                    let session = self.session_for(cmd)?;
                    if !session.bindings.iter().any(|b| b == &name) {
                        session.bindings.push(name);
                    }
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Runtime.removeBinding" => {
                let name = cmd
                    .params
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("name required"))?
                    .to_string();
                let removed = {
                    let session = self.session_for(cmd)?;
                    let before = session.bindings.len();
                    session.bindings.retain(|b| b != &name);
                    before != session.bindings.len()
                };
                if removed {
                    // Drop the global so later calls fail as in Chrome.
                    let _ = self.with_session_interp(cmd, host, |interp| {
                        // `delete` keeps the property index coherent; a raw
                        // `props.retain` would leave `own()` pointing at a
                        // stale slot and `typeof` still answering "function".
                        interp.global_object.borrow_mut().delete(&name);
                        interp.global_scope.borrow_mut().vars.remove(&name);
                        Ok(())
                    })?;
                }
                Ok(JsonValue::obj(vec![]))
            }
            "Runtime.globalLexicalScopeNames" => {
                let names = self.with_session_interp(cmd, host, |interp| {
                    let scope = interp.global_scope.borrow();
                    let mut names: Vec<String> = scope
                        .vars
                        .keys()
                        .filter(|k| {
                            // Lexical (let/const/class) bindings live in the
                            // scope but not on the global object.
                            interp.global_object.borrow().get_prop(k).is_none()
                        })
                        .cloned()
                        .collect();
                    names.sort();
                    Ok(names)
                })?
                .unwrap_or_default();
                Ok(JsonValue::obj(vec![(
                    "names",
                    JsonValue::Arr(names.into_iter().map(JsonValue::str).collect()),
                )]))
            }
            "Runtime.queryObjects" => {
                let proto_id = cmd
                    .params
                    .get("prototypeObjectId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("prototypeObjectId required"))?
                    .to_string();
                let session = self.session_for(cmd)?;
                let Some(JsVal::Object(proto)) = session.remote_objects.get(&proto_id).cloned()
                else {
                    return Err(invalid("prototypeObjectId is not an object"));
                };
                // The engine has no heap walker; the reachable candidates are
                // the session's own remote objects whose prototype chain
                // includes `proto`.
                let hits: Vec<JsVal> = session
                    .remote_objects
                    .values()
                    .filter(|v| match v {
                        JsVal::Object(o) => {
                            let mut cur = o.borrow().proto.clone();
                            let mut depth = 0;
                            let mut found = false;
                            while let Some(p) = cur {
                                if Rc::ptr_eq(&p, &proto) {
                                    found = true;
                                    break;
                                }
                                depth += 1;
                                if depth > 64 {
                                    break;
                                }
                                cur = p.borrow().proto.clone();
                            }
                            found
                        }
                        _ => false,
                    })
                    .cloned()
                    .collect();
                let arr = JsVal::Object(JsObject::new(ObjKind::Array, None));
                if let JsVal::Object(a) = &arr {
                    a.borrow_mut().set_elems(hits.into_iter().map(Some).collect());
                }
                Ok(JsonValue::obj(vec![("objects", remote_object(session, &arr))]))
            }
            "Runtime.runIfWaitingForDebugger" | "Runtime.setAsyncCallStackDepth" => {
                Ok(JsonValue::obj(vec![]))
            }
            other => Err(method_not_found(other)),
        }
    }
}

/// The result half of an evaluation reply: a RemoteObject (or by-value
/// shape) on success, the `exceptionDetails` shape on a thrown value.
fn eval_result_json(
    session: &mut Session,
    outcome: Result<JsVal, String>,
    return_by_value: bool,
) -> JsonValue {
    match outcome {
        Ok(value) => {
            let result = if return_by_value {
                JsonValue::obj(vec![
                    ("type", JsonValue::str(value.type_of())),
                    ("value", js_to_json(&value, 0)),
                    ("description", JsonValue::str(value.to_js_string())),
                ])
            } else {
                remote_object(session, &value)
            };
            JsonValue::obj(vec![("result", result)])
        }
        Err(e) => JsonValue::obj(vec![
            (
                "result",
                JsonValue::obj(vec![
                    ("type", JsonValue::str("undefined")),
                    ("value", JsonValue::Null),
                    ("description", JsonValue::str("")),
                ]),
            ),
            (
                "exceptionDetails",
                JsonValue::obj(vec![
                    ("text", JsonValue::str(e)),
                    ("exceptionId", JsonValue::Num(1.0)),
                    ("columnNumber", JsonValue::Num(0.0)),
                    ("lineNumber", JsonValue::Num(0.0)),
                ]),
            ),
        ]),
    }
}

/// Decode a CDP CallArgument `value` into a live JS value.
fn json_to_js(interp: &mut Interp<'_>, v: &JsonValue) -> JsVal {
    match v {
        JsonValue::Null => JsVal::Null,
        JsonValue::Bool(b) => JsVal::Bool(*b),
        JsonValue::Num(n) => JsVal::Num(*n),
        JsonValue::Str(s) => JsVal::str(s.clone()),
        JsonValue::Arr(items) => {
            let elems: Vec<JsVal> = items.iter().map(|i| json_to_js(interp, i)).collect();
            interp.new_array(elems)
        }
        JsonValue::Obj(entries) => {
            let obj = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            for (k, val) in entries {
                let jv = json_to_js(interp, val);
                obj.borrow_mut().set_prop(k, jv, true);
            }
            JsVal::Object(obj)
        }
    }
}
