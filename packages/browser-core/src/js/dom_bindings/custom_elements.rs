//! `customElements`: the registry, upgrades and lifecycle callbacks.

use std::rc::Rc;
use super::super::interp::Interp;
use super::super::super::dom::Document;
use super::super::super::dom::NodeId;
use super::super::value::JsObject;
use super::super::value::JsValue;
use super::super::value::NativeFn;
use super::super::value::ObjKind;
use super::super::value::ObjRef;
use super::super::value::Prop;
use super::{define_method, handle_of, node_id, wrap_node};

/// The hidden global holding the `customElements` registry's definitions:
/// a plain object mapping each defined name to its constructor.
pub(super) const CE_DEFINITIONS: &str = "__ceDefinitions";

/// The hidden global holding the pending `whenDefined` promises by name.
const CE_WAITERS: &str = "__ceWaiters";

/// The marker property on an upgraded element wrapper.
pub(super) const CE_UPGRADED: &str = "__ceUpgraded";

/// The marker property set once `connectedCallback` ran for the current
/// connection (cleared on disconnect so a re-insertion fires it again).
const CE_CONNECTED: &str = "__ceConnected";

fn hidden_global_object(interp: &mut Interp, name: &str) -> ObjRef {
    let existing = interp.global_object.borrow().get_prop(name);
    if let Some(JsValue::Object(o)) = existing {
        return o;
    }
    let o = JsObject::new(ObjKind::Plain, None);
    interp
        .global_object
        .borrow_mut()
        .set_prop(name, JsValue::Object(o.clone()), false);
    o
}

/// A valid custom element name (HTML §4.13.3): lower-case, starts with
/// an ASCII letter, contains a hyphen, and is not one of the reserved
/// hyphenated SVG/MathML names.
fn is_valid_custom_element_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() || !name.contains('-') {
        return false;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_') || c as u32 >= 0xB7)
    {
        return false;
    }
    !matches!(
        name,
        "annotation-xml"
            | "color-profile"
            | "font-face"
            | "font-face-src"
            | "font-face-uri"
            | "font-face-format"
            | "font-face-name"
            | "missing-glyph"
    )
}

/// The constructor `customElements.define`d for `tag`, if any.
fn custom_element_definition(interp: &mut Interp, tag: &str) -> Option<ObjRef> {
    let defs = interp.global_object.borrow().get_prop(CE_DEFINITIONS)?;
    let JsValue::Object(defs) = defs else {
        return None;
    };
    let found = defs.borrow().get_prop(tag);
    match found {
        Some(JsValue::Object(c)) => Some(c),
        _ => None,
    }
}

/// Upgrade the element at `handle` when `tag` is a defined custom element
/// and the wrapper has not been upgraded yet: the wrapper's prototype
/// becomes the class's `prototype`, the class constructor runs with the
/// wrapper as `this` (so `super()` in a subclass of HTMLElement returns
/// it and field initialisers land on it), and `attributeChangedCallback`
/// fires for each observed attribute already present.
pub(super) fn upgrade_custom_element(interp: &mut Interp, handle: usize, tag: &str) -> Result<bool, JsValue> {
    let Some(ctor) = custom_element_definition(interp, tag) else {
        return Ok(false);
    };
    let wrapper = match wrap_node(interp, handle) {
        JsValue::Object(o) => o,
        _ => return Ok(false),
    };
    if wrapper.borrow().get_prop(CE_UPGRADED).is_some() {
        return Ok(false);
    }
    let proto = match interp.get_property(&JsValue::Object(ctor.clone()), "prototype")? {
        JsValue::Object(p) => Some(p),
        _ => None,
    };
    // The wrapper takes the class's prototype for the constructor run;
    // the marker is set only once construction SUCCEEDED. A throwing
    // constructor leaves the element un-upgraded (HTML's "failed" custom
    // element state: the prototype is restored, the error is reported,
    // and nothing is marked), so a later definition or upgrade attempt
    // is not refused by a stale marker.
    let previous_proto = wrapper.borrow().proto.clone();
    wrapper.borrow_mut().proto = proto;
    let outcome = run_custom_element_constructor(interp, &ctor, &wrapper);
    if let Err(e) = outcome {
        wrapper.borrow_mut().proto = previous_proto;
        return Err(e);
    }
    wrapper
        .borrow_mut()
        .set_prop(CE_UPGRADED, JsValue::Bool(true), false);
    // attributeChangedCallback for observed attributes present at upgrade.
    let observed: Vec<String> = match interp.get_property(&JsValue::Object(ctor), "observedAttributes")? {
        JsValue::Object(list) => {
            let items = interp.iterate(&JsValue::Object(list))?;
            items.iter().map(|v| v.to_js_string()).collect()
        }
        _ => Vec::new(),
    };
    if !observed.is_empty() {
        let cb = interp.get_property(&JsValue::Object(wrapper.clone()), "attributeChangedCallback")?;
        if matches!(&cb, JsValue::Object(f) if f.borrow().is_callable()) {
            let present: Vec<(String, String)> = match interp.dom.clone() {
                Some(dom) => {
                    let doc = dom.borrow();
                    doc.get(node_id(handle))
                        .and_then(|n| n.as_element())
                        .map(|e| {
                            e.attrs
                                .iter()
                                .filter(|(k, _)| observed.iter().any(|o| o == k))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default()
                }
                None => Vec::new(),
            };
            for (k, v) in present {
                interp.call(
                    cb.clone(),
                    JsValue::Object(wrapper.clone()),
                    &[JsValue::str(k), JsValue::Null, JsValue::str(v), JsValue::Null],
                )?;
            }
        }
    }
    Ok(true)
}

/// Run a custom element's constructor with `wrapper` as the element
/// under construction. A class constructor refuses a plain call, so the
/// upgrade drives it through `construct`; the instance it allocates has
/// the wrapper's prototype already, and its own properties (field
/// initialisers) are copied onto the wrapper so they are observable on
/// the element. The `__ceUnderConstruction` slot is what the `HTMLElement`
/// base constructor answers `super()` with, and it is cleared on every
/// path out.
fn run_custom_element_constructor(
    interp: &mut Interp,
    ctor: &ObjRef,
    wrapper: &ObjRef,
) -> Result<(), JsValue> {
    interp
        .global_object
        .borrow_mut()
        .set_prop("__ceUnderConstruction", JsValue::Object(wrapper.clone()), false);
    let out = interp.construct(JsValue::Object(ctor.clone()), &[]);
    interp
        .global_object
        .borrow_mut()
        .set_prop("__ceUnderConstruction", JsValue::Undefined, false);
    match out {
        Ok(JsValue::Object(inst)) if !Rc::ptr_eq(&inst, wrapper) => {
            // Only data properties travel; accessors stay on the class
            // prototype the wrapper now inherits from.
            let props: Vec<(String, JsValue, bool)> = inst
                .borrow()
                .props
                .iter()
                .filter_map(|(k, p)| match p {
                    Prop::Value { value, enumerable } => {
                        Some((k.clone(), value.clone(), *enumerable))
                    }
                    Prop::Accessor { .. } => None,
                })
                .collect();
            let mut b = wrapper.borrow_mut();
            for (k, value, enumerable) in props {
                b.set_prop(&k, value, enumerable);
            }
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether `node` is in the connected tree (a descendant of the document
/// root, not of a detached holder).
fn is_connected(doc: &Document, node: NodeId) -> bool {
    let mut cur = Some(node);
    while let Some(n) = cur {
        if n == NodeId::DOCUMENT {
            return true;
        }
        cur = doc.get(n).and_then(|x| x.parent);
    }
    false
}

/// For each root and its descendants that is a defined custom element:
/// upgrade it (if not yet) and, when it is connected, run
/// `connectedCallback` once per connection. With `require_connected`
/// (node insertion), detached roots are skipped entirely;
/// `customElements.upgrade(root)` passes `false` so a detached subtree is
/// upgraded too (only the connected callback depends on connection).
/// Errors in a callback are reported to the console and do not abort the
/// insertion (the spec reports them as exceptions on the element's
/// global).
pub(super) fn connect_custom_elements(interp: &mut Interp, roots: &[NodeId]) {
    upgrade_candidates(interp, roots, true);
}

fn upgrade_candidates(interp: &mut Interp, roots: &[NodeId], require_connected: bool) {
    let defs_present = interp.global_object.borrow().get_prop(CE_DEFINITIONS).is_some();
    if !defs_present {
        return;
    }
    let Some(dom) = interp.dom.clone() else {
        return;
    };
    let candidates: Vec<(usize, String, bool)> = {
        let doc = dom.borrow();
        let mut out = Vec::new();
        for r in roots {
            let connected = is_connected(&doc, *r);
            if require_connected && !connected {
                continue;
            }
            let mut walk: Vec<NodeId> = vec![*r];
            walk.extend(doc.descendants(*r));
            for n in walk {
                if let Some(e) = doc.get(n).and_then(|x| x.as_element()) {
                    if e.tag.contains('-') {
                        out.push((n.index(), e.tag.clone(), connected));
                    }
                }
            }
        }
        out
    };
    for (h, tag, connected) in candidates {
        if custom_element_definition(interp, &tag).is_none() {
            continue;
        }
        if let Err(e) = upgrade_custom_element(interp, h, &tag) {
            let msg = super::super::interp::to_display(&e);
            interp.hooks.console("error", &format!("uncaught (in custom element upgrade): {msg}"));
            continue;
        }
        if !connected {
            continue;
        }
        if let Err(e) = run_connected_callback(interp, h) {
            let msg = super::super::interp::to_display(&e);
            interp.hooks.console("error", &format!("uncaught (in connectedCallback): {msg}"));
        }
    }
}

fn run_connected_callback(interp: &mut Interp, handle: usize) -> Result<(), JsValue> {
    let wrapper = match wrap_node(interp, handle) {
        JsValue::Object(o) => o,
        _ => return Ok(()),
    };
    if wrapper.borrow().get_prop(CE_CONNECTED).is_some() {
        return Ok(());
    }
    wrapper
        .borrow_mut()
        .set_prop(CE_CONNECTED, JsValue::Bool(true), false);
    let cb = interp.get_property(&JsValue::Object(wrapper.clone()), "connectedCallback")?;
    if matches!(&cb, JsValue::Object(f) if f.borrow().is_callable()) {
        interp.call(cb, JsValue::Object(wrapper), &[])?;
    }
    Ok(())
}

/// `customElements`: `define(name, ctor, options)`, `get(name)`,
/// `whenDefined(name)` (a promise resolved with the constructor when the
/// name is defined), `upgrade(root)`. Defining a name upgrades every
/// matching element already in the document (and runs their
/// `connectedCallback`), the way the spec's "upgrade candidates" work.
pub(super) fn install_custom_elements(interp: &mut Interp) {
    let registry = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
    let define: NativeFn = Rc::new(|interp, _this, args| {
        let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        if !is_valid_custom_element_name(&name) {
            return Err(Interp::throw(format!(
                "SyntaxError: Failed to execute 'define' on 'CustomElementRegistry': \"{name}\" is not a valid custom element name"
            )));
        }
        let ctor = match args.get(1) {
            Some(JsValue::Object(c)) if c.borrow().is_callable() => c.clone(),
            _ => {
                return Err(Interp::throw(
                    "TypeError: Failed to execute 'define' on 'CustomElementRegistry': parameter 2 is not a constructor",
                ))
            }
        };
        let defs = hidden_global_object(interp, CE_DEFINITIONS);
        if defs.borrow().get_prop(&name).is_some() {
            return Err(Interp::throw(format!(
                "NotSupportedError: Failed to execute 'define' on 'CustomElementRegistry': the name \"{name}\" has already been used with this registry"
            )));
        }
        // One constructor per name, and one name per constructor.
        let already: bool = defs
            .borrow()
            .props
            .iter()
            .any(|(_, p)| matches!(p, Prop::Value { value: JsValue::Object(c), .. } if Rc::ptr_eq(c, &ctor)));
        if already {
            return Err(Interp::throw(
                "NotSupportedError: Failed to execute 'define' on 'CustomElementRegistry': this constructor has already been used with this registry",
            ));
        }
        defs.borrow_mut()
            .set_prop(&name, JsValue::Object(ctor.clone()), true);
        // Upgrade the candidates already in the connected document.
        let candidates: Vec<usize> = match interp.dom.clone() {
            Some(dom) => {
                let doc = dom.borrow();
                doc.descendants(NodeId::DOCUMENT)
                    .filter(|n| {
                        doc.get(*n)
                            .and_then(|x| x.as_element())
                            .map(|e| e.tag == name)
                            .unwrap_or(false)
                    })
                    .map(|n| n.index())
                    .collect()
            }
            None => Vec::new(),
        };
        for h in candidates {
            if let Err(e) = upgrade_custom_element(interp, h, &name) {
                let msg = super::super::interp::to_display(&e);
                interp.hooks.console("error", &format!("uncaught (in custom element upgrade): {msg}"));
                continue;
            }
            if let Err(e) = run_connected_callback(interp, h) {
                let msg = super::super::interp::to_display(&e);
                interp.hooks.console("error", &format!("uncaught (in connectedCallback): {msg}"));
            }
        }
        // Settle the `whenDefined` waiters for this name.
        let waiters = hidden_global_object(interp, CE_WAITERS);
        let pending = waiters.borrow().get_prop(&name);
        if let Some(JsValue::Object(list)) = pending {
            let resolvers: Vec<JsValue> = list.borrow().array_values();
            waiters.borrow_mut().delete(&name);
            for r in resolvers {
                interp.call(r, JsValue::Undefined, &[JsValue::Object(ctor.clone())])?;
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, &registry, "define", define);
    let get: NativeFn = Rc::new(|interp, _this, args| {
        let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        Ok(match custom_element_definition(interp, &name) {
            Some(c) => JsValue::Object(c),
            None => JsValue::Undefined,
        })
    });
    define_method(interp, &registry, "get", get);
    let get_name: NativeFn = Rc::new(|interp, _this, args| {
        let Some(JsValue::Object(ctor)) = args.first() else {
            return Ok(JsValue::Null);
        };
        let defs = hidden_global_object(interp, CE_DEFINITIONS);
        let found = defs
            .borrow()
            .props
            .iter()
            .find(|(_, p)| matches!(p, Prop::Value { value: JsValue::Object(c), .. } if Rc::ptr_eq(c, ctor)))
            .map(|(k, _)| k.clone());
        Ok(found.map(JsValue::str).unwrap_or(JsValue::Null))
    });
    define_method(interp, &registry, "getName", get_name);
    let when_defined: NativeFn = Rc::new(|interp, _this, args| {
        let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        if !is_valid_custom_element_name(&name) {
            let err = Interp::throw(format!(
                "SyntaxError: Failed to execute 'whenDefined' on 'CustomElementRegistry': \"{name}\" is not a valid custom element name"
            ));
            return Ok(interp.rejected_promise(err));
        }
        if let Some(c) = custom_element_definition(interp, &name) {
            return Ok(interp.resolved_promise(JsValue::Object(c)));
        }
        let (promise, resolve, _reject) = interp.new_promise_with_resolvers();
        let waiters = hidden_global_object(interp, CE_WAITERS);
        let list = match waiters.borrow().get_prop(&name) {
            Some(JsValue::Object(l)) => Some(l),
            _ => None,
        };
        let list = match list {
            Some(l) => l,
            None => {
                let l = match interp.new_array(Vec::new()) {
                    JsValue::Object(l) => l,
                    _ => return Ok(promise),
                };
                waiters
                    .borrow_mut()
                    .set_prop(&name, JsValue::Object(l.clone()), true);
                l
            }
        };
        list.borrow_mut().elems.push(Some(resolve));
        Ok(promise)
    });
    define_method(interp, &registry, "whenDefined", when_defined);
    let upgrade: NativeFn = Rc::new(|interp, _this, args| {
        if let Some(root) = args.first().and_then(handle_of) {
            upgrade_candidates(interp, &[node_id(root)], false);
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, &registry, "upgrade", upgrade);
    interp
        .global_object
        .borrow_mut()
        .set_prop("customElements", JsValue::Object(registry.clone()), true);
    super::super::interp::Scope::declare(
        &interp.global_scope.clone(),
        "customElements",
        JsValue::Object(registry),
        false,
    );
    // `CustomElementRegistry` as an interface object too.
    let iface: NativeFn = Rc::new(|_i, _t, _a| Err(Interp::throw("TypeError: Illegal constructor")));
    let f = interp.native(iface);
    interp.set_global("CustomElementRegistry", f);
}
