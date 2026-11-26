//! The `document` global, the element prototype and the window surface.

use std::ops::Not as _;
use std::rc::Rc;
use super::super::interp::Interp;
use super::super::super::dom::NodeData;
use super::super::super::dom::NodeId;
use super::super::super::html;
use super::super::value::JsObject;
use super::super::value::JsValue;
use super::super::value::NativeFn;
use super::super::value::ObjKind;
use super::super::value::ObjRef;
use super::super::value::Prop;
use super::{clone_subtree, define_method, dom_list, handle_of, insert_list, install_node_list_interfaces, is_ancestor_of, node_for_insert, node_id, node_tag, wrap_node};
use super::activation::{activate, focus_node, submit_form_steps};
use super::custom_elements::{CE_DEFINITIONS, CE_UPGRADED, install_custom_elements, upgrade_custom_element};
use super::observers::{install_observers};
use super::properties::{css_to_camel, element_matches};
use super::scripts::{start_inserted_scripts};

/// Install `document`, `window`, and element method natives into the realm.
pub(super) fn noop_method() -> NativeFn {
    Rc::new(|_i, _t, _a| Ok(JsValue::Undefined))
}

fn zero_rect_method() -> NativeFn {
    Rc::new(|interp, _this, _args| {
        let r = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        for k in ["x", "y", "top", "left", "right", "bottom", "width", "height"] {
            r.borrow_mut().set_prop(k, JsValue::Num(0.0), true);
        }
        Ok(JsValue::Object(r))
    })
}

pub fn install_document(interp: &mut Interp) {
    // Shared element prototype: every wrapped node (and document itself)
    // inherits these methods, so script sees a uniform DOM surface.
    let element_proto = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));

    install_tree_methods(interp, &element_proto);
    install_attribute_methods(interp, &element_proto);
    install_event_methods(interp, &element_proto);
    install_query_methods(interp, &element_proto);
    install_structure_methods(interp, &element_proto);
    install_insertion_methods(interp, &element_proto);

    // Publish the prototype (hidden, non-enumerable) so wrap_node finds it.
    interp.global_object.borrow_mut().set_prop(
        "__ElementProto",
        JsValue::Object(element_proto.clone()),
        false,
    );

    // document object: a DomNode wrapper for the root, inheriting the
    // element prototype so addEventListener/querySelector work on it too.
    // The document wrapper is the identity for handle 0 too, so
    // `el.ownerDocument === document` holds.
    let doc_obj = match interp.node_wrappers.get(&0) {
        Some(existing) => existing.clone(),
        None => {
            let o = JsObject::new(ObjKind::DomNode(0), Some(element_proto.clone()));
            interp.node_wrappers.insert(0, o.clone());
            o
        }
    };
    install_document_methods(interp, &element_proto, &doc_obj);
    install_window_surface(interp, &doc_obj);
    install_interface_objects(interp, &element_proto);
    // Observers: MutationObserver records nothing (the page settles within
    // one run); IntersectionObserver reports every target as intersecting
    // once, the way a fully visible page would; ResizeObserver reports one
    // size entry. Each gives bundles the callback they wait for.
    install_observers(interp);
    // `Image()` / `new Image()`: an <img> element.
    let image_ctor: NativeFn = Rc::new(|interp, _this, _args| {
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let n = dom.borrow_mut().create_element("img");
        Ok(wrap_node(interp, n.index()))
    });
    let v = interp.native(image_ctor);
    interp.set_global("Image", v);

    // `NodeList` / `HTMLCollection`: the interface objects bundles test
    // with `instanceof` and patch (`NodeList.prototype.forEach = …`).
    // Every DOM list the engine hands out inherits from Array.prototype
    // (so the whole Array surface works on it); the interface prototypes
    // are inserted between: a method added to `NodeList.prototype` is
    // seen by every list, and `list instanceof NodeList` holds.
    install_node_list_interfaces(interp);
    // `customElements`: define / get / whenDefined, with upgrade on
    // creation and insertion and the lifecycle callbacks a defined class
    // expects.
    install_custom_elements(interp);
    // Every interface object has an object `prototype` (WebIDL §3.7.3)
    // pointing back at it, so `x instanceof MouseEvent` answers instead of
    // throwing for a non-object prototype. The constructors above build
    // plain objects, so their results are not instances yet.
    for name in ["PerformanceObserver", "Image", "CustomElementRegistry"] {
        interp.link_prototype_constructor(name);
    }

    let doc_val = JsValue::Object(doc_obj);
    interp
        .global_object
        .borrow_mut()
        .set_prop("document", doc_val.clone(), true);
    super::super::interp::Scope::declare(&interp.global_scope.clone(), "document", doc_val, false);
    // The interface objects and methods installed above get their `name`
    // and `length` like the realm's other built-ins (the shared element
    // prototype is published under a hidden name the walk skips).
    interp.name_builtins_from("Element.prototype", &element_proto);
    interp.name_builtins();
}

fn install_tree_methods(interp: &mut Interp, element_proto: &ObjRef) {
    let append_child: NativeFn = Rc::new(|interp, this, args| {
        let (Some(parent), Some(child)) = (handle_of(&this), args.first().and_then(handle_of))
        else {
            return Err(Interp::throw("TypeError: appendChild expects a node"));
        };
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            if node_id(parent) == node_id(child) || is_ancestor_of(&doc, node_id(child), node_id(parent)) {
                return Err(Interp::throw(
                    "HierarchyRequestError: the new child is an ancestor of the parent",
                ));
            }
            let moved = insert_list(&doc, node_id(child));
            for c in &moved {
                doc.detach(*c);
                doc.append_child(node_id(parent), *c);
            }
            drop(doc);
            start_inserted_scripts(interp, &moved);
        }
        Ok(args.first().cloned().unwrap_or(JsValue::Undefined))
    });
    define_method(interp, element_proto, "appendChild", append_child);

    let remove_child: NativeFn = Rc::new(|interp, _this, args| {
        let Some(child) = args.first().and_then(handle_of) else {
            return Err(Interp::throw("TypeError: removeChild expects a node"));
        };
        if let Some(dom) = interp.dom.clone() {
            dom.borrow_mut().detach(node_id(child));
        }
        Ok(args.first().cloned().unwrap_or(JsValue::Undefined))
    });
    define_method(interp, element_proto, "removeChild", remove_child);

    let remove_self: NativeFn = Rc::new(|interp, this, _args| {
        if let (Some(h), Some(dom)) = (handle_of(&this), interp.dom.clone()) {
            dom.borrow_mut().detach(node_id(h));
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "remove", remove_self);

    let insert_before: NativeFn = Rc::new(|interp, _this, args| {
        let (Some(new), Some(reference)) = (
            args.first().and_then(handle_of),
            args.get(1).and_then(handle_of),
        ) else {
            return Err(Interp::throw("TypeError: insertBefore expects nodes"));
        };
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            if doc.get(node_id(reference)).and_then(|n| n.parent).is_none() {
                return Err(Interp::throw(
                    "NotFoundError: the reference node is not a child of this node",
                ));
            }
            let moved = insert_list(&doc, node_id(new));
            for c in &moved {
                doc.detach(*c);
                doc.insert_before(node_id(reference), *c);
            }
            drop(doc);
            start_inserted_scripts(interp, &moved);
        }
        Ok(args.first().cloned().unwrap_or(JsValue::Undefined))
    });
    // insertBefore(node, null) appends, like the spec says.
    let insert_before_null: NativeFn = Rc::new(|interp, this, args| {
        let Some(parent) = handle_of(&this) else {
            return Err(Interp::throw("TypeError: insertBefore on non-node"));
        };
        let Some(new) = args.first().and_then(handle_of) else {
            return Err(Interp::throw("TypeError: insertBefore expects a node"));
        };
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            let moved = insert_list(&doc, node_id(new));
            for c in &moved {
                doc.detach(*c);
                doc.append_child(node_id(parent), *c);
            }
            drop(doc);
            start_inserted_scripts(interp, &moved);
        }
        Ok(args.first().cloned().unwrap_or(JsValue::Undefined))
    });
    let ib_full: NativeFn = {
        let with_ref = insert_before.clone();
        Rc::new(move |interp, this, args| {
            if args.get(1).map(|v| v.is_nullish()).unwrap_or(true) {
                insert_before_null(interp, this, args)
            } else {
                with_ref(interp, this, args)
            }
        })
    };
    define_method(interp, element_proto, "insertBefore", ib_full);
}

fn install_attribute_methods(interp: &mut Interp, element_proto: &ObjRef) {
    let set_attribute: NativeFn = Rc::new(|interp, this, args| {
        let Some(h) = handle_of(&this) else {
            return Err(Interp::throw("TypeError: setAttribute on non-node"));
        };
        let name = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let value = args.get(1).map(|v| v.to_js_string()).unwrap_or_default();
        if let Some(dom) = interp.dom.clone() {
            dom.borrow_mut().set_attr(node_id(h), &name, &value);
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "setAttribute", set_attribute);

    let get_attribute: NativeFn = Rc::new(|interp, this, args| {
        let Some(h) = handle_of(&this) else {
            return Ok(JsValue::Null);
        };
        let name = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let doc = dom.borrow();
        Ok(doc
            .get(node_id(h))
            .and_then(|n| n.as_element().and_then(|e| e.attr(&name)))
            .map(|v| JsValue::str(v.to_string()))
            .unwrap_or(JsValue::Null))
    });
    define_method(interp, element_proto, "getAttribute", get_attribute);

    let has_attribute: NativeFn = Rc::new(|interp, this, args| {
        let Some(h) = handle_of(&this) else {
            return Ok(JsValue::Bool(false));
        };
        let name = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Bool(false));
        };
        let doc = dom.borrow();
        Ok(JsValue::Bool(
            doc.get(node_id(h))
                .and_then(|n| n.as_element().map(|e| e.attr(&name).is_some()))
                .unwrap_or(false),
        ))
    });
    define_method(interp, element_proto, "hasAttribute", has_attribute);

    let remove_attribute: NativeFn = Rc::new(|interp, this, args| {
        let Some(h) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        let name = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            if doc.get(node_id(h)).is_some() {
                if let NodeData::Element(e) = &mut doc.node_mut(node_id(h)).data {
                    e.attrs.retain(|(n, _)| n != &name);
                }
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "removeAttribute", remove_attribute);
}

fn install_event_methods(interp: &mut Interp, element_proto: &ObjRef) {
    let listener: NativeFn = Rc::new(|interp, this, args| {
        let event = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let cb = args.get(1).cloned().unwrap_or(JsValue::Undefined);
        if matches!(cb, JsValue::Object(_)) {
            match handle_of(&this) {
                Some(h) => interp.add_node_listener(h, &event, cb),
                None => interp.add_listener(&event, cb),
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "addEventListener", listener.clone());
    let remove_listener: NativeFn = Rc::new(|interp, this, args| {
        let event = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let cb = args.get(1).cloned().unwrap_or(JsValue::Undefined);
        match handle_of(&this) {
            Some(h) => interp.remove_node_listener(h, &event, &cb),
            None => {
                if let Some(list) = interp.listeners.get_mut(&event) {
                    list.retain(|c| !super::super::interp::strict_eq(c, &cb));
                }
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "removeEventListener", remove_listener);

    // dispatchEvent(event): the SUPPLIED event object (built by `new
    // Event(...)`, `new CustomEvent(...)`, or a plain object literal) travels
    // through the engine's event model, so the caller observes `target`,
    // `defaultPrevented` and its own custom properties afterwards. A plain
    // literal without the Event methods gets them attached first.
    let dispatch_event: NativeFn = Rc::new(|interp, this, args| {
        let Some(h) = handle_of(&this) else {
            return Err(Interp::throw("TypeError: dispatchEvent on non-node"));
        };
        let Some(JsValue::Object(ev)) = args.first() else {
            return Err(Interp::throw("TypeError: dispatchEvent expects an Event"));
        };
        // An Event inherits its methods; a plain object gets them.
        let has_methods = interp.has_property(ev, "preventDefault")?;
        if !has_methods {
            let cancelable = ev.borrow().get_prop("cancelable").is_some_and(|v| v.truthy());
            let methods: Vec<(&str, JsValue)> = super::super::events::event_methods()
                .into_iter()
                .map(|(k, f)| (k, interp.native(f)))
                .collect();
            let mut b = ev.borrow_mut();
            for (k, v) in methods {
                b.set_prop(k, v, false);
            }
            b.set_prop("cancelable", JsValue::Bool(cancelable), true);
            b.set_prop("defaultPrevented", JsValue::Bool(false), true);
            b.set_prop("isTrusted", JsValue::Bool(false), true);
        } else {
            ev.borrow_mut()
                .set_prop("isTrusted", JsValue::Bool(false), true);
        }
        let ok = interp.dispatch_event_object(h, ev)?;
        Ok(JsValue::Bool(ok))
    });
    define_method(interp, element_proto, "dispatchEvent", dispatch_event);

    // click(): the activation behaviour — a bubbling `click`, then the
    // element's default action (checkbox/radio toggle; a submit button
    // submits its form). Link navigation is the embedder's default action
    // (it owns the network), observable through `pendingNavigation`.
    let click: NativeFn = Rc::new(|interp, this, _args| {
        let Some(h) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        activate(interp, h)?;
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "click", click);

    let focus: NativeFn = Rc::new(|interp, this, _args| {
        if let Some(h) = handle_of(&this) {
            focus_node(interp, h)?;
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "focus", focus);
    let blur: NativeFn = Rc::new(|interp, this, _args| {
        if let Some(h) = handle_of(&this) {
            if interp.focused == Some(h) {
                interp.focused = None;
                interp.dispatch_node_event(h, "blur", false, &[])?;
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "blur", blur);

    // form.submit() — the legacy API: submit WITHOUT firing the cancelable
    // `submit` event (HTML §4.10.21.3). form.requestSubmit() fires the event
    // first, exactly like a user-activated submit button. Both record the
    // navigation for the embedder through `__pendingNavigation*`.
    let submit_fn: NativeFn = Rc::new(|interp, this, _args| {
        if let Some(h) = handle_of(&this) {
            if node_tag(interp, h).as_deref() == Some("form") {
                submit_form_steps(interp, h, false)?;
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "submit", submit_fn);
    let request_submit: NativeFn = Rc::new(|interp, this, _args| {
        if let Some(h) = handle_of(&this) {
            if node_tag(interp, h).as_deref() == Some("form") {
                submit_form_steps(interp, h, true)?;
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "requestSubmit", request_submit);
}

fn install_query_methods(interp: &mut Interp, element_proto: &ObjRef) {
    let matches_fn: NativeFn = Rc::new(|interp, this, args| {
        let sel = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let (Some(h), Some(dom)) = (handle_of(&this), interp.dom.clone()) else {
            return Ok(JsValue::Bool(false));
        };
        let doc = dom.borrow();
        let hit = element_matches(&doc, node_id(h), &sel)?;
        Ok(JsValue::Bool(hit))
    });
    define_method(interp, element_proto, "matches", matches_fn.clone());
    define_method(interp, element_proto, "webkitMatchesSelector", matches_fn.clone());
    define_method(interp, element_proto, "msMatchesSelector", matches_fn);

    let closest: NativeFn = Rc::new(|interp, this, args| {
        let sel = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let (Some(h), Some(dom)) = (handle_of(&this), interp.dom.clone()) else {
            return Ok(JsValue::Null);
        };
        let found = {
            let doc = dom.borrow();
            let mut cur = Some(node_id(h));
            let mut hit = None;
            while let Some(n) = cur {
                if doc.get(n).and_then(|x| x.as_element()).is_some()
                    && element_matches(&doc, n, &sel)?
                {
                    hit = Some(n);
                    break;
                }
                cur = doc.get(n).and_then(|x| x.parent);
            }
            hit
        };
        Ok(match found {
            Some(n) => wrap_node(interp, n.index()),
            None => JsValue::Null,
        })
    });
    define_method(interp, element_proto, "closest", closest);

    let contains: NativeFn = Rc::new(|interp, this, args| {
        let (Some(h), Some(other), Some(dom)) = (
            handle_of(&this),
            args.first().and_then(handle_of),
            interp.dom.clone(),
        ) else {
            return Ok(JsValue::Bool(false));
        };
        let doc = dom.borrow();
        let mut cur = Some(node_id(other));
        while let Some(n) = cur {
            if n == node_id(h) {
                return Ok(JsValue::Bool(true));
            }
            cur = doc.get(n).and_then(|x| x.parent);
        }
        Ok(JsValue::Bool(false))
    });
    define_method(interp, element_proto, "contains", contains);

    let by_tag: NativeFn = Rc::new(|interp, this, args| {
        let tag = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let root = handle_of(&this).map(node_id).unwrap_or(NodeId::DOCUMENT);
        let Some(dom) = interp.dom.clone() else {
            return Ok(interp.new_array(Vec::new()));
        };
        let doc = dom.borrow();
        let handles: Vec<usize> = doc
            .descendants(root)
            .filter(|n| {
                *n != root
                    && doc
                        .get(*n)
                        .and_then(|x| x.as_element())
                        .map(|e| tag == "*" || e.tag == tag)
                        .unwrap_or(false)
            })
            .map(|n| n.index())
            .collect();
        drop(doc);
        Ok(dom_list(interp, handles))
    });
    define_method(interp, element_proto, "getElementsByTagName", by_tag);
    let by_class: NativeFn = Rc::new(|interp, this, args| {
        let class = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let root = handle_of(&this).map(node_id).unwrap_or(NodeId::DOCUMENT);
        let Some(dom) = interp.dom.clone() else {
            return Ok(interp.new_array(Vec::new()));
        };
        let doc = dom.borrow();
        let handles: Vec<usize> = doc
            .descendants(root)
            .filter(|n| {
                *n != root
                    && doc
                        .get(*n)
                        .and_then(|x| x.as_element())
                        .map(|e| class.split_whitespace().all(|c| e.has_class(c)))
                        .unwrap_or(false)
            })
            .map(|n| n.index())
            .collect();
        drop(doc);
        Ok(dom_list(interp, handles))
    });
    define_method(interp, element_proto, "getElementsByClassName", by_class);

    let clone_node: NativeFn = Rc::new(|interp, this, args| {
        let deep = args.first().map(|v| v.truthy()).unwrap_or(false);
        let (Some(h), Some(dom)) = (handle_of(&this), interp.dom.clone()) else {
            return Ok(JsValue::Null);
        };
        let new = {
            let mut doc = dom.borrow_mut();
            clone_subtree(&mut doc, node_id(h), deep)
        };
        Ok(match new {
            Some(n) => wrap_node(interp, n.index()),
            None => JsValue::Null,
        })
    });
    define_method(interp, element_proto, "cloneNode", clone_node);
}

fn install_structure_methods(interp: &mut Interp, element_proto: &ObjRef) {
    // compareDocumentPosition(other): the DOM bitmask (DISCONNECTED 1,
    // PRECEDING 2, FOLLOWING 4, CONTAINS 8, CONTAINED_BY 16). jQuery's
    // `contains` and sort use it.
    let compare_pos: NativeFn = Rc::new(|interp, this, args| {
        let (Some(a), Some(b), Some(dom)) = (
            handle_of(&this),
            args.first().and_then(handle_of),
            interp.dom.clone(),
        ) else {
            return Ok(JsValue::Num(1.0));
        };
        if a == b {
            return Ok(JsValue::Num(0.0));
        }
        let doc = dom.borrow();
        let (na, nb) = (node_id(a), node_id(b));
        let is_ancestor = |anc: NodeId, of: NodeId| -> bool {
            let mut cur = doc.get(of).and_then(|n| n.parent);
            while let Some(p) = cur {
                if p == anc {
                    return true;
                }
                cur = doc.get(p).and_then(|n| n.parent);
            }
            false
        };
        // DOM §4.4: the bits describe OTHER relative to THIS. When other is
        // a descendant of this it is CONTAINED_BY (16) this and FOLLOWS (4)
        // it; when other is an ancestor it CONTAINS (8) this and PRECEDES
        // (2) it.
        if is_ancestor(na, nb) {
            return Ok(JsValue::Num(20.0));
        }
        if is_ancestor(nb, na) {
            return Ok(JsValue::Num(10.0));
        }
        // Document order: walk the whole tree once.
        let mut seen_a = false;
        let mut seen_b = false;
        for n in doc.descendants(NodeId::DOCUMENT) {
            if n == na {
                seen_a = true;
                if !seen_b {
                    break;
                }
            }
            if n == nb {
                seen_b = true;
                if !seen_a {
                    break;
                }
            }
        }
        Ok(JsValue::Num(if seen_a && !seen_b {
            4.0 // other FOLLOWS this
        } else if seen_b && !seen_a {
            2.0 // other PRECEDES this
        } else if !seen_a && !seen_b {
            1.0 // disconnected
        } else {
            4.0
        }))
    });
    define_method(interp, element_proto, "compareDocumentPosition", compare_pos);

    // getAttributeNode(name): { name, value, specified } or null.
    let get_attr_node: NativeFn = Rc::new(|interp, this, args| {
        let Some(h) = handle_of(&this) else {
            return Ok(JsValue::Null);
        };
        let name = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let value = {
            let doc = dom.borrow();
            doc.get(node_id(h))
                .and_then(|n| n.as_element().and_then(|e| e.attr(&name)))
                .map(str::to_string)
        };
        let Some(value) = value else {
            return Ok(JsValue::Null);
        };
        let a = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        a.borrow_mut().set_prop("name", JsValue::str(name), true);
        a.borrow_mut().set_prop("value", JsValue::str(value), true);
        a.borrow_mut().set_prop("specified", JsValue::Bool(true), true);
        Ok(JsValue::Object(a))
    });
    define_method(interp, element_proto, "getAttributeNode", get_attr_node);

    // getElementsByName(name): every element whose `name` attribute matches.
    let by_name: NativeFn = Rc::new(|interp, _this, args| {
        let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let Some(dom) = interp.dom.clone() else {
            return Ok(interp.new_array(Vec::new()));
        };
        let doc = dom.borrow();
        let handles: Vec<usize> = doc
            .descendants(NodeId::DOCUMENT)
            .filter(|n| {
                doc.get(*n)
                    .and_then(|x| x.as_element())
                    .map(|e| e.attr("name") == Some(name.as_str()))
                    .unwrap_or(false)
            })
            .map(|n| n.index())
            .collect();
        drop(doc);
        Ok(dom_list(interp, handles))
    });
    define_method(interp, element_proto, "getElementsByName", by_name);

    // Geometry: without a layout pass inside script execution every box is
    // empty (Chrome reports zeros for detached nodes too). Frameworks use
    // these for feature detection and scroll math, both of which tolerate
    // zeros; the layout the render produces afterwards is authoritative.
    let rect = zero_rect_method();
    define_method(interp, element_proto, "getBoundingClientRect", rect.clone());
    let rects: NativeFn = Rc::new(move |interp, this, args| {
        let r = rect(interp, this, args)?;
        Ok(interp.new_array(vec![r]))
    });
    define_method(interp, element_proto, "getClientRects", rects);
    let noop = noop_method();
    for name in ["scrollIntoView", "scrollTo", "scroll", "scrollBy", "normalize"] {
        define_method(interp, element_proto, name, noop.clone());
    }
    let has_child_nodes: NativeFn = Rc::new(|interp, this, _args| {
        let (Some(h), Some(dom)) = (handle_of(&this), interp.dom.clone()) else {
            return Ok(JsValue::Bool(false));
        };
        let doc = dom.borrow();
        Ok(JsValue::Bool(
            doc.get(node_id(h)).and_then(|n| n.first_child).is_some(),
        ))
    });
    define_method(interp, element_proto, "hasChildNodes", has_child_nodes);
    let get_root: NativeFn = Rc::new(|interp, this, _args| {
        let (Some(h), Some(dom)) = (handle_of(&this), interp.dom.clone()) else {
            return Ok(JsValue::Null);
        };
        let root = {
            let doc = dom.borrow();
            let mut cur = node_id(h);
            while let Some(p) = doc.get(cur).and_then(|n| n.parent) {
                cur = p;
            }
            cur
        };
        Ok(wrap_node(interp, root.index()))
    });
    define_method(interp, element_proto, "getRootNode", get_root);
    let is_equal: NativeFn = Rc::new(|interp, this, args| {
        let (Some(a), Some(b), Some(dom)) = (
            handle_of(&this),
            args.first().and_then(handle_of),
            interp.dom.clone(),
        ) else {
            return Ok(JsValue::Bool(false));
        };
        let doc = dom.borrow();
        Ok(JsValue::Bool(
            super::super::super::extract::outer_html(&doc, node_id(a))
                == super::super::super::extract::outer_html(&doc, node_id(b)),
        ))
    });
    define_method(interp, element_proto, "isEqualNode", is_equal);
    let is_same: NativeFn = Rc::new(|_i, this, args| {
        Ok(JsValue::Bool(
            handle_of(&this).is_some() && handle_of(&this) == args.first().and_then(handle_of),
        ))
    });
    define_method(interp, element_proto, "isSameNode", is_same);
}

fn install_insertion_methods(interp: &mut Interp, element_proto: &ObjRef) {
    // append/prepend/before/after/replaceWith/replaceChild/replaceChildren
    // (strings become text nodes, per the DOM spec's converter).
    let append: NativeFn = Rc::new(|interp, this, args| {
        let Some(parent) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        for a in args {
            let child = node_for_insert(interp, a);
            if let (Some(c), Some(dom)) = (child, interp.dom.clone()) {
                let mut doc = dom.borrow_mut();
                let moved = insert_list(&doc, c);
                for c in &moved {
                    doc.detach(*c);
                    doc.append_child(node_id(parent), *c);
                }
                drop(doc);
                start_inserted_scripts(interp, &moved);
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "append", append);
    let prepend: NativeFn = Rc::new(|interp, this, args| {
        let Some(parent) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        let nodes: Vec<NodeId> = args.iter().filter_map(|a| node_for_insert(interp, a)).collect();
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            // The arguments keep their order: each lands before the one
            // ahead of it, so the first argument ends up first.
            let first = doc.get(node_id(parent)).and_then(|n| n.first_child);
            let moved: Vec<NodeId> = nodes.iter().flat_map(|n| insert_list(&doc, *n)).collect();
            for c in &moved {
                doc.detach(*c);
                match first {
                    Some(f) => doc.insert_before(f, *c),
                    None => doc.append_child(node_id(parent), *c),
                }
            }
            drop(doc);
            start_inserted_scripts(interp, &moved);
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "prepend", prepend);
    let before: NativeFn = Rc::new(|interp, this, args| {
        let Some(me) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        let nodes: Vec<NodeId> = args.iter().filter_map(|a| node_for_insert(interp, a)).collect();
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            if doc.get(node_id(me)).and_then(|n| n.parent).is_some() {
                let moved: Vec<NodeId> = nodes.iter().flat_map(|n| insert_list(&doc, *n)).collect();
                for c in &moved {
                    doc.detach(*c);
                    doc.insert_before(node_id(me), *c);
                }
                drop(doc);
                start_inserted_scripts(interp, &moved);
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "before", before);
    let after: NativeFn = Rc::new(|interp, this, args| {
        let Some(me) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        let nodes: Vec<NodeId> = args.iter().filter_map(|a| node_for_insert(interp, a)).collect();
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            let parent = doc.get(node_id(me)).and_then(|n| n.parent);
            let next = doc.get(node_id(me)).and_then(|n| n.next_sibling);
            if let Some(p) = parent {
                // Inserting each node before the SAME fixed `next` keeps the
                // argument order (a, b) → me, a, b.
                let moved: Vec<NodeId> = nodes.iter().flat_map(|n| insert_list(&doc, *n)).collect();
                for c in &moved {
                    doc.detach(*c);
                    match next {
                        Some(nx) => doc.insert_before(nx, *c),
                        None => doc.append_child(p, *c),
                    }
                }
                drop(doc);
                start_inserted_scripts(interp, &moved);
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "after", after);
    let replace_with: NativeFn = Rc::new(|interp, this, args| {
        let Some(me) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        let nodes: Vec<NodeId> = args.iter().filter_map(|a| node_for_insert(interp, a)).collect();
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            if doc.get(node_id(me)).and_then(|n| n.parent).is_some() {
                let moved: Vec<NodeId> = nodes.iter().flat_map(|n| insert_list(&doc, *n)).collect();
                for c in &moved {
                    doc.detach(*c);
                    doc.insert_before(node_id(me), *c);
                }
                doc.detach(node_id(me));
                drop(doc);
                start_inserted_scripts(interp, &moved);
            }
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "replaceWith", replace_with);
    let replace_child: NativeFn = Rc::new(|interp, this, args| {
        let (Some(new), Some(old)) = (
            args.first().and_then(handle_of),
            args.get(1).and_then(handle_of),
        ) else {
            return Err(Interp::throw("TypeError: replaceChild expects nodes"));
        };
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            let old_parent = doc.get(node_id(old)).and_then(|n| n.parent);
            if old_parent != handle_of(&this).map(node_id) {
                return Err(Interp::throw(
                    "NotFoundError: the node to be replaced is not a child of this node",
                ));
            }
            if old_parent.is_some() {
                let moved = insert_list(&doc, node_id(new));
                for c in &moved {
                    doc.detach(*c);
                    doc.insert_before(node_id(old), *c);
                }
                doc.detach(node_id(old));
                drop(doc);
                start_inserted_scripts(interp, &moved);
            }
        }
        Ok(args.get(1).cloned().unwrap_or(JsValue::Undefined))
    });
    define_method(interp, element_proto, "replaceChild", replace_child);
    let replace_children: NativeFn = Rc::new(|interp, this, args| {
        let Some(parent) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        let nodes: Vec<NodeId> = args.iter().filter_map(|a| node_for_insert(interp, a)).collect();
        if let Some(dom) = interp.dom.clone() {
            let mut doc = dom.borrow_mut();
            doc.remove_children(node_id(parent));
            let moved: Vec<NodeId> = nodes.iter().flat_map(|n| insert_list(&doc, *n)).collect();
            for c in &moved {
                doc.detach(*c);
                doc.append_child(node_id(parent), *c);
            }
            drop(doc);
            start_inserted_scripts(interp, &moved);
        }
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "replaceChildren", replace_children);
    let insert_adjacent_html: NativeFn = Rc::new(|interp, this, args| {
        let Some(me) = handle_of(&this) else {
            return Ok(JsValue::Undefined);
        };
        let pos = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let src = args.get(1).map(|v| v.to_js_string()).unwrap_or_default();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Undefined);
        };
        let mut doc = dom.borrow_mut();
        let holder = doc.create_element("template");
        html::parse_fragment_into(&mut doc, holder, &src);
        let kids: Vec<NodeId> = doc.children(holder).collect();
        let me = node_id(me);
        match pos.as_str() {
            "beforebegin" => {
                if doc.get(me).and_then(|n| n.parent).is_some() {
                    for k in kids {
                        doc.detach(k);
                        doc.insert_before(me, k);
                    }
                }
            }
            "afterbegin" => {
                let first = doc.get(me).and_then(|n| n.first_child);
                for k in kids {
                    doc.detach(k);
                    match first {
                        Some(f) => doc.insert_before(f, k),
                        None => doc.append_child(me, k),
                    }
                }
            }
            "afterend" => {
                let parent = doc.get(me).and_then(|n| n.parent);
                let next = doc.get(me).and_then(|n| n.next_sibling);
                if let Some(p) = parent {
                    for k in kids {
                        doc.detach(k);
                        match next {
                            Some(nx) => doc.insert_before(nx, k),
                            None => doc.append_child(p, k),
                        }
                    }
                }
            }
            _ => {
                for k in kids {
                    doc.detach(k);
                    doc.append_child(me, k);
                }
            }
        }
        doc.detach(holder);
        Ok(JsValue::Undefined)
    });
    define_method(interp, element_proto, "insertAdjacentHTML", insert_adjacent_html);
    let toggle_attribute: NativeFn = Rc::new(|interp, this, args| {
        let Some(h) = handle_of(&this) else {
            return Ok(JsValue::Bool(false));
        };
        let name = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let force = args.get(1).map(|v| v.truthy());
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Bool(false));
        };
        let mut doc = dom.borrow_mut();
        let has = doc
            .get(node_id(h))
            .and_then(|n| n.as_element().map(|e| e.attr(&name).is_some()))
            .unwrap_or(false);
        let want = force.unwrap_or(!has);
        if want && !has {
            doc.set_attr(node_id(h), &name, "");
        } else if !want && has {
            if let NodeData::Element(e) = &mut doc.node_mut(node_id(h)).data {
                e.attrs.retain(|(n, _)| n != &name);
            }
        }
        Ok(JsValue::Bool(want))
    });
    define_method(interp, element_proto, "toggleAttribute", toggle_attribute);
    let attr_names: NativeFn = Rc::new(|interp, this, _args| {
        let (Some(h), Some(dom)) = (handle_of(&this), interp.dom.clone()) else {
            return Ok(interp.new_array(Vec::new()));
        };
        let names: Vec<JsValue> = {
            let doc = dom.borrow();
            doc.get(node_id(h))
                .and_then(|n| n.as_element())
                .map(|e| e.attrs.iter().map(|(k, _)| JsValue::str(k.clone())).collect())
                .unwrap_or_default()
        };
        Ok(interp.new_array(names))
    });
    define_method(interp, element_proto, "getAttributeNames", attr_names);
}

fn install_document_methods(interp: &mut Interp, element_proto: &ObjRef, doc_obj: &ObjRef) {
    // getElementById
    let get_by_id: NativeFn = Rc::new(|interp, _this, args| {
        let id = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let found = dom.borrow_mut().element_by_id(&id);
        Ok(match found {
            Some(n) => wrap_node(interp, n.index()),
            None => JsValue::Null,
        })
    });
    define_method(interp, doc_obj, "getElementById", get_by_id);

    // querySelector / querySelectorAll (CSS via the css module's selector
    // matching against computed candidates).
    let qsa: NativeFn = Rc::new(|interp, this, args| {
        let sel = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let root = match &this {
            JsValue::Object(o) => match &o.borrow().kind {
                ObjKind::DomNode(h) => NodeId(*h as u32),
                _ => NodeId::DOCUMENT,
            },
            _ => NodeId::DOCUMENT,
        };
        let Some(dom) = interp.dom.clone() else {
            return Ok(dom_list(interp, Vec::new()));
        };
        let doc = dom.borrow();
        // Chrome throws on a selector it cannot parse; Sizzle's feature
        // detection (`querySelectorAll("*,:x")` must throw) depends on it.
        let hits = super::super::super::css::query_selector_all_strict(&doc, root, &sel)
            .map_err(|m| Interp::throw(format!("SyntaxError: Failed to execute 'querySelectorAll': {m}")))?;
        drop(doc);
        let handles: Vec<usize> = hits.into_iter().map(|n| n.index()).collect();
        Ok(dom_list(interp, handles))
    });
    define_method(interp, element_proto, "querySelectorAll", qsa.clone());
    define_method(interp, doc_obj, "querySelectorAll", qsa.clone());
    let qs: NativeFn = Rc::new(move |interp, this, args| {
        let all = qsa(interp, this, args)?;
        if let JsValue::Object(o) = &all {
            if let ObjKind::DomList(hs) = &o.borrow().kind {
                return Ok(match hs.first() {
                    Some(h) => wrap_node(interp, *h),
                    None => JsValue::Null,
                });
            }
        }
        Ok(JsValue::Null)
    });
    define_method(interp, element_proto, "querySelector", qs.clone());
    define_method(interp, doc_obj, "querySelector", qs);

    // createElement / createTextNode
    let create_el: NativeFn = Rc::new(|interp, _this, args| {
        let tag = args
            .first()
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let n = dom.borrow_mut().create_element(tag.clone());
        let wrapped = wrap_node(interp, n.index());
        // A defined custom element is upgraded at creation: its
        // constructor runs against the wrapper (HTML §4.13.5).
        upgrade_custom_element(interp, n.index(), &tag)?;
        Ok(wrapped)
    });
    define_method(interp, doc_obj, "createElement", create_el);
    let create_text: NativeFn = Rc::new(|interp, _this, args| {
        let text = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let n = dom.borrow_mut().create_text(&text);
        Ok(wrap_node(interp, n.index()))
    });
    define_method(interp, doc_obj, "createTextNode", create_text);
    let create_comment: NativeFn = Rc::new(|interp, _this, args| {
        let text = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let n = dom.borrow_mut().create_node(NodeData::Comment(text));
        Ok(wrap_node(interp, n.index()))
    });
    define_method(interp, doc_obj, "createComment", create_comment);
    // A DocumentFragment is a detached `template` holder: appending it
    // moves its children (see `node_for_insert`), as the spec requires.
    let create_fragment: NativeFn = Rc::new(|interp, _this, _args| {
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let n = dom.borrow_mut().create_element("#fragment");
        Ok(wrap_node(interp, n.index()))
    });
    define_method(interp, doc_obj, "createDocumentFragment", create_fragment);
    let create_el_ns: NativeFn = Rc::new(|interp, _this, args| {
        let tag = args
            .get(1)
            .map(|v| v.to_js_string())
            .unwrap_or_default()
            .to_lowercase();
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let n = dom.borrow_mut().create_element(tag);
        Ok(wrap_node(interp, n.index()))
    });
    define_method(interp, doc_obj, "createElementNS", create_el_ns);
    // The event interfaces (Event, CustomEvent, MouseEvent, …) and
    // document.createEvent.
    super::super::events::install_event_interfaces(interp, &doc_obj);
    // document.implementation.createHTMLDocument(title): a fresh detached
    // document root in the SAME arena (scripts use it as a parse scratch).
    let implementation = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
    let create_html_doc: NativeFn = Rc::new(|interp, _this, _args| {
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let n = {
            let mut doc = dom.borrow_mut();
            let root = doc.create_element("#document");
            let html_el = doc.create_element("html");
            let head = doc.create_element("head");
            let body = doc.create_element("body");
            doc.append_child(root, html_el);
            doc.append_child(html_el, head);
            doc.append_child(html_el, body);
            root
        };
        Ok(wrap_node(interp, n.index()))
    });
    define_method(interp, &implementation, "createHTMLDocument", create_html_doc);
    let has_feature: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Bool(true)));
    define_method(interp, &implementation, "hasFeature", has_feature);
    doc_obj
        .borrow_mut()
        .set_prop("implementation", JsValue::Object(implementation), false);
    doc_obj
        .borrow_mut()
        .set_prop("defaultView", JsValue::Object(interp.global_object.clone()), false);
    doc_obj
        .borrow_mut()
        .set_prop("readyState", JsValue::str("loading"), true);
    doc_obj
        .borrow_mut()
        .set_prop("compatMode", JsValue::str("CSS1Compat"), true);
    doc_obj
        .borrow_mut()
        .set_prop("characterSet", JsValue::str("UTF-8"), true);
    doc_obj
        .borrow_mut()
        .set_prop("contentType", JsValue::str("text/html"), true);
    doc_obj
        .borrow_mut()
        .set_prop("visibilityState", JsValue::str("visible"), true);
    doc_obj.borrow_mut().set_prop("hidden", JsValue::Bool(false), true);
    doc_obj
        .borrow_mut()
        .set_prop("cookie", JsValue::str(""), true);
    doc_obj
        .borrow_mut()
        .set_prop("referrer", JsValue::str(""), true);
    doc_obj.borrow_mut().set_prop("currentScript", JsValue::Null, true);
    let has_focus: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Bool(true)));
    define_method(interp, doc_obj, "hasFocus", has_focus);
    let noop_doc: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
    for name in ["open", "close", "write", "writeln"] {
        define_method(interp, doc_obj, name, noop_doc.clone());
    }
    let elem_from_point: NativeFn = Rc::new(|interp, _t, _a| {
        let body = interp
            .dom
            .clone()
            .and_then(|d| d.borrow().find_tag("body").map(|n| n.index()));
        Ok(match body {
            Some(b) => wrap_node(interp, b),
            None => JsValue::Null,
        })
    });
    define_method(interp, doc_obj, "elementFromPoint", elem_from_point);
    let create_range: NativeFn = Rc::new(|interp, _t, _a| {
        let r = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        let noop = noop_method();
        for name in [
            "setStart",
            "setEnd",
            "selectNode",
            "selectNodeContents",
            "collapse",
            "detach",
            "deleteContents",
        ] {
            define_method(interp, &r, name, noop.clone());
        }
        // createContextualFragment(html): a fragment holding the parsed nodes.
        let ccf: NativeFn = Rc::new(|interp, _t, args| {
            let src = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let Some(dom) = interp.dom.clone() else {
                return Ok(JsValue::Null);
            };
            let n = {
                let mut doc = dom.borrow_mut();
                let frag = doc.create_element("#fragment");
                html::parse_fragment_into(&mut doc, frag, &src);
                frag
            };
            Ok(wrap_node(interp, n.index()))
        });
        define_method(interp, &r, "createContextualFragment", ccf);
        let rect = zero_rect_method();
        define_method(interp, &r, "getBoundingClientRect", rect);
        Ok(JsValue::Object(r))
    });
    define_method(interp, doc_obj, "createRange", create_range);
    let create_tree_walker: NativeFn = Rc::new(|interp, _t, args| {
        // A TreeWalker over the root's descendants: nextNode() walks them.
        let root = args.first().and_then(handle_of).unwrap_or(0);
        let what = interp.number_arg(args.get(1), -1.0)? as i64;
        let handles: Vec<usize> = match interp.dom.clone() {
            Some(dom) => {
                let doc = dom.borrow();
                doc.descendants(node_id(root))
                    .filter(|n| match doc.get(*n).map(|x| &x.data) {
                        Some(NodeData::Element(_)) => what == -1 || (what & 1) != 0,
                        Some(NodeData::Text(_)) => what == -1 || (what & 4) != 0,
                        Some(NodeData::Comment(_)) => what == -1 || (what & 128) != 0,
                        _ => false,
                    })
                    .map(|n| n.index())
                    .collect()
            }
            None => Vec::new(),
        };
        let w = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        let list = interp.new_array(handles.iter().map(|h| JsValue::Num(*h as f64)).collect());
        w.borrow_mut().set_prop("__nodes", list, false);
        w.borrow_mut().set_prop("__pos", JsValue::Num(0.0), false);
        let root_v = wrap_node(interp, root);
        w.borrow_mut().set_prop("root", root_v.clone(), true);
        w.borrow_mut().set_prop("currentNode", root_v, true);
        let next: NativeFn = Rc::new(|interp, this, _a| {
            let JsValue::Object(o) = &this else {
                return Ok(JsValue::Null);
            };
            let (nodes, pos) = {
                let b = o.borrow();
                (
                    b.get_prop("__nodes"),
                    b.get_prop("__pos").map(|v| v.to_number()).unwrap_or(0.0) as usize,
                )
            };
            let handle = match nodes {
                Some(JsValue::Object(l)) => l.borrow().elem(pos).map(|v| v.to_number() as usize),
                _ => None,
            };
            o.borrow_mut()
                .set_prop("__pos", JsValue::Num((pos + 1) as f64), false);
            Ok(match handle {
                Some(h) => {
                    let n = wrap_node(interp, h);
                    o.borrow_mut().set_prop("currentNode", n.clone(), true);
                    n
                }
                None => JsValue::Null,
            })
        });
        define_method(interp, &w, "nextNode", next);
        Ok(JsValue::Object(w))
    });
    define_method(interp, doc_obj, "createTreeWalker", create_tree_walker);
}

/// The window-level surface frameworks probe.
fn install_window_surface(interp: &mut Interp, doc_obj: &ObjRef) {
    let raf: NativeFn = Rc::new(|interp, _this, args| {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        // One frame ≈ 16ms on the virtual clock; the callback receives the
        // timestamp like a real frame callback.
        let id = interp.set_timer(cb, 16.0, vec![JsValue::Num(interp.now_ms + 16.0)], false);
        Ok(JsValue::Num(id as f64))
    });
    let v = interp.native(raf);
    interp.set_global("requestAnimationFrame", v);
    let ric: NativeFn = Rc::new(|interp, _this, args| {
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        let deadline = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        deadline
            .borrow_mut()
            .set_prop("didTimeout", JsValue::Bool(false), true);
        let tr: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Num(50.0)));
        define_method(interp, &deadline, "timeRemaining", tr);
        let id = interp.set_timer(cb, 1.0, vec![JsValue::Object(deadline)], false);
        Ok(JsValue::Num(id as f64))
    });
    let v = interp.native(ric);
    interp.set_global("requestIdleCallback", v);
    let cancel: NativeFn = Rc::new(|interp, _this, args| {
        let id = interp.number_arg(args.first(), f64::NAN)?;
        if id.is_finite() && id >= 0.0 {
            interp.clear_timer(id as u32);
        }
        Ok(JsValue::Undefined)
    });
    for name in ["cancelAnimationFrame", "cancelIdleCallback"] {
        let v = interp.native(cancel.clone());
        interp.set_global(name, v);
    }
    // getComputedStyle(el): the element's inline declarations plus the
    // defaults frameworks read for feature detection (display, position).
    // Layout-derived values need the render pass; this is the pre-layout
    // view the same way `style` is.
    let gcs: NativeFn = Rc::new(|interp, _this, args| {
        let style = match args.first() {
            Some(el @ JsValue::Object(_)) => interp.get_property(el, "style")?,
            _ => JsValue::Undefined,
        };
        let obj = match style {
            JsValue::Object(o) => o,
            _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
        };
        {
            let mut b = obj.borrow_mut();
            for (k, v) in [
                ("display", "block"),
                ("position", "static"),
                ("visibility", "visible"),
                ("opacity", "1"),
                ("overflow", "visible"),
                ("boxSizing", "content-box"),
                ("direction", "ltr"),
                ("fontSize", "16px"),
                ("lineHeight", "normal"),
                ("color", "rgb(0, 0, 0)"),
                ("backgroundColor", "rgba(0, 0, 0, 0)"),
                ("transform", "none"),
                ("transition", "all 0s ease 0s"),
                ("animationName", "none"),
                ("pointerEvents", "auto"),
                ("zIndex", "auto"),
                ("width", "auto"),
                ("height", "auto"),
                ("paddingTop", "0px"),
                ("paddingRight", "0px"),
                ("paddingBottom", "0px"),
                ("paddingLeft", "0px"),
                ("marginTop", "0px"),
                ("marginRight", "0px"),
                ("marginBottom", "0px"),
                ("marginLeft", "0px"),
                ("borderTopWidth", "0px"),
                ("borderRightWidth", "0px"),
                ("borderBottomWidth", "0px"),
                ("borderLeftWidth", "0px"),
                ("boxShadow", "none"),
                ("textAlign", "start"),
                ("whiteSpace", "normal"),
                ("float", "none"),
                ("top", "auto"),
                ("left", "auto"),
                ("right", "auto"),
                ("bottom", "auto"),
            ] {
                if b.get_prop(k).is_none() {
                    b.set_prop(k, JsValue::str(v), true);
                }
            }
        }
        let gpv: NativeFn = Rc::new(|interp, this, args| {
            let k = css_to_camel(args.first().map(|v| v.to_js_string()).unwrap_or_default().trim());
            let v = interp.get_property(&this, &k)?;
            Ok(if v.is_nullish() { JsValue::str("") } else { v })
        });
        define_method(interp, &obj, "getPropertyValue", gpv);
        Ok(JsValue::Object(obj))
    });
    let v = interp.native(gcs);
    interp.set_global("getComputedStyle", v);
    let match_media: NativeFn = Rc::new(|interp, _this, args| {
        let q = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let m = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        // The engine's media evaluator decides, at the default desktop
        // viewport; queries it does not understand do not match.
        let matches = super::super::super::css::parse_stylesheet_with_env(
            &format!("@media {q} {{ x {{ y: z }} }}"),
            super::super::super::css::MediaEnv {
                width: 1280.0,
                height: 720.0,
            },
        )
        .rules
        .is_empty()
            .not();
        m.borrow_mut().set_prop("matches", JsValue::Bool(matches), true);
        m.borrow_mut().set_prop("media", JsValue::str(q), true);
        m.borrow_mut().set_prop("onchange", JsValue::Null, true);
        let noop = noop_method();
        for name in ["addListener", "removeListener", "addEventListener", "removeEventListener", "dispatchEvent"] {
            define_method(interp, &m, name, noop.clone());
        }
        Ok(JsValue::Object(m))
    });
    let v = interp.native(match_media);
    interp.set_global("matchMedia", v);
    let noop_win: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
    for name in ["scrollTo", "scroll", "scrollBy", "focus", "blur", "postMessage", "print", "stop"] {
        let v = interp.native(noop_win.clone());
        interp.set_global(name, v);
    }
    let get_selection: NativeFn = Rc::new(|interp, _t, _a| {
        let s = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        s.borrow_mut().set_prop("rangeCount", JsValue::Num(0.0), true);
        s.borrow_mut().set_prop("type", JsValue::str("None"), true);
        s.borrow_mut().set_prop("anchorNode", JsValue::Null, true);
        s.borrow_mut().set_prop("focusNode", JsValue::Null, true);
        let noop = noop_method();
        for name in ["removeAllRanges", "addRange", "collapse", "toString", "getRangeAt"] {
            define_method(interp, &s, name, noop.clone());
        }
        Ok(JsValue::Object(s))
    });
    let v = interp.native(get_selection.clone());
    interp.set_global("getSelection", v);
    define_method(interp, doc_obj, "getSelection", get_selection);
}

fn install_interface_objects(interp: &mut Interp, element_proto: &ObjRef) {
    // Interface constructors bundles `instanceof` against. Each is a
    // plain constructor whose `prototype` is the shared element prototype,
    // so `el instanceof HTMLElement`, `Node.ELEMENT_NODE` and
    // `Element.prototype.matches` all resolve.
    let iface_ctor: NativeFn = Rc::new(|_i, _t, _a| {
        Err(Interp::throw("TypeError: Illegal constructor"))
    });
    // `HTMLElement` is constructible from a `super()` in a custom element
    // class (HTML §4.13.4 "HTML element constructors"): during an upgrade
    // it answers with the element under construction; for a plain
    // `new MyEl()` it creates an element of the class's defined name.
    // Anything else is an Illegal constructor, as in Chrome.
    let html_element_ctor: NativeFn = Rc::new(|interp, this, _a| {
        let pending = interp.global_object.borrow().get_prop("__ceUnderConstruction");
        if let Some(JsValue::Object(el)) = pending {
            return Ok(JsValue::Object(el));
        }
        // `new X()`: the class is `this`'s prototype's constructor; its
        // defined name is the tag to create.
        let class_ctor = match &this {
            JsValue::Object(o) => o
                .borrow()
                .proto
                .as_ref()
                .and_then(|p| p.borrow().get_prop("constructor")),
            _ => None,
        };
        let Some(JsValue::Object(class_ctor)) = class_ctor else {
            return Err(Interp::throw("TypeError: Illegal constructor"));
        };
        let defs = interp.global_object.borrow().get_prop(CE_DEFINITIONS);
        let tag = match defs {
            Some(JsValue::Object(d)) => d
                .borrow()
                .props
                .iter()
                .find(|(_, p)| matches!(p, Prop::Value { value: JsValue::Object(c), .. } if Rc::ptr_eq(c, &class_ctor)))
                .map(|(k, _)| k.clone()),
            _ => None,
        };
        let Some(tag) = tag else {
            return Err(Interp::throw("TypeError: Illegal constructor"));
        };
        let Some(dom) = interp.dom.clone() else {
            return Err(Interp::throw("TypeError: Illegal constructor"));
        };
        let n = dom.borrow_mut().create_element(tag);
        let wrapper = match wrap_node(interp, n.index()) {
            JsValue::Object(w) => w,
            other => return Ok(other),
        };
        // The element takes the class's prototype and counts as upgraded:
        // the class body about to run IS its constructor.
        let proto = match &this {
            JsValue::Object(o) => o.borrow().proto.clone(),
            _ => None,
        };
        wrapper.borrow_mut().proto = proto;
        wrapper
            .borrow_mut()
            .set_prop(CE_UPGRADED, JsValue::Bool(true), false);
        Ok(JsValue::Object(wrapper))
    });
    for name in [
        "Node",
        "Element",
        "HTMLElement",
        "HTMLDivElement",
        "HTMLSpanElement",
        "HTMLAnchorElement",
        "HTMLInputElement",
        "HTMLButtonElement",
        "HTMLImageElement",
        "HTMLIFrameElement",
        "HTMLFormElement",
        "HTMLSelectElement",
        "HTMLTextAreaElement",
        "HTMLScriptElement",
        "HTMLStyleElement",
        "HTMLTemplateElement",
        "HTMLUnknownElement",
        "SVGElement",
        "Document",
        "HTMLDocument",
        "DocumentFragment",
        "Text",
        "Comment",
        "CharacterData",
        "EventTarget",
        "ShadowRoot",
        "Window",
    ] {
        let ctor_fn = if name == "HTMLElement" {
            html_element_ctor.clone()
        } else {
            iface_ctor.clone()
        };
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(interp.function_proto.clone()));
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(element_proto.clone()),
            false,
        );
        if name == "Node" {
            let mut b = ctor.borrow_mut();
            for (k, v) in [
                ("ELEMENT_NODE", 1.0),
                ("ATTRIBUTE_NODE", 2.0),
                ("TEXT_NODE", 3.0),
                ("CDATA_SECTION_NODE", 4.0),
                ("PROCESSING_INSTRUCTION_NODE", 7.0),
                ("COMMENT_NODE", 8.0),
                ("DOCUMENT_NODE", 9.0),
                ("DOCUMENT_TYPE_NODE", 10.0),
                ("DOCUMENT_FRAGMENT_NODE", 11.0),
                ("DOCUMENT_POSITION_DISCONNECTED", 1.0),
                ("DOCUMENT_POSITION_PRECEDING", 2.0),
                ("DOCUMENT_POSITION_FOLLOWING", 4.0),
                ("DOCUMENT_POSITION_CONTAINS", 8.0),
                ("DOCUMENT_POSITION_CONTAINED_BY", 16.0),
            ] {
                b.set_prop(k, JsValue::Num(v), false);
            }
        }
        interp.set_global(name, JsValue::Object(ctor));
    }
    let node_filter = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
    for (k, v) in [
        ("SHOW_ALL", -1.0),
        ("SHOW_ELEMENT", 1.0),
        ("SHOW_TEXT", 4.0),
        ("SHOW_COMMENT", 128.0),
        ("FILTER_ACCEPT", 1.0),
        ("FILTER_REJECT", 2.0),
        ("FILTER_SKIP", 3.0),
    ] {
        node_filter.borrow_mut().set_prop(k, JsValue::Num(v), false);
    }
    interp.set_global("NodeFilter", JsValue::Object(node_filter));
}
