//! dom_bindings — the glue between the JS interpreter and the arena DOM:
//! `document` / element wrappers whose property reads and writes go straight
//! to the real `dom::Document`, so scripts mutate the same tree that layout,
//! extraction, and screenshots consume.
//!
//! Wrapper objects carry `ObjKind::DomNode(handle)`; property access on them
//! is intercepted in `eval.rs` (get) and here (set). Like the rest of the
//! engine this module is panic-free: unknown handles degrade to undefined.

use std::rc::Rc;

use super::super::dom::{Document, NodeId};
use super::interp::Interp;
use super::value::{JsObject, JsValue, NativeFn, ObjKind, ObjRef, SYM_TO_STRING_TAG, symbol_key};

mod activation;
mod custom_elements;
mod document;
mod observers;
mod properties;
mod scripts;

pub use activation::{activate, activate_with, focus_node, form_owner, submit_form, submit_form_steps};
pub use document::install_document;
pub use properties::{facet_keys, get_dom_property, get_facet_property, set_dom_property, set_facet_property};
pub use scripts::script_inserted;

/// Wrap an arena node handle as a JS object sharing the element prototype
/// (installed by [`install_document`]) so every wrapper carries the DOM
/// methods (appendChild, setAttribute, querySelector…).
pub fn wrap_node(interp: &mut Interp, handle: usize) -> JsValue {
    if let Some(existing) = interp.node_wrappers.get(&handle) {
        return JsValue::Object(existing.clone());
    }
    let proto = interp
        .global_object
        .borrow()
        .get_prop("__ElementProto")
        .and_then(|v| match v {
            JsValue::Object(o) => Some(o),
            _ => None,
        })
        .unwrap_or_else(|| interp.object_proto.clone());
    let obj = JsObject::new(ObjKind::DomNode(handle), Some(proto));
    // Bounded: a hostile script creating millions of nodes cannot grow the
    // table past the arena it mirrors, and the arena is itself bounded.
    if interp.node_wrappers.len() < 4_000_000 {
        interp.node_wrappers.insert(handle, obj.clone());
    }
    JsValue::Object(obj)
}

/// The most dynamically inserted scripts one realm starts. Loaders that
/// inject a chunk per module (webpack, Turbopack, RequireJS) stay well
/// below this; a page that appends scripts in a loop is cut off here
/// rather than given unbounded egress.
pub const MAX_DYNAMIC_SCRIPTS: usize = 200;

/// `NodeList`, `HTMLCollection`, `HTMLAllCollection`, `DOMTokenList`,
/// `NamedNodeMap`, `DOMStringMap`: interface objects with a prototype
/// chain the engine's DOM lists sit on. The list prototype inherits from
/// `Array.prototype` (so `forEach`, `map`, `entries`, spread and
/// `for…of` all work on a NodeList, as in Chrome for the ones the spec
/// defines and as a superset for the rest), and a method a bundle adds
/// to `NodeList.prototype` is visible on every list.
fn install_node_list_interfaces(interp: &mut Interp) {
    let list_proto = JsObject::new(ObjKind::Plain, Some(interp.array_proto.clone()));
    // `item(i)`: the DOM accessor spelled as a method.
    let item: NativeFn = Rc::new(|interp, this, args| {
        let i = interp.number_arg(args.first(), f64::NAN)?;
        // Written negated so a NaN index answers null too.
        #[allow(clippy::neg_cmp_op_on_partial_ord)]
        if !(i >= 0.0) {
            return Ok(JsValue::Null);
        }
        let v = interp.get_property(&this, &(i as usize).to_string())?;
        Ok(if matches!(v, JsValue::Undefined) { JsValue::Null } else { v })
    });
    define_method(interp, &list_proto, "item", item);
    // `namedItem(name)`: the element with that id or name.
    let named_item: NativeFn = Rc::new(|interp, this, args| {
        let name = args.first().map(|v| v.to_js_string()).unwrap_or_default();
        let handles: Vec<usize> = match &this {
            JsValue::Object(o) => match &o.borrow().kind {
                ObjKind::DomList(h) => h.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        let Some(dom) = interp.dom.clone() else {
            return Ok(JsValue::Null);
        };
        let hit = {
            let doc = dom.borrow();
            handles.into_iter().find(|h| {
                doc.get(node_id(*h))
                    .and_then(|n| n.as_element())
                    .map(|e| e.attr("id") == Some(name.as_str()) || e.attr("name") == Some(name.as_str()))
                    .unwrap_or(false)
            })
        };
        Ok(match hit {
            Some(h) => wrap_node(interp, h),
            None => JsValue::Null,
        })
    });
    define_method(interp, &list_proto, "namedItem", named_item);
    // `Symbol.toStringTag` is a STRING data property (ES §20.1.3.6 reads
    // it as a value), so `Object.prototype.toString` names the interface.
    list_proto
        .borrow_mut()
        .set_prop(&symbol_key(SYM_TO_STRING_TAG), JsValue::str("NodeList"), false);
    let iface_ctor: NativeFn = Rc::new(|_i, _t, _a| Err(Interp::throw("TypeError: Illegal constructor")));
    // `NodeList` owns the shared list prototype (every list the engine
    // hands out is a NodeList-shaped live list). The other collection
    // interfaces get their OWN prototype, inheriting the list methods, so
    // `x instanceof HTMLCollection` holds only for values created as that
    // interface and `Object.prototype.toString` names each one.
    let node_list = JsObject::new(ObjKind::Native(iface_ctor.clone()), Some(interp.function_proto.clone()));
    node_list
        .borrow_mut()
        .set_prop("prototype", JsValue::Object(list_proto.clone()), false);
    list_proto
        .borrow_mut()
        .set_prop("constructor", JsValue::Object(node_list.clone()), false);
    interp.set_global("NodeList", JsValue::Object(node_list));
    for name in [
        "HTMLCollection",
        "HTMLAllCollection",
        "RadioNodeList",
        "DOMTokenList",
        "NamedNodeMap",
        "DOMStringMap",
        "StyleSheetList",
        "HTMLFormControlsCollection",
    ] {
        let proto = JsObject::new(ObjKind::Plain, Some(list_proto.clone()));
        proto
            .borrow_mut()
            .set_prop(&symbol_key(SYM_TO_STRING_TAG), JsValue::str(name), false);
        let ctor = JsObject::new(ObjKind::Native(iface_ctor.clone()), Some(interp.function_proto.clone()));
        ctor.borrow_mut()
            .set_prop("prototype", JsValue::Object(proto.clone()), false);
        proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor.clone()), false);
        interp.set_global(name, JsValue::Object(ctor));
    }
    // Every DOM list the bindings create inherits from this prototype.
    interp.dom_list_proto = Some(list_proto);
}

/// A live DOM list on the realm's `NodeList.prototype` (which itself
/// inherits `Array.prototype`), falling back to `Array.prototype` when a
/// list is built before the interfaces are installed.
fn dom_list(interp: &Interp, handles: Vec<usize>) -> JsValue {
    let proto = interp
        .dom_list_proto
        .clone()
        .unwrap_or_else(|| interp.array_proto.clone());
    JsValue::Object(JsObject::new(ObjKind::DomList(handles), Some(proto)))
}

/// The DomNode handle inside a JS value, if it is a node wrapper.
fn handle_of(v: &JsValue) -> Option<usize> {
    match v {
        JsValue::Object(o) => match &o.borrow().kind {
            ObjKind::DomNode(h) => Some(*h),
            _ => None,
        },
        _ => None,
    }
}

/// The lowercase tag name of a live DOM node, if the handle names an element.
fn node_tag(interp: &Interp, handle: usize) -> Option<String> {
    let dom = interp.dom.clone()?;
    let doc = dom.borrow();
    doc.get(node_id(handle))
        .and_then(|n| n.as_element())
        .map(|e| e.tag.clone())
}

fn node_id(handle: usize) -> NodeId {
    NodeId(handle as u32)
}

/// Copy `node` (and, when `deep`, its subtree) into fresh arena nodes.
pub fn clone_subtree(doc: &mut Document, node: NodeId, deep: bool) -> Option<NodeId> {
    let data = doc.get(node)?.data.clone();
    let new = doc.create_node(data);
    if deep {
        let kids: Vec<NodeId> = doc.children(node).collect();
        for k in kids {
            if let Some(nk) = clone_subtree(doc, k, true) {
                doc.append_child(new, nk);
            }
        }
    }
    Some(new)
}

/// The node a `append`/`prepend`/`before`/`after`/`replaceWith` argument
/// stands for: a node handle as is, anything else as a fresh text node.
/// A document fragment (the detached `#fragment` holder) is spliced: its
/// children move and the holder is discarded, so the fragment's first
/// child is what gets inserted and the rest follow by the caller's loop.
fn node_for_insert(interp: &mut Interp, v: &JsValue) -> Option<NodeId> {
    let dom = interp.dom.clone()?;
    if let Some(h) = handle_of(v) {
        return Some(node_id(h));
    }
    let text = v.to_js_string();
    let id = dom.borrow_mut().create_text(&text);
    Some(id)
}

/// The nodes an insertion of `node` moves: the node itself, or, for a
/// DocumentFragment (the detached `#fragment` holder), its children — the
/// holder never enters the tree, exactly as the DOM spec's "insert"
/// algorithm empties a fragment into its new parent.
fn insert_list(doc: &Document, node: NodeId) -> Vec<NodeId> {
    let is_fragment = doc
        .get(node)
        .and_then(|n| n.as_element())
        .map(|e| e.tag == "#fragment")
        .unwrap_or(false);
    if is_fragment {
        doc.children(node).collect()
    } else {
        vec![node]
    }
}

/// Whether `anc` is `node` itself or one of its ancestors.
fn is_ancestor_of(doc: &Document, anc: NodeId, node: NodeId) -> bool {
    let mut cur = Some(node);
    while let Some(n) = cur {
        if n == anc {
            return true;
        }
        cur = doc.get(n).and_then(|x| x.parent);
    }
    false
}

fn define_method(interp: &mut Interp, target: &ObjRef, name: &str, f: NativeFn) {
    let fo = JsObject::new(ObjKind::Native(f), Some(interp.function_proto.clone()));
    target
        .borrow_mut()
        .set_prop(name, JsValue::Object(fo), false);
}

#[cfg(test)]
mod argument_conversion_tests {
    use super::super::interp::test_support::eval_in_page;

    const ONE: &str = "({ valueOf() { return 1; } })";
    const THROWS: &str = "({ valueOf() { throw 'arg'; } })";

    #[test]
    fn list_item_indices_go_through_to_number() {
        let body = "<p id=a title=t lang=en></p><p id=b></p>";
        assert_eq!(
            eval_in_page(body, &format!("return document.querySelectorAll('p').item({ONE}).id")),
            "b"
        );
        assert_eq!(
            eval_in_page(body, &format!("return document.getElementById('a').attributes.item({ONE}).name")),
            "title"
        );
        assert_eq!(
            eval_in_page(body, &format!("try {{ document.querySelectorAll('p').item({THROWS}); }} catch (e) {{ return e; }}")),
            "arg"
        );
    }

    #[test]
    fn frame_and_walker_arguments_go_through_to_number() {
        assert_eq!(
            eval_in_page("", &format!("try {{ cancelAnimationFrame({THROWS}); }} catch (e) {{ return e; }}")),
            "arg"
        );
        assert_eq!(
            eval_in_page("<p></p>", &format!("try {{ document.createTreeWalker(document.body, {THROWS}); }} catch (e) {{ return e; }}")),
            "arg"
        );
    }
}

#[cfg(test)]
mod event_interface_tests {
    use super::super::interp::test_support::eval_in_page;

    #[test]
    fn constructed_events_are_instances_of_their_interface() {
        assert_eq!(
            eval_in_page(
                "",
                "const e = new Event('x'); \
                 return [e instanceof Event, Object.getPrototypeOf(e) === Event.prototype, typeof e.preventDefault, e.hasOwnProperty('preventDefault'), \
                         e.preventDefault === Event.prototype.preventDefault, Object.prototype.toString.call(e), e.type, e.bubbles, e.cancelable, e.isTrusted].join()"
            ),
            "true,true,function,false,true,[object Event],x,false,false,false"
        );
        assert_eq!(
            eval_in_page(
                "",
                "const c = new CustomEvent('c', { detail: { n: 1 }, bubbles: true }); const m = new MouseEvent('click', { clientX: 5, ctrlKey: true }); \
                 const k = new KeyboardEvent('keydown', { key: 'a' }); const i = new InputEvent('input', { data: 'z' }); const f = new FocusEvent('focus'); \
                 return [c instanceof CustomEvent, c instanceof Event, c.detail.n, c.bubbles, m instanceof MouseEvent, m instanceof UIEvent, m instanceof Event, m.clientX, m.button, m.ctrlKey, \
                         k instanceof KeyboardEvent, k.key, k.code, i instanceof InputEvent, i.data, f instanceof FocusEvent, f instanceof UIEvent, \
                         Object.getPrototypeOf(MouseEvent.prototype) === UIEvent.prototype, Object.getPrototypeOf(UIEvent.prototype) === Event.prototype, m.constructor === MouseEvent].join()"
            ),
            "true,true,1,true,true,true,true,5,0,true,true,a,,true,z,true,true,true,true,true"
        );
        assert_eq!(
            eval_in_page(
                "",
                "const a = new Event('a', { cancelable: true }), b = new Event('b'); a.preventDefault(); b.preventDefault(); \
                 let threw; try { new Event(); } catch (e) { threw = String(e).split(':')[0] === 'TypeError'; } \
                 return [a.defaultPrevented, b.defaultPrevented, threw, Event.AT_TARGET, Event.prototype.BUBBLING_PHASE, a.eventPhase, Event.name, Event.length].join()"
            ),
            "true,false,true,2,3,0,Event,1"
        );
    }

    #[test]
    fn dispatched_events_are_instances_too() {
        // click() focuses the button before the click event fires.
        assert_eq!(
            eval_in_page(
                "<div id='p'><button id='b'>go</button><input id='c' type='checkbox'></div>",
                "const seen = []; const b = document.getElementById('b'), c = document.getElementById('c'); \
                 b.addEventListener('click', (e) => seen.push('click:' + (e instanceof MouseEvent) + (e instanceof Event) + e.isTrusted + e.hasOwnProperty('stopPropagation'))); \
                 b.addEventListener('focus', (e) => seen.push('focus:' + (e instanceof FocusEvent))); \
                 c.addEventListener('input', (e) => seen.push('input:' + (e instanceof Event))); \
                 b.click(); c.click(); return seen.join(' ')"
            ),
            "focus:true click:truetruetruefalse input:true"
        );
        // dispatchEvent carries the caller's object; stopPropagation on the
        // prototype stops the bubbling.
        assert_eq!(
            eval_in_page(
                "<div id='p'><span id='s'>x</span></div>",
                "const s = document.getElementById('s'), p = document.getElementById('p'); const seen = []; const ev = new CustomEvent('ping', { bubbles: true, detail: 7 }); \
                 s.addEventListener('ping', (e) => { seen.push(e === ev, e.detail, e.target === s); e.stopPropagation(); }); p.addEventListener('ping', () => seen.push('bubbled')); \
                 const ok = s.dispatchEvent(ev); return [seen.join(), ok, ev.isTrusted, ev.eventPhase].join(' ')"
            ),
            "true,7,true true false 0"
        );
    }

    #[test]
    fn subclasses_legacy_creation_and_plain_objects_keep_working() {
        assert_eq!(
            eval_in_page(
                "<p>a</p><p>b</p>",
                "class Ping extends Event { constructor() { super('ping', { bubbles: true }); this.extra = 1; } } \
                 const p = document.querySelector('p'); let got; p.addEventListener('ping', (e) => { got = e; }); const ev = new Ping(); p.dispatchEvent(ev); \
                 const m = document.createEvent('MouseEvents'); m.initMouseEvent('click', true, true, window, 0, 0, 0, 3, 4); \
                 const c = document.createEvent('CustomEvent'); c.initCustomEvent('cc', false, false, 9); \
                 const legacy = document.createEvent('Event'); legacy.initEvent('lg', true, false); \
                 let plain = 0; p.addEventListener('plain', () => plain++); p.dispatchEvent({ type: 'plain' }); \
                 const seen = []; [].forEach.call(document.querySelectorAll('p'), (q) => seen.push(q.textContent)); \
                 return [got === ev, ev instanceof Ping, ev instanceof Event, ev.type, ev.extra, m instanceof MouseEvent, m.type, m.clientX, m.bubbles, \
                         c instanceof CustomEvent, c.detail, legacy instanceof Event, legacy.type, legacy.bubbles, plain, seen.join('')].join()"
            ),
            "true,true,true,ping,1,true,click,3,true,true,9,true,lg,true,1,ab"
        );
    }
}
