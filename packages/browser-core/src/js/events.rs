//! events — the DOM event interfaces (DOM §2.2-§2.5, UI Events): `Event`
//! and the subclasses the engine dispatches or a page constructs
//! (`CustomEvent`, `UIEvent`, `FocusEvent`, `MouseEvent`, `PointerEvent`,
//! `WheelEvent`, `KeyboardEvent`, `InputEvent`). Each is a constructor
//! whose prototype chain carries the shared methods (`preventDefault`,
//! `stopPropagation`, the legacy `init*Event`), so a constructed event, a
//! `document.createEvent` one and every event the engine dispatches are
//! instances of their interface and of `Event`.
//!
//! An event's state stays in own data properties (`type`, `target`,
//! `bubbles`, `defaultPrevented`, the interface's members) that the
//! dispatcher in `globals.rs` reads and writes.

use std::rc::Rc;

use super::interp::Interp;
use super::value::{symbol_key, JsObject, JsValue, NativeFn, ObjKind, ObjRef, SYM_TO_STRING_TAG};

/// An interface member's default, which also says how an init
/// dictionary's value converts (WebIDL: boolean, double, DOMString, any).
#[derive(Clone, Copy)]
enum Member {
    Bool,
    Num,
    Str,
    /// `any` / a nullable object: kept as given, `null` by default.
    Any,
}

/// An event interface: its name, its parent's, and its own members.
type Interface = (&'static str, Option<&'static str>, &'static [(&'static str, Member)]);

/// Every interface, parents before children.
const INTERFACES: &[Interface] = &[
    ("Event", None, &[]),
    ("CustomEvent", Some("Event"), &[("detail", Member::Any)]),
    ("UIEvent", Some("Event"), &[("view", Member::Any), ("detail", Member::Num)]),
    ("FocusEvent", Some("UIEvent"), &[("relatedTarget", Member::Any)]),
    (
        "MouseEvent",
        Some("UIEvent"),
        &[
            ("screenX", Member::Num),
            ("screenY", Member::Num),
            ("clientX", Member::Num),
            ("clientY", Member::Num),
            ("ctrlKey", Member::Bool),
            ("shiftKey", Member::Bool),
            ("altKey", Member::Bool),
            ("metaKey", Member::Bool),
            ("button", Member::Num),
            ("buttons", Member::Num),
            ("relatedTarget", Member::Any),
            ("movementX", Member::Num),
            ("movementY", Member::Num),
        ],
    ),
    (
        "PointerEvent",
        Some("MouseEvent"),
        &[
            ("pointerId", Member::Num),
            ("pointerType", Member::Str),
            ("isPrimary", Member::Bool),
            ("pressure", Member::Num),
        ],
    ),
    (
        "WheelEvent",
        Some("MouseEvent"),
        &[("deltaX", Member::Num), ("deltaY", Member::Num), ("deltaZ", Member::Num), ("deltaMode", Member::Num)],
    ),
    (
        "KeyboardEvent",
        Some("UIEvent"),
        &[
            ("key", Member::Str),
            ("code", Member::Str),
            ("location", Member::Num),
            ("ctrlKey", Member::Bool),
            ("shiftKey", Member::Bool),
            ("altKey", Member::Bool),
            ("metaKey", Member::Bool),
            ("repeat", Member::Bool),
            ("isComposing", Member::Bool),
            ("charCode", Member::Num),
            ("keyCode", Member::Num),
        ],
    ),
    (
        "InputEvent",
        Some("UIEvent"),
        &[("data", Member::Any), ("inputType", Member::Str), ("isComposing", Member::Bool)],
    ),
];

/// The interface an engine-dispatched event of type `event` belongs to.
pub fn interface_for_type(event: &str) -> &'static str {
    match event {
        "click" | "dblclick" | "auxclick" | "contextmenu" | "mousedown" | "mouseup" | "mousemove" | "mouseover"
        | "mouseout" | "mouseenter" | "mouseleave" => "MouseEvent",
        "pointerdown" | "pointerup" | "pointermove" | "pointerover" | "pointerout" | "pointerenter" | "pointerleave"
        | "pointercancel" => "PointerEvent",
        "wheel" => "WheelEvent",
        "keydown" | "keyup" | "keypress" => "KeyboardEvent",
        "input" | "beforeinput" => "InputEvent",
        "focus" | "blur" | "focusin" | "focusout" => "FocusEvent",
        _ => "Event",
    }
}

/// The interface `document.createEvent(name)` makes (DOM §4.5 step 2,
/// case-insensitive); an unknown name gives a plain `Event`.
fn interface_for_create_event(name: &str) -> &'static str {
    match name.to_ascii_lowercase().as_str() {
        "customevent" => "CustomEvent",
        "uievent" | "uievents" => "UIEvent",
        "focusevent" => "FocusEvent",
        "mouseevent" | "mouseevents" => "MouseEvent",
        "pointerevent" => "PointerEvent",
        "wheelevent" => "WheelEvent",
        "keyboardevent" | "keyboardevents" => "KeyboardEvent",
        "inputevent" => "InputEvent",
        _ => "Event",
    }
}

/// Every member `iface` has, its ancestors' first.
fn members_of(iface: &str) -> Vec<(&'static str, Member)> {
    let mut chain = Vec::new();
    let mut cur = Some(iface);
    while let Some(name) = cur {
        let Some((_, parent, members)) = INTERFACES.iter().find(|(n, _, _)| *n == name) else { break };
        chain.push(*members);
        cur = *parent;
    }
    let mut out: Vec<(&'static str, Member)> = Vec::new();
    for members in chain.into_iter().rev() {
        for (k, m) in members.iter() {
            if !out.iter().any(|(o, _)| o == k) {
                out.push((k, *m));
            }
        }
    }
    out
}

fn default_value(m: Member) -> JsValue {
    match m {
        Member::Bool => JsValue::Bool(false),
        Member::Num => JsValue::Num(0.0),
        Member::Str => JsValue::str(""),
        Member::Any => JsValue::Null,
    }
}

impl<'h> Interp<'h> {
    /// The installed prototype of event interface `iface`.
    pub fn event_proto(&self, iface: &str) -> Option<ObjRef> {
        self.event_protos.iter().find(|(n, _)| *n == iface).map(|(_, p)| p.clone())
    }

    /// Give `ev` an event's own state: `type`, the dispatch fields, the
    /// flags (`bubbles`, `cancelable`, `composed`) and every member of
    /// `iface` at its default, then the values `init` (an init
    /// dictionary, read through [[Get]] and converted per member) names.
    fn init_event_object(&mut self, ev: &ObjRef, ty: &str, iface: &str, init: Option<&JsValue>, trusted: bool) -> Result<(), JsValue> {
        {
            let mut b = ev.borrow_mut();
            b.set_prop("type", JsValue::str(ty), true);
            b.set_prop("target", JsValue::Null, true);
            b.set_prop("currentTarget", JsValue::Null, true);
            b.set_prop("eventPhase", JsValue::Num(0.0), true);
            b.set_prop("bubbles", JsValue::Bool(false), true);
            b.set_prop("cancelable", JsValue::Bool(false), true);
            b.set_prop("composed", JsValue::Bool(false), true);
            b.set_prop("defaultPrevented", JsValue::Bool(false), true);
            b.set_prop("isTrusted", JsValue::Bool(trusted), true);
            b.set_prop("timeStamp", JsValue::Num(self.now_ms), true);
        }
        let members = members_of(iface);
        for (k, m) in &members {
            ev.borrow_mut().set_prop(k, default_value(*m), true);
        }
        let Some(dict @ JsValue::Object(_)) = init else { return Ok(()) };
        let flags = [("bubbles", Member::Bool), ("cancelable", Member::Bool), ("composed", Member::Bool)];
        for (k, m) in flags.iter().chain(members.iter()) {
            let v = self.get_property(dict, k)?;
            if matches!(v, JsValue::Undefined) {
                continue;
            }
            let v = match m {
                Member::Bool => JsValue::Bool(v.truthy()),
                Member::Num => JsValue::Num(self.to_number_value(&v)?),
                Member::Str => JsValue::str(self.to_string_value(&v)?),
                Member::Any => v,
            };
            ev.borrow_mut().set_prop(k, v, true);
        }
        Ok(())
    }

    /// An engine-dispatched (trusted, cancelable) event of type `event`,
    /// an instance of the interface its type belongs to, with `target`
    /// set and `extra` members (`clientX`, `key`, `detail`, …) applied
    /// over the interface defaults. Without the DOM interfaces installed
    /// the event is a plain object carrying the methods itself.
    pub fn new_dispatch_event(&mut self, event: &str, target: JsValue, bubbles: bool, extra: &[(&str, JsValue)]) -> ObjRef {
        let iface = interface_for_type(event);
        let proto = self.event_proto(iface);
        let has_proto = proto.is_some();
        let ev = JsObject::new(ObjKind::Plain, Some(proto.unwrap_or_else(|| self.object_proto.clone())));
        // Reading a missing init dictionary cannot fail.
        let _ = self.init_event_object(&ev, event, iface, None, true);
        {
            let mut b = ev.borrow_mut();
            b.set_prop("target", target.clone(), true);
            b.set_prop("currentTarget", target, true);
            b.set_prop("bubbles", JsValue::Bool(bubbles), true);
            b.set_prop("cancelable", JsValue::Bool(true), true);
            for (k, v) in extra {
                b.set_prop(k, v.clone(), true);
            }
        }
        if !has_proto {
            for (name, f) in event_methods() {
                let fv = self.native(f);
                ev.borrow_mut().set_prop(name, fv, false);
            }
        }
        ev
    }
}

/// The methods `Event.prototype` carries (and a plain object passed to
/// `dispatchEvent` is given).
pub fn event_methods() -> Vec<(&'static str, NativeFn)> {
    // preventDefault only takes effect on a cancelable event (DOM §2.7).
    let prevent: NativeFn = Rc::new(|_interp, this, _args| {
        if let JsValue::Object(o) = &this {
            let cancelable = o.borrow().get_prop("cancelable").is_some_and(|v| v.truthy());
            if cancelable {
                o.borrow_mut().set_prop("defaultPrevented", JsValue::Bool(true), true);
            }
        }
        Ok(JsValue::Undefined)
    });
    // stopPropagation: the remaining listeners on the CURRENT node still
    // run; stopImmediatePropagation: nothing further runs at all.
    let stop: NativeFn = Rc::new(|_interp, this, _args| {
        if let JsValue::Object(o) = &this {
            o.borrow_mut().set_prop("__propagationStopped", JsValue::Bool(true), false);
        }
        Ok(JsValue::Undefined)
    });
    let stop_immediate: NativeFn = Rc::new(|_interp, this, _args| {
        if let JsValue::Object(o) = &this {
            let mut b = o.borrow_mut();
            b.set_prop("__propagationStopped", JsValue::Bool(true), false);
            b.set_prop("__immediateStopped", JsValue::Bool(true), false);
        }
        Ok(JsValue::Undefined)
    });
    vec![("preventDefault", prevent), ("stopPropagation", stop), ("stopImmediatePropagation", stop_immediate)]
}

/// A legacy `init*Event` method: positional arguments assign the event's
/// `type`, `bubbles` and `cancelable`, then the listed members in order.
fn legacy_init(members: &'static [(&'static str, Member)]) -> NativeFn {
    Rc::new(move |interp, this, args| {
        let JsValue::Object(o) = &this else { return Ok(JsValue::Undefined) };
        let ty = match args.first() {
            Some(v) => interp.to_string_value(v)?,
            None => String::new(),
        };
        let mut b = o.borrow_mut();
        b.set_prop("type", JsValue::str(ty), true);
        b.set_prop("bubbles", JsValue::Bool(args.get(1).is_some_and(JsValue::truthy)), true);
        b.set_prop("cancelable", JsValue::Bool(args.get(2).is_some_and(JsValue::truthy)), true);
        for (i, (k, m)) in members.iter().enumerate() {
            let v = args.get(i + 3).cloned().unwrap_or(JsValue::Undefined);
            let v = match (m, v) {
                (Member::Bool, v) => JsValue::Bool(v.truthy()),
                (Member::Num, v) => JsValue::Num(v.to_number()),
                (Member::Str, JsValue::Undefined) => JsValue::str(""),
                (Member::Str, v) => JsValue::str(v.to_js_string()),
                (Member::Any, JsValue::Undefined) => JsValue::Null,
                (Member::Any, v) => v,
            };
            b.set_prop(k, v, true);
        }
        Ok(JsValue::Undefined)
    })
}

const INIT_UI: &[(&str, Member)] = &[("view", Member::Any), ("detail", Member::Num)];
const INIT_CUSTOM: &[(&str, Member)] = &[("detail", Member::Any)];
const INIT_MOUSE: &[(&str, Member)] = &[
    ("view", Member::Any),
    ("detail", Member::Num),
    ("screenX", Member::Num),
    ("screenY", Member::Num),
    ("clientX", Member::Num),
    ("clientY", Member::Num),
    ("ctrlKey", Member::Bool),
    ("altKey", Member::Bool),
    ("shiftKey", Member::Bool),
    ("metaKey", Member::Bool),
    ("button", Member::Num),
    ("relatedTarget", Member::Any),
];
const INIT_KEYBOARD: &[(&str, Member)] = &[
    ("view", Member::Any),
    ("key", Member::Str),
    ("location", Member::Num),
    ("ctrlKey", Member::Bool),
    ("altKey", Member::Bool),
    ("shiftKey", Member::Bool),
    ("metaKey", Member::Bool),
];

/// Install the event interfaces as globals and record their prototypes
/// for the dispatcher, plus `document.createEvent` on `doc`.
pub fn install_event_interfaces(interp: &mut Interp, doc: &ObjRef) {
    interp.event_protos.clear();
    let tag_key = symbol_key(SYM_TO_STRING_TAG);
    for (name, parent, _) in INTERFACES {
        let parent_proto = parent.and_then(|p| interp.event_proto(p)).unwrap_or_else(|| interp.object_proto.clone());
        let parent_ctor = parent
            .and_then(|p| match interp.global_object.borrow().get_prop(p) {
                Some(JsValue::Object(c)) => Some(c),
                _ => None,
            })
            .unwrap_or_else(|| interp.function_proto.clone());
        let proto = JsObject::new(ObjKind::Plain, Some(parent_proto));
        let iface: &'static str = name;
        let proto_for_ctor = proto.clone();
        // `new Event(type, init)`: the receiver `construct` allocated from
        // new.target's prototype (a subclass's included) becomes the
        // event; called without `new` the event is made here.
        let ctor_fn: NativeFn = Rc::new(move |interp, this, args| {
            let Some(ty) = args.first() else {
                return Err(Interp::throw(format!(
                    "TypeError: Failed to construct '{iface}': 1 argument required, but only 0 present."
                )));
            };
            let ty = interp.to_string_value(ty)?;
            let ev = match (&interp.new_target, &this) {
                (Some(JsValue::Object(_)), JsValue::Object(t)) if matches!(t.borrow().kind, ObjKind::Plain) => t.clone(),
                _ => JsObject::new(ObjKind::Plain, Some(proto_for_ctor.clone())),
            };
            interp.init_event_object(&ev, &ty, iface, args.get(1), false)?;
            Ok(JsValue::Object(ev))
        });
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(parent_ctor));
        {
            let mut p = proto.borrow_mut();
            p.set_prop("constructor", JsValue::Object(ctor.clone()), false);
            p.set_prop(&tag_key, JsValue::str(*name), false);
        }
        ctor.borrow_mut().set_prop("prototype", JsValue::Object(proto.clone()), false);
        let methods: Vec<(&str, NativeFn)> = match *name {
            "Event" => {
                let mut m = event_methods();
                m.push(("initEvent", legacy_init(&[])));
                for (k, v) in [("NONE", 0.0), ("CAPTURING_PHASE", 1.0), ("AT_TARGET", 2.0), ("BUBBLING_PHASE", 3.0)] {
                    proto.borrow_mut().set_prop(k, JsValue::Num(v), false);
                    ctor.borrow_mut().set_prop(k, JsValue::Num(v), false);
                }
                m
            }
            "CustomEvent" => vec![("initCustomEvent", legacy_init(INIT_CUSTOM))],
            "UIEvent" => vec![("initUIEvent", legacy_init(INIT_UI))],
            "MouseEvent" => vec![("initMouseEvent", legacy_init(INIT_MOUSE))],
            "KeyboardEvent" => vec![("initKeyboardEvent", legacy_init(INIT_KEYBOARD))],
            _ => Vec::new(),
        };
        for (k, f) in methods {
            let fv = interp.native(f);
            proto.borrow_mut().set_prop(k, fv, false);
        }
        interp.event_protos.push((name, proto));
        interp.set_global(name, JsValue::Object(ctor));
    }
    // document.createEvent(interface): an uninitialised, untrusted event
    // of that interface for the legacy init*Event methods.
    let create_event: NativeFn = Rc::new(|interp, _this, args| {
        let name = match args.first() {
            Some(v) => interp.to_string_value(v)?,
            None => String::new(),
        };
        let iface = interface_for_create_event(&name);
        let proto = interp.event_proto(iface).unwrap_or_else(|| interp.object_proto.clone());
        let ev = JsObject::new(ObjKind::Plain, Some(proto));
        interp.init_event_object(&ev, "", iface, None, false)?;
        Ok(JsValue::Object(ev))
    });
    let f = interp.native(create_event);
    doc.borrow_mut().set_prop("createEvent", f, false);
}
