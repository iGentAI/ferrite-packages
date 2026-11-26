//! MutationObserver, IntersectionObserver and ResizeObserver.

use std::rc::Rc;
use super::super::interp::Interp;
use super::super::value::JsObject;
use super::super::value::JsValue;
use super::super::value::NativeFn;
use super::super::value::ObjKind;
use super::{define_method};
use super::document::{noop_method};

/// MutationObserver / IntersectionObserver / ResizeObserver / 
/// PerformanceObserver constructors.
pub(super) fn install_observers(interp: &mut Interp) {
    // MutationObserver: observe/disconnect/takeRecords; no records are
    // produced (the whole script run is one synchronous mutation batch
    // from the page's point of view, and layout reads the final tree).
    let mo: NativeFn = Rc::new(|interp, this, args| {
        let obj = match &this {
            JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
            _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
        };
        obj.borrow_mut()
            .set_prop("__callback", args.first().cloned().unwrap_or(JsValue::Undefined), false);
        let noop = noop_method();
        define_method(interp, &obj, "observe", noop.clone());
        define_method(interp, &obj, "disconnect", noop);
        let take: NativeFn = Rc::new(|interp, _t, _a| Ok(interp.new_array(Vec::new())));
        define_method(interp, &obj, "takeRecords", take);
        Ok(JsValue::Object(obj))
    });
    let ctor = JsObject::new(ObjKind::Native(mo), Some(interp.function_proto.clone()));
    let proto = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
    ctor.borrow_mut()
        .set_prop("prototype", JsValue::Object(proto), false);
    interp.set_global("MutationObserver", JsValue::Object(ctor));

    // IntersectionObserver: observe(target) schedules one callback with an
    // intersecting entry for that target (a fully visible page).
    let io: NativeFn = Rc::new(|interp, this, args| {
        let obj = match &this {
            JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
            _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
        };
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        obj.borrow_mut().set_prop("__callback", cb, false);
        obj.borrow_mut().set_prop("root", JsValue::Null, true);
        obj.borrow_mut().set_prop("rootMargin", JsValue::str("0px"), true);
        let observe: NativeFn = Rc::new(|interp, this, args| {
            let JsValue::Object(o) = &this else {
                return Ok(JsValue::Undefined);
            };
            let cb = o.borrow().get_prop("__callback").unwrap_or(JsValue::Undefined);
            let target = args.first().cloned().unwrap_or(JsValue::Null);
            let entry = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            entry.borrow_mut().set_prop("target", target, true);
            entry
                .borrow_mut()
                .set_prop("isIntersecting", JsValue::Bool(true), true);
            entry
                .borrow_mut()
                .set_prop("intersectionRatio", JsValue::Num(1.0), true);
            entry
                .borrow_mut()
                .set_prop("time", JsValue::Num(interp.now_ms), true);
            let rect = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            for k in ["x", "y", "top", "left", "right", "bottom", "width", "height"] {
                rect.borrow_mut().set_prop(k, JsValue::Num(0.0), true);
            }
            entry
                .borrow_mut()
                .set_prop("boundingClientRect", JsValue::Object(rect.clone()), true);
            entry
                .borrow_mut()
                .set_prop("intersectionRect", JsValue::Object(rect.clone()), true);
            entry
                .borrow_mut()
                .set_prop("rootBounds", JsValue::Object(rect), true);
            let entries = interp.new_array(vec![JsValue::Object(entry)]);
            if matches!(cb, JsValue::Object(_)) {
                // Deliver on the virtual clock like a real observer (after
                // the current task), with (entries, observer).
                interp.set_timer(cb, 0.0, vec![entries, this.clone()], false);
            }
            Ok(JsValue::Undefined)
        });
        define_method(interp, &obj, "observe", observe);
        let noop = noop_method();
        define_method(interp, &obj, "unobserve", noop.clone());
        define_method(interp, &obj, "disconnect", noop);
        let take: NativeFn = Rc::new(|interp, _t, _a| Ok(interp.new_array(Vec::new())));
        define_method(interp, &obj, "takeRecords", take);
        Ok(JsValue::Object(obj))
    });
    let ctor = JsObject::new(ObjKind::Native(io), Some(interp.function_proto.clone()));
    let proto = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
    ctor.borrow_mut()
        .set_prop("prototype", JsValue::Object(proto), false);
    interp.set_global("IntersectionObserver", JsValue::Object(ctor));

    // ResizeObserver: observe(target) delivers one entry once.
    let ro: NativeFn = Rc::new(|interp, this, args| {
        let obj = match &this {
            JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
            _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
        };
        let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
        obj.borrow_mut().set_prop("__callback", cb, false);
        let observe: NativeFn = Rc::new(|interp, this, args| {
            let JsValue::Object(o) = &this else {
                return Ok(JsValue::Undefined);
            };
            let cb = o.borrow().get_prop("__callback").unwrap_or(JsValue::Undefined);
            let target = args.first().cloned().unwrap_or(JsValue::Null);
            let entry = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            entry.borrow_mut().set_prop("target", target, true);
            let rect = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            for k in ["x", "y", "top", "left", "right", "bottom", "width", "height"] {
                rect.borrow_mut().set_prop(k, JsValue::Num(0.0), true);
            }
            entry
                .borrow_mut()
                .set_prop("contentRect", JsValue::Object(rect), true);
            let size = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            size.borrow_mut().set_prop("inlineSize", JsValue::Num(0.0), true);
            size.borrow_mut().set_prop("blockSize", JsValue::Num(0.0), true);
            let sizes = interp.new_array(vec![JsValue::Object(size)]);
            entry.borrow_mut().set_prop("contentBoxSize", sizes.clone(), true);
            entry.borrow_mut().set_prop("borderBoxSize", sizes, true);
            let entries = interp.new_array(vec![JsValue::Object(entry)]);
            if matches!(cb, JsValue::Object(_)) {
                interp.set_timer(cb, 0.0, vec![entries, this.clone()], false);
            }
            Ok(JsValue::Undefined)
        });
        define_method(interp, &obj, "observe", observe);
        let noop = noop_method();
        define_method(interp, &obj, "unobserve", noop.clone());
        define_method(interp, &obj, "disconnect", noop);
        Ok(JsValue::Object(obj))
    });
    let ctor = JsObject::new(ObjKind::Native(ro), Some(interp.function_proto.clone()));
    let proto = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
    ctor.borrow_mut()
        .set_prop("prototype", JsValue::Object(proto), false);
    interp.set_global("ResizeObserver", JsValue::Object(ctor));

    // PerformanceObserver: observe/disconnect, never fires.
    let po: NativeFn = Rc::new(|interp, this, _args| {
        let obj = match &this {
            JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
            _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
        };
        let noop = noop_method();
        define_method(interp, &obj, "observe", noop.clone());
        define_method(interp, &obj, "disconnect", noop);
        let take: NativeFn = Rc::new(|interp, _t, _a| Ok(interp.new_array(Vec::new())));
        define_method(interp, &obj, "takeRecords", take);
        Ok(JsValue::Object(obj))
    });
    let ctor = JsObject::new(ObjKind::Native(po), Some(interp.function_proto.clone()));
    let supported = interp.new_array(Vec::new());
    ctor.borrow_mut()
        .set_prop("supportedEntryTypes", supported, false);
    interp.set_global("PerformanceObserver", JsValue::Object(ctor));
}
