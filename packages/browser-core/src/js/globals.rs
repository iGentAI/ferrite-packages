//! globals — realm bootstrap: `Interp::new` plus the global object install
//! (console, Math, JSON, Object/Array statics, Promise, timers, fetch/XHR,
//! addEventListener). Split from `interp.rs` to keep each half reviewable.
//!
//! Panic-free like the rest of the engine: no indexing, no unwrap.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::rc::Rc;

use super::interp::{HostHooks, Interp, Scope};
use super::value::{JsObject, JsValue, NativeFn, ObjKind, ObjRef, Prop, WELL_KNOWN_SYMBOLS, iterator_key};

impl<'h> Interp<'h> {
    /// Build a fresh realm over the provided host hooks: intrinsic
    /// prototypes, global scope, and the standard globals installed.
    pub fn new(hooks: &'h mut dyn HostHooks) -> Interp<'h> {
        let object_proto = JsObject::new(ObjKind::Plain, None);
        let function_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let array_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let string_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let number_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let boolean_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let promise_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let error_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let regexp_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let date_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let symbol_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let map_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let set_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let iterator_proto = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let generator_proto = JsObject::new(ObjKind::Plain, Some(iterator_proto.clone()));
        let global_object = JsObject::new(ObjKind::Plain, Some(object_proto.clone()));
        let global_scope = Scope::new(None);

        let mut interp = Interp {
            global_scope,
            global_object,
            object_proto,
            function_proto,
            array_proto,
            string_proto,
            number_proto,
            boolean_proto,
            promise_proto,
            error_proto,
            regexp_proto,
            date_proto,
            symbol_proto,
            map_proto,
            set_proto,
            iterator_proto,
            generator_proto,
            next_symbol_id: WELL_KNOWN_SYMBOLS,
            symbol_registry: HashMap::new(),
            known_symbols: HashMap::new(),
            microtasks: VecDeque::new(),
            timers: Vec::new(),
            next_timer_id_pub: 1,
            now_ms: 0.0,
            step_budget: 5_000_000,
            hooks,
            dom: None,
            listeners: HashMap::new(),
            node_listeners: HashMap::new(),
            focused: None,
            node_wrappers: HashMap::new(),
            dom_list_proto: None,
            super_this: None,
            timers_fired_count: 0,
            new_target: None,
            call_depth: 0,
            error_trace: Vec::new(),
            deadline: None,
            monotonic: None,
            stack_base: super::interp::stack_mark(),
            stack_budget_bytes: super::interp::DEFAULT_STACK_BUDGET_BYTES,
            started_scripts: std::collections::HashSet::new(),
            dynamic_scripts: 0,
            dynamic_scripts_ok: 0,
            external_scripts: HashMap::new(),
            script_step_budget: 5_000_000,
            dynamic_steps: 0,
            script_strict: false,
            intrinsic_iterators: super::interp::IntrinsicIterators::default(),
            empty_string: JsValue::str(""),
            named_builtins: std::collections::HashSet::new(),
            array_species: None,
            event_protos: Vec::new(),
        };
        interp.install_globals();
        interp
    }

    /// Total timer callbacks fired so far (for reports).
    pub fn timers_fired(&self) -> u32 {
        self.timers_fired_count
    }

    /// Register an event listener (used by addEventListener natives).
    pub fn add_listener(&mut self, event: &str, callback: JsValue) {
        self.listeners
            .entry(event.to_string())
            .or_default()
            .push(callback);
    }

    /// Register a node-scoped event listener (element.addEventListener).
    pub fn add_node_listener(&mut self, handle: usize, event: &str, callback: JsValue) {
        self.node_listeners
            .entry((handle, event.to_string()))
            .or_default()
            .push(callback);
    }

    /// Remove a node-scoped listener (element.removeEventListener).
    pub fn remove_node_listener(&mut self, handle: usize, event: &str, callback: &JsValue) {
        if let Some(list) = self.node_listeners.get_mut(&(handle, event.to_string())) {
            list.retain(|cb| !super::interp::strict_eq(cb, callback));
        }
    }

    /// Fire the listeners registered for a simple document-level event
    /// (`DOMContentLoaded`, `load`): window-level listeners plus those
    /// registered on `document` (node handle 0). No bubbling model.
    pub fn dispatch_simple_event(&mut self, event: &str) -> Result<(), JsValue> {
        let mut cbs = self.listeners.get(event).cloned().unwrap_or_default();
        if let Some(doc_cbs) = self.node_listeners.get(&(0, event.to_string())) {
            cbs.extend(doc_cbs.iter().cloned());
        }
        let target = match self.dom {
            Some(_) => self.wrap_dom_node(0),
            None => JsValue::Null,
        };
        for cb in cbs {
            // An `Event` targeted at the document (DOMContentLoaded and
            // load are not cancelable and do not bubble here).
            let ev = self.make_event(event, target.clone(), false, &[]);
            ev.borrow_mut().set_prop("cancelable", JsValue::Bool(false), true);
            if let Err(e) = self.call(cb, JsValue::Undefined, &[JsValue::Object(ev)]) {
                let msg = super::interp::to_display(&e);
                self.hooks
                    .console("error", &format!("uncaught (in {event} listener): {msg}"));
            }
            self.drain_microtasks()?;
        }
        Ok(())
    }

    /// Build a DOM event for the engine to dispatch: an instance of the
    /// interface its type belongs to (`MouseEvent` for `click`, …) with
    /// `type`, `target`, `bubbles`, trusted and cancelable, plus any
    /// `extra` members (`key`, `clientX`, `detail`); see
    /// `Interp::new_dispatch_event`.
    pub fn make_event(
        &mut self,
        event: &str,
        target: JsValue,
        bubbles: bool,
        extra: &[(&str, JsValue)],
    ) -> ObjRef {
        self.new_dispatch_event(event, target, bubbles, extra)
    }

    /// Dispatch a DOM event at `handle`, following the DOM event model's
    /// target + bubble phases: the target's listeners first, then each
    /// ancestor's (elements, then the document), then window-level
    /// listeners. Inline `on<event>` attributes run as handlers at each
    /// node. Returns `Ok(true)` when the default action may proceed (no
    /// listener called `preventDefault()`).
    pub fn dispatch_node_event(
        &mut self,
        handle: usize,
        event: &str,
        bubbles: bool,
        extra: &[(&str, JsValue)],
    ) -> Result<bool, JsValue> {
        let target = self.wrap_dom_node(handle);
        let ev = self.make_event(event, target, bubbles, extra);
        self.dispatch_event_object(handle, &ev)
    }

    /// Dispatch an EXISTING event object at `handle` (the `dispatchEvent`
    /// path): the object itself travels to every listener, so `target`,
    /// `currentTarget`, `defaultPrevented` and any custom properties the
    /// caller set are observable on the caller's own object afterwards.
    /// `type` and `bubbles` are read off the object. Returns `Ok(true)` when
    /// the default action may proceed.
    pub fn dispatch_event_object(&mut self, handle: usize, ev: &ObjRef) -> Result<bool, JsValue> {
        let target = self.wrap_dom_node(handle);
        let (event, bubbles) = {
            let mut b = ev.borrow_mut();
            b.set_prop("target", target.clone(), true);
            b.set_prop("currentTarget", target, true);
            b.set_prop("__propagationStopped", JsValue::Bool(false), false);
            b.set_prop("__immediateStopped", JsValue::Bool(false), false);
            (
                b.get_prop("type").map(|v| v.to_js_string()).unwrap_or_default(),
                b.get_prop("bubbles").map(|v| v.truthy()).unwrap_or(false),
            )
        };
        let event = event.as_str();
        // Propagation path: the target, then its ancestors (when bubbling).
        let mut path: Vec<usize> = vec![handle];
        if bubbles {
            if let Some(dom) = self.dom.clone() {
                let doc = dom.borrow();
                let mut cur = doc
                    .get(super::super::dom::NodeId(handle as u32))
                    .and_then(|n| n.parent);
                while let Some(p) = cur {
                    path.push(p.index());
                    cur = doc.get(p).and_then(|n| n.parent);
                }
            }
        }
        let ev_val = JsValue::Object(ev.clone());
        let mut stopped = false;
        for (i, h) in path.into_iter().enumerate() {
            let current = self.wrap_dom_node(h);
            {
                let mut b = ev.borrow_mut();
                b.set_prop("currentTarget", current.clone(), true);
                // AT_TARGET = 2, BUBBLING_PHASE = 3.
                b.set_prop("eventPhase", JsValue::Num(if i == 0 { 2.0 } else { 3.0 }), true);
            }
            // Inline handler attribute (`onclick="..."`).
            let inline_src = self.dom.clone().and_then(|dom| {
                let doc = dom.borrow();
                doc.get(super::super::dom::NodeId(h as u32))
                    .and_then(|n| n.as_element())
                    .and_then(|e| e.attr(&format!("on{event}")))
                    .map(str::to_string)
            });
            // The inline handler is the first listener at this node: the
            // same stop-flag checks apply to it as to every later callback.
            let mut immediate = false;
            if let Some(src) = inline_src {
                self.run_inline_handler(&src, current.clone(), &ev_val, event);
                self.drain_microtasks()?;
                let (p, i) = stop_flags(ev);
                stopped |= p;
                immediate = i;
            }
            if !immediate {
                // Property handler (`el.onclick = fn`) then addEventListener list.
                let mut cbs: Vec<JsValue> = self
                    .node_listeners
                    .get(&(h, format!("__on:{event}")))
                    .cloned()
                    .unwrap_or_default();
                cbs.extend(
                    self.node_listeners
                        .get(&(h, event.to_string()))
                        .cloned()
                        .unwrap_or_default(),
                );
                for cb in cbs {
                    if let Err(e) = self.call(cb, current.clone(), std::slice::from_ref(&ev_val)) {
                        let msg = super::interp::to_display(&e);
                        self.hooks
                            .console("error", &format!("uncaught (in {event} listener): {msg}"));
                    }
                    self.drain_microtasks()?;
                    let (p, i) = stop_flags(ev);
                    stopped |= p;
                    if i {
                        break;
                    }
                }
            }
            if stopped {
                break;
            }
        }
        if bubbles && !stopped {
            let cbs = self.listeners.get(event).cloned().unwrap_or_default();
            let window = JsValue::Object(self.global_object.clone());
            ev.borrow_mut().set_prop("currentTarget", window.clone(), true);
            for cb in cbs {
                if let Err(e) = self.call(cb, window.clone(), std::slice::from_ref(&ev_val)) {
                    let msg = super::interp::to_display(&e);
                    self.hooks
                        .console("error", &format!("uncaught (in {event} listener): {msg}"));
                }
                self.drain_microtasks()?;
                // Window is the last node of the path: stopPropagation has
                // nothing left to stop, stopImmediatePropagation still does.
                if stop_flags(ev).1 {
                    break;
                }
            }
        }
        let prevented = {
            let mut b = ev.borrow_mut();
            // NONE = 0 once dispatch is over; currentTarget is null.
            b.set_prop("eventPhase", JsValue::Num(0.0), true);
            b.set_prop("currentTarget", JsValue::Null, true);
            b.get_prop("defaultPrevented")
                .map(|v| v.truthy())
                .unwrap_or(false)
        };
        Ok(!prevented)
    }

    /// Run an inline `on<event>="..."` attribute body as a handler with
    /// `this` bound to the element and `event` in scope. Errors are reported
    /// to the console sink, never propagated (a broken inline handler must
    /// not break the dispatch).
    fn run_inline_handler(&mut self, body: &str, this: JsValue, ev: &JsValue, event: &str) {
        let src = format!("(function(event) {{\n{body}\n}})");
        let prog = match super::parser::parse(&src) {
            Ok(p) => p,
            Err(e) => {
                self.hooks.console(
                    "error",
                    &format!("SyntaxError in inline on{event} handler: {}", e.message),
                );
                return;
            }
        };
        let f = match self.run_program(&prog) {
            Ok(f) => f,
            Err(e) => {
                let msg = super::interp::to_display(&e);
                self.hooks
                    .console("error", &format!("inline on{event} handler: {msg}"));
                return;
            }
        };
        if let Err(e) = self.call(f, this, std::slice::from_ref(ev)) {
            let msg = super::interp::to_display(&e);
            self.hooks
                .console("error", &format!("uncaught (in inline on{event}): {msg}"));
        }
    }

    pub(super) fn native(&mut self, f: NativeFn) -> JsValue {
        JsValue::Object(JsObject::new(
            ObjKind::Native(f),
            Some(self.function_proto.clone()),
        ))
    }

    /// Drop the persistent DOM realm (`Page.navigate` tears the world down).
    pub fn reset_realm(&mut self) {
        self.listeners.clear();
        self.node_listeners.clear();
        self.focused = None;
    }

    pub(super) fn set_global(&mut self, name: &str, v: JsValue) {
        self.global_object
            .borrow_mut()
            .set_prop(name, v.clone(), false);
        Scope::declare(&self.global_scope.clone(), name, v, false);
    }

    /// Install every standard global into the realm.
    fn install_globals(&mut self) {
        self.install_console();
        self.install_timers();
        self.install_math();
        self.install_json();
        self.install_object_statics();
        self.install_array_statics();
        self.install_number_statics();
        self.install_promise();
        self.install_prototypes();
        // Gap builtins (Date, Promise.race, hasOwnProperty, array/string
        // extras, isFinite) live in builtins_ext.rs to keep files reviewable.
        self.install_gap_builtins();
        // ES2015+ surface (Symbol, Map/Set, Proxy/Reflect, descriptors, the
        // iterator protocol) lives in builtins_es.rs.
        self.install_es_builtins();
        let g = JsValue::Object(self.global_object.clone());
        self.set_global("window", g.clone());
        self.set_global("globalThis", g.clone());
        self.set_global("self", g.clone());
        self.set_global("top", g.clone());
        self.set_global("parent", g.clone());
        self.set_global("frames", g);
        self.install_navigator();
        // `location`, storage, URL, encoding, typed arrays and the rest of
        // the web platform live in builtins_web.rs.
        self.install_web_builtins();
        self.install_window_metrics();
        self.install_window_listeners();
        self.install_fetch();
        self.install_xhr();

        // Every constructor's `prototype.constructor` points back at it
        // (ES §20-§27 each say so). Bundles call `x.constructor(...)` to
        // clone a value (`"".constructor(v)` as ToString, `fn.constructor
        // (src)` as Function) and compare `o.constructor === Object`; an
        // intrinsic prototype missing the link answers `Object` instead,
        // which is how a lodash `toString` helper came to call a String
        // wrapper object. One pass here after every installer has run,
        // filling only links that are still absent.
        let names = [
            "Object", "Array", "String", "Number", "Boolean", "Function", "Promise",
            "Date", "RegExp", "Error", "TypeError", "RangeError", "SyntaxError",
            "EvalError", "ReferenceError", "URIError", "AggregateError", "Map", "Set",
            "WeakMap", "WeakSet", "Symbol", "XMLHttpRequest", "URL", "URLSearchParams",
            "Headers", "Event", "CustomEvent", "MutationObserver", "IntersectionObserver",
            "ResizeObserver", "ArrayBuffer", "Int8Array", "Uint8Array", "Uint8ClampedArray",
            "Int16Array", "Uint16Array", "Int32Array", "Uint32Array", "Float32Array",
            "Float64Array", "TextEncoder", "TextDecoder", "AbortController", "Response",
            "Request", "FormData",
        ];
        for name in names {
            self.link_prototype_constructor(name);
        }

        // The intrinsic `[Symbol.iterator]` functions, as installed: the
        // `for...of` fast path compares against these (see
        // `LoopSource::open`).
        let key = iterator_key();
        let iter_of = |p: &ObjRef| match p.borrow().get_prop(&key) {
            Some(JsValue::Object(f)) => Some(f),
            _ => None,
        };
        // %TypedArray%.prototype is the prototype of every view prototype.
        let typed_proto = match self.global_object.borrow().get_prop("Uint8Array") {
            Some(JsValue::Object(u8)) => match u8.borrow().get_prop("prototype") {
                Some(JsValue::Object(p)) => p.borrow().proto.clone(),
                _ => None,
            },
            _ => None,
        };
        self.intrinsic_iterators = super::interp::IntrinsicIterators {
            array: iter_of(&self.array_proto),
            typed: typed_proto.as_ref().and_then(iter_of),
            map: iter_of(&self.map_proto),
            set: iter_of(&self.set_proto),
        };
        self.install_species_getters();
        // Function.prototype is itself a function of length 0 named "",
        // which a function that lost its own `name` inherits from.
        self.function_proto
            .borrow_mut()
            .define_function_meta(0.0, JsValue::str(""));
        if let Some(tp) = &typed_proto {
            let tp = tp.clone();
            self.name_builtins_from("%TypedArray%.prototype", &tp);
        }
        self.name_builtins();
    }

    fn install_console(&mut self) {
        let console = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        for level in ["log", "info", "warn", "error", "debug"] {
            let lvl: &'static str = match level {
                "info" => "info",
                "warn" => "warn",
                "error" => "error",
                "debug" => "debug",
                _ => "log",
            };
            let f: NativeFn = Rc::new(move |interp, _this, args| {
                let msg = args
                    .iter()
                    .map(|a| a.to_js_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                interp.hooks.console(lvl, &msg);
                Ok(JsValue::Undefined)
            });
            let fv = self.native(f);
            console.borrow_mut().set_prop(level, fv, false);
        }
        self.set_global("console", JsValue::Object(console));
    }

    fn install_timers(&mut self) {
        let set_timeout: NativeFn = Rc::new(|interp, _this, args| {
            let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
            let delay = interp.number_arg(args.get(1), 0.0)?;
            let rest: Vec<JsValue> = args.get(2..).map(|s| s.to_vec()).unwrap_or_default();
            let id = interp.set_timer(cb, delay, rest, false);
            Ok(JsValue::Num(id as f64))
        });
        let v = self.native(set_timeout);
        self.set_global("setTimeout", v);
        let set_interval: NativeFn = Rc::new(|interp, _this, args| {
            let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
            let delay = interp.number_arg(args.get(1), 0.0)?;
            let rest: Vec<JsValue> = args.get(2..).map(|s| s.to_vec()).unwrap_or_default();
            let id = interp.set_timer(cb, delay, rest, true);
            Ok(JsValue::Num(id as f64))
        });
        let v = self.native(set_interval);
        self.set_global("setInterval", v);
        for name in ["clearTimeout", "clearInterval"] {
            let clear: NativeFn = Rc::new(|interp, _this, args| {
                let id = interp.number_arg(args.first(), f64::NAN)?;
                if id.is_finite() && id >= 0.0 {
                    interp.clear_timer(id as u32);
                }
                Ok(JsValue::Undefined)
            });
            let v = self.native(clear);
            self.set_global(name, v);
        }
    }

    fn install_math(&mut self) {
        let math = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        math.borrow_mut()
            .set_prop("PI", JsValue::Num(core::f64::consts::PI), false);
        math.borrow_mut()
            .set_prop("E", JsValue::Num(core::f64::consts::E), false);
        for (name, v) in [
            ("LN2", core::f64::consts::LN_2),
            ("LN10", core::f64::consts::LN_10),
            ("LOG2E", core::f64::consts::LOG2_E),
            ("LOG10E", core::f64::consts::LOG10_E),
            ("SQRT2", core::f64::consts::SQRT_2),
            ("SQRT1_2", core::f64::consts::FRAC_1_SQRT_2),
        ] {
            math.borrow_mut().set_prop(name, JsValue::Num(v), false);
        }
        type MathFn = fn(f64) -> f64;
        let unary: [(&str, MathFn); 28] = [
            ("floor", f64::floor),
            ("ceil", f64::ceil),
            // ES Math.round: halves round toward +∞ (so -2.5 → -2), and a
            // value in (-0.5, 0] rounds to -0, not +0.
            ("round", |x: f64| {
                if !x.is_finite() {
                    x
                } else {
                    let r = (x + 0.5).floor();
                    if r == 0.0 && x < 0.0 {
                        -0.0
                    } else {
                        r
                    }
                }
            }),
            ("trunc", f64::trunc),
            ("abs", f64::abs),
            ("sqrt", f64::sqrt),
            ("cbrt", f64::cbrt),
            ("sin", f64::sin),
            ("cos", f64::cos),
            ("tan", f64::tan),
            ("asin", f64::asin),
            ("acos", f64::acos),
            ("atan", f64::atan),
            ("sinh", f64::sinh),
            ("cosh", f64::cosh),
            ("tanh", f64::tanh),
            ("asinh", f64::asinh),
            ("acosh", f64::acosh),
            ("atanh", f64::atanh),
            ("log", f64::ln),
            ("log2", f64::log2),
            ("log10", f64::log10),
            ("log1p", f64::ln_1p),
            ("exp", f64::exp),
            ("expm1", f64::exp_m1),
            ("sign", |x: f64| {
                if x.is_nan() || x == 0.0 {
                    x
                } else {
                    x.signum()
                }
            }),
            ("fround", |x: f64| x as f32 as f64),
            ("clz32", |x: f64| {
                let u = if x.is_finite() { (x as i64 & 0xffff_ffff) as u32 } else { 0 };
                u.leading_zeros() as f64
            }),
        ];
        for (name, func) in unary {
            let f: NativeFn = Rc::new(move |interp, _t, args| {
                Ok(JsValue::Num(func(
                    interp.number_arg(args.first(), f64::NAN)?,
                )))
            });
            let fv = self.native(f);
            math.borrow_mut().set_prop(name, fv, false);
        }
        // Any NaN argument makes the result NaN (ES §21.3.2.24/25);
        // `f64::min` / `f64::max` would drop it.
        let min: NativeFn = Rc::new(|interp, _t, args| {
            let mut acc = f64::INFINITY;
            for v in args {
                let n = interp.to_number_value(v)?;
                if n.is_nan() {
                    return Ok(JsValue::Num(f64::NAN));
                }
                acc = acc.min(n);
            }
            Ok(JsValue::Num(acc))
        });
        let fv = self.native(min);
        math.borrow_mut().set_prop("min", fv, false);
        let max: NativeFn = Rc::new(|interp, _t, args| {
            let mut acc = f64::NEG_INFINITY;
            for v in args {
                let n = interp.to_number_value(v)?;
                if n.is_nan() {
                    return Ok(JsValue::Num(f64::NAN));
                }
                acc = acc.max(n);
            }
            Ok(JsValue::Num(acc))
        });
        let fv = self.native(max);
        math.borrow_mut().set_prop("max", fv, false);
        let pow: NativeFn = Rc::new(|interp, _t, args| {
            let a = interp.number_arg(args.first(), f64::NAN)?;
            let b = interp.number_arg(args.get(1), f64::NAN)?;
            Ok(JsValue::Num(a.powf(b)))
        });
        let fv = self.native(pow);
        math.borrow_mut().set_prop("pow", fv, false);
        let atan2: NativeFn = Rc::new(|interp, _t, args| {
            let y = interp.number_arg(args.first(), f64::NAN)?;
            let x = interp.number_arg(args.get(1), f64::NAN)?;
            Ok(JsValue::Num(y.atan2(x)))
        });
        let fv = self.native(atan2);
        math.borrow_mut().set_prop("atan2", fv, false);
        let hypot: NativeFn = Rc::new(|interp, _t, args| {
            // An infinite argument wins over a NaN one (ES §21.3.2.18).
            let mut ns: Vec<f64> = Vec::with_capacity(args.len());
            for v in args {
                ns.push(interp.to_number_value(v)?);
            }
            if ns.iter().any(|n| n.is_infinite()) {
                return Ok(JsValue::Num(f64::INFINITY));
            }
            Ok(JsValue::Num(ns.iter().fold(0.0_f64, |acc, n| acc.hypot(*n))))
        });
        let fv = self.native(hypot);
        math.borrow_mut().set_prop("hypot", fv, false);
        let imul: NativeFn = Rc::new(|interp, _t, args| {
            let a = super::eval::to_i32(interp.number_arg(args.first(), 0.0)?);
            let b = super::eval::to_i32(interp.number_arg(args.get(1), 0.0)?);
            Ok(JsValue::Num(a.wrapping_mul(b) as f64))
        });
        let fv = self.native(imul);
        math.borrow_mut().set_prop("imul", fv, false);
        // Deterministic "random" (stateless engine; pages needing entropy get
        // a fixed midpoint — documented in the capability report).
        let random: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Num(0.5)));
        let fv = self.native(random);
        math.borrow_mut().set_prop("random", fv, false);
        self.set_global("Math", JsValue::Object(math));
    }

    fn install_json(&mut self) {
        let json = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        let stringify: NativeFn = Rc::new(|interp, _t, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            Ok(match super::json::stringify(interp, &v)? {
                Some(s) => JsValue::str(s),
                None => JsValue::Undefined,
            })
        });
        let fv = self.native(stringify);
        json.borrow_mut().set_prop("stringify", fv, false);
        let parse: NativeFn = Rc::new(|interp, _t, args| {
            let s = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            super::json::parse(interp, &s)
        });
        let fv = self.native(parse);
        json.borrow_mut().set_prop("parse", fv, false);
        self.set_global("JSON", JsValue::Object(json));
    }

    fn install_navigator(&mut self) {
        // A Chrome-like navigator: bundles branch on `userAgent`, `language`,
        // `platform` and `userAgentData`; the real UA the app sends on the
        // wire is the embedder's concern, this is what scripts observe.
        let ua = JsValue::str(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        );
        let nav = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        {
            let mut b = nav.borrow_mut();
            b.set_prop("userAgent", ua, true);
            b.set_prop("appVersion", JsValue::str("5.0 (X11)"), true);
            b.set_prop("appName", JsValue::str("Netscape"), true);
            b.set_prop("appCodeName", JsValue::str("Mozilla"), true);
            b.set_prop("product", JsValue::str("Gecko"), true);
            b.set_prop("vendor", JsValue::str("Google Inc."), true);
            b.set_prop("platform", JsValue::str("Linux x86_64"), true);
            b.set_prop("language", JsValue::str("en-US"), true);
            b.set_prop("cookieEnabled", JsValue::Bool(true), true);
            b.set_prop("onLine", JsValue::Bool(true), true);
            b.set_prop("doNotTrack", JsValue::Null, true);
            b.set_prop("hardwareConcurrency", JsValue::Num(4.0), true);
            b.set_prop("maxTouchPoints", JsValue::Num(0.0), true);
            b.set_prop("webdriver", JsValue::Bool(false), true);
        }
        let langs = self.new_array(vec![JsValue::str("en-US"), JsValue::str("en")]);
        nav.borrow_mut().set_prop("languages", langs, true);
        let plugins = self.new_array(Vec::new());
        nav.borrow_mut().set_prop("plugins", plugins.clone(), true);
        nav.borrow_mut().set_prop("mimeTypes", plugins, true);
        let uad = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        uad.borrow_mut().set_prop("mobile", JsValue::Bool(false), true);
        uad.borrow_mut().set_prop("platform", JsValue::str("Linux"), true);
        let brands = self.new_array(Vec::new());
        uad.borrow_mut().set_prop("brands", brands, true);
        nav.borrow_mut().set_prop("userAgentData", JsValue::Object(uad), true);
        let send_beacon: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Bool(true)));
        let f = self.native(send_beacon);
        nav.borrow_mut().set_prop("sendBeacon", f, false);
        let connection = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        connection.borrow_mut().set_prop("effectiveType", JsValue::str("4g"), true);
        connection.borrow_mut().set_prop("saveData", JsValue::Bool(false), true);
        nav.borrow_mut().set_prop("connection", JsValue::Object(connection), true);
        self.set_global("navigator", JsValue::Object(nav));
    }

    fn install_window_metrics(&mut self) {
        self.set_global("innerWidth", JsValue::Num(1280.0));
        self.set_global("innerHeight", JsValue::Num(720.0));
        self.set_global("outerWidth", JsValue::Num(1280.0));
        self.set_global("outerHeight", JsValue::Num(720.0));
        self.set_global("devicePixelRatio", JsValue::Num(1.0));
        self.set_global("scrollX", JsValue::Num(0.0));
        self.set_global("scrollY", JsValue::Num(0.0));
        self.set_global("pageXOffset", JsValue::Num(0.0));
        self.set_global("pageYOffset", JsValue::Num(0.0));
        self.set_global("screenX", JsValue::Num(0.0));
        self.set_global("screenY", JsValue::Num(0.0));
        self.set_global("name", JsValue::str(""));
        self.set_global("origin", JsValue::str("null"));
        self.set_global("isSecureContext", JsValue::Bool(true));
        self.set_global("frameElement", JsValue::Null);
        self.set_global("opener", JsValue::Null);
        self.set_global("closed", JsValue::Bool(false));
    }

    fn install_window_listeners(&mut self) {
        let add_listener: NativeFn = Rc::new(|interp, _this, args| {
            let event = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let cb = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            if matches!(cb, JsValue::Object(_)) {
                interp.add_listener(&event, cb);
            }
            Ok(JsValue::Undefined)
        });
        let v = self.native(add_listener);
        self.set_global("addEventListener", v);
        let remove_listener: NativeFn = Rc::new(|interp, _this, args| {
            let event = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let cb = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            if let Some(list) = interp.listeners.get_mut(&event) {
                list.retain(|c| !super::interp::strict_eq(c, &cb));
            }
            Ok(JsValue::Undefined)
        });
        let v = self.native(remove_listener);
        self.set_global("removeEventListener", v);
        // window.dispatchEvent(ev): the window-level listeners for the
        // event's type run with the event object; returns !defaultPrevented.
        let dispatch: NativeFn = Rc::new(|interp, _this, args| {
            let Some(JsValue::Object(ev)) = args.first() else {
                return Err(Interp::throw("TypeError: dispatchEvent expects an Event"));
            };
            let event = ev
                .borrow()
                .get_prop("type")
                .map(|v| v.to_js_string())
                .unwrap_or_default();
            let window = JsValue::Object(interp.global_object.clone());
            {
                let mut b = ev.borrow_mut();
                b.set_prop("target", window.clone(), true);
                b.set_prop("currentTarget", window.clone(), true);
            }
            let cbs = interp.listeners.get(&event).cloned().unwrap_or_default();
            let ev_val = JsValue::Object(ev.clone());
            for cb in cbs {
                if let Err(e) = interp.call(cb, window.clone(), std::slice::from_ref(&ev_val)) {
                    let msg = super::interp::to_display(&e);
                    interp
                        .hooks
                        .console("error", &format!("uncaught (in {event} listener): {msg}"));
                }
                interp.drain_microtasks()?;
                if stop_flags(ev).1 {
                    break;
                }
            }
            let prevented = ev
                .borrow()
                .get_prop("defaultPrevented")
                .map(|v| v.truthy())
                .unwrap_or(false);
            Ok(JsValue::Bool(!prevented))
        });
        let v = self.native(dispatch);
        self.set_global("dispatchEvent", v);
    }

    fn install_fetch(&mut self) {
        let fetch: NativeFn = Rc::new(|interp, _this, args| {
            let url = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let mut method = "GET".to_string();
            let mut headers: Vec<(String, String)> = Vec::new();
            let mut body: Option<Vec<u8>> = None;
            if let Some(JsValue::Object(opts)) = args.get(1) {
                let b = opts.borrow();
                if let Some(m) = b.get_prop("method") {
                    method = m.to_js_string();
                }
                if let Some(bv) = b.get_prop("body") {
                    if !bv.is_nullish() {
                        body = Some(bv.to_js_string().into_bytes());
                    }
                }
                if let Some(JsValue::Object(h)) = b.get_prop("headers") {
                    for (k, p) in &h.borrow().props {
                        if let Prop::Value { value, .. } = p {
                            headers.push((k.clone(), value.to_js_string()));
                        }
                    }
                }
            }
            let result = interp.hooks.fetch(&url, &method, &headers, body.as_deref());
            let promise = interp.new_promise();
            match result {
                Ok((status, resp_headers, resp_body)) => {
                    let resp = interp.make_response(status, &resp_headers, resp_body);
                    interp.resolve_promise(&promise, resp, true);
                }
                Err(e) => {
                    let err = JsValue::str(format!("TypeError: fetch failed: {e}"));
                    interp.resolve_promise(&promise, err, false);
                }
            }
            Ok(JsValue::Object(promise))
        });
        let v = self.native(fetch);
        self.set_global("fetch", v);
    }

    /// Make `<name>.prototype.constructor` refer to `<name>` when the
    /// constructor exists, has an object `prototype`, and the prototype
    /// does not already carry an own `constructor`. Constructors without a
    /// `prototype` property get a fresh one so `instanceof` and
    /// `prototype.constructor` both work.
    pub(super) fn link_prototype_constructor(&mut self, name: &str) {
        let ctor = match self.global_object.borrow().get_prop(name) {
            Some(JsValue::Object(c)) if c.borrow().is_callable() => c,
            _ => return,
        };
        let proto = match ctor.borrow().get_prop("prototype") {
            Some(JsValue::Object(p)) => Some(p),
            _ => None,
        };
        let proto = match proto {
            Some(p) => p,
            None => {
                let p = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
                ctor.borrow_mut()
                    .set_prop("prototype", JsValue::Object(p.clone()), false);
                p
            }
        };
        if proto.borrow().own("constructor").is_none() {
            proto
                .borrow_mut()
                .set_prop("constructor", JsValue::Object(ctor), false);
        }
    }
}

/// Read an event object's (propagationStopped, immediateStopped) flags.
fn stop_flags(ev: &ObjRef) -> (bool, bool) {
    let b = ev.borrow();
    (
        b.get_prop("__propagationStopped")
            .map(|v| v.truthy())
            .unwrap_or(false),
        b.get_prop("__immediateStopped")
            .map(|v| v.truthy())
            .unwrap_or(false),
    )
}

impl<'h> Interp<'h> {
    /// Build a fetch Response-like object: status/ok/text()/json().
    pub fn make_response(
        &mut self,
        status: u16,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> JsValue {
        let resp = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        resp.borrow_mut()
            .set_prop("status", JsValue::Num(status as f64), true);
        resp.borrow_mut()
            .set_prop("ok", JsValue::Bool((200..300).contains(&status)), true);
        let text = String::from_utf8_lossy(&body).into_owned();
        let text_rc = Rc::new(text);
        let headers_obj = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        for (k, v) in headers {
            headers_obj.borrow_mut().set_prop(
                &k.to_ascii_lowercase(),
                JsValue::str(v.clone()),
                true,
            );
        }
        resp.borrow_mut()
            .set_prop("headers", JsValue::Object(headers_obj), true);
        let t1 = text_rc.clone();
        let text_fn: NativeFn = Rc::new(move |interp, _t, _a| {
            let p = interp.new_promise();
            interp.resolve_promise(&p, JsValue::Str(t1.clone()), true);
            Ok(JsValue::Object(p))
        });
        let fv = self.native(text_fn);
        resp.borrow_mut().set_prop("text", fv, false);
        let t2 = text_rc;
        let json_fn: NativeFn = Rc::new(move |interp, _t, _a| {
            let p = interp.new_promise();
            match super::json::parse(interp, &t2) {
                Ok(v) => interp.resolve_promise(&p, v, true),
                Err(_) => {
                    let e = JsValue::str("SyntaxError: response is not JSON");
                    interp.resolve_promise(&p, e, false);
                }
            }
            Ok(JsValue::Object(p))
        });
        let fv = self.native(json_fn);
        resp.borrow_mut().set_prop("json", fv, false);
        JsValue::Object(resp)
    }

    /// `XMLHttpRequest`: an event target whose request travels through the
    /// same `HostHooks::fetch` as `fetch()`. The response is delivered
    /// ASYNCHRONOUSLY, as a task on the virtual clock, the way a browser
    /// does: `send()` returns first, so `onload` / `addEventListener("load")`
    /// handlers a page attaches AFTER `send()` still fire (loaders do
    /// exactly that), `readyState` steps through 1 → 2 → 4 with a
    /// `readystatechange` at each step, and `load` / `error` / `loadend`
    /// fire in the browser's order. `responseType` selects `response`
    /// (`"json"` parses, `"arraybuffer"` hands out a byte array); the
    /// response headers the embedder returns answer `getResponseHeader` /
    /// `getAllResponseHeaders`.
    fn install_xhr(&mut self) {
        let ctor: NativeFn = Rc::new(|interp, this, _args| {
            let obj = match this {
                JsValue::Object(o) if !o.borrow().is_callable() => o,
                _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
            };
            obj.borrow_mut().class_name = "XMLHttpRequest";
            {
                let mut b = obj.borrow_mut();
                b.set_prop("readyState", JsValue::Num(0.0), true);
                b.set_prop("status", JsValue::Num(0.0), true);
                b.set_prop("statusText", JsValue::str(""), true);
                b.set_prop("responseText", JsValue::str(""), true);
                b.set_prop("response", JsValue::str(""), true);
                b.set_prop("responseType", JsValue::str(""), true);
                b.set_prop("responseURL", JsValue::str(""), true);
                b.set_prop("responseXML", JsValue::Null, true);
                b.set_prop("timeout", JsValue::Num(0.0), true);
                b.set_prop("withCredentials", JsValue::Bool(false), true);
                for h in ["onreadystatechange", "onload", "onerror", "onloadend", "onabort", "ontimeout", "onprogress", "onloadstart"] {
                    b.set_prop(h, JsValue::Null, true);
                }
                b.set_prop("UNSENT", JsValue::Num(0.0), false);
                b.set_prop("OPENED", JsValue::Num(1.0), false);
                b.set_prop("HEADERS_RECEIVED", JsValue::Num(2.0), false);
                b.set_prop("LOADING", JsValue::Num(3.0), false);
                b.set_prop("DONE", JsValue::Num(4.0), false);
            }
            // Listener table: event name → callbacks (hidden).
            let listeners = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            obj.borrow_mut()
                .set_prop("__listeners", JsValue::Object(listeners), false);
            // `upload` is an event target of its own that never fires.
            let upload = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            let noop: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
            for name in ["addEventListener", "removeEventListener", "dispatchEvent"] {
                let f = interp.native(noop.clone());
                upload.borrow_mut().set_prop(name, f, false);
            }
            obj.borrow_mut().set_prop("upload", JsValue::Object(upload), true);
            Ok(JsValue::Object(obj))
        });
        let ctor_obj = JsObject::new(ObjKind::Native(ctor), Some(self.function_proto.clone()));
        let proto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        proto.borrow_mut().class_name = "XMLHttpRequest";

        let open: NativeFn = Rc::new(|_i, this, args| {
            if let JsValue::Object(o) = &this {
                let m = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                let u = args.get(1).map(|v| v.to_js_string()).unwrap_or_default();
                let mut b = o.borrow_mut();
                b.set_prop("__method", JsValue::str(m.to_ascii_uppercase()), false);
                b.set_prop("__url", JsValue::str(u), false);
                b.set_prop("__headers", JsValue::Undefined, false);
                b.set_prop("__aborted", JsValue::Bool(false), false);
                b.set_prop("readyState", JsValue::Num(1.0), true);
            }
            xhr_fire(_i, &this, "readystatechange")?;
            Ok(JsValue::Undefined)
        });
        let f = self.native(open);
        proto.borrow_mut().set_prop("open", f, false);

        let set_hdr: NativeFn = Rc::new(|_i, this, args| {
            if let JsValue::Object(o) = &this {
                let k = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                let v = args.get(1).map(|v| v.to_js_string()).unwrap_or_default();
                let key = format!("__hdr_{k}");
                o.borrow_mut().set_prop(&key, JsValue::str(v), false);
            }
            Ok(JsValue::Undefined)
        });
        let f = self.native(set_hdr);
        proto.borrow_mut().set_prop("setRequestHeader", f, false);

        let add_listener: NativeFn = Rc::new(|interp, this, args| {
            let event = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let cb = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            if !matches!(cb, JsValue::Object(_)) {
                return Ok(JsValue::Undefined);
            }
            if let Some(table) = xhr_listeners(&this) {
                let list = match table.borrow().get_prop(&event) {
                    Some(JsValue::Object(l)) => Some(l),
                    _ => None,
                };
                match list {
                    Some(l) => l.borrow_mut().elems.push(Some(cb)),
                    None => {
                        let l = interp.new_array(vec![cb]);
                        table.borrow_mut().set_prop(&event, l, true);
                    }
                }
            }
            Ok(JsValue::Undefined)
        });
        let f = self.native(add_listener);
        proto.borrow_mut().set_prop("addEventListener", f, false);
        let remove_listener: NativeFn = Rc::new(|_i, this, args| {
            let event = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let cb = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            if let Some(table) = xhr_listeners(&this) {
                if let Some(JsValue::Object(l)) = table.borrow().get_prop(&event) {
                    l.borrow_mut()
                        .elems
                        .retain(|c| !c.as_ref().is_some_and(|c| super::interp::strict_eq(c, &cb)));
                }
            }
            Ok(JsValue::Undefined)
        });
        let f = self.native(remove_listener);
        proto.borrow_mut().set_prop("removeEventListener", f, false);
        let dispatch: NativeFn = Rc::new(|interp, this, args| {
            let event = match args.first() {
                Some(JsValue::Object(ev)) => ev
                    .borrow()
                    .get_prop("type")
                    .map(|v| v.to_js_string())
                    .unwrap_or_default(),
                _ => return Err(Interp::throw("TypeError: dispatchEvent expects an Event")),
            };
            xhr_fire(interp, &this, &event)?;
            Ok(JsValue::Bool(true))
        });
        let f = self.native(dispatch);
        proto.borrow_mut().set_prop("dispatchEvent", f, false);

        let get_header: NativeFn = Rc::new(|_i, this, args| {
            let name = args
                .first()
                .map(|v| v.to_js_string().to_ascii_lowercase())
                .unwrap_or_default();
            let JsValue::Object(o) = &this else {
                return Ok(JsValue::Null);
            };
            let headers = o.borrow().get_prop("__headers");
            if let Some(JsValue::Object(h)) = headers {
                if let Some(v) = h.borrow().get_prop(&name) {
                    return Ok(v);
                }
            }
            Ok(JsValue::Null)
        });
        let f = self.native(get_header);
        proto.borrow_mut().set_prop("getResponseHeader", f, false);
        let all_headers: NativeFn = Rc::new(|_i, this, _a| {
            let JsValue::Object(o) = &this else {
                return Ok(JsValue::str(""));
            };
            let headers = o.borrow().get_prop("__headers");
            let mut out = String::new();
            if let Some(JsValue::Object(h)) = headers {
                for (k, p) in &h.borrow().props {
                    if let Prop::Value { value, .. } = p {
                        out.push_str(k);
                        out.push_str(": ");
                        out.push_str(&value.to_js_string());
                        out.push_str("\r\n");
                    }
                }
            }
            Ok(JsValue::str(out))
        });
        let f = self.native(all_headers);
        proto.borrow_mut().set_prop("getAllResponseHeaders", f, false);
        let override_mime: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
        let f = self.native(override_mime);
        proto.borrow_mut().set_prop("overrideMimeType", f, false);

        let abort: NativeFn = Rc::new(|interp, this, _a| {
            if let JsValue::Object(o) = &this {
                let state = o.borrow().get_prop("readyState").map(|v| v.to_number()).unwrap_or(0.0);
                let mut b = o.borrow_mut();
                b.set_prop("__aborted", JsValue::Bool(true), false);
                b.set_prop("status", JsValue::Num(0.0), true);
                b.set_prop("readyState", JsValue::Num(if state > 0.0 && state < 4.0 { 4.0 } else { 0.0 }), true);
                drop(b);
                if state > 0.0 && state < 4.0 {
                    xhr_fire(interp, &this, "readystatechange")?;
                    xhr_fire(interp, &this, "abort")?;
                    xhr_fire(interp, &this, "loadend")?;
                    o.borrow_mut().set_prop("readyState", JsValue::Num(0.0), true);
                }
            }
            Ok(JsValue::Undefined)
        });
        let f = self.native(abort);
        proto.borrow_mut().set_prop("abort", f, false);

        let send: NativeFn = Rc::new(|interp, this, args| {
            let JsValue::Object(o) = &this else {
                return Ok(JsValue::Undefined);
            };
            let state = o.borrow().get_prop("readyState").map(|v| v.to_number()).unwrap_or(0.0);
            if state != 1.0 {
                return Err(Interp::throw(
                    "InvalidStateError: Failed to execute 'send' on 'XMLHttpRequest': The object's state must be OPENED.",
                ));
            }
            let method = o
                .borrow()
                .get_prop("__method")
                .map(|v| v.to_js_string())
                .unwrap_or_else(|| "GET".into());
            let url = o
                .borrow()
                .get_prop("__url")
                .map(|v| v.to_js_string())
                .unwrap_or_default();
            let headers: Vec<(String, String)> = o
                .borrow()
                .props
                .iter()
                .filter_map(|(k, p)| {
                    let name = k.strip_prefix("__hdr_")?;
                    match p {
                        Prop::Value { value, .. } => Some((name.to_string(), value.to_js_string())),
                        _ => None,
                    }
                })
                .collect();
            // A URLSearchParams / FormData body serialises through
            // toString; objects with `__pairs` are exactly that.
            let body = match args.first().filter(|v| !v.is_nullish()) {
                Some(v) => Some(interp.to_string_value(v)?.into_bytes()),
                None => None,
            };
            // The request itself is synchronous against the host (the hook
            // owns transport); the RESULT is delivered on the next task.
            let result = interp.hooks.fetch(&url, &method, &headers, body.as_deref());
            let outcome = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            match result {
                Ok((status, resp_headers, resp_body)) => {
                    let h = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                    for (k, v) in &resp_headers {
                        h.borrow_mut().set_prop(&k.to_ascii_lowercase(), JsValue::str(v.clone()), true);
                    }
                    let bytes: Vec<JsValue> = resp_body.iter().map(|b| JsValue::Num(*b as f64)).collect();
                    let bytes_arr = interp.new_array(bytes);
                    let mut b = outcome.borrow_mut();
                    b.set_prop("ok", JsValue::Bool(true), true);
                    b.set_prop("status", JsValue::Num(status as f64), true);
                    b.set_prop("text", JsValue::str(String::from_utf8_lossy(&resp_body).into_owned()), true);
                    b.set_prop("bytes", bytes_arr, true);
                    b.set_prop("headers", JsValue::Object(h), true);
                    b.set_prop("url", JsValue::str(url.clone()), true);
                }
                Err(e) => {
                    let mut b = outcome.borrow_mut();
                    b.set_prop("ok", JsValue::Bool(false), true);
                    b.set_prop("error", JsValue::str(e), true);
                }
            }
            let deliver: NativeFn = Rc::new(|interp, this, args| {
                let JsValue::Object(o) = &this else {
                    return Ok(JsValue::Undefined);
                };
                let Some(JsValue::Object(outcome)) = args.first() else {
                    return Ok(JsValue::Undefined);
                };
                if o.borrow().get_prop("__aborted").map(|v| v.truthy()).unwrap_or(false) {
                    return Ok(JsValue::Undefined);
                }
                let ok = outcome.borrow().get_prop("ok").map(|v| v.truthy()).unwrap_or(false);
                if ok {
                    let (status, text, bytes, headers, url) = {
                        let b = outcome.borrow();
                        (
                            b.get_prop("status").unwrap_or(JsValue::Num(0.0)),
                            b.get_prop("text").unwrap_or(JsValue::str("")),
                            b.get_prop("bytes").unwrap_or(JsValue::Undefined),
                            b.get_prop("headers").unwrap_or(JsValue::Undefined),
                            b.get_prop("url").unwrap_or(JsValue::str("")),
                        )
                    };
                    let status_n = status.to_number();
                    {
                        let mut b = o.borrow_mut();
                        b.set_prop("status", status.clone(), true);
                        b.set_prop("statusText", JsValue::str(status_text(status_n as u16)), true);
                        b.set_prop("__headers", headers, false);
                        b.set_prop("responseURL", url, true);
                        b.set_prop("readyState", JsValue::Num(2.0), true);
                    }
                    xhr_fire(interp, &this, "readystatechange")?;
                    o.borrow_mut().set_prop("readyState", JsValue::Num(3.0), true);
                    xhr_fire(interp, &this, "readystatechange")?;
                    xhr_fire(interp, &this, "progress")?;
                    // `response` follows responseType; responseText is the
                    // text for "" / "text" (and throws in Chrome otherwise,
                    // which pages never rely on — it stays readable here).
                    let rtype = o.borrow().get_prop("responseType").map(|v| v.to_js_string()).unwrap_or_default();
                    let response = match rtype.as_str() {
                        "json" => {
                            let s = text.to_js_string();
                            super::json::parse(interp, &s).unwrap_or(JsValue::Null)
                        }
                        "arraybuffer" | "blob" => {
                            // An ArrayBuffer over the response bytes (a Blob
                            // type is not modelled; the buffer is what a
                            // reader of either gets to the bytes through).
                            let data: Vec<u8> = match &bytes {
                                JsValue::Object(a) => a
                                    .borrow()
                                    .array_values()
                                    .iter()
                                    .map(|v| {
                                        let n = v.to_number();
                                        if n.is_finite() { (n as i64).rem_euclid(256) as u8 } else { 0 }
                                    })
                                    .collect(),
                                _ => Vec::new(),
                            };
                            interp.new_array_buffer(data)
                        }
                        _ => text.clone(),
                    };
                    {
                        let mut b = o.borrow_mut();
                        b.set_prop("responseText", text, true);
                        b.set_prop("response", response, true);
                        b.set_prop("readyState", JsValue::Num(4.0), true);
                    }
                    xhr_fire(interp, &this, "readystatechange")?;
                    xhr_fire(interp, &this, "load")?;
                    xhr_fire(interp, &this, "loadend")?;
                } else {
                    {
                        let mut b = o.borrow_mut();
                        b.set_prop("status", JsValue::Num(0.0), true);
                        b.set_prop("readyState", JsValue::Num(4.0), true);
                    }
                    xhr_fire(interp, &this, "readystatechange")?;
                    xhr_fire(interp, &this, "error")?;
                    xhr_fire(interp, &this, "loadend")?;
                }
                Ok(JsValue::Undefined)
            });
            let deliver_fn = interp.native(deliver);
            // Bind `this` for the timer callback (timers call with undefined).
            let bound = JsObject::new(
                ObjKind::Bound {
                    target: match deliver_fn {
                        JsValue::Object(f) => f,
                        _ => return Ok(JsValue::Undefined),
                    },
                    this_arg: Box::new(this.clone()),
                    bound_args: vec![JsValue::Object(outcome)],
                },
                Some(interp.function_proto.clone()),
            );
            xhr_fire(interp, &this, "loadstart")?;
            interp.set_timer(JsValue::Object(bound), 0.0, Vec::new(), false);
            Ok(JsValue::Undefined)
        });
        let f = self.native(send);
        proto.borrow_mut().set_prop("send", f, false);

        for (k, v) in [("UNSENT", 0.0), ("OPENED", 1.0), ("HEADERS_RECEIVED", 2.0), ("LOADING", 3.0), ("DONE", 4.0)] {
            ctor_obj.borrow_mut().set_prop(k, JsValue::Num(v), false);
        }
        proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor_obj.clone()), false);
        ctor_obj
            .borrow_mut()
            .set_prop("prototype", JsValue::Object(proto), false);
        self.set_global("XMLHttpRequest", JsValue::Object(ctor_obj));
    }
}

/// The hidden listener table of an XHR object.
fn xhr_listeners(this: &JsValue) -> Option<ObjRef> {
    match this {
        JsValue::Object(o) => match o.borrow().get_prop("__listeners") {
            Some(JsValue::Object(t)) => Some(t),
            _ => None,
        },
        _ => None,
    }
}

/// Fire an XHR event: the `on<event>` handler property first, then the
/// `addEventListener` list, each with an Event object whose `target` is
/// the request. Handler errors go to the console; they never abort the
/// delivery of the remaining events.
fn xhr_fire(interp: &mut Interp, this: &JsValue, event: &str) -> Result<(), JsValue> {
    let JsValue::Object(o) = this else {
        return Ok(());
    };
    let mut cbs: Vec<JsValue> = Vec::new();
    if let Some(h) = o.borrow().get_prop(&format!("on{event}")) {
        if matches!(&h, JsValue::Object(f) if f.borrow().is_callable()) {
            cbs.push(h);
        }
    }
    if let Some(table) = xhr_listeners(this) {
        if let Some(JsValue::Object(l)) = table.borrow().get_prop(event) {
            cbs.extend(l.borrow().elems.iter().flatten().cloned());
        }
    }
    if cbs.is_empty() {
        return Ok(());
    }
    let ev = interp.make_event(event, this.clone(), false, &[("lengthComputable", JsValue::Bool(false)), ("loaded", JsValue::Num(0.0)), ("total", JsValue::Num(0.0))]);
    let ev_val = JsValue::Object(ev);
    for cb in cbs {
        if let Err(e) = interp.call(cb, this.clone(), std::slice::from_ref(&ev_val)) {
            let msg = super::interp::to_display(&e);
            interp
                .hooks
                .console("error", &format!("uncaught (in XMLHttpRequest {event} handler): {msg}"));
        }
        interp.drain_microtasks()?;
    }
    Ok(())
}

/// The reason phrase for a status code (`statusText`).
fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}


#[cfg(test)]
mod argument_conversion_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ {body}; }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn timer_arguments_go_through_to_number() {
        assert_eq!(caught("setTimeout(() => {}, { valueOf() { throw 'delay'; } })"), "delay");
        assert_eq!(caught("setInterval(() => {}, Symbol('s'))"), "TypeError");
        assert_eq!(caught("clearTimeout({ valueOf() { throw 'id'; } })"), "id");
    }

    #[test]
    fn math_arguments_go_through_to_number() {
        assert_eq!(eval_js("Math.abs({ valueOf() { return -3; } })"), "3");
        assert_eq!(eval_js("Math.pow({ valueOf() { return 2; } }, '3')"), "8");
        assert_eq!(eval_js("Math.hypot({ valueOf() { return 3; } }, 4)"), "5");
        assert_eq!(eval_js("Math.imul({ valueOf() { return 3; } }, 4)"), "12");
        assert_eq!(caught("Math.atan2({ valueOf() { throw 'atan'; } }, 1)"), "atan");
    }

    #[test]
    fn string_index_arguments_go_through_to_number() {
        let one = "{ valueOf() { return 1; } }";
        assert_eq!(eval_js(&format!("'abc'.charAt({one})")), "b");
        assert_eq!(eval_js(&format!("'abc'.charCodeAt({one})")), "98");
        assert_eq!(eval_js(&format!("'abc'.codePointAt({one})")), "98");
        assert_eq!(eval_js(&format!("'abc'.slice({one})")), "bc");
        assert_eq!(eval_js(&format!("'abc'.substring({one})")), "bc");
        assert_eq!(eval_js(&format!("'abc'.substr({one}, {one})")), "b");
        assert_eq!(eval_js(&format!("'abc'.at({one})")), "b");
        assert_eq!(eval_js("'ab'.repeat({ valueOf() { return 2; } })"), "abab");
        assert_eq!(eval_js("'a'.padStart({ valueOf() { return 3; } }, '-')"), "--a");
        assert_eq!(caught("'abc'.slice({ valueOf() { throw 'slice'; } })"), "slice");
        assert_eq!(caught("'abc'.padEnd(Symbol('s'))"), "TypeError");
    }
}
