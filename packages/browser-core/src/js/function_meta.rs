//! function_meta — the `length` and `name` every function object carries
//! (ES §10.2.9 SetFunctionName, §10.2.10 SetFunctionLength): an
//! interpreted function takes them from its definition when it is created,
//! an anonymous function definition takes the name of what it is assigned
//! to (NamedEvaluation), a bound function derives both from its target,
//! and the realm's built-ins are named after the property that holds them,
//! with their specified `length`, once the installers have run.
//!
//! Both properties are non-writable, non-enumerable and configurable, and
//! they lead a function's own keys, as they do in every engine.

use std::collections::VecDeque;
use std::rc::Rc;

use super::ast::{Expr, FnDef, Stmt};
use super::interp::{Interp, ScopeRef};
use super::value::{is_symbol_key, JsValue, ObjKind, ObjRef, Prop};

/// ExpectedArgumentCount (ES §15.1.5): the parameters before the first one
/// with a default value or the rest parameter.
pub fn expected_argument_count(def: &FnDef) -> usize {
    def.params.iter().take_while(|p| p.default.is_none() && !p.rest).count()
}

/// IsAnonymousFunctionDefinition (ES §8.4.3): a function, arrow or class
/// expression without a name of its own.
pub fn is_anonymous_function_definition(e: &Expr) -> bool {
    match e {
        Expr::Function(d) => d.name.is_none(),
        Expr::Class(c) => c.name.is_none(),
        _ => false,
    }
}

/// Whether a class field's initializer function (`body: return <expr>`)
/// returns an anonymous function definition, which takes the field's name.
pub fn field_initializer_is_anonymous(f: &JsValue) -> bool {
    let JsValue::Object(o) = f else { return false };
    let b = o.borrow();
    let ObjKind::Function { def, .. } = &b.kind else { return false };
    matches!(def.body.first(), Some(Stmt::Return(Some(e))) if is_anonymous_function_definition(e))
}

impl<'h> Interp<'h> {
    /// The name SetFunctionName gives a function stored under the
    /// property-table key `key`: a symbol's description in brackets (the
    /// empty string for a symbol without one), any other key as it is,
    /// after `prefix` and a space when there is one (`get`, `set`).
    pub fn function_name_for_key(&mut self, key: &str, prefix: Option<&str>) -> String {
        let base = if is_symbol_key(key) {
            match self.symbol_for_key(key) {
                JsValue::Symbol(s) => s.description.as_ref().map(|d| format!("[{d}]")).unwrap_or_default(),
                _ => String::new(),
            }
        } else {
            key.to_string()
        };
        match prefix {
            Some(p) => format!("{p} {base}"),
            None => base,
        }
    }

    /// Name a function that NamedEvaluation created anonymous: one whose
    /// own `name` is still the empty string. A class whose static `name`
    /// member replaced the property keeps it.
    pub fn name_anonymous_function(&mut self, v: &JsValue, name: &str) {
        let JsValue::Object(o) = v else { return };
        let mut b = o.borrow_mut();
        if !b.is_callable() {
            return;
        }
        let unnamed = matches!(b.own_slot("name"), Some(Prop::Value { value: JsValue::Str(s), .. }) if s.is_empty());
        if unnamed {
            b.set_prop("name", JsValue::str(name), false);
        }
    }

    /// NamedEvaluation (ES §8.4.5): evaluate `expr`, and when it is an
    /// anonymous function definition give the function `name`.
    pub fn eval_named(&mut self, expr: &Expr, scope: &ScopeRef, name: &str) -> Result<JsValue, JsValue> {
        let v = self.eval(expr, scope)?;
        if is_anonymous_function_definition(expr) {
            self.name_anonymous_function(&v, name);
        }
        Ok(v)
    }

    /// Give every built-in function reachable from the global object (its
    /// constructors, their statics and prototypes, namespace objects such
    /// as `Math` and `JSON`, accessors included) its `name` and `length`,
    /// leaving any function that already has a `name` alone. Run once the
    /// installers have built the realm, and again once the DOM bindings
    /// have added theirs.
    pub fn name_builtins(&mut self) {
        let roots = vec![
            (String::new(), self.global_object.clone(), 0),
            ("%IteratorPrototype%".to_string(), self.iterator_proto.clone(), 1),
            ("%GeneratorPrototype%".to_string(), self.generator_proto.clone(), 1),
        ];
        self.name_builtins_in(roots);
    }

    /// `name_builtins` for the functions held by one intrinsic object the
    /// global object does not reach directly, under the path `path`.
    pub(super) fn name_builtins_from(&mut self, path: &str, obj: &ObjRef) {
        self.name_builtins_in(vec![(path.to_string(), obj.clone(), 1)]);
    }

    fn name_builtins_in(&mut self, roots: Vec<(String, ObjRef, u8)>) {
        // Breadth first, so a function is named for its shallowest path
        // (`Number.isFinite`, not a path through another constructor's
        // prototype that leads back to `Number`). The global object is
        // always re-read (installers add to it); any other object is
        // walked once per realm.
        let global = Rc::as_ptr(&self.global_object) as *const () as usize;
        let mut queue: VecDeque<(String, ObjRef, u8)> = roots.into();
        while let Some((path, obj, depth)) = queue.pop_front() {
            let addr = Rc::as_ptr(&obj) as *const () as usize;
            if !self.named_builtins.insert(addr) && addr != global {
                continue;
            }
            // (key, function or object value, getter, setter) of every
            // slot that holds a host function or an object to descend.
            type Slot = (String, Option<ObjRef>, Option<ObjRef>, Option<ObjRef>);
            let slots: Vec<Slot> = obj
                .borrow()
                .props
                .iter()
                // Hidden engine slots (`__ElementProto`) are skipped;
                // `__proto__`-style names are real properties.
                .filter(|(k, _)| !k.starts_with("__") || k.ends_with("__"))
                .filter_map(|(k, p)| match p {
                    Prop::Value { value: JsValue::Object(v), .. } => {
                        let wanted = {
                            let b = v.borrow();
                            match &b.kind {
                                ObjKind::Native(_) => true,
                                ObjKind::Plain | ObjKind::DomNode(0) => depth < 4,
                                _ => false,
                            }
                        };
                        wanted.then(|| (k.clone(), Some(v.clone()), None, None))
                    }
                    Prop::Accessor { get, set, .. } => {
                        let native = |f: &Option<ObjRef>| f.as_ref().is_some_and(is_unnamed_native);
                        (native(get) || native(set)).then(|| (k.clone(), None, get.clone(), set.clone()))
                    }
                    Prop::Value { .. } => None,
                })
                .collect();
            for (key, value, get, set) in slots {
                let label = self.function_name_for_key(&key, None);
                for (f, prefix, len) in [(get, "get", 0.0), (set, "set", 1.0)] {
                    if let Some(f) = f.filter(is_unnamed_native) {
                        f.borrow_mut().define_function_meta(len, JsValue::str(format!("{prefix} {label}")));
                    }
                }
                let Some(v) = value else { continue };
                let child = if path.is_empty() { label.clone() } else { format!("{path}.{label}") };
                if is_unnamed_native(&v) {
                    let len = builtin_length(&child);
                    v.borrow_mut().define_function_meta(len, JsValue::str(label));
                }
                if depth < 4 && !self.named_builtins.contains(&(Rc::as_ptr(&v) as *const () as usize)) {
                    queue.push_back((child, v, depth.saturating_add(1)));
                }
            }
        }
    }
}

/// A host function that has no own `name` yet.
fn is_unnamed_native(f: &ObjRef) -> bool {
    let b = f.borrow();
    matches!(b.kind, ObjKind::Native(_)) && b.own("name").is_none()
}

/// The `length` the specification gives a built-in function, by the path
/// from the global object (`Array.prototype.push`, `Math.max`); 0 for one
/// the table does not list. Prototype methods shared by several
/// constructors are listed under each.
pub fn builtin_length(path: &str) -> f64 {
    match BUILTIN_LENGTHS.binary_search_by(|(p, _)| p.cmp(&path)) {
        Ok(i) => BUILTIN_LENGTHS.get(i).map(|(_, n)| *n as f64).unwrap_or(0.0),
        Err(_) => 0.0,
    }
}

/// Built-in function lengths (ES §19-§28 and the DOM/HTML interfaces the
/// engine installs), sorted by path for binary search; a length of 0 is
/// the default and not listed.
const BUILTIN_LENGTHS: &[(&str, u8)] = &[
    ("%GeneratorPrototype%.next", 1),
    ("%GeneratorPrototype%.return", 1),
    ("%GeneratorPrototype%.throw", 1),
    ("%TypedArray%.prototype.at", 1),
    ("%TypedArray%.prototype.copyWithin", 2),
    ("%TypedArray%.prototype.every", 1),
    ("%TypedArray%.prototype.fill", 1),
    ("%TypedArray%.prototype.filter", 1),
    ("%TypedArray%.prototype.find", 1),
    ("%TypedArray%.prototype.findIndex", 1),
    ("%TypedArray%.prototype.findLast", 1),
    ("%TypedArray%.prototype.findLastIndex", 1),
    ("%TypedArray%.prototype.forEach", 1),
    ("%TypedArray%.prototype.includes", 1),
    ("%TypedArray%.prototype.indexOf", 1),
    ("%TypedArray%.prototype.join", 1),
    ("%TypedArray%.prototype.lastIndexOf", 1),
    ("%TypedArray%.prototype.map", 1),
    ("%TypedArray%.prototype.reduce", 1),
    ("%TypedArray%.prototype.reduceRight", 1),
    ("%TypedArray%.prototype.set", 1),
    ("%TypedArray%.prototype.slice", 2),
    ("%TypedArray%.prototype.some", 1),
    ("%TypedArray%.prototype.sort", 1),
    ("%TypedArray%.prototype.subarray", 2),
    ("AggregateError", 2),
    ("Array", 1),
    ("Array.from", 1),
    ("Array.isArray", 1),
    ("Array.prototype.at", 1),
    ("Array.prototype.concat", 1),
    ("Array.prototype.copyWithin", 2),
    ("Array.prototype.every", 1),
    ("Array.prototype.fill", 1),
    ("Array.prototype.filter", 1),
    ("Array.prototype.find", 1),
    ("Array.prototype.findIndex", 1),
    ("Array.prototype.findLast", 1),
    ("Array.prototype.findLastIndex", 1),
    ("Array.prototype.flatMap", 1),
    ("Array.prototype.forEach", 1),
    ("Array.prototype.includes", 1),
    ("Array.prototype.indexOf", 1),
    ("Array.prototype.join", 1),
    ("Array.prototype.lastIndexOf", 1),
    ("Array.prototype.map", 1),
    ("Array.prototype.push", 1),
    ("Array.prototype.reduce", 1),
    ("Array.prototype.reduceRight", 1),
    ("Array.prototype.slice", 2),
    ("Array.prototype.some", 1),
    ("Array.prototype.sort", 1),
    ("Array.prototype.splice", 2),
    ("Array.prototype.unshift", 1),
    ("ArrayBuffer", 1),
    ("ArrayBuffer.isView", 1),
    ("ArrayBuffer.prototype.slice", 2),
    ("BigInt", 1),
    ("BigInt.asIntN", 2),
    ("BigInt.asUintN", 2),
    ("Boolean", 1),
    ("CustomEvent", 1),
    ("CustomEvent.prototype.initCustomEvent", 1),
    ("DataView", 1),
    ("DataView.prototype.getFloat32", 1),
    ("DataView.prototype.getFloat64", 1),
    ("DataView.prototype.getInt16", 1),
    ("DataView.prototype.getInt32", 1),
    ("DataView.prototype.getInt8", 1),
    ("DataView.prototype.getUint16", 1),
    ("DataView.prototype.getUint32", 1),
    ("DataView.prototype.getUint8", 1),
    ("DataView.prototype.setFloat32", 2),
    ("DataView.prototype.setFloat64", 2),
    ("DataView.prototype.setInt16", 2),
    ("DataView.prototype.setInt32", 2),
    ("DataView.prototype.setInt8", 2),
    ("DataView.prototype.setUint16", 2),
    ("DataView.prototype.setUint32", 2),
    ("DataView.prototype.setUint8", 2),
    ("Date", 7),
    ("Date.UTC", 7),
    ("Date.parse", 1),
    ("Date.prototype.[Symbol.toPrimitive]", 1),
    ("Date.prototype.setDate", 1),
    ("Date.prototype.setFullYear", 3),
    ("Date.prototype.setHours", 4),
    ("Date.prototype.setMilliseconds", 1),
    ("Date.prototype.setMinutes", 3),
    ("Date.prototype.setMonth", 2),
    ("Date.prototype.setSeconds", 2),
    ("Date.prototype.setTime", 1),
    ("Date.prototype.setUTCDate", 1),
    ("Date.prototype.setUTCFullYear", 3),
    ("Date.prototype.setUTCHours", 4),
    ("Date.prototype.setUTCMilliseconds", 1),
    ("Date.prototype.setUTCMinutes", 3),
    ("Date.prototype.setUTCMonth", 2),
    ("Date.prototype.setUTCSeconds", 2),
    ("Date.prototype.setYear", 1),
    ("Date.prototype.toJSON", 1),
    ("Element.prototype.addEventListener", 2),
    ("Element.prototype.animate", 1),
    ("Element.prototype.appendChild", 1),
    ("Element.prototype.attachShadow", 1),
    ("Element.prototype.closest", 1),
    ("Element.prototype.compareDocumentPosition", 1),
    ("Element.prototype.contains", 1),
    ("Element.prototype.dispatchEvent", 1),
    ("Element.prototype.getAttribute", 1),
    ("Element.prototype.getAttributeNS", 2),
    ("Element.prototype.getAttributeNode", 1),
    ("Element.prototype.getElementsByClassName", 1),
    ("Element.prototype.getElementsByName", 1),
    ("Element.prototype.getElementsByTagName", 1),
    ("Element.prototype.hasAttribute", 1),
    ("Element.prototype.hasAttributeNS", 2),
    ("Element.prototype.insertAdjacentElement", 2),
    ("Element.prototype.insertAdjacentHTML", 2),
    ("Element.prototype.insertAdjacentText", 2),
    ("Element.prototype.insertBefore", 2),
    ("Element.prototype.isEqualNode", 1),
    ("Element.prototype.isSameNode", 1),
    ("Element.prototype.lookupNamespaceURI", 1),
    ("Element.prototype.matches", 1),
    ("Element.prototype.msMatchesSelector", 1),
    ("Element.prototype.querySelector", 1),
    ("Element.prototype.querySelectorAll", 1),
    ("Element.prototype.removeAttribute", 1),
    ("Element.prototype.removeAttributeNS", 2),
    ("Element.prototype.removeChild", 1),
    ("Element.prototype.removeEventListener", 2),
    ("Element.prototype.replaceChild", 2),
    ("Element.prototype.setAttribute", 2),
    ("Element.prototype.setAttributeNS", 3),
    ("Element.prototype.toggleAttribute", 1),
    ("Element.prototype.webkitMatchesSelector", 1),
    ("Error", 1),
    ("EvalError", 1),
    ("Event", 1),
    ("Event.prototype.initEvent", 1),
    ("Float32Array", 3),
    ("Float32Array.from", 1),
    ("Float64Array", 3),
    ("Float64Array.from", 1),
    ("FocusEvent", 1),
    ("FormData.prototype.append", 2),
    ("FormData.prototype.delete", 1),
    ("FormData.prototype.forEach", 1),
    ("FormData.prototype.get", 1),
    ("FormData.prototype.getAll", 1),
    ("FormData.prototype.has", 1),
    ("FormData.prototype.set", 2),
    ("Function", 1),
    ("Function.prototype.[Symbol.hasInstance]", 1),
    ("Function.prototype.apply", 2),
    ("Function.prototype.bind", 1),
    ("Function.prototype.call", 1),
    ("Headers.prototype.append", 2),
    ("Headers.prototype.delete", 1),
    ("Headers.prototype.forEach", 1),
    ("Headers.prototype.get", 1),
    ("Headers.prototype.has", 1),
    ("Headers.prototype.set", 2),
    ("InputEvent", 1),
    ("Int16Array", 3),
    ("Int16Array.from", 1),
    ("Int32Array", 3),
    ("Int32Array.from", 1),
    ("Int8Array", 3),
    ("Int8Array.from", 1),
    ("IntersectionObserver", 1),
    ("JSON.parse", 2),
    ("JSON.stringify", 3),
    ("KeyboardEvent", 1),
    ("KeyboardEvent.prototype.initKeyboardEvent", 1),
    ("Map.groupBy", 2),
    ("Map.prototype.delete", 1),
    ("Map.prototype.forEach", 1),
    ("Map.prototype.get", 1),
    ("Map.prototype.has", 1),
    ("Map.prototype.set", 2),
    ("Math.abs", 1),
    ("Math.acos", 1),
    ("Math.acosh", 1),
    ("Math.asin", 1),
    ("Math.asinh", 1),
    ("Math.atan", 1),
    ("Math.atan2", 2),
    ("Math.atanh", 1),
    ("Math.cbrt", 1),
    ("Math.ceil", 1),
    ("Math.clz32", 1),
    ("Math.cos", 1),
    ("Math.cosh", 1),
    ("Math.exp", 1),
    ("Math.expm1", 1),
    ("Math.floor", 1),
    ("Math.fround", 1),
    ("Math.hypot", 2),
    ("Math.imul", 2),
    ("Math.log", 1),
    ("Math.log10", 1),
    ("Math.log1p", 1),
    ("Math.log2", 1),
    ("Math.max", 2),
    ("Math.min", 2),
    ("Math.pow", 2),
    ("Math.round", 1),
    ("Math.sign", 1),
    ("Math.sin", 1),
    ("Math.sinh", 1),
    ("Math.sqrt", 1),
    ("Math.tan", 1),
    ("Math.tanh", 1),
    ("Math.trunc", 1),
    ("MouseEvent", 1),
    ("MouseEvent.prototype.initMouseEvent", 1),
    ("MutationObserver", 1),
    ("NodeList.prototype.forEach", 1),
    ("NodeList.prototype.item", 1),
    ("NodeList.prototype.namedItem", 1),
    ("Number", 1),
    ("Number.isFinite", 1),
    ("Number.isInteger", 1),
    ("Number.isNaN", 1),
    ("Number.isSafeInteger", 1),
    ("Number.parseFloat", 1),
    ("Number.parseInt", 2),
    ("Number.prototype.toExponential", 1),
    ("Number.prototype.toFixed", 1),
    ("Number.prototype.toPrecision", 1),
    ("Number.prototype.toString", 1),
    ("Object", 1),
    ("Object.assign", 2),
    ("Object.create", 2),
    ("Object.defineProperties", 2),
    ("Object.defineProperty", 3),
    ("Object.entries", 1),
    ("Object.freeze", 1),
    ("Object.fromEntries", 1),
    ("Object.getOwnPropertyDescriptor", 2),
    ("Object.getOwnPropertyDescriptors", 1),
    ("Object.getOwnPropertyNames", 1),
    ("Object.getOwnPropertySymbols", 1),
    ("Object.getPrototypeOf", 1),
    ("Object.groupBy", 2),
    ("Object.hasOwn", 2),
    ("Object.is", 2),
    ("Object.isExtensible", 1),
    ("Object.isFrozen", 1),
    ("Object.isSealed", 1),
    ("Object.keys", 1),
    ("Object.preventExtensions", 1),
    ("Object.prototype.__defineGetter__", 2),
    ("Object.prototype.__defineSetter__", 2),
    ("Object.prototype.__lookupGetter__", 1),
    ("Object.prototype.__lookupSetter__", 1),
    ("Object.prototype.hasOwnProperty", 1),
    ("Object.prototype.isPrototypeOf", 1),
    ("Object.prototype.propertyIsEnumerable", 1),
    ("Object.seal", 1),
    ("Object.setPrototypeOf", 2),
    ("Object.values", 1),
    ("PerformanceObserver", 1),
    ("PointerEvent", 1),
    ("Promise", 1),
    ("Promise.all", 1),
    ("Promise.allSettled", 1),
    ("Promise.any", 1),
    ("Promise.prototype.catch", 1),
    ("Promise.prototype.finally", 1),
    ("Promise.prototype.then", 2),
    ("Promise.race", 1),
    ("Promise.reject", 1),
    ("Promise.resolve", 1),
    ("Proxy", 2),
    ("RangeError", 1),
    ("ReferenceError", 1),
    ("Reflect.apply", 3),
    ("Reflect.construct", 2),
    ("Reflect.defineProperty", 3),
    ("Reflect.deleteProperty", 2),
    ("Reflect.get", 2),
    ("Reflect.getOwnPropertyDescriptor", 2),
    ("Reflect.getPrototypeOf", 1),
    ("Reflect.has", 2),
    ("Reflect.isExtensible", 1),
    ("Reflect.ownKeys", 1),
    ("Reflect.preventExtensions", 1),
    ("Reflect.set", 3),
    ("Reflect.setPrototypeOf", 2),
    ("RegExp", 2),
    ("RegExp.prototype.[Symbol.matchAll]", 1),
    ("RegExp.prototype.[Symbol.match]", 1),
    ("RegExp.prototype.[Symbol.replace]", 2),
    ("RegExp.prototype.[Symbol.search]", 1),
    ("RegExp.prototype.[Symbol.split]", 2),
    ("RegExp.prototype.compile", 2),
    ("RegExp.prototype.exec", 1),
    ("RegExp.prototype.test", 1),
    ("Request", 1),
    ("ResizeObserver", 1),
    ("Response.json", 1),
    ("Response.redirect", 1),
    ("Set.prototype.add", 1),
    ("Set.prototype.delete", 1),
    ("Set.prototype.forEach", 1),
    ("Set.prototype.has", 1),
    ("String", 1),
    ("String.fromCharCode", 1),
    ("String.fromCodePoint", 1),
    ("String.prototype.at", 1),
    ("String.prototype.charAt", 1),
    ("String.prototype.charCodeAt", 1),
    ("String.prototype.codePointAt", 1),
    ("String.prototype.concat", 1),
    ("String.prototype.endsWith", 1),
    ("String.prototype.includes", 1),
    ("String.prototype.indexOf", 1),
    ("String.prototype.lastIndexOf", 1),
    ("String.prototype.localeCompare", 1),
    ("String.prototype.match", 1),
    ("String.prototype.matchAll", 1),
    ("String.prototype.padEnd", 1),
    ("String.prototype.padStart", 1),
    ("String.prototype.repeat", 1),
    ("String.prototype.replace", 2),
    ("String.prototype.replaceAll", 2),
    ("String.prototype.search", 1),
    ("String.prototype.slice", 2),
    ("String.prototype.split", 2),
    ("String.prototype.startsWith", 1),
    ("String.prototype.substr", 2),
    ("String.prototype.substring", 2),
    ("String.raw", 1),
    ("Symbol.for", 1),
    ("Symbol.keyFor", 1),
    ("Symbol.prototype.[Symbol.toPrimitive]", 1),
    ("SyntaxError", 1),
    ("TextEncoder.prototype.encodeInto", 2),
    ("TypeError", 1),
    ("UIEvent", 1),
    ("UIEvent.prototype.initUIEvent", 1),
    ("URIError", 1),
    ("URL", 1),
    ("URL.canParse", 1),
    ("URL.createObjectURL", 1),
    ("URL.parse", 1),
    ("URL.revokeObjectURL", 1),
    ("URLSearchParams.prototype.append", 2),
    ("URLSearchParams.prototype.delete", 1),
    ("URLSearchParams.prototype.forEach", 1),
    ("URLSearchParams.prototype.get", 1),
    ("URLSearchParams.prototype.getAll", 1),
    ("URLSearchParams.prototype.has", 1),
    ("URLSearchParams.prototype.set", 2),
    ("Uint16Array", 3),
    ("Uint16Array.from", 1),
    ("Uint32Array", 3),
    ("Uint32Array.from", 1),
    ("Uint8Array", 3),
    ("Uint8Array.from", 1),
    ("Uint8ClampedArray", 3),
    ("Uint8ClampedArray.from", 1),
    ("WheelEvent", 1),
    ("XMLHttpRequest.prototype.addEventListener", 2),
    ("XMLHttpRequest.prototype.dispatchEvent", 1),
    ("XMLHttpRequest.prototype.getResponseHeader", 1),
    ("XMLHttpRequest.prototype.open", 2),
    ("XMLHttpRequest.prototype.overrideMimeType", 1),
    ("XMLHttpRequest.prototype.removeEventListener", 2),
    ("XMLHttpRequest.prototype.setRequestHeader", 2),
    ("addEventListener", 2),
    ("atob", 1),
    ("btoa", 1),
    ("cancelAnimationFrame", 1),
    ("cancelIdleCallback", 1),
    ("crypto.getRandomValues", 1),
    ("customElements.define", 2),
    ("customElements.get", 1),
    ("customElements.getName", 1),
    ("customElements.upgrade", 1),
    ("customElements.whenDefined", 1),
    ("decodeURI", 1),
    ("decodeURIComponent", 1),
    ("dispatchEvent", 1),
    ("document.adoptNode", 1),
    ("document.createAttribute", 1),
    ("document.createComment", 1),
    ("document.createElement", 1),
    ("document.createElementNS", 2),
    ("document.createEvent", 1),
    ("document.createNodeIterator", 1),
    ("document.createTextNode", 1),
    ("document.createTreeWalker", 1),
    ("document.elementFromPoint", 2),
    ("document.elementsFromPoint", 2),
    ("document.execCommand", 1),
    ("document.getElementById", 1),
    ("document.getElementsByClassName", 1),
    ("document.getElementsByName", 1),
    ("document.getElementsByTagName", 1),
    ("document.importNode", 1),
    ("document.queryCommandSupported", 1),
    ("document.querySelector", 1),
    ("document.querySelectorAll", 1),
    ("encodeURI", 1),
    ("encodeURIComponent", 1),
    ("escape", 1),
    ("eval", 1),
    ("fetch", 1),
    ("getComputedStyle", 1),
    ("history.pushState", 2),
    ("history.replaceState", 2),
    ("isFinite", 1),
    ("isNaN", 1),
    ("localStorage.getItem", 1),
    ("localStorage.key", 1),
    ("localStorage.removeItem", 1),
    ("localStorage.setItem", 2),
    ("location.assign", 1),
    ("location.replace", 1),
    ("matchMedia", 1),
    ("navigator.sendBeacon", 1),
    ("parseFloat", 1),
    ("parseInt", 2),
    ("performance.getEntriesByName", 1),
    ("performance.getEntriesByType", 1),
    ("performance.mark", 1),
    ("performance.measure", 1),
    ("postMessage", 1),
    ("queueMicrotask", 1),
    ("removeEventListener", 2),
    ("requestAnimationFrame", 1),
    ("requestIdleCallback", 1),
    ("sessionStorage.getItem", 1),
    ("sessionStorage.key", 1),
    ("sessionStorage.removeItem", 1),
    ("sessionStorage.setItem", 2),
    ("setInterval", 1),
    ("setTimeout", 1),
    ("structuredClone", 1),
    ("unescape", 1),
];

#[cfg(test)]
mod function_meta_tests {
    use super::super::interp::test_support::{eval_in_page, eval_js};

    fn run(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn interpreted_functions_have_length_and_name() {
        assert_eq!(run("return [(function f(a, b) {}).length, (function f(a, b) {}).name].join()"), "2,f");
        // Parameters after the first default and the rest parameter do
        // not count; destructuring parameters do.
        assert_eq!(
            run("return [(function (a, b = 1, c) {}).length, ((a, ...r) => 0).length, (({ a }, [b]) => 0).length, (async function () {}).length, (function* g(x) {}).length].join()"),
            "1,1,2,0,1"
        );
        assert_eq!(run("return [(class Foo {}).name, (class { constructor(a, b) {} }).length, (class {}).name, class Bar extends Array {}.name].join()"), "Foo,2,,Bar");
        assert_eq!(run("return [new Function('a', 'b', 'return a').length, new Function('a', 'b', 'return a').name].join()"), "2,anonymous");
    }

    #[test]
    fn the_properties_are_read_only_hidden_and_configurable() {
        assert_eq!(
            run("function f(a) {} const l = Object.getOwnPropertyDescriptor(f, 'length'), n = Object.getOwnPropertyDescriptor(f, 'name'); \
                 return [l.value, l.writable, l.enumerable, l.configurable, n.value, n.writable, n.enumerable, n.configurable].join()"),
            "1,false,false,true,f,false,false,true"
        );
        assert_eq!(run("return Object.getOwnPropertyNames(function f() {}).slice(0, 2).join()"), "length,name");
        assert_eq!(run("return Object.getOwnPropertyNames(Array).slice(0, 3).join()"), "length,name,prototype");
        assert_eq!(run("return Object.keys(function f() {}).length"), "0");
        // A write is ignored in sloppy code and refused in strict code; a
        // delete works, after which the name is Function.prototype's.
        assert_eq!(run("function f() {} f.name = 'x'; return f.name"), "f");
        assert_eq!(run("'use strict'; function f() {} f.name = 'x'; return f.name"), "TypeError");
        assert_eq!(run("function f() {} delete f.name; return [f.hasOwnProperty('name'), JSON.stringify(f.name)].join()"), "false,\"\"");
        assert_eq!(run("function f() {} Object.defineProperty(f, 'name', { value: 'g' }); return f.name"), "g");
    }

    #[test]
    fn built_ins_carry_their_specified_name_and_length() {
        assert_eq!(run("return [Array.name, Array.length, Object.name, Object.length, Function.prototype.name === '', Function.prototype.length].join()"), "Array,1,Object,1,true,0");
        assert_eq!(
            run("return [Object.keys.name, Object.keys.length, Object.defineProperty.length, Array.prototype.push.name, Array.prototype.push.length, Array.prototype.reduce.length, JSON.stringify.length, Math.max.length, parseInt.length, Promise.length, Promise.prototype.then.length, String.prototype.indexOf.length, Map.prototype.set.length].join()"),
            "keys,1,3,push,1,1,3,2,2,1,2,1,2"
        );
        assert_eq!(run("return Array.prototype[Symbol.iterator].name"), "values");
        assert_eq!(run("return [Function.prototype[Symbol.hasInstance].name, Object.getOwnPropertyDescriptor(Map.prototype, 'size').get.name].join()"), "[Symbol.hasInstance],get size");
        assert_eq!(run("return [setTimeout.name, setTimeout.length].join()"), "setTimeout,1");
    }

    #[test]
    fn bound_functions_derive_name_and_length_from_their_target() {
        assert_eq!(run("function f(a, b, c) {} const g = f.bind(null, 1); return [g.name, g.length, g.bind(null).name, f.bind(null, 1, 2, 3, 4).length].join()"), "bound f,2,bound bound f,0");
        assert_eq!(run("const f = function () {}; Object.defineProperty(f, 'length', { value: -5 }); return f.bind().length"), "0");
        assert_eq!(run("const f = function () {}; Object.defineProperty(f, 'name', { value: 7 }); return JSON.stringify(f.bind().name)"), "\"bound \"");
        assert_eq!(run("return Function.prototype.bind.call({})"), "TypeError");
    }

    #[test]
    fn methods_and_accessors_are_named_by_their_key() {
        assert_eq!(run("const o = { m() {}, get x() { return 1; }, set x(v) {} }; const d = Object.getOwnPropertyDescriptor(o, 'x'); return [o.m.name, d.get.name, d.set.name, d.get.length, d.set.length].join()"), "m,get x,set x,0,1");
        assert_eq!(run("class A { m(a) {} static s() {} get g() { return 1; } } const d = Object.getOwnPropertyDescriptor(A.prototype, 'g'); return [A.prototype.m.name, A.prototype.m.length, A.s.name, d.get.name].join()"), "m,1,s,get g");
        assert_eq!(run("const s = Symbol('tag'); const o = { [Symbol.iterator]() {}, [s]: function () {}, [Symbol()]: () => 0 }; return [o[Symbol.iterator].name, o[s].name, JSON.stringify(o[Object.getOwnPropertySymbols(o)[2]].name)].join()"), "[Symbol.iterator],[tag],\"\"");
        assert_eq!(run("class A { static [Symbol.iterator]() {} } return A[Symbol.iterator].name"), "[Symbol.iterator]");
        assert_eq!(run("class A { #m() {} n() { return this.#m.name; } } return new A().n()"), "#m");
    }

    #[test]
    fn anonymous_definitions_take_the_name_they_are_assigned_to() {
        assert_eq!(run("var g = () => 1; let h = function () {}; const k = class {}; return [g.name, h.name, k.name].join()"), "g,h,k");
        assert_eq!(run("let x; x = function () {}; let y; y ??= () => 0; return [x.name, y.name].join()"), "x,y");
        assert_eq!(run("const o = { a: () => 0, 'b c': function () {}, d: class {} }; return [o.a.name, o['b c'].name, o.d.name].join()"), "a,b c,d");
        assert_eq!(run("function f(cb = () => {}) { return cb.name; } return f()"), "cb");
        assert_eq!(run("const { p = function () {} } = {}; const [q = () => 0] = []; let r; [r = class {}] = []; return [p.name, q.name, r.name].join()"), "p,q,r");
        assert_eq!(run("class A { f = () => {}; static s = function () {}; } return [new A().f.name, A.s.name].join()"), "f,s");
        // A named definition keeps its own name; a non-definition is not
        // renamed; a class's static `name` member wins.
        assert_eq!(run("var n = function named() {}; var q = (0, function () {}); var C = class { static name() { return 'own'; } }; return [n.name, JSON.stringify(q.name), C.name()].join()"), "named,\"\",own");
        // Assigning to a property does not name the function.
        assert_eq!(run("const o = {}; o.p = function () {}; return JSON.stringify(o.p.name)"), "\"\"");
    }

    #[test]
    fn only_constructors_carry_a_prototype() {
        // Arrows, async functions, methods and accessors are not
        // constructors and have no `prototype` (ES 10.2.5 MakeConstructor
        // is applied only to ordinary functions, generators and classes).
        assert_eq!(
            run("const o = { m() {}, get x() { return 1; }, async a() {} }; class C { m() {} static s() {} } \
                 return [() => 0, async function () {}, async () => 0, o.m, Object.getOwnPropertyDescriptor(o, 'x').get, o.a, C.prototype.m, C.s].map((f) => 'prototype' in f).join()"),
            "false,false,false,false,false,false,false,false"
        );
        assert_eq!(run("return Object.getOwnPropertyNames(() => 0).join()"), "length,name");
        assert_eq!(
            run("function F() {} return [typeof F.prototype, F.prototype.constructor === F, typeof (function* () {}).prototype, typeof class {}.prototype, Object.getOwnPropertyNames(F).join(' ')].join()"),
            "object,true,object,object,length name prototype"
        );
        // An arrow is not a constructor and has no prototype to test against.
        assert_eq!(run("const f = () => 0; try { new f(); } catch (e) { return String(e).split(':')[0]; }"), "TypeError");
        assert_eq!(run("return ({}) instanceof (() => 0)"), "TypeError");
    }

    #[test]
    fn host_interfaces_and_node_lists_keep_working() {
        assert_eq!(
            eval_in_page(
                "<p>a</p><p>b</p>",
                "const seen = []; [].forEach.call(document.querySelectorAll('p'), (p) => seen.push(p.textContent)); \
                 return [seen.join(''), typeof document.querySelector, document.querySelector.name, Array.prototype.slice.call(document.querySelectorAll('p')).length].join()"
            ),
            "ab,function,querySelector,2"
        );
    }
}
