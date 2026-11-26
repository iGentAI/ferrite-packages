//! builtins — the standard-library half of the realm bootstrap: Object /
//! Array / Number statics, the Promise constructor and its statics, and the
//! prototype methods for arrays, strings, numbers, and functions.
//!
//! Split from `globals.rs` so each half stays reviewable. Panic-free: no
//! indexing, no unwrap; every failure is a thrown `JsValue`.

use std::rc::Rc;

use super::interp::{Interp, Job};
use super::value::{JsObject, JsValue, NativeFn, ObjKind, format_number};

impl<'h> Interp<'h> {
    /// `Object.keys/values/entries/assign/freeze/create/getPrototypeOf`.
    pub(super) fn install_object_statics(&mut self) {
        let ctor = JsObject::new(ObjKind::Plain, Some(self.function_proto.clone()));

        let keys: NativeFn = Rc::new(|interp, _t, args| {
            let out = match args.first() {
                Some(JsValue::Object(o)) => interp
                    .enumerable_own_string_keys(o)?
                    .into_iter()
                    .map(JsValue::str)
                    .collect(),
                Some(JsValue::Str(s)) => (0..s.chars().count()).map(|i| JsValue::str(i.to_string())).collect(),
                _ => Vec::new(),
            };
            Ok(interp.new_array(out))
        });
        let f = self.native(keys);
        ctor.borrow_mut().set_prop("keys", f, false);

        let values: NativeFn = Rc::new(|interp, _t, args| {
            let mut out = Vec::new();
            if let Some(JsValue::Object(o)) = args.first() {
                let keys = interp.enumerable_own_string_keys(o)?;
                for k in keys {
                    out.push(interp.get_property(&JsValue::Object(o.clone()), &k)?);
                }
            }
            Ok(interp.new_array(out))
        });
        let f = self.native(values);
        ctor.borrow_mut().set_prop("values", f, false);

        let entries: NativeFn = Rc::new(|interp, _t, args| {
            let mut out = Vec::new();
            if let Some(JsValue::Object(o)) = args.first() {
                let keys = interp.enumerable_own_string_keys(o)?;
                for k in keys {
                    let v = interp.get_property(&JsValue::Object(o.clone()), &k)?;
                    let pair = interp.new_array(vec![JsValue::str(k), v]);
                    out.push(pair);
                }
            }
            Ok(interp.new_array(out))
        });
        let f = self.native(entries);
        ctor.borrow_mut().set_prop("entries", f, false);

        let assign: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(target)) = args.first() else {
                return Err(Interp::throw("TypeError: Object.assign target"));
            };
            for src in args.get(1..).unwrap_or_default() {
                if let JsValue::Object(s) = src {
                    // Enumerable own string AND symbol keys (ES §20.1.2.1).
                    let keys = interp.enumerable_own_keys(s, true)?;
                    for k in keys {
                        let v = interp.get_property(src, &k)?;
                        // Set(to, key, value, true): a refused write throws.
                        if !interp.try_set_property(&JsValue::Object(target.clone()), &k, v)? {
                            return Err(Interp::throw(format!(
                                "TypeError: Cannot assign to read only property '{k}' of object"
                            )));
                        }
                    }
                }
            }
            Ok(JsValue::Object(target.clone()))
        });
        let f = self.native(assign);
        ctor.borrow_mut().set_prop("assign", f, false);

        let create: NativeFn = Rc::new(|interp, _t, args| {
            // ES §20.1.2.2: the prototype must be an object or null;
            // anything else (including a missing argument) is a TypeError.
            let proto = match args.first() {
                Some(JsValue::Object(p)) => Some(p.clone()),
                // `Object.create(null)`: no prototype at all.
                Some(JsValue::Null) => None,
                _ => {
                    return Err(Interp::throw(
                        "TypeError: Object prototype may only be an Object or null",
                    ))
                }
            };
            if matches!(args.get(1), Some(v) if !matches!(v, JsValue::Object(_) | JsValue::Undefined)) {
                return Err(Interp::throw(
                    "TypeError: Property description must be an object",
                ));
            }
            let obj = JsObject::new(ObjKind::Plain, proto);
            // The optional second argument is a descriptor map, applied
            // exactly as `Object.defineProperties` would: Babel's
            // `_inherits` builds every subclass prototype as
            // `Object.create(Parent.prototype, { constructor: { value: Sub,
            // … } })`, and `Object.getPrototypeOf(this).constructor` is how
            // its `_createSuper` finds `new.target`.
            if let Some(descs @ JsValue::Object(_)) = args.get(1) {
                let define = interp.get_property(
                    &JsValue::Object(interp.global_object.clone()),
                    "Object",
                )?;
                let define = interp.get_property(&define, "defineProperties")?;
                if matches!(&define, JsValue::Object(f) if f.borrow().is_callable()) {
                    interp.call(define, JsValue::Undefined, &[JsValue::Object(obj.clone()), descs.clone()])?;
                }
            }
            Ok(JsValue::Object(obj))
        });
        let f = self.native(create);
        ctor.borrow_mut().set_prop("create", f, false);

        // Object.getPrototypeOf (ES §20.1.2.12): ToObject, so a primitive
        // answers its wrapper's prototype and null or undefined throws,
        // then [[GetPrototypeOf]] (a Proxy's trap).
        let get_proto: NativeFn = Rc::new(|interp, _t, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            if v.is_nullish() {
                return Err(Interp::throw("TypeError: Cannot convert undefined or null to object"));
            }
            let JsValue::Object(o) = interp.to_object(&v) else {
                return Ok(JsValue::Null);
            };
            Ok(interp.get_prototype_of(&o)?.map(JsValue::Object).unwrap_or(JsValue::Null))
        });
        let f = self.native(get_proto);
        ctor.borrow_mut().set_prop("getPrototypeOf", f, false);

        self.set_global("Object", JsValue::Object(ctor));
    }

    /// The `Array` constructor (`Array(n)`, `new Array(a, b)`) with
    /// `prototype`, `from` and `of` (`isArray` and the prototype methods
    /// are builtins_array.rs's).
    pub(super) fn install_array_statics(&mut self) {
        let array_call: NativeFn = Rc::new(|interp, this, args| {
            // One numeric argument is a length, every index a hole;
            // anything else lists elements.
            let arr = match args {
                [JsValue::Num(n)] => {
                    if !n.is_finite() || *n < 0.0 || n.fract() != 0.0 || *n > 4_294_967_295.0 {
                        return Err(Interp::throw("RangeError: Invalid array length"));
                    }
                    let arr = interp.new_array(Vec::new());
                    if let JsValue::Object(a) = &arr {
                        a.borrow_mut().trailing_holes = *n as usize;
                    }
                    arr
                }
                other => interp.new_array(other.to_vec()),
            };
            // Constructed (`new Array`, or a subclass's `super(...)`), the
            // array takes the prototype new.target selected (ES 23.1.1.1
            // step 2, GetPrototypeFromConstructor), which `construct` has
            // already given the receiver it allocated.
            if let (Some(JsValue::Object(_)), JsValue::Object(t), JsValue::Object(a)) = (&interp.new_target, &this, &arr) {
                let proto = {
                    let tb = t.borrow();
                    (!tb.is_callable()).then(|| tb.proto.clone()).flatten()
                };
                if let Some(p) = proto {
                    a.borrow_mut().proto = Some(p);
                }
            }
            Ok(arr)
        });
        let ctor = JsObject::new(ObjKind::Native(array_call), Some(self.function_proto.clone()));
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.array_proto.clone()),
            false,
        );
        self.array_proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor.clone()), false);

        let from: NativeFn = Rc::new(|interp, _t, args| {
            let src = args.first().cloned().unwrap_or(JsValue::Undefined);
            let items = interp.iterate(&src).unwrap_or_default();
            // Optional map function.
            let mapped = match args.get(1) {
                Some(f @ JsValue::Object(fo)) if fo.borrow().is_callable() => {
                    let mut out = Vec::new();
                    for (i, item) in items.into_iter().enumerate() {
                        out.push(interp.call(
                            f.clone(),
                            JsValue::Undefined,
                            &[item, JsValue::Num(i as f64)],
                        )?);
                    }
                    out
                }
                _ => items,
            };
            Ok(interp.new_array(mapped))
        });
        let f = self.native(from);
        ctor.borrow_mut().set_prop("from", f, false);

        let of: NativeFn = Rc::new(|interp, _t, args| Ok(interp.new_array(args.to_vec())));
        let f = self.native(of);
        ctor.borrow_mut().set_prop("of", f, false);

        self.set_global("Array", JsValue::Object(ctor));
    }

    /// `Number.isInteger/parseFloat/parseInt/NaN/isNaN` + global aliases.
    pub(super) fn install_number_statics(&mut self) {
        let ctor = JsObject::new(ObjKind::Plain, Some(self.function_proto.clone()));

        let is_integer: NativeFn = Rc::new(|_i, _t, args| {
            Ok(JsValue::Bool(matches!(
                args.first(),
                Some(JsValue::Num(n)) if n.is_finite() && n.fract() == 0.0
            )))
        });
        let f = self.native(is_integer);
        ctor.borrow_mut().set_prop("isInteger", f, false);

        let is_nan_static: NativeFn = Rc::new(|_i, _t, args| {
            Ok(JsValue::Bool(
                matches!(args.first(), Some(JsValue::Num(n)) if n.is_nan()),
            ))
        });
        let f = self.native(is_nan_static);
        ctor.borrow_mut().set_prop("isNaN", f, false);

        let parse_float: NativeFn = Rc::new(|_i, _t, args| {
            let s = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let t = s.trim();
            // Longest numeric prefix.
            let mut end = 0usize;
            let bytes = t.as_bytes();
            let mut seen_dot = false;
            let mut seen_exp = false;
            for (i, c) in t.char_indices() {
                let ok = c.is_ascii_digit()
                    || (i == 0 && (c == '+' || c == '-'))
                    || (c == '.' && !seen_dot && !seen_exp)
                    || ((c == 'e' || c == 'E') && !seen_exp && i > 0)
                    || ((c == '+' || c == '-')
                        && i > 0
                        && matches!(bytes.get(i.wrapping_sub(1)), Some(b'e') | Some(b'E')));
                if !ok {
                    break;
                }
                if c == '.' {
                    seen_dot = true;
                }
                if c == 'e' || c == 'E' {
                    seen_exp = true;
                }
                end = i + c.len_utf8();
            }
            let v = t
                .get(..end)
                .and_then(|p| p.parse::<f64>().ok())
                .unwrap_or(f64::NAN);
            Ok(JsValue::Num(v))
        });
        let f = self.native(parse_float.clone());
        ctor.borrow_mut().set_prop("parseFloat", f, false);
        let f = self.native(parse_float);
        self.set_global("parseFloat", f);

        let parse_int: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "undefined")?;
            let radix = interp
                .opt_number_arg(args.get(1))?
                .filter(|r| r.is_finite() && *r >= 2.0 && *r <= 36.0)
                .unwrap_or(10.0) as u32;
            let t = s.trim();
            let (neg, t) = match t.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, t.strip_prefix('+').unwrap_or(t)),
            };
            let t = if radix == 16 {
                t.strip_prefix("0x")
                    .or_else(|| t.strip_prefix("0X"))
                    .unwrap_or(t)
            } else {
                t
            };
            let mut val: f64 = f64::NAN;
            let mut acc: f64 = 0.0;
            let mut any = false;
            for c in t.chars() {
                match c.to_digit(radix) {
                    Some(d) => {
                        acc = acc * radix as f64 + d as f64;
                        any = true;
                    }
                    None => break,
                }
            }
            if any {
                val = if neg { -acc } else { acc };
            }
            Ok(JsValue::Num(val))
        });
        let f = self.native(parse_int.clone());
        ctor.borrow_mut().set_prop("parseInt", f, false);
        let f = self.native(parse_int);
        self.set_global("parseInt", f);

        ctor.borrow_mut()
            .set_prop("NaN", JsValue::Num(f64::NAN), false);
        ctor.borrow_mut()
            .set_prop("MAX_SAFE_INTEGER", JsValue::Num(9007199254740991.0), false);
        self.set_global("Number", JsValue::Object(ctor));

        let is_nan: NativeFn = Rc::new(|interp, _t, args| {
            Ok(JsValue::Bool(interp.number_arg(args.first(), f64::NAN)?.is_nan()))
        });
        let f = self.native(is_nan);
        self.set_global("isNaN", f);

        self.set_global("NaN", JsValue::Num(f64::NAN));
        self.set_global("Infinity", JsValue::Num(f64::INFINITY));
        self.set_global("undefined", JsValue::Undefined);
    }

    /// The `Promise` constructor with `resolve/reject/all` statics; `then/
    /// catch/finally` live on `promise_proto`.
    pub(super) fn install_promise(&mut self) {
        // Constructor: new Promise((resolve, reject) => ...)
        let ctor_fn: NativeFn = Rc::new(|interp, _t, args| {
            let promise = interp.new_promise();
            let Some(executor @ JsValue::Object(_)) = args.first() else {
                return Err(Interp::throw("TypeError: Promise executor required"));
            };
            let p_res = promise.clone();
            let resolve: NativeFn = Rc::new(move |interp, _t, args| {
                let v = args.first().cloned().unwrap_or(JsValue::Undefined);
                interp.resolve_promise(&p_res, v, true);
                Ok(JsValue::Undefined)
            });
            let p_rej = promise.clone();
            let reject: NativeFn = Rc::new(move |interp, _t, args| {
                let v = args.first().cloned().unwrap_or(JsValue::Undefined);
                interp.resolve_promise(&p_rej, v, false);
                Ok(JsValue::Undefined)
            });
            let rf = interp.native(resolve);
            let jf = interp.native(reject);
            if let Err(e) = interp.call(executor.clone(), JsValue::Undefined, &[rf, jf]) {
                interp.resolve_promise(&promise, e, false);
            }
            Ok(JsValue::Object(promise))
        });
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.promise_proto.clone()),
            false,
        );

        let resolve_static: NativeFn = Rc::new(|interp, _t, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            let p = interp.new_promise();
            interp.resolve_promise(&p, v, true);
            Ok(JsValue::Object(p))
        });
        let f = self.native(resolve_static);
        ctor.borrow_mut().set_prop("resolve", f, false);

        let reject_static: NativeFn = Rc::new(|interp, _t, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            let p = interp.new_promise();
            interp.resolve_promise(&p, v, false);
            Ok(JsValue::Object(p))
        });
        let f = self.native(reject_static);
        ctor.borrow_mut().set_prop("reject", f, false);

        let all: NativeFn = Rc::new(|interp, _t, args| {
            let src = args.first().cloned().unwrap_or(JsValue::Undefined);
            let items = interp.iterate(&src)?;
            let result = interp.new_promise();
            // Await each in order (sequential virtual time is fine for pages).
            let mut out = Vec::new();
            for item in items {
                match &item {
                    JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::Promise(_)) => {
                        match interp.await_promise(o) {
                            Ok(v) => out.push(v),
                            Err(e) => {
                                interp.resolve_promise(&result, e, false);
                                return Ok(JsValue::Object(result));
                            }
                        }
                    }
                    other => out.push(other.clone()),
                }
            }
            let arr = interp.new_array(out);
            interp.resolve_promise(&result, arr, true);
            Ok(JsValue::Object(result))
        });
        let f = self.native(all);
        ctor.borrow_mut().set_prop("all", f, false);

        self.set_global("Promise", JsValue::Object(ctor));
        let then: NativeFn = Rc::new(|interp, this, args| {
            let JsValue::Object(p) = &this else {
                return Err(Interp::throw("TypeError: then on non-promise"));
            };
            let derived = interp.new_promise();
            let on_f = match args.first() {
                Some(JsValue::Object(f)) if f.borrow().is_callable() => Some(f.clone()),
                _ => None,
            };
            let on_r = match args.get(1) {
                Some(JsValue::Object(f)) if f.borrow().is_callable() => Some(f.clone()),
                _ => None,
            };
            interp.add_reactions(p, on_f, on_r, derived.clone());
            Ok(JsValue::Object(derived))
        });
        let f = self.native(then);
        self.promise_proto.borrow_mut().set_prop("then", f, false);

        let catch: NativeFn = Rc::new(|interp, this, args| {
            let JsValue::Object(p) = &this else {
                return Err(Interp::throw("TypeError: catch on non-promise"));
            };
            let derived = interp.new_promise();
            let on_r = match args.first() {
                Some(JsValue::Object(f)) if f.borrow().is_callable() => Some(f.clone()),
                _ => None,
            };
            interp.add_reactions(p, None, on_r, derived.clone());
            Ok(JsValue::Object(derived))
        });
        let f = self.native(catch);
        self.promise_proto.borrow_mut().set_prop("catch", f, false);

        let finally: NativeFn = Rc::new(|interp, this, args| {
            let JsValue::Object(p) = &this else {
                return Err(Interp::throw("TypeError: finally on non-promise"));
            };
            let derived = interp.new_promise();
            let cb = match args.first() {
                Some(JsValue::Object(f)) if f.borrow().is_callable() => Some(f.clone()),
                _ => None,
            };
            // finally runs the callback for both outcomes, passing through.
            interp.add_reactions(p, cb.clone(), cb, derived.clone());
            Ok(JsValue::Object(derived))
        });
        let f = self.native(finally);
        self.promise_proto
            .borrow_mut()
            .set_prop("finally", f, false);

        // queueMicrotask
        let qm: NativeFn = Rc::new(|interp, _t, args| {
            if let Some(JsValue::Object(f)) = args.first() {
                if f.borrow().is_callable() {
                    let derived = interp.new_promise();
                    interp.microtasks.push_back(Job::Reaction {
                        handler: Some(f.clone()),
                        arg: JsValue::Undefined,
                        fulfilled: true,
                        derived,
                    });
                }
            }
            Ok(JsValue::Undefined)
        });
        let f = self.native(qm);
        self.set_global("queueMicrotask", f);
    }

    /// Prototype methods for strings, numbers, functions (the array ones
    /// are builtins_array.rs's).
    pub(super) fn install_prototypes(&mut self) {
        self.install_string_proto();
        self.install_number_proto();
        self.install_function_proto();
        self.install_error_ctor();
        self.install_regexp_proto();
    }

    /// RegExp.prototype.test / exec over the std-only regex engine.
    fn install_regexp_proto(&mut self) {
        fn regex_of(this: &JsValue) -> Option<(String, String)> {
            let JsValue::Object(o) = this else {
                return None;
            };
            let b = o.borrow();
            match &b.kind {
                ObjKind::RegExp { source, flags } => Some((source.clone(), flags.clone())),
                _ => None,
            }
        }
        // exec: the full match array (groups, `index`, `input`, `groups`)
        // with `lastIndex` semantics for global / sticky regexes.
        let exec: NativeFn = Rc::new(|interp, this, args| {
            let Some((source, flags)) = regex_of(&this) else {
                return Err(Interp::throw("TypeError: exec on non-RegExp"));
            };
            let input = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            Ok(interp.regexp_exec(&this, &source, &flags, &input))
        });
        let f = self.native(exec);
        self.regexp_proto.borrow_mut().set_prop("exec", f, false);
        // test: whether exec matches, so it honours lastIndex too (a global
        // regex reused across calls).
        let test_g: NativeFn = Rc::new(|interp, this, args| {
            let Some((source, flags)) = regex_of(&this) else {
                return Err(Interp::throw("TypeError: test on non-RegExp"));
            };
            let input = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let r = interp.regexp_exec(&this, &source, &flags, &input);
            Ok(JsValue::Bool(!matches!(r, JsValue::Null)))
        });
        let f = self.native(test_g);
        self.regexp_proto.borrow_mut().set_prop("test", f, false);
        // [Symbol.replace] / [Symbol.split] / [Symbol.match] are reached
        // through the String methods in builtins_ext / builtins_es.
    }

    fn install_string_proto(&mut self) {
        let methods: Vec<(&str, NativeFn)> = vec![
            (
                "charAt",
                Rc::new(|interp, this, args| {
                    let s = this.to_js_string();
                    let i = interp.number_arg(args.first(), 0.0)?.max(0.0) as usize;
                    Ok(JsValue::str(
                        s.chars().nth(i).map(|c| c.to_string()).unwrap_or_default(),
                    ))
                }),
            ),
            (
                "charCodeAt",
                Rc::new(|interp, this, args| {
                    let s = this.to_js_string();
                    let i = interp.number_arg(args.first(), 0.0)?.max(0.0) as usize;
                    Ok(match s.chars().nth(i) {
                        Some(c) => JsValue::Num(c as u32 as f64),
                        None => JsValue::Num(f64::NAN),
                    })
                }),
            ),
            (
                "indexOf",
                Rc::new(|_i, this, args| {
                    let s = this.to_js_string();
                    let needle = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                    Ok(JsValue::Num(match s.find(&needle) {
                        Some(byte_idx) => s
                            .get(..byte_idx)
                            .map(|p| p.chars().count() as f64)
                            .unwrap_or(-1.0),
                        None => -1.0,
                    }))
                }),
            ),
            (
                "includes",
                Rc::new(|_i, this, args| {
                    let s = this.to_js_string();
                    let needle = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                    Ok(JsValue::Bool(s.contains(&needle)))
                }),
            ),
            (
                "startsWith",
                Rc::new(|_i, this, args| {
                    let s = this.to_js_string();
                    let needle = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                    Ok(JsValue::Bool(s.starts_with(&needle)))
                }),
            ),
            (
                "endsWith",
                Rc::new(|_i, this, args| {
                    let s = this.to_js_string();
                    let needle = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                    Ok(JsValue::Bool(s.ends_with(&needle)))
                }),
            ),
            (
                "slice",
                Rc::new(|interp, this, args| {
                    let s: Vec<char> = this.to_js_string().chars().collect();
                    let len = s.len() as i64;
                    let norm = |v: Option<f64>, d: i64| -> i64 {
                        match v {
                            Some(n) if !n.is_nan() => {
                                if n < 0.0 {
                                    (len + n as i64).max(0)
                                } else {
                                    (n as i64).min(len)
                                }
                            }
                            _ => d,
                        }
                    };
                    let start = norm(interp.opt_number_arg(args.first())?, 0);
                    let end = norm(interp.opt_number_arg(args.get(1))?, len);
                    let out: String = s
                        .into_iter()
                        .skip(start.max(0) as usize)
                        .take((end - start).max(0) as usize)
                        .collect();
                    Ok(JsValue::str(out))
                }),
            ),
            (
                "substring",
                Rc::new(|interp, this, args| {
                    let s: Vec<char> = this.to_js_string().chars().collect();
                    let len = s.len() as i64;
                    let norm = |v: Option<f64>, d: i64| -> i64 {
                        match v {
                            Some(n) if !n.is_nan() => (n.max(0.0) as i64).min(len),
                            _ => d,
                        }
                    };
                    let mut a = norm(interp.opt_number_arg(args.first())?, 0);
                    let mut b = norm(interp.opt_number_arg(args.get(1))?, len);
                    if a > b {
                        core::mem::swap(&mut a, &mut b);
                    }
                    let out: String = s
                        .into_iter()
                        .skip(a as usize)
                        .take((b - a) as usize)
                        .collect();
                    Ok(JsValue::str(out))
                }),
            ),
            (
                "toUpperCase",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string().to_uppercase()))),
            ),
            (
                "toLowerCase",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string().to_lowercase()))),
            ),
            (
                "trim",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string().trim().to_string()))),
            ),
            (
                "split",
                Rc::new(|interp, this, args| {
                    let s = this.to_js_string();
                    let limit = match args.get(1) {
                        Some(v) if !matches!(v, JsValue::Undefined) => {
                            let n = interp.to_number_value(v)?;
                            if n.is_finite() && n >= 0.0 {
                                n as usize
                            } else {
                                usize::MAX
                            }
                        }
                        _ => usize::MAX,
                    };
                    let mut out: Vec<JsValue> = match args.first() {
                        None | Some(JsValue::Undefined) => vec![JsValue::str(s)],
                        Some(JsValue::Object(o))
                            if matches!(o.borrow().kind, ObjKind::RegExp { .. }) =>
                        {
                            let (source, flags) = match &o.borrow().kind {
                                ObjKind::RegExp { source, flags } => {
                                    (source.clone(), flags.clone())
                                }
                                _ => (String::new(), String::new()),
                            };
                            regex_split(interp, &s, &source, &flags)
                        }
                        Some(sep) => {
                            let sep = sep.to_js_string();
                            if sep.is_empty() {
                                s.chars().map(|c| JsValue::str(c.to_string())).collect()
                            } else {
                                s.split(&sep as &str)
                                    .map(|p| JsValue::str(p.to_string()))
                                    .collect()
                            }
                        }
                    };
                    out.truncate(limit);
                    Ok(interp.new_array(out))
                }),
            ),
            (
                "repeat",
                Rc::new(|interp, this, args| {
                    let s = this.to_js_string();
                    let n = interp.number_arg(args.first(), 0.0)?;
                    if !(0.0..=10_000.0).contains(&n) {
                        return Err(Interp::throw("RangeError: repeat count"));
                    }
                    Ok(JsValue::str(s.repeat(n as usize)))
                }),
            ),
            (
                "padStart",
                Rc::new(|interp, this, args| {
                    let s = this.to_js_string();
                    let padding = string_padding(interp, &s, args)?;
                    Ok(JsValue::str(format!("{padding}{s}")))
                }),
            ),
            (
                "padEnd",
                Rc::new(|interp, this, args| {
                    let s = this.to_js_string();
                    let padding = string_padding(interp, &s, args)?;
                    Ok(JsValue::str(format!("{s}{padding}")))
                }),
            ),
            (
                "concat",
                Rc::new(|_i, this, args| {
                    let mut s = this.to_js_string();
                    for a in args {
                        s.push_str(&a.to_js_string());
                    }
                    Ok(JsValue::str(s))
                }),
            ),
            (
                "toString",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string()))),
            ),
            (
                "matchAll",
                Rc::new(|interp, this, args| {
                    // Every match of a GLOBAL regex as an iterator of match
                    // arrays (a non-global regex is a TypeError, per spec).
                    let input = this.to_js_string();
                    let (source, flags) = match args.first() {
                        Some(JsValue::Object(o))
                            if matches!(o.borrow().kind, ObjKind::RegExp { .. }) =>
                        {
                            match &o.borrow().kind {
                                ObjKind::RegExp { source, flags } => {
                                    (source.clone(), flags.clone())
                                }
                                _ => (String::new(), String::new()),
                            }
                        }
                        Some(v) => (regex_escape_str(&v.to_js_string()), "g".to_string()),
                        None => (String::new(), "g".to_string()),
                    };
                    if !flags.contains('g') {
                        return Err(Interp::throw(
                            "TypeError: String.prototype.matchAll called with a non-global RegExp argument",
                        ));
                    }
                    let Some(re) = super::regex::compile(&source, &flags) else {
                        return Ok(interp.make_list_iterator(Vec::new()));
                    };
                    let n_chars = input.chars().count();
                    let mut items = Vec::new();
                    let mut from = 0usize;
                    let mut guard = 0usize;
                    while from <= n_chars && guard < 100_000 {
                        guard += 1;
                        let Some(caps) = re.find_captures_from(&input, from, false) else {
                            break;
                        };
                        from = if caps.end == caps.start { caps.end + 1 } else { caps.end };
                        items.push(interp.match_array(&caps, &input));
                    }
                    Ok(interp.make_list_iterator(items))
                }),
            ),
        ];
        for (name, f) in methods {
            let fv = self.native(f);
            self.string_proto.borrow_mut().set_prop(name, fv, false);
        }
    }

    /// The match array `exec` / `match` / `matchAll` hand out: the groups
    /// (strings or undefined), `index`, `input` and `groups`.
    pub fn match_array(&mut self, caps: &super::regex::Captures, input: &str) -> JsValue {
        let items: Vec<JsValue> = caps
            .groups
            .iter()
            .map(|g| match g {
                Some(s) => JsValue::str(s.clone()),
                None => JsValue::Undefined,
            })
            .collect();
        let arr = self.new_array(items);
        let groups = if caps.names.iter().any(|n| n.is_some()) {
            let g = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
            for (i, n) in caps.names.iter().enumerate() {
                if let Some(n) = n {
                    let v = match caps.groups.get(i) {
                        Some(Some(s)) => JsValue::str(s.clone()),
                        _ => JsValue::Undefined,
                    };
                    g.borrow_mut().set_prop(n, v, true);
                }
            }
            JsValue::Object(g)
        } else {
            JsValue::Undefined
        };
        if let JsValue::Object(a) = &arr {
            let mut b = a.borrow_mut();
            b.set_prop("index", JsValue::Num(caps.start as f64), true);
            b.set_prop("input", JsValue::str(input.to_string()), true);
            b.set_prop("groups", groups, true);
        }
        arr
    }

    /// `RegExp.prototype.exec` over the engine's regex: the match array
    /// (whole match, groups as strings or undefined, `index`, `input`,
    /// `groups`), scanning from `lastIndex` for global/sticky regexes and
    /// writing it back (0 on failure), as the spec's RegExpBuiltinExec does.
    pub fn regexp_exec(&mut self, re_obj: &JsValue, source: &str, flags: &str, input: &str) -> JsValue {
        let global = flags.contains('g');
        let sticky = flags.contains('y');
        let JsValue::Object(o) = re_obj else {
            return JsValue::Null;
        };
        let last_index = if global || sticky {
            // ToLength(lastIndex): NaN → 0, negative → 0, +∞ → clamps past
            // the input, so the scan fails and lastIndex resets to 0.
            let n = o
                .borrow()
                .get_prop("lastIndex")
                .map(|v| v.to_number())
                .unwrap_or(0.0);
            if n.is_nan() || n <= 0.0 {
                0
            } else if n.is_infinite() || n > (usize::MAX / 2) as f64 {
                usize::MAX / 2
            } else {
                n as usize
            }
        } else {
            0
        };
        let Some(re) = super::regex::compile(source, flags) else {
            return JsValue::Null;
        };
        let caps = re.find_captures_from(input, last_index, sticky);
        let Some(caps) = caps else {
            if global || sticky {
                o.borrow_mut().set_prop("lastIndex", JsValue::Num(0.0), false);
            }
            return JsValue::Null;
        };
        if global || sticky {
            // Per spec lastIndex is the match END (an empty match leaves it
            // where it was; the String scanners step past empty matches
            // themselves, and a bare `exec` loop is bounded by the step
            // budget like any other loop).
            o.borrow_mut()
                .set_prop("lastIndex", JsValue::Num(caps.end as f64), false);
        }
        self.match_array(&caps, input)
    }

    fn install_number_proto(&mut self) {
        // (regex helpers live at module level below)
        let to_fixed: NativeFn = Rc::new(|interp, this, args| {
            let n = this.to_number();
            let digits = interp
                .number_arg(args.first(), 0.0)?
                .clamp(0.0, 20.0) as usize;
            Ok(JsValue::str(format!("{n:.digits$}")))
        });
        let f = self.native(to_fixed);
        self.number_proto.borrow_mut().set_prop("toFixed", f, false);

        // toString(radix): base 10 is the ordinary Number-to-String; any
        // other base (2..36) renders the integer part by repeated division
        // and the fraction digit by digit until it is exhausted, as engines
        // do for `(255).toString(16)`, `(0.1).toString(2)` and the
        // `Math.random().toString(36).slice(2)` id idiom.
        let to_string: NativeFn = Rc::new(|interp, this, args| {
            let n = this.to_number();
            let radix = match args.first() {
                Some(v) if !matches!(v, JsValue::Undefined) => interp.to_number_value(v)?,
                _ => 10.0,
            };
            if !radix.is_finite() || !(2.0..=36.0).contains(&radix.trunc()) {
                return Err(Interp::throw("RangeError: toString() radix must be between 2 and 36"));
            }
            let radix = radix.trunc() as u32;
            if radix == 10 || !n.is_finite() || n == 0.0 {
                return Ok(JsValue::str(format_number(n)));
            }
            Ok(JsValue::str(number_to_radix_string(n, radix)))
        });
        let f = self.native(to_string);
        self.number_proto
            .borrow_mut()
            .set_prop("toString", f, false);
    }

    fn install_function_proto(&mut self) {
        let call: NativeFn = Rc::new(|interp, this, args| {
            let this_arg = args.first().cloned().unwrap_or(JsValue::Undefined);
            let rest = args.get(1..).unwrap_or_default();
            interp.call(this, this_arg, rest)
        });
        let f = self.native(call);
        self.function_proto.borrow_mut().set_prop("call", f, false);

        let apply: NativeFn = Rc::new(|interp, this, args| {
            let this_arg = args.first().cloned().unwrap_or(JsValue::Undefined);
            // CreateListFromArrayLike: arrays directly, and anything with a
            // `length` (a NodeList, `arguments`, a jQuery collection) by
            // index — `push.apply(results, el.getElementsByTagName(...))` is
            // how Sizzle copies a NodeList into its result array.
            let arr = match args.get(1) {
                Some(v @ JsValue::Object(o)) if matches!(o.borrow().kind, ObjKind::Array) => {
                    interp.array_like_items(v)?
                }
                Some(v @ JsValue::Object(_)) => interp.iterate(v)?,
                Some(JsValue::Undefined) | Some(JsValue::Null) | None => Vec::new(),
                Some(_) => {
                    return Err(Interp::throw(
                        "TypeError: CreateListFromArrayLike called on non-object",
                    ))
                }
            };
            interp.call(this, this_arg, &arr)
        });
        let f = self.native(apply);
        self.function_proto.borrow_mut().set_prop("apply", f, false);

        let bind: NativeFn = Rc::new(|interp, this, args| {
            let target = match &this {
                JsValue::Object(t) if t.borrow().is_callable() => t.clone(),
                _ => return Err(Interp::throw("TypeError: Bind must be called on a function")),
            };
            let target = &target;
            let this_arg = args.first().cloned().unwrap_or(JsValue::Undefined);
            let bound_args = args.get(1..).unwrap_or_default().to_vec();
            // The bound function's `length` is what is left of the
            // target's own numeric `length` after the bound arguments, and
            // its `name` is "bound " and the target's string `name` (ES
            // §20.2.3.2 steps 4-9).
            let mut length = 0.0;
            if interp.has_own_property(target, "length")? {
                if let JsValue::Num(l) = interp.get_property(&this, "length")? {
                    length = if l == f64::INFINITY {
                        l
                    } else if l.is_nan() || l == f64::NEG_INFINITY {
                        0.0
                    } else {
                        (l.trunc() - bound_args.len() as f64).max(0.0)
                    };
                }
            }
            let name = match interp.get_property(&this, "name")? {
                JsValue::Str(n) => format!("bound {n}"),
                _ => "bound ".to_string(),
            };
            let obj = JsObject::new(
                ObjKind::Bound {
                    target: target.clone(),
                    this_arg: Box::new(this_arg),
                    bound_args,
                },
                Some(
                    target
                        .borrow()
                        .proto
                        .clone()
                        .unwrap_or_else(|| target.clone()),
                ),
            );
            obj.borrow_mut().define_function_meta(length, JsValue::str(name));
            Ok(JsValue::Object(obj))
        });
        let f = self.native(bind);
        self.function_proto.borrow_mut().set_prop("bind", f, false);
    }

    fn install_error_ctor(&mut self) {
        for name in ["Error", "TypeError", "RangeError", "SyntaxError"] {
            let proto = self.error_proto.clone();
            let n = name.to_string();
            let ctor: NativeFn = Rc::new(move |_i, this, args| {
                let msg = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                // `new Error(...)` gives us a fresh `this`; bare calls make one.
                let obj = match &this {
                    JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                    _ => JsObject::new(ObjKind::Error, Some(proto.clone())),
                };
                {
                    let mut b = obj.borrow_mut();
                    b.kind = ObjKind::Error;
                    b.set_prop("name", JsValue::str(n.clone()), false);
                    b.set_prop("message", JsValue::str(msg), false);
                }
                Ok(JsValue::Object(obj))
            });
            let ctor_obj = JsObject::new(ObjKind::Native(ctor), Some(self.function_proto.clone()));
            ctor_obj.borrow_mut().set_prop(
                "prototype",
                JsValue::Object(self.error_proto.clone()),
                false,
            );
            self.set_global(name, JsValue::Object(ctor_obj));
        }
        let to_string: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string())));
        let f = self.native(to_string);
        self.error_proto.borrow_mut().set_prop("toString", f, false);
    }
}

/// `String.prototype.split` with a regex separator (ES §22.1.3.23 through
/// `RegExp.prototype[Symbol.split]`): the pieces between matches, with
/// every capture group spliced in after its piece, and an empty match
/// splitting between characters. A separator that never matches yields
/// the whole string; an empty input yields `[]` when the regex matches the
/// empty string and `[""]` otherwise.
/// The fill `padStart`/`padEnd` add to `s`: empty when it is already long
/// enough or the pad string is empty.
fn string_padding(interp: &mut Interp, s: &str, args: &[JsValue]) -> Result<String, JsValue> {
    let target = interp.number_arg(args.first(), 0.0)?.max(0.0) as usize;
    let pad = match args.get(1) {
        Some(v) if !matches!(v, JsValue::Undefined) => interp.to_string_value(v)?,
        _ => " ".to_string(),
    };
    let need = target.saturating_sub(s.chars().count());
    Ok(pad.chars().cycle().take(need).collect())
}

fn regex_split(interp: &mut Interp, input: &str, source: &str, flags: &str) -> Vec<JsValue> {
    let Some(re) = super::regex::compile(source, flags) else {
        return vec![JsValue::str(input.to_string())];
    };
    let chars: Vec<char> = input.chars().collect();
    let n = chars.len();
    if n == 0 {
        return if re.find_captures_from(input, 0, true).is_some() {
            Vec::new()
        } else {
            vec![JsValue::str(String::new())]
        };
    }
    let mut out: Vec<JsValue> = Vec::new();
    let mut piece_start = 0usize; // p
    let mut q = 0usize;
    let mut guard = 0usize;
    while q < n && guard < 100_000 {
        guard += 1;
        // Sticky match at q (the spec's SplitMatcher).
        let Some(caps) = re.find_captures_from(input, q, true) else {
            q += 1;
            continue;
        };
        let e = caps.end.min(n);
        if e == piece_start {
            // An empty match at the piece start does not split here.
            q += 1;
            continue;
        }
        let piece: String = chars.get(piece_start..q).unwrap_or(&[]).iter().collect();
        out.push(JsValue::str(piece));
        for g in caps.groups.iter().skip(1) {
            out.push(match g {
                Some(s) => JsValue::str(s.clone()),
                None => JsValue::Undefined,
            });
        }
        piece_start = e;
        q = if e == q { q + 1 } else { e };
    }
    let tail: String = chars.get(piece_start..).unwrap_or(&[]).iter().collect();
    out.push(JsValue::str(tail));
    let _ = interp;
    out
}

/// Number → string in a non-decimal radix (2..36): sign, the integer part
/// by repeated division, then the fraction digit by digit until the
/// remaining fraction is exactly zero. The fraction of an f64 has at most
/// 1074 binary places (`Number.MIN_VALUE` is 2^-1074), so the digit loop
/// is bounded at 1100 for every radix; in a non-power-of-two radix the
/// remainder never reaches zero and the bound is what stops the loop, the
/// same termination engines apply.
fn number_to_radix_string(n: f64, radix: u32) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let digit = |d: u32| DIGITS.get(d as usize).copied().unwrap_or(b'0') as char;
    let neg = n < 0.0;
    let n = n.abs();
    let mut int_part = n.trunc();
    let mut frac = n - int_part;
    let r = radix as f64;
    let mut int_digits: Vec<char> = Vec::new();
    if int_part == 0.0 {
        int_digits.push('0');
    }
    // Bounded: an f64 has at most ~1100 binary digits.
    while int_part >= 1.0 && int_digits.len() < 1100 {
        let d = (int_part % r) as u32;
        int_digits.push(digit(d));
        int_part = (int_part / r).trunc();
    }
    int_digits.reverse();
    let mut out = String::with_capacity(int_digits.len() + 24);
    if neg {
        out.push('-');
    }
    out.extend(int_digits);
    if frac > 0.0 {
        out.push('.');
        let mut count = 0;
        while frac > 0.0 && count < 1100 {
            frac *= r;
            let d = frac.trunc();
            out.push(digit(d as u32));
            frac -= d;
            count += 1;
        }
    }
    out
}

/// Escape regex metacharacters so a plain string can be compiled literally.
fn regex_escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\^$.|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
