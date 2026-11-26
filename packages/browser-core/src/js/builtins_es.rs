//! builtins_es — the ES2015+ standard-library surface framework bundles
//! reach for: `Symbol` (well-known symbols and the registry), `Map` / `Set` /
//! `WeakMap` / `WeakSet`, `Proxy` and `Reflect` (Vue 3 reactivity), the
//! property-descriptor half of `Object`, the iterator protocol behind
//! spread / `for...of` / `Array.from`, `Object.prototype.toString`, the full
//! error hierarchy, and the `Array` / `String` / `Number` methods minified
//! bundles call.
//!
//! Same rules as the rest of the engine: std-only, panic-free, no indexing,
//! every failure a thrown `JsValue`.

use std::rc::Rc;

use super::interp::Interp;
use super::value::{JsObject, JsValue, MapData, NativeFn, ObjKind, ObjRef, Prop, SYM_ASYNC_ITERATOR, SYM_HAS_INSTANCE, SYM_IS_CONCAT_SPREADABLE, SYM_ITERATOR, SYM_MATCH, SYM_MATCH_ALL, SYM_REPLACE, SYM_SEARCH, SYM_SPECIES, SYM_SPLIT, SYM_TO_PRIMITIVE, SYM_TO_STRING_TAG, SYM_UNSCOPABLES, SymbolData, array_index, format_number, is_symbol_key, iterator_key, symbol_key, well_known_symbol};

impl<'h> Interp<'h> {
    /// Install the ES2015+ surface. Called from `install_globals` after the
    /// ES5 statics so these definitions win where they overlap.
    pub(super) fn install_es_builtins(&mut self) {
        self.install_symbol();
        self.install_iterator_protocol();
        self.install_object_descriptors();
        self.install_map_set();
        self.install_proxy_reflect();
        self.install_object_proto_extras();
        self.install_error_hierarchy();
        self.install_string_es();
        self.install_number_es();
        self.install_function_es();
        self.install_regexp_ctor();
        // The receiver-agnostic Array.prototype methods and Array.isArray.
        self.install_array_generic();
    }

    /// The `RegExp` constructor (`new RegExp(src, flags)`, `RegExp(re)`),
    /// plus `source` / `flags` / `global` / `ignoreCase` / `multiline` /
    /// `sticky` / `lastIndex` on instances, and `toString`.
    fn install_regexp_ctor(&mut self) {
        let regexp_proto = self.regexp_proto.clone();
        let ctor_fn: NativeFn = Rc::new(move |interp, this, args| {
            let (source, flags) = match args.first() {
                Some(JsValue::Object(o)) if matches!(o.borrow().kind, ObjKind::RegExp { .. }) => {
                    match &o.borrow().kind {
                        ObjKind::RegExp { source, flags } => (
                            source.clone(),
                            args.get(1)
                                .filter(|f| !f.is_nullish())
                                .map(|f| f.to_js_string())
                                .unwrap_or_else(|| flags.clone()),
                        ),
                        _ => (String::new(), String::new()),
                    }
                }
                Some(v) if !v.is_nullish() => (
                    v.to_js_string(),
                    args.get(1)
                        .filter(|f| !f.is_nullish())
                        .map(|f| f.to_js_string())
                        .unwrap_or_default(),
                ),
                _ => (
                    "(?:)".to_string(),
                    args.get(1)
                        .filter(|f| !f.is_nullish())
                        .map(|f| f.to_js_string())
                        .unwrap_or_default(),
                ),
            };
            if flags.chars().any(|c| !"dgimsuvy".contains(c)) {
                return Err(Interp::throw(format!(
                    "SyntaxError: Invalid flags supplied to RegExp constructor '{flags}'"
                )));
            }
            let obj = match &this {
                JsValue::Object(o) if !o.borrow().is_callable() && matches!(o.borrow().kind, ObjKind::Plain) => {
                    o.clone()
                }
                _ => JsObject::new(ObjKind::Plain, Some(regexp_proto.clone())),
            };
            {
                let mut b = obj.borrow_mut();
                b.kind = ObjKind::RegExp { source, flags };
                b.class_name = "RegExp";
                b.proto = Some(interp.regexp_proto.clone());
                b.set_prop("lastIndex", JsValue::Num(0.0), false);
            }
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.regexp_proto.clone()),
            false,
        );
        self.regexp_proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor.clone()), false);
        self.set_global("RegExp", JsValue::Object(ctor));

        fn parts(this: &JsValue) -> Option<(String, String)> {
            let JsValue::Object(o) = this else { return None };
            match &o.borrow().kind {
                ObjKind::RegExp { source, flags } => Some((source.clone(), flags.clone())),
                _ => None,
            }
        }
        let accessors: Vec<(&str, NativeFn)> = vec![
            ("source", Rc::new(|_i, this, _a| Ok(parts(&this).map(|(s, _)| JsValue::str(s)).unwrap_or(JsValue::Undefined)))),
            ("flags", Rc::new(|_i, this, _a| Ok(parts(&this).map(|(_, f)| JsValue::str(f)).unwrap_or(JsValue::Undefined)))),
            ("global", Rc::new(|_i, this, _a| Ok(JsValue::Bool(parts(&this).map(|(_, f)| f.contains('g')).unwrap_or(false))))),
            ("ignoreCase", Rc::new(|_i, this, _a| Ok(JsValue::Bool(parts(&this).map(|(_, f)| f.contains('i')).unwrap_or(false))))),
            ("multiline", Rc::new(|_i, this, _a| Ok(JsValue::Bool(parts(&this).map(|(_, f)| f.contains('m')).unwrap_or(false))))),
            ("sticky", Rc::new(|_i, this, _a| Ok(JsValue::Bool(parts(&this).map(|(_, f)| f.contains('y')).unwrap_or(false))))),
            ("unicode", Rc::new(|_i, this, _a| Ok(JsValue::Bool(parts(&this).map(|(_, f)| f.contains('u')).unwrap_or(false))))),
            ("dotAll", Rc::new(|_i, this, _a| Ok(JsValue::Bool(parts(&this).map(|(_, f)| f.contains('s')).unwrap_or(false))))),
        ];
        for (name, f) in accessors {
            let g = self.native(f);
            if let JsValue::Object(go) = g {
                self.regexp_proto.borrow_mut().set_accessor(name, Some(go), None, false);
            }
        }
        let to_string: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string())));
        let f = self.native(to_string);
        self.regexp_proto.borrow_mut().set_prop("toString", f, false);
    }

    /// `Symbol()`, `Symbol.for`, `Symbol.keyFor` and the well-known symbols.
    fn install_symbol(&mut self) {
        let ctor_fn: NativeFn = Rc::new(|interp, _t, args| {
            let description = args
                .first()
                .filter(|v| !matches!(v, JsValue::Undefined))
                .map(|v| v.to_js_string());
            let id = interp.next_symbol_id;
            interp.next_symbol_id = interp.next_symbol_id.saturating_add(1);
            Ok(JsValue::Symbol(Rc::new(SymbolData { id, description })))
        });
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
        for (name, id) in [
            ("iterator", SYM_ITERATOR),
            ("asyncIterator", SYM_ASYNC_ITERATOR),
            ("hasInstance", SYM_HAS_INSTANCE),
            ("toPrimitive", SYM_TO_PRIMITIVE),
            ("toStringTag", SYM_TO_STRING_TAG),
            ("species", SYM_SPECIES),
            ("unscopables", SYM_UNSCOPABLES),
            ("isConcatSpreadable", SYM_IS_CONCAT_SPREADABLE),
            ("match", SYM_MATCH),
            ("replace", SYM_REPLACE),
            ("search", SYM_SEARCH),
            ("split", SYM_SPLIT),
            ("matchAll", SYM_MATCH_ALL),
        ] {
            ctor.borrow_mut()
                .set_prop(name, well_known_symbol(id), false);
        }
        let for_fn: NativeFn = Rc::new(|interp, _t, args| {
            let key = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            if let Some(existing) = interp.symbol_registry.get(&key) {
                return Ok(existing.clone());
            }
            let id = interp.next_symbol_id;
            interp.next_symbol_id = interp.next_symbol_id.saturating_add(1);
            let sym = JsValue::Symbol(Rc::new(SymbolData {
                id,
                description: Some(key.clone()),
            }));
            interp.symbol_registry.insert(key, sym.clone());
            Ok(sym)
        });
        let f = self.native(for_fn);
        ctor.borrow_mut().set_prop("for", f, false);
        let key_for: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Symbol(s)) = args.first() else {
                return Err(Interp::throw("TypeError: Symbol.keyFor requires a symbol"));
            };
            for (k, v) in &interp.symbol_registry {
                if matches!(v, JsValue::Symbol(o) if o.id == s.id) {
                    return Ok(JsValue::str(k.clone()));
                }
            }
            Ok(JsValue::Undefined)
        });
        let f = self.native(key_for);
        ctor.borrow_mut().set_prop("keyFor", f, false);
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.symbol_proto.clone()),
            false,
        );
        self.set_global("Symbol", JsValue::Object(ctor));

        let to_string: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string())));
        let f = self.native(to_string);
        self.symbol_proto
            .borrow_mut()
            .set_prop("toString", f.clone(), false);
        let value_of: NativeFn = Rc::new(|_i, this, _a| Ok(this));
        let f = self.native(value_of);
        self.symbol_proto.borrow_mut().set_prop("valueOf", f, false);
    }

    /// The iteration protocol: `%IteratorPrototype%[Symbol.iterator]`, the
    /// generator prototype's `next`/`return`/`throw`, and `Symbol.iterator`
    /// on Array / String / Map / Set so spread and `for...of` see real
    /// iterators instead of the engine's internal fast path.
    fn install_iterator_protocol(&mut self) {
        let self_iter: NativeFn = Rc::new(|_i, this, _a| Ok(this));
        let f = self.native(self_iter);
        self.iterator_proto
            .borrow_mut()
            .set_prop(&iterator_key(), f, false);

        // `next(v)` sends `v` in as the value of the suspended `yield`.
        let next_with: NativeFn = Rc::new(|interp, this, args| {
            let JsValue::Object(o) = &this else {
                return Err(Interp::throw("TypeError: next on non-generator"));
            };
            let gen = o.clone();
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            interp.generator_resume(&gen, super::interp::GenResume::Next(v))
        });
        let f = self.native(next_with);
        self.generator_proto.borrow_mut().set_prop("next", f, false);
        // `return(v)` completes the body from its suspension point: every
        // `finally` between there and the function boundary runs first.
        let ret: NativeFn = Rc::new(|interp, this, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            let JsValue::Object(o) = &this else {
                return Err(Interp::throw("TypeError: return on non-generator"));
            };
            let gen = o.clone();
            interp.generator_resume(&gen, super::interp::GenResume::Return(v))
        });
        let f = self.native(ret);
        self.generator_proto
            .borrow_mut()
            .set_prop("return", f, false);
        // `throw(e)` throws `e` at the suspension point, where the body's
        // own `catch` may take it and keep yielding.
        let thr: NativeFn = Rc::new(|interp, this, args| {
            let e = args.first().cloned().unwrap_or(JsValue::Undefined);
            let JsValue::Object(o) = &this else {
                return Err(Interp::throw("TypeError: throw on non-generator"));
            };
            let gen = o.clone();
            interp.generator_resume(&gen, super::interp::GenResume::Throw(e))
        });
        let f = self.native(thr);
        self.generator_proto.borrow_mut().set_prop("throw", f, false);

        // String / Map / Set iterators (the Array one is builtins_array.rs's
        // `values`): build an index-walking generator-free iterator object
        // over a snapshot of the values.
        let make_values_iter: NativeFn = Rc::new(|interp, this, _a| {
            let items = interp.iterate(&this)?;
            Ok(interp.make_list_iterator(items))
        });
        let f = self.native(make_values_iter);
        self.string_proto
            .borrow_mut()
            .set_prop(&iterator_key(), f, false);

        let map_iter: NativeFn = Rc::new(|interp, this, _a| {
            let JsValue::Object(o) = &this else {
                return Err(Interp::throw("TypeError: not a Map"));
            };
            let items: Vec<(JsValue, JsValue)> = match &o.borrow().kind {
                ObjKind::Map(m) | ObjKind::Set(m) => m.items(),
                _ => return Err(Interp::throw("TypeError: not a Map")),
            };
            let is_set = matches!(o.borrow().kind, ObjKind::Set(_));
            let out: Vec<JsValue> = items
                .into_iter()
                .map(|(k, v)| {
                    if is_set {
                        k
                    } else {
                        interp.new_array(vec![k, v])
                    }
                })
                .collect();
            Ok(interp.make_list_iterator(out))
        });
        let f = self.native(map_iter.clone());
        self.map_proto
            .borrow_mut()
            .set_prop(&iterator_key(), f, false);
        let f = self.native(map_iter);
        self.set_proto
            .borrow_mut()
            .set_prop(&iterator_key(), f, false);
    }

    /// `Object.defineProperty` / `defineProperties` /
    /// `getOwnPropertyDescriptor(s)` / `getOwnPropertyNames` /
    /// `getOwnPropertySymbols` / `setPrototypeOf` / `freeze` / `isFrozen` /
    /// `seal` / `isSealed` / `preventExtensions` / `isExtensible` / `is` /
    /// `fromEntries`.
    fn install_object_descriptors(&mut self) {
        let Some(JsValue::Object(ctor)) = self.global_object.borrow().get_prop("Object") else {
            return;
        };

        let define_property: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(target)) = args.first() else {
                return Err(Interp::throw(
                    "TypeError: Object.defineProperty called on non-object",
                ));
            };
            let key = args
                .get(1)
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            let desc = interp.to_property_descriptor(args.get(2).unwrap_or(&JsValue::Undefined))?;
            if !interp.define_own_property(target, &key, &desc)? {
                return Err(Interp::throw(format!(
                    "TypeError: Cannot redefine property: {key}"
                )));
            }
            Ok(args.first().cloned().unwrap_or(JsValue::Undefined))
        });
        let f = self.native(define_property);
        ctor.borrow_mut().set_prop("defineProperty", f, false);

        let define_properties: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(target)) = args.first() else {
                return Err(Interp::throw(
                    "TypeError: Object.defineProperties called on non-object",
                ));
            };
            let Some(descs @ JsValue::Object(dobj)) = args.get(1) else {
                return Err(Interp::throw("TypeError: Object.defineProperties descriptors must be an object"));
            };
            // ObjectDefineProperties (ES §20.1.2.3.1): every enumerable own
            // key (string and symbol), its descriptor read through [[Get]]
            // and converted, all of them before the first is defined.
            let keys = interp.enumerable_own_keys(dobj, true)?;
            let mut descriptors = Vec::with_capacity(keys.len());
            for k in keys {
                let v = interp.get_property(descs, &k)?;
                descriptors.push((k, interp.to_property_descriptor(&v)?));
            }
            for (k, d) in descriptors {
                if !interp.define_own_property(target, &k, &d)? {
                    return Err(Interp::throw(format!(
                        "TypeError: Cannot redefine property: {k}"
                    )));
                }
            }
            Ok(args.first().cloned().unwrap_or(JsValue::Undefined))
        });
        let f = self.native(define_properties);
        ctor.borrow_mut().set_prop("defineProperties", f, false);

        let get_descriptor: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(o)) = args.first() else {
                return Ok(JsValue::Undefined);
            };
            let key = args
                .get(1)
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            let o = o.clone();
            Ok(match interp.own_property_descriptor(&o, &key)? {
                Some(d) => JsValue::Object(d),
                None => JsValue::Undefined,
            })
        });
        let f = self.native(get_descriptor);
        ctor.borrow_mut()
            .set_prop("getOwnPropertyDescriptor", f, false);

        let get_descriptors: NativeFn = Rc::new(|interp, _t, args| {
            let out = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            if let Some(JsValue::Object(o)) = args.first() {
                let o = o.clone();
                for k in interp.own_property_keys(&o)? {
                    if let Some(d) = interp.own_property_descriptor(&o, &k)? {
                        out.borrow_mut().set_prop(&k, JsValue::Object(d), true);
                    }
                }
            }
            Ok(JsValue::Object(out))
        });
        let f = self.native(get_descriptors);
        ctor.borrow_mut()
            .set_prop("getOwnPropertyDescriptors", f, false);

        let own_names: NativeFn = Rc::new(|interp, _t, args| {
            let out: Vec<JsValue> = match args.first() {
                Some(JsValue::Object(o)) => {
                    let o = o.clone();
                    interp
                        .own_property_keys(&o)?
                        .into_iter()
                        .filter(|k| !is_symbol_key(k))
                        .map(JsValue::str)
                        .collect()
                }
                Some(JsValue::Str(s)) => {
                    let mut v: Vec<JsValue> =
                        (0..s.chars().count()).map(|i| JsValue::str(i.to_string())).collect();
                    v.push(JsValue::str("length"));
                    v
                }
                _ => Vec::new(),
            };
            Ok(interp.new_array(out))
        });
        let f = self.native(own_names);
        ctor.borrow_mut().set_prop("getOwnPropertyNames", f, false);

        let own_symbols: NativeFn = Rc::new(|interp, _t, args| {
            let mut out: Vec<JsValue> = Vec::new();
            if let Some(JsValue::Object(o)) = args.first() {
                let o = o.clone();
                for k in interp.own_property_keys(&o)? {
                    if is_symbol_key(&k) {
                        out.push(interp.symbol_for_key(&k));
                    }
                }
            }
            Ok(interp.new_array(out))
        });
        let f = self.native(own_symbols);
        ctor.borrow_mut()
            .set_prop("getOwnPropertySymbols", f, false);

        // Object.setPrototypeOf (ES §20.1.2.23): a null or undefined
        // target and a prototype that is neither an object nor null are
        // TypeErrors, a primitive target is returned unchanged, and a
        // refused change (non-extensible, or a cycle) throws.
        let set_proto: NativeFn = Rc::new(|interp, _t, args| {
            let target = args.first().cloned().unwrap_or(JsValue::Undefined);
            if target.is_nullish() {
                return Err(Interp::throw(
                    "TypeError: Object.setPrototypeOf called on null or undefined",
                ));
            }
            let proto = prototype_argument(args.get(1))?;
            let JsValue::Object(o) = &target else {
                return Ok(target);
            };
            if !interp.set_prototype_of(o, proto)? {
                return Err(Interp::throw(
                    "TypeError: Object.setPrototypeOf: the prototype cannot be changed",
                ));
            }
            Ok(target)
        });
        let f = self.native(set_proto);
        ctor.borrow_mut().set_prop("setPrototypeOf", f, false);

        // freeze / seal / preventExtensions and their predicates (ES
        // §20.1.2.6, .20, .18, .15, .16, .14): a primitive argument is
        // returned unchanged, or answered as frozen, sealed and not
        // extensible; an object goes through SetIntegrityLevel,
        // [[PreventExtensions]], TestIntegrityLevel and [[IsExtensible]],
        // which consult a Proxy's traps, and a refusal is a TypeError.
        for (name, frozen) in [("freeze", true), ("seal", false)] {
            let f: NativeFn = Rc::new(move |interp, _t, args| {
                let v = args.first().cloned().unwrap_or(JsValue::Undefined);
                if let JsValue::Object(o) = &v {
                    if !interp.set_integrity_level(o, frozen)? {
                        return Err(Interp::throw(format!(
                            "TypeError: Cannot {name} the object: it could not be made non-extensible"
                        )));
                    }
                }
                Ok(v)
            });
            let f = self.native(f);
            ctor.borrow_mut().set_prop(name, f, false);
        }
        for (name, frozen) in [("isFrozen", true), ("isSealed", false)] {
            let f: NativeFn = Rc::new(move |interp, _t, args| {
                Ok(JsValue::Bool(match args.first() {
                    Some(JsValue::Object(o)) => interp.test_integrity_level(o, frozen)?,
                    _ => true,
                }))
            });
            let f = self.native(f);
            ctor.borrow_mut().set_prop(name, f, false);
        }
        let prevent: NativeFn = Rc::new(|interp, _t, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            if let JsValue::Object(o) = &v {
                if !interp.prevent_extensions(o)? {
                    return Err(Interp::throw(
                        "TypeError: Cannot prevent extensions: the object refused",
                    ));
                }
            }
            Ok(v)
        });
        let f = self.native(prevent);
        ctor.borrow_mut().set_prop("preventExtensions", f, false);
        let is_extensible: NativeFn = Rc::new(|interp, _t, args| {
            Ok(JsValue::Bool(match args.first() {
                Some(JsValue::Object(o)) => interp.is_extensible(o)?,
                _ => false,
            }))
        });
        let f = self.native(is_extensible);
        ctor.borrow_mut().set_prop("isExtensible", f, false);

        // Object.is: SameValue (NaN equals NaN, +0 differs from -0).
        let is_fn: NativeFn = Rc::new(|_i, _t, args| {
            let a = args.first().cloned().unwrap_or(JsValue::Undefined);
            let b = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            let same = match (&a, &b) {
                (JsValue::Num(x), JsValue::Num(y)) => {
                    if x.is_nan() && y.is_nan() {
                        true
                    } else {
                        x == y && x.is_sign_negative() == y.is_sign_negative()
                    }
                }
                _ => a.strict_eq(&b),
            };
            Ok(JsValue::Bool(same))
        });
        let f = self.native(is_fn);
        ctor.borrow_mut().set_prop("is", f, false);

        let from_entries: NativeFn = Rc::new(|interp, _t, args| {
            let src = args.first().cloned().unwrap_or(JsValue::Undefined);
            let items = interp.iterate(&src)?;
            let obj = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            for item in items {
                let k = interp.get_property(&item, "0")?;
                let v = interp.get_property(&item, "1")?;
                let key = interp.to_property_key(&k)?;
                obj.borrow_mut().set_prop(&key, v, true);
            }
            Ok(JsValue::Object(obj))
        });
        let f = self.native(from_entries);
        ctor.borrow_mut().set_prop("fromEntries", f, false);

        // Object(value) / new Object(): the constructor itself, so bundles
        // that call `Object(x)` for boxing get a real object back.
        let object_call: NativeFn = Rc::new(|interp, _t, args| match args.first() {
            Some(JsValue::Object(o)) => Ok(JsValue::Object(o.clone())),
            Some(v) if !v.is_nullish() => Ok(interp.to_object(v)),
            _ => {
                let o = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                Ok(JsValue::Object(o))
            }
        });
        ctor.borrow_mut().kind = ObjKind::Native(object_call);
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.object_proto.clone()),
            false,
        );
        self.object_proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor), false);
    }

    /// `Map` / `Set` / `WeakMap` / `WeakSet` with their prototypes.
    fn install_map_set(&mut self) {
        for (name, is_map) in [
            ("Map", true),
            ("WeakMap", true),
            ("Set", false),
            ("WeakSet", false),
        ] {
            let class: &'static str = name;
            // Weak collections get their own prototype (no iteration, no
            // size, no clear) chained to the strong one for the shared
            // get/has/set/delete methods.
            let proto = if name.starts_with("Weak") {
                let base = if is_map { self.map_proto.clone() } else { self.set_proto.clone() };
                let p = JsObject::new(ObjKind::Plain, Some(base));
                for hidden in ["size", "clear", "forEach", "keys", "values", "entries", &iterator_key()] {
                    p.borrow_mut().set_prop(hidden, JsValue::Undefined, false);
                }
                p
            } else if is_map {
                self.map_proto.clone()
            } else {
                self.set_proto.clone()
            };
            let proto_for_ctor = proto.clone();
            let ctor_fn: NativeFn = Rc::new(move |interp, this, args| {
                let obj = match &this {
                    JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                    _ => JsObject::new(ObjKind::Plain, Some(proto_for_ctor.clone())),
                };
                {
                    let mut b = obj.borrow_mut();
                    b.kind = if is_map {
                        ObjKind::Map(MapData::default())
                    } else {
                        ObjKind::Set(MapData::default())
                    };
                    b.class_name = class;
                    if b.proto.is_none() {
                        b.proto = Some(proto_for_ctor.clone());
                    }
                }
                // Seed from an iterable argument.
                if let Some(src) = args.first().filter(|v| !v.is_nullish()) {
                    let items = interp.iterate(src)?;
                    let weak = class.starts_with("Weak");
                    for item in items {
                        if is_map {
                            let k = interp.get_property(&item, "0")?;
                            let v = interp.get_property(&item, "1")?;
                            if weak && !matches!(k, JsValue::Object(_) | JsValue::Symbol(_)) {
                                return Err(Interp::throw("TypeError: Invalid value used as weak map key"));
                            }
                            if let ObjKind::Map(m) = &mut obj.borrow_mut().kind {
                                m.set(k, v);
                            }
                        } else {
                            if weak && !matches!(item, JsValue::Object(_) | JsValue::Symbol(_)) {
                                return Err(Interp::throw("TypeError: Invalid value used in weak set"));
                            }
                            if let ObjKind::Set(m) = &mut obj.borrow_mut().kind {
                                m.set(item, JsValue::Undefined);
                            }
                        }
                    }
                }
                Ok(JsValue::Object(obj))
            });
            let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
            ctor.borrow_mut()
                .set_prop("prototype", JsValue::Object(proto), false);
            self.set_global(name, JsValue::Object(ctor));
        }

        // Receiver checks: a Map method on a non-Map receiver is a TypeError
        // (`Map.prototype.get.call({})`), as is a Set method on a Map.
        fn with_data<T>(
            this: &JsValue,
            what: &str,
            f: impl FnOnce(&MapData) -> T,
        ) -> Result<T, JsValue> {
            let JsValue::Object(o) = this else {
                return Err(Interp::throw(format!("TypeError: {what} called on incompatible receiver")));
            };
            let b = o.borrow();
            match &b.kind {
                ObjKind::Map(m) | ObjKind::Set(m) => Ok(f(m)),
                _ => Err(Interp::throw(format!("TypeError: {what} called on incompatible receiver"))),
            }
        }
        fn with_data_mut<T>(
            this: &JsValue,
            what: &str,
            f: impl FnOnce(&mut MapData) -> T,
        ) -> Result<T, JsValue> {
            let JsValue::Object(o) = this else {
                return Err(Interp::throw(format!("TypeError: {what} called on incompatible receiver")));
            };
            let mut b = o.borrow_mut();
            match &mut b.kind {
                ObjKind::Map(m) | ObjKind::Set(m) => Ok(f(m)),
                _ => Err(Interp::throw(format!("TypeError: {what} called on incompatible receiver"))),
            }
        }
        /// WeakMap / WeakSet only accept object keys.
        fn check_weak_key(this: &JsValue, k: &JsValue) -> Result<(), JsValue> {
            let weak = matches!(this, JsValue::Object(o) if matches!(o.borrow().class_name, "WeakMap" | "WeakSet"));
            if weak && !matches!(k, JsValue::Object(_) | JsValue::Symbol(_)) {
                return Err(Interp::throw("TypeError: Invalid value used as weak map key"));
            }
            Ok(())
        }

        // Shared methods; `add` (Set) and `set` (Map) differ only in arity.
        let get: NativeFn = Rc::new(|_i, this, args| {
            let k = args.first().cloned().unwrap_or(JsValue::Undefined);
            Ok(with_data(&this, "Map.prototype.get", |m| m.get(&k))?.unwrap_or(JsValue::Undefined))
        });
        let has: NativeFn = Rc::new(|_i, this, args| {
            let k = args.first().cloned().unwrap_or(JsValue::Undefined);
            Ok(JsValue::Bool(with_data(&this, "has", |m| m.has(&k))?))
        });
        let set_fn: NativeFn = Rc::new(|_i, this, args| {
            let k = args.first().cloned().unwrap_or(JsValue::Undefined);
            let v = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            check_weak_key(&this, &k)?;
            with_data_mut(&this, "Map.prototype.set", |m| m.set(k, v))?;
            Ok(this)
        });
        let add: NativeFn = Rc::new(|_i, this, args| {
            let k = args.first().cloned().unwrap_or(JsValue::Undefined);
            check_weak_key(&this, &k)?;
            with_data_mut(&this, "Set.prototype.add", |m| m.set(k, JsValue::Undefined))?;
            Ok(this)
        });
        let delete: NativeFn = Rc::new(|_i, this, args| {
            let k = args.first().cloned().unwrap_or(JsValue::Undefined);
            Ok(JsValue::Bool(with_data_mut(&this, "delete", |m| m.delete(&k))?))
        });
        let clear: NativeFn = Rc::new(|_i, this, _a| {
            with_data_mut(&this, "clear", |m| m.clear())?;
            Ok(JsValue::Undefined)
        });
        let for_each: NativeFn = Rc::new(|interp, this, args| {
            let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
            let this_arg = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            let items = with_data(&this, "forEach", |m| m.items())?;
            let is_set = matches!(&this, JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::Set(_)));
            for (k, v) in items {
                let value = if is_set { k.clone() } else { v };
                interp.call(cb.clone(), this_arg.clone(), &[value, k, this.clone()])?;
            }
            Ok(JsValue::Undefined)
        });
        let size_getter: NativeFn = Rc::new(|_i, this, _a| {
            Ok(JsValue::Num(with_data(&this, "size", |m| m.live as f64)?))
        });
        let keys_fn: NativeFn = Rc::new(|interp, this, _a| {
            let items = with_data(&this, "keys", |m| m.items())?;
            let out: Vec<JsValue> = items.into_iter().map(|(k, _)| k).collect();
            Ok(interp.make_list_iterator(out))
        });
        let values_fn: NativeFn = Rc::new(|interp, this, _a| {
            let is_set = matches!(&this, JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::Set(_)));
            let items = with_data(&this, "values", |m| m.items())?;
            let out: Vec<JsValue> = items
                .into_iter()
                .map(|(k, v)| if is_set { k } else { v })
                .collect();
            Ok(interp.make_list_iterator(out))
        });
        let entries_fn: NativeFn = Rc::new(|interp, this, _a| {
            let is_set = matches!(&this, JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::Set(_)));
            let items = with_data(&this, "entries", |m| m.items())?;
            let out: Vec<JsValue> = items
                .into_iter()
                .map(|(k, v)| {
                    let v = if is_set { k.clone() } else { v };
                    interp.new_array(vec![k, v])
                })
                .collect();
            Ok(interp.make_list_iterator(out))
        });

        for proto in [self.map_proto.clone(), self.set_proto.clone()] {
            let is_map = Rc::ptr_eq(&proto, &self.map_proto);
            for (name, f) in [
                ("get", get.clone()),
                ("has", has.clone()),
                ("delete", delete.clone()),
                ("clear", clear.clone()),
                ("forEach", for_each.clone()),
                ("keys", keys_fn.clone()),
                ("values", values_fn.clone()),
                ("entries", entries_fn.clone()),
            ] {
                let fv = self.native(f);
                proto.borrow_mut().set_prop(name, fv, false);
            }
            let fv = self.native(if is_map { set_fn.clone() } else { add.clone() });
            proto
                .borrow_mut()
                .set_prop(if is_map { "set" } else { "add" }, fv, false);
            let getter = self.native(size_getter.clone());
            if let JsValue::Object(g) = getter {
                proto.borrow_mut().set_accessor("size", Some(g), None, false);
            }
        }
    }

    /// `Proxy` and `Reflect` — Vue 3's reactivity core.
    fn install_proxy_reflect(&mut self) {
        let proxy_ctor: NativeFn = Rc::new(|_i, _t, args| {
            let (Some(JsValue::Object(target)), Some(JsValue::Object(handler))) =
                (args.first(), args.get(1))
            else {
                return Err(Interp::throw(
                    "TypeError: Cannot create proxy with a non-object as target or handler",
                ));
            };
            let proto = target.borrow().proto.clone();
            let obj = JsObject::new(
                ObjKind::Proxy {
                    target: target.clone(),
                    handler: handler.clone(),
                },
                proto,
            );
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(
            ObjKind::Native(proxy_ctor),
            Some(self.function_proto.clone()),
        );
        self.set_global("Proxy", JsValue::Object(ctor));

        let reflect = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        // Reflect.get (ES §28.1.6): a non-object target is a TypeError; a
        // getter runs with the receiver (the target by default) as `this`.
        let get: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(target)) = args.first() else {
                return Err(Interp::throw("TypeError: Reflect.get called on non-object"));
            };
            let key = args
                .get(1)
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            match args.get(2) {
                Some(receiver) => interp.get_with_receiver(target, &key, receiver),
                None => interp.get_property(&JsValue::Object(target.clone()), &key),
            }
        });
        let f = self.native(get);
        reflect.borrow_mut().set_prop("get", f, false);
        // Reflect.set (ES §28.1.12): a non-object target is a TypeError;
        // the result is whether [[Set]] took the write, with the receiver
        // (the target by default) as a setter's `this` and as the object a
        // data write lands on.
        let set: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(target)) = args.first() else {
                return Err(Interp::throw("TypeError: Reflect.set called on non-object"));
            };
            let key = args
                .get(1)
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            let v = args.get(2).cloned().unwrap_or(JsValue::Undefined);
            let done = match args.get(3) {
                Some(receiver) => interp.set_with_receiver(target, &key, v, receiver)?,
                None => interp.try_set_property(&JsValue::Object(target.clone()), &key, v)?,
            };
            Ok(JsValue::Bool(done))
        });
        let f = self.native(set);
        reflect.borrow_mut().set_prop("set", f, false);
        let has: NativeFn = Rc::new(|interp, _t, args| {
            let target = args.first().cloned().unwrap_or(JsValue::Undefined);
            let key = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            interp.binary_op(super::ast::BinaryOp::In, key, target)
        });
        let f = self.native(has);
        reflect.borrow_mut().set_prop("has", f, false);
        let own_keys: NativeFn = Rc::new(|interp, _t, args| {
            let mut out: Vec<JsValue> = Vec::new();
            if let Some(JsValue::Object(o)) = args.first() {
                let o = o.clone();
                for k in interp.own_property_keys(&o)? {
                    out.push(interp.key_value(&k));
                }
            }
            Ok(interp.new_array(out))
        });
        let f = self.native(own_keys);
        reflect.borrow_mut().set_prop("ownKeys", f, false);
        let reflect_gopd: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(o)) = args.first() else {
                return Err(Interp::throw(
                    "TypeError: Reflect.getOwnPropertyDescriptor called on non-object",
                ));
            };
            let key = args
                .get(1)
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            let o = o.clone();
            Ok(match interp.own_property_descriptor(&o, &key)? {
                Some(d) => JsValue::Object(d),
                None => JsValue::Undefined,
            })
        });
        let f = self.native(reflect_gopd);
        reflect
            .borrow_mut()
            .set_prop("getOwnPropertyDescriptor", f, false);
        // Reflect.isExtensible / preventExtensions (ES §28.1.10, .11): a
        // non-object target is a TypeError; the result is the operation's.
        let reflect_is_ext: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(o)) = args.first() else {
                return Err(Interp::throw("TypeError: Reflect.isExtensible called on non-object"));
            };
            Ok(JsValue::Bool(interp.is_extensible(o)?))
        });
        let f = self.native(reflect_is_ext);
        reflect.borrow_mut().set_prop("isExtensible", f, false);
        let reflect_prevent: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(o)) = args.first() else {
                return Err(Interp::throw("TypeError: Reflect.preventExtensions called on non-object"));
            };
            Ok(JsValue::Bool(interp.prevent_extensions(o)?))
        });
        let f = self.native(reflect_prevent);
        reflect.borrow_mut().set_prop("preventExtensions", f, false);
        let delete_property: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(o)) = args.first() else {
                return Err(Interp::throw(
                    "TypeError: Reflect.deleteProperty called on non-object",
                ));
            };
            let key = args
                .get(1)
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            let o = o.clone();
            Ok(JsValue::Bool(interp.delete_property(&o, &key)?))
        });
        let f = self.native(delete_property);
        reflect.borrow_mut().set_prop("deleteProperty", f, false);
        let apply: NativeFn = Rc::new(|interp, _t, args| {
            let f = args.first().cloned().unwrap_or(JsValue::Undefined);
            let this_arg = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            let list = match args.get(2) {
                Some(v) => interp.iterate(v)?,
                None => Vec::new(),
            };
            interp.call(f, this_arg, &list)
        });
        let f = self.native(apply);
        reflect.borrow_mut().set_prop("apply", f, false);
        let construct: NativeFn = Rc::new(|interp, _t, args| {
            let f = args.first().cloned().unwrap_or(JsValue::Undefined);
            let list = match args.get(1) {
                Some(v) => interp.iterate(v)?,
                None => Vec::new(),
            };
            let nt = args.get(2).cloned().unwrap_or_else(|| f.clone());
            interp.construct_with_target(f, &list, nt)
        });
        let f = self.native(construct);
        reflect.borrow_mut().set_prop("construct", f, false);
        // Reflect.getPrototypeOf (ES §28.1.8): a non-object target is a
        // TypeError; otherwise [[GetPrototypeOf]] (a Proxy's trap).
        let get_proto: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(o)) = args.first() else {
                return Err(Interp::throw("TypeError: Reflect.getPrototypeOf called on non-object"));
            };
            let o = o.clone();
            Ok(interp.get_prototype_of(&o)?.map(JsValue::Object).unwrap_or(JsValue::Null))
        });
        let f = self.native(get_proto);
        reflect.borrow_mut().set_prop("getPrototypeOf", f, false);
        // Reflect.setPrototypeOf (ES §28.1.13): a target that is not an
        // object and a prototype that is neither an object nor null are
        // TypeErrors; a refused change is reported as `false`.
        let set_proto: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(o)) = args.first() else {
                return Err(Interp::throw(
                    "TypeError: Reflect.setPrototypeOf called on non-object",
                ));
            };
            let proto = prototype_argument(args.get(1))?;
            Ok(JsValue::Bool(interp.set_prototype_of(o, proto)?))
        });
        let f = self.native(set_proto);
        reflect.borrow_mut().set_prop("setPrototypeOf", f, false);
        let define_prop: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Object(target)) = args.first() else {
                return Err(Interp::throw(
                    "TypeError: Reflect.defineProperty called on non-object",
                ));
            };
            let key = args
                .get(1)
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            let desc = interp.to_property_descriptor(args.get(2).unwrap_or(&JsValue::Undefined))?;
            Ok(JsValue::Bool(interp.define_own_property(target, &key, &desc)?))
        });
        let f = self.native(define_prop);
        reflect.borrow_mut().set_prop("defineProperty", f, false);
        self.set_global("Reflect", JsValue::Object(reflect));
    }

    /// `Object.prototype` extras: `toString` with `Symbol.toStringTag`,
    /// `valueOf`, `propertyIsEnumerable`, `isPrototypeOf`, `toLocaleString`.
    fn install_object_proto_extras(&mut self) {
        let to_string: NativeFn = Rc::new(|interp, this, _a| {
            let tag = match &this {
                JsValue::Undefined => "Undefined".to_string(),
                JsValue::Null => "Null".to_string(),
                JsValue::Bool(_) => "Boolean".to_string(),
                JsValue::Num(_) => "Number".to_string(),
                JsValue::Str(_) => "String".to_string(),
                JsValue::Symbol(_) => "Symbol".to_string(),
                JsValue::Object(o) => {
                    let custom = interp
                        .get_property(&this, &symbol_key(SYM_TO_STRING_TAG))
                        .ok()
                        .filter(|v| matches!(v, JsValue::Str(_)))
                        .map(|v| v.to_js_string());
                    custom.unwrap_or_else(|| o.borrow().class_name.to_string())
                }
            };
            Ok(JsValue::str(format!("[object {tag}]")))
        });
        let f = self.native(to_string);
        self.object_proto
            .borrow_mut()
            .set_prop("toString", f.clone(), false);
        self.object_proto
            .borrow_mut()
            .set_prop("toLocaleString", f, false);

        let value_of: NativeFn = Rc::new(|_i, this, _a| Ok(this));
        let f = self.native(value_of);
        self.object_proto.borrow_mut().set_prop("valueOf", f, false);

        // Object.prototype.propertyIsEnumerable (ES 20.1.3.4):
        // ToPropertyKey, ToObject, then [[GetOwnProperty]], which a Proxy
        // answers through its `getOwnPropertyDescriptor` trap.
        let prop_is_enumerable: NativeFn = Rc::new(|interp, this, args| {
            let key = interp.to_property_key(args.first().unwrap_or(&JsValue::Undefined))?;
            if this.is_nullish() {
                return Err(Interp::throw("TypeError: Cannot convert undefined or null to object"));
            }
            let JsValue::Object(o) = interp.to_object(&this) else {
                return Ok(JsValue::Bool(false));
            };
            if Interp::proxy_parts(&o).is_some() {
                let d = interp.own_prop_desc(&o, &key)?;
                return Ok(JsValue::Bool(d.is_some_and(|d| d.enumerable == Some(true))));
            }
            let enumerable = own_enumerable(&o.borrow(), &key);
            Ok(JsValue::Bool(enumerable))
        });
        let f = self.native(prop_is_enumerable);
        self.object_proto
            .borrow_mut()
            .set_prop("propertyIsEnumerable", f, false);

        // Object.prototype.isPrototypeOf (ES §20.1.3.3): walks V's chain
        // through [[GetPrototypeOf]], so a Proxy on it answers with its
        // trap.
        let is_proto_of: NativeFn = Rc::new(|interp, this, args| {
            let (JsValue::Object(me), Some(JsValue::Object(other))) = (&this, args.first()) else {
                return Ok(JsValue::Bool(false));
            };
            let mut cur = interp.get_prototype_of(other)?;
            while let Some(p) = cur {
                if Rc::ptr_eq(&p, me) {
                    return Ok(JsValue::Bool(true));
                }
                interp.charge_pub()?;
                cur = interp.get_prototype_of(&p)?;
            }
            Ok(JsValue::Bool(false))
        });
        let f = self.native(is_proto_of);
        self.object_proto
            .borrow_mut()
            .set_prop("isPrototypeOf", f, false);

        // Object.prototype.__proto__ (ES B.2.2.1): an accessor over
        // [[GetPrototypeOf]] / [[SetPrototypeOf]]. The getter converts its
        // receiver with ToObject; the setter ignores a value that is not
        // an object or null and a primitive receiver, and refuses a cycle
        // or a non-extensible object with a TypeError.
        let get_proto: NativeFn = Rc::new(|interp, this, _a| {
            if this.is_nullish() {
                return Err(Interp::throw("TypeError: Cannot convert undefined or null to object"));
            }
            let JsValue::Object(o) = interp.to_object(&this) else {
                return Ok(JsValue::Null);
            };
            Ok(interp.get_prototype_of(&o)?.map(JsValue::Object).unwrap_or(JsValue::Null))
        });
        let set_proto: NativeFn = Rc::new(|interp, this, args| {
            if this.is_nullish() {
                return Err(Interp::throw("TypeError: Object.prototype.__proto__ called on null or undefined"));
            }
            let proto = match args.first() {
                Some(JsValue::Object(p)) => Some(p.clone()),
                Some(JsValue::Null) => None,
                _ => return Ok(JsValue::Undefined),
            };
            let JsValue::Object(o) = &this else {
                return Ok(JsValue::Undefined);
            };
            if !interp.set_prototype_of(o, proto)? {
                return Err(Interp::throw("TypeError: Object.prototype.__proto__ setter could not set the prototype"));
            }
            Ok(JsValue::Undefined)
        });
        let (JsValue::Object(g), JsValue::Object(s)) = (self.native(get_proto), self.native(set_proto)) else {
            return;
        };
        self.object_proto
            .borrow_mut()
            .set_accessor("__proto__", Some(g), Some(s), false);
    }

    /// The remaining error constructors plus `stack` / `cause` and the
    /// per-type prototypes `instanceof` needs.
    fn install_error_hierarchy(&mut self) {
        for name in [
            "EvalError",
            "ReferenceError",
            "URIError",
            "AggregateError",
        ] {
            let base_proto = self.error_proto.clone();
            let proto = JsObject::new(ObjKind::Plain, Some(base_proto));
            proto.borrow_mut().set_prop("name", JsValue::str(name), false);
            let proto_for_ctor = proto.clone();
            let n = name.to_string();
            let ctor: NativeFn = Rc::new(move |_i, this, args| {
                let msg = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                let obj = match &this {
                    JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                    _ => JsObject::new(ObjKind::Error, Some(proto_for_ctor.clone())),
                };
                {
                    let mut b = obj.borrow_mut();
                    b.kind = ObjKind::Error;
                    if b.proto.is_none() {
                        b.proto = Some(proto_for_ctor.clone());
                    }
                    b.set_prop("name", JsValue::str(n.clone()), false);
                    b.set_prop("message", JsValue::str(msg), false);
                    b.set_prop("stack", JsValue::str(format!("{n}: at <anonymous>")), false);
                }
                Ok(JsValue::Object(obj))
            });
            let ctor_obj = JsObject::new(ObjKind::Native(ctor), Some(self.function_proto.clone()));
            ctor_obj
                .borrow_mut()
                .set_prop("prototype", JsValue::Object(proto), false);
            self.set_global(name, JsValue::Object(ctor_obj));
        }
        // `stack` on the base error prototype so `e.stack` is never undefined.
        self.error_proto
            .borrow_mut()
            .set_prop("stack", JsValue::str("Error: at <anonymous>"), false);
    }

    /// `String` methods and statics bundles use.
    fn install_string_es(&mut self) {
        let methods: Vec<(&str, NativeFn)> = vec![
            (
                "trimStart",
                Rc::new(|_i, this, _a| {
                    Ok(JsValue::str(this.to_js_string().trim_start().to_string()))
                }),
            ),
            (
                "trimEnd",
                Rc::new(|_i, this, _a| {
                    Ok(JsValue::str(this.to_js_string().trim_end().to_string()))
                }),
            ),
            (
                "codePointAt",
                Rc::new(|interp, this, args| {
                    let s = this.to_js_string();
                    let i = interp.number_arg(args.first(), 0.0)?.max(0.0) as usize;
                    Ok(match s.chars().nth(i) {
                        Some(c) => JsValue::Num(c as u32 as f64),
                        None => JsValue::Undefined,
                    })
                }),
            ),
            (
                "lastIndexOf",
                Rc::new(|_i, this, args| {
                    let s = this.to_js_string();
                    let needle = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                    Ok(JsValue::Num(match s.rfind(&needle) {
                        Some(b) => s.get(..b).map(|p| p.chars().count() as f64).unwrap_or(-1.0),
                        None => -1.0,
                    }))
                }),
            ),
            (
                "substr",
                Rc::new(|interp, this, args| {
                    let s: Vec<char> = this.to_js_string().chars().collect();
                    let len = s.len() as i64;
                    let start = match interp.opt_number_arg(args.first())? {
                        Some(n) if !n.is_nan() => {
                            if n < 0.0 {
                                (len + n as i64).max(0)
                            } else {
                                (n as i64).min(len)
                            }
                        }
                        _ => 0,
                    };
                    let count = match interp.opt_number_arg(args.get(1))? {
                        Some(n) if !n.is_nan() => n.max(0.0) as usize,
                        _ => (len - start).max(0) as usize,
                    };
                    let out: String = s.into_iter().skip(start.max(0) as usize).take(count).collect();
                    Ok(JsValue::str(out))
                }),
            ),
            (
                "localeCompare",
                Rc::new(|_i, this, args| {
                    let a = this.to_js_string();
                    let b = args.first().map(|v| v.to_js_string()).unwrap_or_default();
                    Ok(JsValue::Num(match a.cmp(&b) {
                        core::cmp::Ordering::Less => -1.0,
                        core::cmp::Ordering::Equal => 0.0,
                        core::cmp::Ordering::Greater => 1.0,
                    }))
                }),
            ),
            (
                "normalize",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string()))),
            ),
            (
                "toLocaleUpperCase",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string().to_uppercase()))),
            ),
            (
                "toLocaleLowerCase",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string().to_lowercase()))),
            ),
            (
                "valueOf",
                Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string()))),
            ),
            (
                "search",
                Rc::new(|_i, this, args| {
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
                        Some(v) => (v.to_js_string(), String::new()),
                        None => return Ok(JsValue::Num(-1.0)),
                    };
                    Ok(JsValue::Num(
                        super::regex::compile(&source, &flags)
                            .and_then(|r| r.find(&input))
                            .map(|(s, _)| s as f64)
                            .unwrap_or(-1.0),
                    ))
                }),
            ),
        ];
        for (name, f) in methods {
            let fv = self.native(f);
            self.string_proto.borrow_mut().set_prop(name, fv, false);
        }

        // The String constructor: `String(x)`, `new String(x)`, plus
        // `fromCharCode` / `fromCodePoint` / `raw`.
        let string_proto = self.string_proto.clone();
        let ctor_fn: NativeFn = Rc::new(move |interp, this, args| {
            let s = match args.first() {
                Some(JsValue::Symbol(sym)) => {
                    // Explicit String(symbol) is allowed (unlike implicit
                    // ToString), and renders the description form.
                    format!("Symbol({})", sym.description.clone().unwrap_or_default())
                }
                Some(v) => interp.to_string_value(v)?,
                None => String::new(),
            };
            // `new String(x)` gets a wrapper object; a bare call returns the
            // primitive.
            match &this {
                JsValue::Object(o) if !o.borrow().is_callable() && o.borrow().proto.is_some() => {
                    let is_fresh = o.borrow().props.is_empty()
                        && matches!(o.borrow().kind, ObjKind::Plain);
                    if is_fresh {
                        let mut b = o.borrow_mut();
                        b.kind = ObjKind::Primitive(Box::new(JsValue::str(s.clone())));
                        b.class_name = "String";
                        b.proto = Some(string_proto.clone());
                        drop(b);
                        return Ok(JsValue::Object(o.clone()));
                    }
                    Ok(JsValue::str(s))
                }
                _ => Ok(JsValue::str(s)),
            }
        });
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.string_proto.clone()),
            false,
        );
        let from_char_code: NativeFn = Rc::new(|interp, _t, args| {
            let mut out = String::new();
            for a in args {
                let n = interp.to_number_value(a)?;
                if n.is_finite() && n >= 0.0 {
                    if let Some(c) = char::from_u32(n as u32) {
                        out.push(c);
                    }
                }
            }
            Ok(JsValue::str(out))
        });
        let f = self.native(from_char_code.clone());
        ctor.borrow_mut().set_prop("fromCharCode", f, false);
        let f = self.native(from_char_code);
        ctor.borrow_mut().set_prop("fromCodePoint", f, false);
        let raw: NativeFn = Rc::new(|interp, _t, args| {
            let strings = args.first().cloned().unwrap_or(JsValue::Undefined);
            let parts = interp.iterate(&strings).unwrap_or_default();
            let mut out = String::new();
            for (i, p) in parts.iter().enumerate() {
                out.push_str(&p.to_js_string());
                if let Some(sub) = args.get(i.saturating_add(1)) {
                    out.push_str(&sub.to_js_string());
                }
            }
            Ok(JsValue::str(out))
        });
        let f = self.native(raw);
        ctor.borrow_mut().set_prop("raw", f, false);
        self.set_global("String", JsValue::Object(ctor));
        self.string_proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor_ref(self)), false);
    }

    /// `Number` statics and prototype methods beyond the ES5 set, and the
    /// `Boolean` constructor.
    fn install_number_es(&mut self) {
        if let Some(JsValue::Object(number)) = self.global_object.borrow().get_prop("Number") {
            for (name, v) in [
                ("MIN_SAFE_INTEGER", -9007199254740991.0),
                ("EPSILON", f64::EPSILON),
                ("MAX_VALUE", f64::MAX),
                ("MIN_VALUE", f64::MIN_POSITIVE),
                ("POSITIVE_INFINITY", f64::INFINITY),
                ("NEGATIVE_INFINITY", f64::NEG_INFINITY),
            ] {
                number.borrow_mut().set_prop(name, JsValue::Num(v), false);
            }
            let is_safe: NativeFn = Rc::new(|_i, _t, args| {
                Ok(JsValue::Bool(matches!(
                    args.first(),
                    Some(JsValue::Num(n)) if n.is_finite() && n.fract() == 0.0
                        && n.abs() <= 9007199254740991.0
                )))
            });
            let f = JsValue::Object(JsObject::new(
                ObjKind::Native(is_safe),
                Some(self.function_proto.clone()),
            ));
            number.borrow_mut().set_prop("isSafeInteger", f, false);
            number.borrow_mut().set_prop(
                "prototype",
                JsValue::Object(self.number_proto.clone()),
                false,
            );
            // Number(x) coerces (the ES5 install left it a plain object).
            let call: NativeFn = Rc::new(|interp, _t, args| {
                Ok(JsValue::Num(match args.first() {
                    Some(v) => interp.to_number_value(v)?,
                    None => 0.0,
                }))
            });
            number.borrow_mut().kind = ObjKind::Native(call);
        }
        let extras: Vec<(&str, NativeFn)> = vec![
            (
                "valueOf",
                Rc::new(|_i, this, _a| Ok(JsValue::Num(this.to_number()))),
            ),
            (
                "toPrecision",
                Rc::new(|interp, this, args| {
                    let n = this.to_number();
                    let precision = match args.first() {
                        Some(v) if !matches!(v, JsValue::Undefined) => Some(interp.to_number_value(v)?),
                        _ => None,
                    };
                    match precision {
                        Some(p) if p.is_finite() && (1.0..=21.0).contains(&p) && n.is_finite() => {
                            let digits = (p as usize).saturating_sub(1);
                            // Fixed notation when the exponent fits, else
                            // exponential (the spec's e < -6 || e >= p rule).
                            let e = if n == 0.0 { 0 } else { n.abs().log10().floor() as i64 };
                            if e < -6 || e >= p as i64 {
                                let s = format!("{n:.digits$e}");
                                // Rust prints `1.5e2`; JS prints `1.5e+2`.
                                let s = match s.split_once('e') {
                                    Some((m, ex)) if !ex.starts_with('-') => format!("{m}e+{ex}"),
                                    _ => s,
                                };
                                Ok(JsValue::str(s))
                            } else {
                                let frac = (p as i64 - 1 - e).max(0) as usize;
                                Ok(JsValue::str(format!("{n:.frac$}")))
                            }
                        }
                        _ => Ok(JsValue::str(format_number(n))),
                    }
                }),
            ),
            (
                "toLocaleString",
                Rc::new(|_i, this, _a| {
                    // Group the integer part with commas (en-US default).
                    let n = this.to_number();
                    if !n.is_finite() {
                        return Ok(JsValue::str(format_number(n)));
                    }
                    let neg = n < 0.0;
                    let s = format_number(n.abs());
                    let (int_part, frac) = match s.split_once('.') {
                        Some((a, b)) => (a.to_string(), Some(b.to_string())),
                        None => (s, None),
                    };
                    let mut grouped = String::new();
                    let digits: Vec<char> = int_part.chars().collect();
                    for (i, c) in digits.iter().enumerate() {
                        if i > 0 && (digits.len() - i).is_multiple_of(3) {
                            grouped.push(',');
                        }
                        grouped.push(*c);
                    }
                    let mut out = String::new();
                    if neg {
                        out.push('-');
                    }
                    out.push_str(&grouped);
                    if let Some(f) = frac {
                        out.push('.');
                        out.push_str(&f);
                    }
                    Ok(JsValue::str(out))
                }),
            ),
        ];
        for (name, f) in extras {
            let fv = self.native(f);
            self.number_proto.borrow_mut().set_prop(name, fv, false);
        }
        // Boolean constructor.
        let bool_ctor: NativeFn = Rc::new(|_i, _t, args| {
            Ok(JsValue::Bool(
                args.first().map(|v| v.truthy()).unwrap_or(false),
            ))
        });
        let ctor = JsObject::new(ObjKind::Native(bool_ctor), Some(self.function_proto.clone()));
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.boolean_proto.clone()),
            false,
        );
        self.set_global("Boolean", JsValue::Object(ctor));
        let to_string: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string())));
        let f = self.native(to_string);
        self.boolean_proto
            .borrow_mut()
            .set_prop("toString", f, false);
        let value_of: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::Bool(this.truthy())));
        let f = self.native(value_of);
        self.boolean_proto.borrow_mut().set_prop("valueOf", f, false);
    }

    /// `Function.prototype.toString` / `name` / `length`, and the
    /// `Function` constructor (bundles feature-detect with `new Function`).
    fn install_function_es(&mut self) {
        let to_string: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::str(this.to_js_string())));
        let f = self.native(to_string);
        self.function_proto
            .borrow_mut()
            .set_prop("toString", f, false);

        // Function.prototype[Symbol.hasInstance] (ES §20.2.3.6):
        // OrdinaryHasInstance(this, V); non-writable, non-enumerable and
        // non-configurable, so no function can lose it by assignment.
        let has_instance: NativeFn = Rc::new(|interp, this, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            Ok(JsValue::Bool(interp.ordinary_has_instance(&this, &v)?))
        });
        let f = self.native(has_instance);
        if let JsValue::Object(fo) = &f {
            fo.borrow_mut().set_prop("name", JsValue::str("[Symbol.hasInstance]"), false);
        }
        let key = symbol_key(SYM_HAS_INSTANCE);
        {
            let mut fp = self.function_proto.borrow_mut();
            fp.set_prop(&key, f, false);
            fp.non_writable.insert(key.clone());
            fp.non_configurable.insert(key);
        }

        let ctor_fn: NativeFn = Rc::new(|interp, _t, args| {
            // new Function(arg1, ..., body): compile and evaluate in the
            // global scope, under the same fuel as any other script.
            let mut params: Vec<String> = Vec::new();
            let n = args.len();
            for a in args.get(..n.saturating_sub(1)).unwrap_or_default() {
                params.push(a.to_js_string());
            }
            let body = args.last().map(|v| v.to_js_string()).unwrap_or_default();
            let src = format!("(function anonymous({}) {{\n{}\n}})", params.join(","), body);
            let prog = super::parser::parse(&src)
                .map_err(|e| Interp::throw(format!("SyntaxError: {}", e.message)))?;
            interp.run_program(&prog)
        });
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
        ctor.borrow_mut().set_prop(
            "prototype",
            JsValue::Object(self.function_proto.clone()),
            false,
        );
        self.set_global("Function", JsValue::Object(ctor));

        // Global `eval`: same compile-and-run path, global scope.
        let eval_fn: NativeFn = Rc::new(|interp, _t, args| {
            let Some(JsValue::Str(src)) = args.first() else {
                return Ok(args.first().cloned().unwrap_or(JsValue::Undefined));
            };
            let prog = super::parser::parse(src)
                .map_err(|e| Interp::throw(format!("SyntaxError: {}", e.message)))?;
            interp.run_program(&prog)
        });
        let f = self.native(eval_fn);
        self.set_global("eval", f);
    }
}

impl<'h> Interp<'h> {
    /// [[HasProperty]] (the `in` operator; OrdinaryHasProperty, ES
    /// §10.1.7.1, and §10.5.7 for a Proxy): an own property, exotic ones
    /// included (array and typed-array elements, a String wrapper's
    /// characters, a DOM list's items), or the same question put to the
    /// prototype. A Proxy anywhere on the chain answers with its `has`
    /// trap, or by asking its target.
    pub fn has_property(&mut self, o: &ObjRef, key: &str) -> Result<bool, JsValue> {
        let mut cur = Some(o.clone());
        while let Some(c) = cur {
            if let Some((target, handler)) = Self::proxy_parts(&c) {
                if let Some(trap) = self.proxy_trap(&handler, "has")? {
                    let kv = self.key_value(key);
                    let out = self
                        .call(trap, JsValue::Object(handler), &[JsValue::Object(target.clone()), kv])?
                        .truthy();
                    // Invariants (ES 10.5.7 steps 9-10): a trap may not
                    // hide a non-configurable own property of the target,
                    // nor any own property of a non-extensible target.
                    if !out {
                        if let Some(d) = self.own_prop_desc(&target, key)? {
                            if d.configurable == Some(false) {
                                return Err(Self::throw(format!(
                                    "TypeError: 'has' on proxy: trap returned falsish for property '{key}' which exists in the proxy target as non-configurable"
                                )));
                            }
                            if !self.is_extensible(&target)? {
                                return Err(Self::throw(format!(
                                    "TypeError: 'has' on proxy: trap returned falsish for property '{key}' but the proxy target is not extensible"
                                )));
                            }
                        }
                    }
                    return Ok(out);
                }
                self.charge_pub()?;
                cur = Some(target);
                continue;
            }
            let b = c.borrow();
            let own = b.has_own_key(key)
                || match (&b.kind, key.parse::<usize>()) {
                    (ObjKind::DomList(h), Ok(i)) => i < h.len(),
                    _ => false,
                };
            if own {
                return Ok(true);
            }
            // A typed array answers a numeric key itself (ES §10.4.5.2).
            if b.typed_len().is_some() && super::value::typed_index_key(key).is_some() {
                return Ok(false);
            }
            cur = b.proto.clone();
        }
        Ok(false)
    }

    /// ToPropertyDescriptor (ES §6.2.6.5): read the six descriptor fields
    /// through [[HasProperty]] and [[Get]], so an inherited field or one
    /// behind a getter counts, with the flags as booleans; refuse a getter
    /// or setter that is neither callable nor undefined and a descriptor
    /// that mixes accessor and data fields.
    pub(super) fn read_property_descriptor(&mut self, desc: &JsValue) -> Result<PropDesc, JsValue> {
        let JsValue::Object(src) = desc else {
            return Err(Self::throw("TypeError: Property description must be an object"));
        };
        let mut out = PropDesc::default();
        for name in ["enumerable", "configurable", "value", "writable", "get", "set"] {
            if !self.has_property(src, name)? {
                continue;
            }
            let v = self.get_property(desc, name)?;
            match name {
                "enumerable" => out.enumerable = Some(v.truthy()),
                "configurable" => out.configurable = Some(v.truthy()),
                "writable" => out.writable = Some(v.truthy()),
                "value" => out.value = Some(v),
                _ => {
                    let callable = matches!(&v, JsValue::Object(f) if f.borrow().is_callable());
                    if !callable && !matches!(v, JsValue::Undefined) {
                        return Err(Self::throw(format!(
                            "TypeError: Property descriptor's '{name}' must be a function or undefined"
                        )));
                    }
                    if name == "get" {
                        out.get = Some(v);
                    } else {
                        out.set = Some(v);
                    }
                }
            }
        }
        if out.is_accessor() && out.is_data() {
            return Err(Self::throw(
                "TypeError: Invalid property descriptor. Cannot both specify accessors and a value or writable attribute",
            ));
        }
        Ok(out)
    }

    /// ToPropertyDescriptor and then FromPropertyDescriptor (ES §6.2.6.4):
    /// a fresh plain object holding only the fields present. Every
    /// definition goes through this copy, so a Proxy's `defineProperty`
    /// trap never sees the caller's object.
    pub fn to_property_descriptor(&mut self, desc: &JsValue) -> Result<ObjRef, JsValue> {
        let d = self.read_property_descriptor(desc)?;
        Ok(d.to_object(self))
    }

    /// [[GetOwnProperty]] as a descriptor record: through a Proxy's trap
    /// (and its invariant checks), straight from an ordinary object's slots.
    pub(super) fn own_prop_desc(&mut self, o: &ObjRef, key: &str) -> Result<Option<PropDesc>, JsValue> {
        if Self::proxy_parts(o).is_none() {
            return Ok(ordinary_own_desc(&o.borrow(), key));
        }
        Ok(self.own_property_descriptor(o, key)?.map(|d| PropDesc::read(&d.borrow())))
    }

    /// [[IsExtensible]] (ES §10.1.3, §10.5.3 for a Proxy): a Proxy's
    /// `isExtensible` trap must agree with its target.
    pub fn is_extensible(&mut self, o: &ObjRef) -> Result<bool, JsValue> {
        let Some((target, handler)) = Self::proxy_parts(o) else {
            return Ok(!o.borrow().non_extensible);
        };
        let Some(trap) = self.proxy_trap(&handler, "isExtensible")? else {
            return self.is_extensible(&target);
        };
        let reported = self
            .call(trap, JsValue::Object(handler), &[JsValue::Object(target.clone())])?
            .truthy();
        let actual = self.is_extensible(&target)?;
        if reported != actual {
            return Err(Self::throw(format!(
                "TypeError: 'isExtensible' on proxy: trap result does not reflect extensibility of proxy target (which is '{actual}')"
            )));
        }
        Ok(reported)
    }

    /// [[PreventExtensions]] (ES §10.1.4, §10.5.4 for a Proxy): a Proxy's
    /// `preventExtensions` trap may report success only for a target that
    /// is no longer extensible.
    pub fn prevent_extensions(&mut self, o: &ObjRef) -> Result<bool, JsValue> {
        let Some((target, handler)) = Self::proxy_parts(o) else {
            o.borrow_mut().non_extensible = true;
            return Ok(true);
        };
        let Some(trap) = self.proxy_trap(&handler, "preventExtensions")? else {
            return self.prevent_extensions(&target);
        };
        let ok = self
            .call(trap, JsValue::Object(handler), &[JsValue::Object(target.clone())])?
            .truthy();
        if ok && self.is_extensible(&target)? {
            return Err(Self::throw(
                "TypeError: 'preventExtensions' on proxy: trap returned truish but the proxy target is extensible",
            ));
        }
        Ok(ok)
    }

    /// SetIntegrityLevel (ES §7.3.15): `false` when [[PreventExtensions]]
    /// is refused; a TypeError when a property cannot be redefined. An
    /// ordinary object records the level in its flags; a Proxy goes through
    /// its traps: `preventExtensions`, `ownKeys`, and for each key
    /// `defineProperty` (after `getOwnPropertyDescriptor` when freezing).
    pub fn set_integrity_level(&mut self, o: &ObjRef, frozen: bool) -> Result<bool, JsValue> {
        if Self::proxy_parts(o).is_none() {
            let mut b = o.borrow_mut();
            if frozen && b.typed_len().is_some_and(|n| n > 0) {
                return Err(Self::throw(
                    "TypeError: Cannot freeze array buffer views with elements",
                ));
            }
            b.non_extensible = true;
            if frozen {
                b.frozen = true;
            } else {
                b.sealed = true;
            }
            return Ok(true);
        }
        if !self.prevent_extensions(o)? {
            return Ok(false);
        }
        for k in self.own_property_keys(o)? {
            let mut desc = PropDesc {
                configurable: Some(false),
                ..PropDesc::default()
            };
            if frozen {
                match self.own_prop_desc(o, &k)? {
                    None => continue,
                    Some(current) if !current.is_accessor() => desc.writable = Some(false),
                    Some(_) => {}
                }
            }
            let d = desc.to_object(self);
            if !self.define_own_property(o, &k, &d)? {
                return Err(Self::throw(format!("TypeError: Cannot redefine property: {k}")));
            }
        }
        Ok(true)
    }

    /// TestIntegrityLevel (ES §7.3.16): not extensible, every own property
    /// non-configurable and, for `frozen`, every data property read-only —
    /// through a Proxy's `isExtensible`, `ownKeys` and
    /// `getOwnPropertyDescriptor` traps.
    pub fn test_integrity_level(&mut self, o: &ObjRef, frozen: bool) -> Result<bool, JsValue> {
        if Self::proxy_parts(o).is_none() {
            return Ok(o.borrow().test_integrity(frozen));
        }
        if self.is_extensible(o)? {
            return Ok(false);
        }
        for k in self.own_property_keys(o)? {
            if let Some(d) = self.own_prop_desc(o, &k)? {
                if d.configurable == Some(true) || (frozen && d.is_data() && d.writable == Some(true)) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// [[DefineOwnProperty]] (ES §10.1.6, §10.5.6 for a Proxy): a Proxy's
    /// `defineProperty` trap decides by its result's truthiness (resolved
    /// with GetMethod semantics; no trap forwards to the target), and an
    /// ordinary object applies the descriptor. False means refused, which
    /// `Object.defineProperty` turns into a TypeError and
    /// `Reflect.defineProperty` returns.
    pub fn define_own_property(&mut self, o: &ObjRef, key: &str, desc: &ObjRef) -> Result<bool, JsValue> {
        let Some((target, handler)) = Self::proxy_parts(o) else {
            // A typed array's integer index (ES §10.4.5.3): only a
            // writable, enumerable, configurable data definition inside
            // the view is accepted, and its value lands in the buffer.
            let typed = match &o.borrow().kind {
                ObjKind::TypedArray(t) => t.index_of_key(key).map(|i| (t.clone(), i)),
                _ => None,
            };
            if let Some((t, i)) = typed {
                let d = PropDesc::read(&desc.borrow());
                let Some(i) = i else {
                    return Ok(false);
                };
                if d.configurable == Some(false)
                    || d.enumerable == Some(false)
                    || d.is_accessor()
                    || d.writable == Some(false)
                {
                    return Ok(false);
                }
                if let Some(v) = &d.value {
                    let n = self.to_number_value(v)?;
                    t.set(i, n);
                }
                return Ok(true);
            }
            // An Array's `length` converts its new value first
            // (ArraySetLength steps 3-5: a RangeError before any check).
            let length_value = matches!(o.borrow().kind, ObjKind::Array)
                && key == "length"
                && desc.borrow().own("value").is_some();
            if length_value {
                let mut d = PropDesc::read(&desc.borrow());
                let v = d.value.clone().unwrap_or(JsValue::Undefined);
                d.value = Some(JsValue::Num(self.array_length_value(&v)? as f64));
                let converted = d.to_object(self);
                return Ok(apply_descriptor(o, key, &converted));
            }
            // A String wrapper's characters and `length` cannot change: a
            // compatible definition is accepted with nothing to write.
            if o.borrow().string_own(key).is_some() {
                return Ok(descriptor_is_allowed(o, key, desc));
            }
            return Ok(apply_descriptor(o, key, desc));
        };
        let Some(trap) = self.proxy_trap(&handler, "defineProperty")? else {
            return self.define_own_property(&target, key, desc);
        };
        // The trap gets its own FromPropertyDescriptor copy.
        let d = PropDesc::read(&desc.borrow());
        let fresh = d.to_object(self);
        let kv = self.key_value(key);
        let ok = self
            .call(
                trap,
                JsValue::Object(handler),
                &[JsValue::Object(target.clone()), kv, JsValue::Object(fresh)],
            )?
            .truthy();
        if !ok {
            return Ok(false);
        }
        // Invariants (ES §10.5.6 steps 9-16): no property added to a
        // non-extensible target, none reported non-configurable that the
        // target does not hold as such, nothing the target's own descriptor
        // could not have accepted, and no non-configurable writable
        // property reported made read-only.
        let target_desc = self.own_prop_desc(&target, key)?;
        let extensible = self.is_extensible(&target)?;
        let setting_config_false = d.configurable == Some(false);
        let refused = match &target_desc {
            None => !extensible || setting_config_false,
            Some(td) => {
                !is_compatible_descriptor(extensible, &d, Some(td))
                    || (setting_config_false && td.configurable == Some(true))
                    || (td.is_data()
                        && td.configurable == Some(false)
                        && td.writable == Some(true)
                        && d.writable == Some(false))
            }
        };
        if refused {
            return Err(Self::throw(format!(
                "TypeError: 'defineProperty' on proxy: trap returned truish for defining property '{key}' which is incompatible with the proxy target"
            )));
        }
        Ok(true)
    }
}

/// A Property Descriptor record (ES §6.2.6): every field may be absent.
#[derive(Clone, Default)]
pub(super) struct PropDesc {
    pub value: Option<JsValue>,
    pub writable: Option<bool>,
    pub get: Option<JsValue>,
    pub set: Option<JsValue>,
    pub enumerable: Option<bool>,
    pub configurable: Option<bool>,
}

impl PropDesc {
    /// Read a descriptor object whose fields are own data properties, as
    /// `to_property_descriptor` and `own_property_descriptor` make them.
    pub(super) fn read(d: &JsObject) -> PropDesc {
        let field = |name: &str| d.own(name).map(|_| d.get_prop(name).unwrap_or(JsValue::Undefined));
        let flag = |name: &str| field(name).map(|v| v.truthy());
        PropDesc {
            value: field("value"),
            writable: flag("writable"),
            get: field("get"),
            set: field("set"),
            enumerable: flag("enumerable"),
            configurable: flag("configurable"),
        }
    }

    pub(super) fn is_accessor(&self) -> bool {
        self.get.is_some() || self.set.is_some()
    }

    pub(super) fn is_data(&self) -> bool {
        self.value.is_some() || self.writable.is_some()
    }

    /// CompletePropertyDescriptor (ES §6.2.6.6).
    pub(super) fn complete(&mut self) {
        if self.is_accessor() {
            self.get.get_or_insert(JsValue::Undefined);
            self.set.get_or_insert(JsValue::Undefined);
        } else {
            self.value.get_or_insert(JsValue::Undefined);
            self.writable.get_or_insert(false);
        }
        self.enumerable.get_or_insert(false);
        self.configurable.get_or_insert(false);
    }

    /// FromPropertyDescriptor (ES §6.2.6.4): a fresh plain object with the
    /// fields present, in the order `value`, `writable`, `get`, `set`,
    /// `enumerable`, `configurable`.
    pub(super) fn to_object(&self, interp: &Interp) -> ObjRef {
        let out = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
        {
            let mut b = out.borrow_mut();
            let flag = |v: bool| JsValue::Bool(v);
            let fields = [
                ("value", self.value.clone()),
                ("writable", self.writable.map(flag)),
                ("get", self.get.clone()),
                ("set", self.set.clone()),
                ("enumerable", self.enumerable.map(flag)),
                ("configurable", self.configurable.map(flag)),
            ];
            for (name, v) in fields {
                if let Some(v) = v {
                    b.set_prop(name, v, true);
                }
            }
        }
        out
    }
}

/// An ordinary object's own property as a complete descriptor record:
/// a property-table slot, a dense array element or `length`, or a typed
/// array element.
pub(super) fn ordinary_own_desc(b: &JsObject, key: &str) -> Option<PropDesc> {
    let (value, accessor, enumerable) = match b.own_slot(key) {
        Some(Prop::Value { value, enumerable }) => (Some(value.clone()), None, *enumerable),
        Some(Prop::Accessor { get, set, enumerable }) => (None, Some((get.clone(), set.clone())), *enumerable),
        None => match &b.kind {
            ObjKind::Array if key == "length" => (Some(JsValue::Num(b.array_length() as f64)), None, false),
            ObjKind::Array => {
                let i = array_index(key)?;
                (Some(b.elem(i).cloned()?), None, !b.non_enumerable_elems.contains(&i))
            }
            ObjKind::TypedArray(t) => (Some(JsValue::Num(t.index_of_key(key)?.and_then(|i| t.get(i))?)), None, true),
            ObjKind::Primitive(_) => (Some(b.string_own(key)?), None, key != "length"),
            _ => return None,
        },
    };
    let configurable = Some(b.is_configurable(key));
    let enumerable = Some(enumerable);
    Some(match accessor {
        Some((get, set)) => PropDesc {
            get: Some(get.map(JsValue::Object).unwrap_or(JsValue::Undefined)),
            set: Some(set.map(JsValue::Object).unwrap_or(JsValue::Undefined)),
            enumerable,
            configurable,
            ..PropDesc::default()
        },
        None => PropDesc {
            value,
            writable: Some(b.is_writable(key)),
            enumerable,
            configurable,
            ..PropDesc::default()
        },
    })
}

/// IsCompatiblePropertyDescriptor (ES §10.1.6.2): whether an object with
/// own descriptor `current` (None: absent) and extensibility `extensible`
/// could accept `desc` (ValidateAndApplyPropertyDescriptor without an
/// object to apply it to).
pub(super) fn is_compatible_descriptor(extensible: bool, desc: &PropDesc, current: Option<&PropDesc>) -> bool {
    let Some(current) = current else {
        return extensible;
    };
    if current.configurable == Some(false) {
        if desc.configurable == Some(true) {
            return false;
        }
        if desc.enumerable.is_some() && desc.enumerable != current.enumerable {
            return false;
        }
        let generic = !desc.is_accessor() && !desc.is_data();
        if !generic && desc.is_accessor() != current.is_accessor() {
            return false;
        }
        let differs = |a: &Option<JsValue>, b: &Option<JsValue>| match (a, b) {
            (Some(a), Some(b)) => !same_value(a, b),
            (Some(_), None) => true,
            _ => false,
        };
        if current.is_accessor() {
            if differs(&desc.get, &current.get) || differs(&desc.set, &current.set) {
                return false;
            }
        } else if current.writable == Some(false)
            && (desc.writable == Some(true) || differs(&desc.value, &current.value))
        {
            return false;
        }
    }
    true
}

/// The `String` constructor object currently installed (for `constructor`).
fn ctor_ref(interp: &Interp) -> ObjRef {
    match interp.global_object.borrow().get_prop("String") {
        Some(JsValue::Object(o)) => o,
        _ => interp.function_proto.clone(),
    }
}

/// Apply an ECMAScript property descriptor object to `target[key]`:
/// false when it is refused, or when an Array `length` shrink stopped at
/// an element that cannot be deleted (the attributes still apply, as
/// ArraySetLength does).
fn apply_descriptor(target: &ObjRef, key: &str, desc: &ObjRef) -> bool {
    if !descriptor_is_allowed(target, key, desc) {
        return false;
    }
    let (configurable, writable, accessor) = {
        let d = desc.borrow();
        (
            descriptor_flag(&d, "configurable"),
            descriptor_flag(&d, "writable"),
            d.own("get").is_some() || d.own("set").is_some(),
        )
    };
    let (existed, was_accessor) = {
        let t = target.borrow();
        (t.has_own_key(key), matches!(t.own_slot(key), Some(Prop::Accessor { .. })))
    };
    let complete = write_descriptor(target, key, desc);
    let mut t = target.borrow_mut();
    // A new property is non-configurable unless the descriptor says
    // otherwise; an existing one becomes so when the descriptor says
    // `configurable: false` (the reverse was refused above).
    if (!existed && configurable != Some(true)) || configurable == Some(false) {
        t.non_configurable.insert(key.to_string());
    }
    // Writability belongs to data properties: an accessor has none; a new
    // data property (or an accessor turned into one) is non-writable
    // unless the descriptor says `writable: true`; an existing data
    // property changes only when the descriptor names `writable`.
    if accessor {
        t.set_writable(key, true);
    } else if writable == Some(false) || ((!existed || was_accessor) && writable != Some(true)) {
        t.set_writable(key, false);
    } else if writable == Some(true) {
        t.set_writable(key, true);
    }
    complete
}

/// A boolean field of a descriptor object: `None` when absent.
fn descriptor_flag(d: &JsObject, name: &str) -> Option<bool> {
    d.own(name).map(|_| d.get_prop(name).map(|v| v.truthy()).unwrap_or(false))
}

/// ValidateAndApplyPropertyDescriptor's refusals (ES §10.1.6.3) for what
/// this engine tracks: a new property on a non-extensible object, and on a
/// non-configurable property any attempt to make it configurable, to flip
/// its enumerability, to turn a data property into an accessor or back,
/// or, when it is also non-writable, to make it writable or give it a
/// different value.
fn descriptor_is_allowed(target: &ObjRef, key: &str, desc: &ObjRef) -> bool {
    let t = target.borrow();
    if !t.has_own_key(key) {
        // ArrayDefineOwnProperty (ES §10.4.2.1): a new index at or past a
        // read-only `length` is refused.
        let past_fixed_length = matches!(t.kind, ObjKind::Array)
            && array_index(key).is_some_and(|i| i >= t.array_length())
            && !t.is_writable("length");
        return !t.non_extensible && !past_fixed_length;
    }
    if t.is_configurable(key) {
        return true;
    }
    let d = desc.borrow();
    let flag = |name: &str| descriptor_flag(&d, name);
    if flag("configurable") == Some(true) {
        return false;
    }
    if flag("enumerable").is_some_and(|e| e != own_enumerable(&t, key)) {
        return false;
    }
    let is_accessor_now = matches!(t.own_slot(key), Some(Prop::Accessor { .. }));
    let wants_accessor = d.own("get").is_some() || d.own("set").is_some();
    let wants_data = d.own("value").is_some() || d.own("writable").is_some();
    if (wants_accessor && !is_accessor_now) || (wants_data && is_accessor_now) {
        return false;
    }
    if is_accessor_now || t.is_writable(key) {
        return true;
    }
    if flag("writable") == Some(true) {
        return false;
    }
    match d.get_prop("value") {
        Some(v) if d.own("value").is_some() => own_data_value(&t, key).is_some_and(|cur| same_value(&cur, &v)),
        _ => true,
    }
}

/// An own property's [[Enumerable]] attribute: the property-table slot's
/// flag, or true for a dense array element or typed-array element (an
/// array's `length` is in neither and is not enumerable).
pub(super) fn own_enumerable(t: &JsObject, key: &str) -> bool {
    if t.own(key).is_some() {
        return t.is_enumerable(key);
    }
    if let (ObjKind::Array, Some(i)) = (&t.kind, array_index(key)) {
        return t.elem(i).is_some() && !t.non_enumerable_elems.contains(&i);
    }
    key != "length" && t.has_own_key(key)
}

/// An own data property's current value: a property-table slot, a dense
/// array element, or an array's `length`.
pub(super) fn own_data_value(t: &JsObject, key: &str) -> Option<JsValue> {
    if let Some(v) = t.get_prop(key) {
        return Some(v);
    }
    if matches!(t.kind, ObjKind::Array) {
        if key == "length" {
            return Some(JsValue::Num(t.array_length() as f64));
        }
        return array_index(key).and_then(|i| t.elem(i).cloned());
    }
    t.string_own(key)
}

/// SameValue (ES §7.2.10): NaN equals NaN, +0 differs from -0.
pub(super) fn same_value(a: &JsValue, b: &JsValue) -> bool {
    match (a, b) {
        (JsValue::Num(x), JsValue::Num(y)) if x.is_nan() && y.is_nan() => true,
        (JsValue::Num(x), JsValue::Num(y)) => x == y && x.is_sign_negative() == y.is_sign_negative(),
        _ => a.strict_eq(b),
    }
}

/// Write a validated descriptor's fields onto `target` (ES §10.1.6.3
/// ValidateAndApplyPropertyDescriptor, steps 2 and 6-7; `writable` and
/// `configurable` are recorded by the caller); false only when an Array
/// `length` shrink stopped early. The fields present decide the kind: a
/// `get` or `set` field makes an accessor even when its value is
/// undefined, a `value` or `writable` field makes data, and neither leaves
/// the property's kind alone. A field the descriptor leaves out keeps its
/// current state, or its default on a new property; a property that
/// changes kind keeps only its enumerability (and configurability), so an
/// accessor turned into data without a `value` holds undefined.
///
/// Every lookup here reads the target's OWN slots under one borrow: it
/// must not walk a prototype chain while the target is mutably borrowed
/// (a prototype that is the target itself, or a Proxy whose trap
/// re-enters, would panic the engine).
fn write_descriptor(target: &ObjRef, key: &str, desc: &ObjRef) -> bool {
    let (get, set, value, writable_given, enumerable) = {
        let d = desc.borrow();
        let field = |name: &str| d.own(name).map(|_| d.get_prop(name).unwrap_or(JsValue::Undefined));
        let function = |v: JsValue| match v {
            JsValue::Object(f) if f.borrow().is_callable() => Some(f),
            _ => None,
        };
        (
            field("get").map(function),
            field("set").map(function),
            field("value"),
            d.own("writable").is_some(),
            descriptor_flag(&d, "enumerable"),
        )
    };
    let mut b = target.borrow_mut();
    let enumerable = enumerable.unwrap_or_else(|| own_enumerable(&b, key));
    let dense_index = match b.kind {
        ObjKind::Array => array_index(key).filter(|i| *i < super::eval::MAX_DENSE),
        _ => None,
    };
    let current_accessor = match b.own_slot(key) {
        Some(Prop::Accessor { get, set, .. }) => Some((get.clone(), set.clone())),
        _ => None,
    };
    if get.is_some() || set.is_some() {
        // An accessor on an Array index lives in the property table; the
        // dense store keeps a hole there (growing to reach the index) so
        // no stale value sits beside it.
        if let Some(i) = dense_index {
            b.put_elem(i, JsValue::Undefined);
            if let Some(slot) = b.elems.get_mut(i) {
                *slot = None;
            }
            b.non_enumerable_elems.remove(&i);
        }
        let (g0, s0) = current_accessor.unwrap_or((None, None));
        b.put_accessor(key, get.unwrap_or(g0), set.unwrap_or(s0), enumerable);
        return true;
    }
    if value.is_none() && !writable_given {
        // A generic descriptor: an existing property keeps its kind and
        // value and takes the enumerability; a new one is data holding
        // undefined (an Array index extends the dense store to reach it).
        if !b.has_own_key(key) {
            match dense_index {
                Some(i) => b.put_elem(i, JsValue::Undefined),
                None => b.set_prop(key, JsValue::Undefined, enumerable),
            }
            return true;
        }
        match b.own(key).and_then(|i| b.props.get_mut(i)).map(|(_, p)| p) {
            Some(Prop::Accessor { enumerable: e, .. } | Prop::Value { enumerable: e, .. }) => *e = enumerable,
            // A dense array element records its flag beside the store;
            // an array's `length` is never enumerable (and not
            // configurable, so it cannot be made so).
            None => {
                if let Some(i) = dense_index {
                    set_elem_enumerable(&mut b, i, enumerable);
                }
            }
        }
        return true;
    }
    // A data descriptor. Without a `value` an existing data property
    // keeps its value; an accessor turned into data, or a new property,
    // holds undefined.
    let value = match value {
        Some(v) => Some(v),
        None if current_accessor.is_some() || !b.has_own_key(key) => Some(JsValue::Undefined),
        None => None,
    };
    if matches!(b.kind, ObjKind::Array) && key == "length" {
        // `define_own_property` converted the value (ArraySetLength); the
        // length is set before any `writable: false` applies.
        return match value {
            Some(v) => {
                let n = v.to_number();
                b.set_array_length(if n.is_finite() && n >= 0.0 { n as usize } else { 0 })
            }
            None => true,
        };
    }
    // A data descriptor on an ARRAY index writes the element slot (and
    // drops an accessor the table held), so the array's dense storage and
    // its property table cannot disagree.
    if let Some(i) = dense_index {
        b.remove_slot(key);
        if let Some(v) = value {
            b.put_elem(i, v);
        }
        set_elem_enumerable(&mut b, i, enumerable);
        return true;
    }
    match value {
        Some(v) => b.set_prop(key, v, enumerable),
        None => {
            if let Some(Prop::Value { enumerable: e, .. }) = b.own(key).and_then(|i| b.props.get_mut(i)).map(|(_, p)| p) {
                *e = enumerable;
            }
        }
    }
    // An Array index past the dense cap: `length` still covers it.
    if let (ObjKind::Array, Some(i)) = (&b.kind, array_index(key)) {
        if i >= b.array_length() {
            b.trailing_holes = i.saturating_add(1).saturating_sub(b.elems.len());
        }
    }
    true
}

/// Record a dense Array element's [[Enumerable]] attribute.
fn set_elem_enumerable(b: &mut JsObject, i: usize, enumerable: bool) {
    if enumerable {
        b.non_enumerable_elems.remove(&i);
    } else {
        b.non_enumerable_elems.insert(i);
    }
}

/// A `setPrototypeOf` prototype argument: an object or null, anything
/// else (undefined included) a TypeError.
fn prototype_argument(v: Option<&JsValue>) -> Result<Option<ObjRef>, JsValue> {
    match v {
        Some(JsValue::Object(p)) => Ok(Some(p.clone())),
        Some(JsValue::Null) => Ok(None),
        _ => Err(Interp::throw(
            "TypeError: Object prototype may only be an Object or null",
        )),
    }
}

#[cfg(test)]
mod set_prototype_of_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String({body}); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn reflect_set_prototype_of_refuses_bad_arguments_and_reports_failure() {
        assert_eq!(caught("Reflect.setPrototypeOf(1, null)"), "TypeError");
        assert_eq!(caught("Reflect.setPrototypeOf(undefined, {})"), "TypeError");
        assert_eq!(caught("Reflect.setPrototypeOf({}, 1)"), "TypeError");
        assert_eq!(caught("Reflect.setPrototypeOf({}, undefined)"), "TypeError");
        assert_eq!(caught("Reflect.setPrototypeOf(Object.preventExtensions({}), {})"), "false");
        assert_eq!(
            caught("(() => { const a = {}; const b = Object.create(a); return Reflect.setPrototypeOf(a, b); })()"),
            "false"
        );
        assert_eq!(
            caught("(() => { const o = {}; return Reflect.setPrototypeOf(o, null) && Object.getPrototypeOf(o) === null; })()"),
            "true"
        );
        assert_eq!(
            caught("(() => { const t = {}, proto = {}; Reflect.setPrototypeOf(new Proxy(t, {}), proto); return Object.getPrototypeOf(t) === proto; })()"),
            "true"
        );
    }

    #[test]
    fn object_set_prototype_of_throws_where_reflect_returns_false() {
        assert_eq!(caught("Object.setPrototypeOf(null, {})"), "TypeError");
        assert_eq!(caught("Object.setPrototypeOf({}, 1)"), "TypeError");
        assert_eq!(caught("Object.setPrototypeOf(1, {})"), "1");
        assert_eq!(caught("Object.setPrototypeOf(Object.preventExtensions({}), {})"), "TypeError");
        assert_eq!(
            caught("(() => { const a = {}; return Object.setPrototypeOf(a, Object.create(a)); })()"),
            "TypeError"
        );
    }
}

#[cfg(test)]
mod configurability_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_property_defined_without_configurable_cannot_be_deleted() {
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1 }); return delete o.x + ':' + o.x"),
            "false:1"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1, configurable: true }); return delete o.x + ':' + ('x' in o)"),
            "true:false"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { get() { return 1; } }); return delete o.x + ':' + o.x"),
            "false:1"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1 }); return Reflect.deleteProperty(o, 'x')"),
            "false"
        );
        assert_eq!(caught("const o = { a: 1 }; return delete o.a + ':' + ('a' in o)"), "true:false");
        assert_eq!(caught("return delete ({}).missing"), "true");
    }

    #[test]
    fn descriptors_report_and_keep_configurability() {
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1 }); return Object.getOwnPropertyDescriptor(o, 'x').configurable"),
            "false"
        );
        assert_eq!(
            caught("return Object.getOwnPropertyDescriptor({ a: 1 }, 'a').configurable"),
            "true"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1 }); Object.defineProperty(o, 'x', { configurable: true })"),
            "TypeError"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1 }); return Reflect.defineProperty(o, 'x', { enumerable: true })"),
            "false"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1 }); Object.defineProperty(o, 'x', { get() {} })"),
            "TypeError"
        );
        assert_eq!(
            caught("Object.defineProperty(Object.preventExtensions({}), 'x', { value: 1 })"),
            "TypeError"
        );
        assert_eq!(
            caught("return Reflect.defineProperty(Object.preventExtensions({}), 'x', { value: 1 })"),
            "false"
        );
        assert_eq!(caught("Reflect.defineProperty(1, 'x', { value: 1 })"), "TypeError");
    }

    #[test]
    fn array_index_deletes_check_configurability_before_touching_the_slot() {
        assert_eq!(
            caught("const a = [1, 2, 3]; Object.defineProperty(a, 1, { value: 2, configurable: false }); return delete a[1] + ':' + a.join()"),
            "false:1,2,3"
        );
        assert_eq!(
            caught("const a = Object.freeze([1, 2]); return delete a[0] + ':' + a.join()"),
            "false:1,2"
        );
        assert_eq!(
            caught("const a = Object.seal([1, 2]); return delete a[1] + ':' + a.join()"),
            "false:1,2"
        );
        assert_eq!(caught("const a = [1, 2]; return delete a.length + ':' + a.length"), "false:2");
        assert_eq!(
            caught("const a = [1, 2, 3]; Object.defineProperty(a, 1, { configurable: false }); a.length = 0; return a.length"),
            "2"
        );
        // Redefining an existing element without `configurable` keeps it
        // configurable.
        assert_eq!(
            caught("const a = [1, 2]; Object.defineProperty(a, 1, { value: 5 }); return delete a[1]"),
            "true"
        );
    }

    #[test]
    fn a_proxy_cannot_report_a_non_configurable_property_deleted() {
        assert_eq!(
            caught("const t = {}; Object.defineProperty(t, 'x', { value: 1 }); return delete new Proxy(t, { deleteProperty() { return true; } }).x"),
            "TypeError"
        );
    }
}

#[cfg(test)]
mod writability_tests {
    use super::super::interp::test_support::eval_js;

    /// Run `body` after `prologue` and render its result or the caught
    /// error's name.
    fn caught(prologue: &str, body: &str) -> String {
        eval_js(&format!(
            "{prologue} let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    const STRICT: &str = "'use strict';";

    #[test]
    fn a_frozen_object_keeps_its_values() {
        assert_eq!(
            caught("", "const o = Object.freeze({ a: 1 }); o.a = 2; o.b = 3; o.a += 1; return o.a + ':' + o.b"),
            "1:undefined"
        );
        assert_eq!(
            caught("", "const a = Object.freeze([1, 2]); a[0] = 9; a[5] = 1; a.length = 0; return a.join()"),
            "1,2"
        );
        assert_eq!(caught(STRICT, "Object.freeze({ a: 1 }).a = 2"), "TypeError");
        assert_eq!(caught(STRICT, "Object.freeze({}).b = 2"), "TypeError");
        assert_eq!(caught(STRICT, "const a = Object.freeze([1]); a[0]++"), "TypeError");
        // Array mutators and Object.assign write with throw = true.
        assert_eq!(caught("", "const a = Object.freeze([1, 2]); a.push(3)"), "TypeError");
        assert_eq!(
            caught("", "const a = Object.freeze([1, 2]); try { a.pop(); } catch (e) {} try { a.sort((x, y) => y - x); } catch (e) {} return a.join()"),
            "1,2"
        );
        assert_eq!(caught("", "Object.assign(Object.freeze({ a: 1 }), { a: 2 })"), "TypeError");
        // A sealed array stays writable but cannot grow or shrink.
        assert_eq!(
            caught("", "const a = Object.seal([1, 2]); a[0] = 5; a.reverse(); return a.join()"),
            "2,5"
        );
        assert_eq!(caught("", "Object.seal([1]).push(2)"), "TypeError");
        assert_eq!(caught("", "Object.seal([1]).pop()"), "TypeError");
        // A non-extensible object takes no new property, array element
        // included, and keeps its writable ones writable.
        assert_eq!(
            caught("", "const o = Object.preventExtensions({ a: 1 }); o.b = 1; o.a = 2; return ('b' in o) + ':' + o.a"),
            "false:2"
        );
        assert_eq!(
            caught("", "const a = Object.preventExtensions([1]); a[1] = 2; return a.length"),
            "1"
        );
    }

    #[test]
    fn an_inherited_read_only_property_or_a_getter_without_setter_refuses_the_write() {
        assert_eq!(
            caught("", "const c = Object.create(Object.freeze({ x: 1 })); c.x = 2; return c.hasOwnProperty('x') + ':' + c.x"),
            "false:1"
        );
        assert_eq!(caught(STRICT, "Object.create(Object.freeze({ x: 1 })).x = 2"), "TypeError");
        assert_eq!(caught("", "const o = { get x() { return 1; } }; o.x = 2; return o.x"), "1");
        assert_eq!(caught(STRICT, "const o = { get x() { return 1; } }; o.x = 2"), "TypeError");
        assert_eq!(
            caught("", "class A { get v() { return 'getter'; } } const a = new A(); a.v = 1; return a.v"),
            "getter"
        );
    }

    #[test]
    fn define_property_tracks_writable_per_property() {
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); o.x = 2; return o.x"),
            "1"
        );
        assert_eq!(
            caught(STRICT, "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); o.x = 2"),
            "TypeError"
        );
        // A writable defined property takes writes and keeps its
        // enumerability.
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1, writable: true }); o.x = 2; return o.x + ':' + Object.keys(o).length"),
            "2:0"
        );
        // writable: false on an existing configurable property; it can
        // still be redefined, and deleted and recreated writable.
        assert_eq!(
            caught("", "const o = { x: 1 }; Object.defineProperty(o, 'x', { writable: false }); o.x = 2; const a = o.x; Object.defineProperty(o, 'x', { value: 3 }); return a + ':' + o.x"),
            "1:3"
        );
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1, configurable: true }); delete o.x; o.x = 2; return o.x"),
            "2"
        );
        // Non-configurable and non-writable: the value is fixed.
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); Object.defineProperty(o, 'x', { value: 2 })"),
            "TypeError"
        );
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); Object.defineProperty(o, 'x', { value: 1 }); return o.x"),
            "1"
        );
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); Object.defineProperty(o, 'x', { writable: true })"),
            "TypeError"
        );
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); return Reflect.defineProperty(o, 'x', { value: 2 })"),
            "false"
        );
        assert_eq!(
            caught("", "const o = Object.freeze({ x: 1 }); Object.defineProperty(o, 'x', { value: 2 })"),
            "TypeError"
        );
        // Non-configurable but writable may still become read-only.
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1, writable: true }); Object.defineProperty(o, 'x', { writable: false }); o.x = 2; return o.x"),
            "1"
        );
        // Array elements and length.
        assert_eq!(
            caught("", "const a = [1, 2]; Object.defineProperty(a, 0, { writable: false }); a[0] = 9; a[1] = 8; return a.join()"),
            "1,8"
        );
        assert_eq!(
            caught("", "const a = [1, 2]; Object.defineProperty(a, 'length', { writable: false }); a[2] = 3; a.length = 0; try { a.push(4); } catch (e) { return String(e).split(':')[0] + ':' + a.join(); } return 'pushed'"),
            "TypeError:1,2"
        );
    }

    #[test]
    fn descriptors_and_is_frozen_report_writability() {
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); return Object.getOwnPropertyDescriptor(o, 'x').writable"),
            "false"
        );
        assert_eq!(
            caught("", "return Object.getOwnPropertyDescriptor({ a: 1 }, 'a').writable"),
            "true"
        );
        assert_eq!(
            caught("", "return Object.getOwnPropertyDescriptor(Object.freeze({ a: 1 }), 'a').writable"),
            "false"
        );
        assert_eq!(
            caught("", "const d = Object.getOwnPropertyDescriptor([1, 2], 'length'); return [d.value, d.writable, d.enumerable, d.configurable].join()"),
            "2,true,false,false"
        );
        assert_eq!(caught("", "return Object.isFrozen(Object.preventExtensions({}))"), "true");
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); Object.preventExtensions(o); return Object.isFrozen(o)"),
            "true"
        );
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1, writable: true }); Object.preventExtensions(o); return Object.isFrozen(o) + ':' + Object.isSealed(o)"),
            "false:true"
        );
        assert_eq!(
            caught("", "return Object.isFrozen(Object.seal({ a: 1 })) + ':' + Object.isFrozen(Object.freeze({ a: 1 })) + ':' + Object.isFrozen({})"),
            "false:true:false"
        );
        // An empty sealed array still has a writable `length`.
        assert_eq!(
            caught("", "return Object.isFrozen(Object.seal([])) + ':' + Object.isSealed(Object.seal([]))"),
            "false:true"
        );
        assert_eq!(caught("", "Object.freeze(new Uint8Array(1))"), "TypeError");
        assert_eq!(caught("", "return Object.isFrozen(Object.freeze(new Uint8Array(0)))"), "true");
    }

    #[test]
    fn reflect_set_reports_whether_the_write_happened() {
        assert_eq!(caught("", "return Reflect.set(Object.freeze({ a: 1 }), 'a', 2)"), "false");
        assert_eq!(
            caught("", "const o = {}; Object.defineProperty(o, 'x', { value: 1 }); return Reflect.set(o, 'x', 2) + ':' + o.x"),
            "false:1"
        );
        assert_eq!(caught("", "const o = {}; return Reflect.set(o, 'x', 2) + ':' + o.x"), "true:2");
        assert_eq!(caught("", "return Reflect.set({ get x() { return 1; } }, 'x', 2)"), "false");
        assert_eq!(caught("", "return Reflect.set(Object.preventExtensions({}), 'x', 2)"), "false");
        assert_eq!(caught("", "return Reflect.set(Object.freeze([1]), 0, 2)"), "false");
        assert_eq!(caught("", "return Reflect.set(new Uint8Array(1), 'length', 2)"), "false");
        assert_eq!(caught("", "Reflect.set(1, 'x', 2)"), "TypeError");
    }
}

#[cfg(test)]
mod descriptor_normalization_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// A Proxy whose `defineProperty` trap records the descriptor it is
    /// handed and accepts the definition.
    const RECORDING: &str = "let got = 'not called'; const p = new Proxy({}, { defineProperty(t, k, d) { got = d; return true; } });";

    #[test]
    fn a_define_property_trap_receives_a_normalized_copy() {
        assert_eq!(
            caught(&format!("{RECORDING} const d = {{ value: 1, extra: 2 }}; Object.defineProperty(p, 'x', d); return (got === d) + JSON.stringify(got)")),
            "false{\"value\":1}"
        );
        // Fields come back in the spec's order, flags as booleans, and an
        // inherited field or one behind a getter counts.
        assert_eq!(
            caught(&format!("{RECORDING} const f = () => 1; Reflect.defineProperty(p, 'x', {{ configurable: 1, enumerable: 0, get: f }}); return Object.keys(got).join() + ':' + (got.get === f) + got.enumerable + got.configurable")),
            "get,enumerable,configurable:truefalsetrue"
        );
        assert_eq!(
            caught(&format!("{RECORDING} const d = Object.create({{ enumerable: 'yes' }}); Object.defineProperty(d, 'value', {{ get() {{ return 7; }} }}); Object.defineProperty(p, 'x', d); return JSON.stringify(got)")),
            "{\"value\":7,\"enumerable\":true}"
        );
        assert_eq!(
            caught(&format!("{RECORDING} Object.defineProperties(p, {{ a: {{ writable: 0, set: undefined }} }}); return 'unreached'")),
            "TypeError"
        );
    }

    #[test]
    fn a_malformed_descriptor_is_a_type_error_before_any_trap_runs() {
        for desc in ["{ get: 1 }", "{ set: 'no' }", "{ get() {}, value: 1 }", "{ set(v) {}, writable: true }", "1", "undefined"] {
            assert_eq!(
                caught(&format!("{RECORDING} try {{ Object.defineProperty(p, 'x', {desc}); }} catch (e) {{ return String(e).split(':')[0] + ':' + got; }} return 'accepted'")),
                "TypeError:not called",
                "{desc}"
            );
        }
        assert_eq!(caught("Reflect.defineProperty({}, 'x', { get: {} })"), "TypeError");
        assert_eq!(caught("Object.defineProperties({}, { a: { get: 5 } })"), "TypeError");
        // Every descriptor converts before the first one is defined.
        assert_eq!(
            caught("const o = {}; try { Object.defineProperties(o, { a: { value: 1 }, b: { get: 5 } }); } catch (e) {} return 'a' in o"),
            "false"
        );
    }

    #[test]
    fn an_ordinary_definition_reads_inherited_descriptor_fields() {
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', Object.create({ value: 3, enumerable: true })); return o.x + ':' + Object.keys(o)"),
            "3:x"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { get value() { return 'got'; }, get writable() { return true; } }); o.x += '!'; return o.x"),
            "got!"
        );
    }
}

#[cfg(test)]
mod proxy_integrity_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// A Proxy over `{ a: 1 }` whose traps log their calls and forward.
    const LOGGING: &str = "const log = []; const t = { a: 1 }; const p = new Proxy(t, {
        preventExtensions(tt) { log.push('pe'); return Reflect.preventExtensions(tt); },
        isExtensible(tt) { log.push('ie'); return Reflect.isExtensible(tt); },
        ownKeys(tt) { log.push('ok'); return Reflect.ownKeys(tt); },
        getOwnPropertyDescriptor(tt, k) { log.push('gopd:' + k); return Reflect.getOwnPropertyDescriptor(tt, k); },
        defineProperty(tt, k, d) { log.push('dp:' + k + JSON.stringify(d)); return Reflect.defineProperty(tt, k, d); },
    });";

    #[test]
    fn freeze_and_seal_go_through_the_traps() {
        assert_eq!(
            caught(&format!("{LOGGING} Object.freeze(p); const froze = log.join(); log.length = 0; const r = Object.isFrozen(p); return froze + '|' + log.join() + '|' + r + Object.isFrozen(t)")),
            "pe,ok,gopd:a,dp:a{\"writable\":false,\"configurable\":false}|ie,ok,gopd:a|truetrue"
        );
        assert_eq!(
            caught(&format!("{LOGGING} Object.seal(p); const sealed = log.join(); log.length = 0; const r = Object.isSealed(p); return sealed + '|' + log.join() + '|' + r + Object.isSealed(t) + Object.isFrozen(t)")),
            "pe,ok,dp:a{\"configurable\":false}|ie,ok,gopd:a|truetruefalse"
        );
        assert_eq!(
            caught(&format!("{LOGGING} Object.preventExtensions(p); const r = Object.isExtensible(p); return log.join() + ':' + r + Object.isExtensible(t)")),
            "pe,ie:falsefalse"
        );
        // Without traps the operations reach the target.
        assert_eq!(caught("const t = { a: 1 }; Object.freeze(new Proxy(t, {})); return Object.isFrozen(t)"), "true");
        assert_eq!(caught("const a = [1]; Object.freeze(new Proxy(a, {})); return Object.isFrozen(a)"), "true");
        assert_eq!(caught("return Object.isFrozen(new Proxy(Object.freeze({ a: 1 }), {})) + ':' + Object.isFrozen(new Proxy({ a: 1 }, {}))"), "true:false");
        assert_eq!(caught("return Object.isExtensible(new Proxy(Object.preventExtensions({}), {}))"), "false");
    }

    #[test]
    fn a_refusing_trap_makes_freeze_seal_and_prevent_extensions_throw() {
        assert_eq!(caught("Object.preventExtensions(new Proxy({}, { preventExtensions() { return false; } }))"), "TypeError");
        assert_eq!(caught("Object.freeze(new Proxy({}, { preventExtensions() { return false; } }))"), "TypeError");
        assert_eq!(caught("Object.seal(new Proxy({ a: 1 }, { defineProperty() { return false; } }))"), "TypeError");
        assert_eq!(caught("return Reflect.preventExtensions(new Proxy({}, { preventExtensions() { return false; } }))"), "false");
    }

    #[test]
    fn integrity_traps_are_held_to_the_targets_state() {
        // preventExtensions may not report success for an extensible target.
        assert_eq!(caught("Object.preventExtensions(new Proxy({}, { preventExtensions() { return true; } }))"), "TypeError");
        assert_eq!(caught("Reflect.preventExtensions(new Proxy({}, { preventExtensions() { return true; } }))"), "TypeError");
        // isExtensible must agree with the target.
        assert_eq!(caught("Object.isExtensible(new Proxy({}, { isExtensible() { return false; } }))"), "TypeError");
        assert_eq!(caught("Object.isFrozen(new Proxy({}, { isExtensible() { return false; } }))"), "TypeError");
        // getOwnPropertyDescriptor may not hide a non-configurable property,
        // invent one, or report one non-configurable that is not.
        const FIXED: &str = "const t = {}; Object.defineProperty(t, 'x', { value: 1 });";
        assert_eq!(caught(&format!("{FIXED} Object.getOwnPropertyDescriptor(new Proxy(t, {{ getOwnPropertyDescriptor() {{ return undefined; }} }}), 'x')")), "TypeError");
        assert_eq!(caught("Object.getOwnPropertyDescriptor(new Proxy(Object.preventExtensions({}), { getOwnPropertyDescriptor() { return { value: 1, configurable: true }; } }), 'x')"), "TypeError");
        assert_eq!(caught("Object.getOwnPropertyDescriptor(new Proxy({ x: 1 }, { getOwnPropertyDescriptor() { return { value: 1, configurable: false }; } }), 'x')"), "TypeError");
        assert_eq!(caught(&format!("{FIXED} Object.getOwnPropertyDescriptor(new Proxy(t, {{ getOwnPropertyDescriptor() {{ return {{ value: 2, configurable: false }}; }} }}), 'x')")), "TypeError");
        assert_eq!(caught("Object.getOwnPropertyDescriptor(new Proxy({}, { getOwnPropertyDescriptor() { return 1; } }), 'x')"), "TypeError");
        // The reported descriptor is a completed copy of the trap's.
        assert_eq!(
            caught("const d = { value: 2, configurable: true, extra: 1 }; const got = Object.getOwnPropertyDescriptor(new Proxy({ a: 1 }, { getOwnPropertyDescriptor() { return d; } }), 'a'); return (got === d) + JSON.stringify(got)"),
            "false{\"value\":2,\"writable\":false,\"enumerable\":false,\"configurable\":true}"
        );
        // ownKeys must list every non-configurable key of the target.
        assert_eq!(caught(&format!("{FIXED} Object.keys(new Proxy(t, {{ ownKeys() {{ return []; }} }}))")), "TypeError");
        assert_eq!(caught(&format!("{FIXED} return Reflect.ownKeys(new Proxy(t, {{ ownKeys() {{ return ['x', 'y']; }} }})).join()")), "x,y");
        // defineProperty may not report a non-configurable property made
        // read-only when the target's is writable, nor a change the target's
        // non-writable property refuses.
        assert_eq!(
            caught("const t = {}; Object.defineProperty(t, 'x', { value: 1, writable: true }); Object.defineProperty(new Proxy(t, { defineProperty() { return true; } }), 'x', { value: 1, writable: false, configurable: false })"),
            "TypeError"
        );
        assert_eq!(
            caught(&format!("{FIXED} Object.defineProperty(new Proxy(t, {{ defineProperty() {{ return true; }} }}), 'x', {{ value: 2 }})")),
            "TypeError"
        );
    }

    #[test]
    fn the_reflect_forms_refuse_a_primitive_and_the_object_forms_pass_it_through() {
        assert_eq!(caught("Reflect.isExtensible(1)"), "TypeError");
        assert_eq!(caught("Reflect.preventExtensions('s')"), "TypeError");
        assert_eq!(
            caught("return [Object.preventExtensions(1), Object.isExtensible(1), Object.isFrozen(1), Object.isSealed('s'), Object.freeze(2), Object.seal(true)].join()"),
            "1,false,true,true,2,true"
        );
        // An array's own keys include `length`, after the indices.
        assert_eq!(caught("const a = [1]; a.x = 2; return Reflect.ownKeys(a).join() + ':' + Object.getOwnPropertyNames(new Proxy(a, {})).join()"), "0,length,x:0,length,x");
    }
}

#[cfg(test)]
mod receiver_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn reflect_set_runs_a_setter_with_the_receiver_as_this() {
        assert_eq!(
            caught("const t = {}; let self; Object.defineProperty(t, 'x', { set(v) { self = this; } }); const r = {}; return Reflect.set(t, 'x', 1, r) + ':' + (self === r)"),
            "true:true"
        );
        assert_eq!(
            caught("const t = Object.create({ set x(v) { this.seen = v; } }); const r = {}; Reflect.set(t, 'x', 5, r); return r.seen + ':' + t.seen"),
            "5:undefined"
        );
        // Through a Proxy without a set trap the receiver still reaches the
        // setter; a set trap is handed it.
        assert_eq!(
            caught("const t = { set x(v) { this.seen = v; } }; const r = {}; Reflect.set(new Proxy(t, {}), 'x', 2, r); return r.seen + ':' + t.seen"),
            "2:undefined"
        );
        assert_eq!(
            caught("let got; const r = {}; Reflect.set(new Proxy({}, { set(t, k, v, recv) { got = recv; return true; } }), 'x', 1, r); return got === r"),
            "true"
        );
    }

    #[test]
    fn reflect_set_writes_a_data_property_on_the_receiver() {
        assert_eq!(caught("const t = { y: 1 }, r = {}; return Reflect.set(t, 'y', 5, r) + ':' + t.y + ':' + r.y"), "true:1:5");
        assert_eq!(caught("const r = { y: 0 }; return Reflect.set({}, 'y', 5, r) + ':' + r.y"), "true:5");
        // The receiver's own property keeps its attributes.
        assert_eq!(
            caught("const r = {}; Object.defineProperty(r, 'y', { value: 0, writable: true }); Reflect.set({}, 'y', 5, r); return r.y + ':' + Object.keys(r).length"),
            "5:0"
        );
        // Refusals: a read-only property on the target, a read-only or
        // accessor property on the receiver, a primitive or non-extensible
        // receiver.
        assert_eq!(caught("return Reflect.set(Object.freeze({ y: 1 }), 'y', 5, {})"), "false");
        assert_eq!(caught("const r = {}; Object.defineProperty(r, 'y', { value: 0 }); return Reflect.set({ y: 1 }, 'y', 5, r) + ':' + r.y"), "false:0");
        assert_eq!(caught("return Reflect.set({ y: 1 }, 'y', 5, { get y() { return 0; } })"), "false");
        assert_eq!(caught("return Reflect.set({}, 'y', 5, 1)"), "false");
        assert_eq!(caught("return Reflect.set({}, 'y', 5, Object.preventExtensions({}))"), "false");
        // The receiver's own definition goes through its defineProperty trap.
        assert_eq!(
            caught("const log = []; const r = new Proxy({}, { defineProperty(t, k, d) { log.push(k + JSON.stringify(d)); return Reflect.defineProperty(t, k, d); } }); Reflect.set({}, 'y', 5, r); return log.join()"),
            "y{\"value\":5,\"writable\":true,\"enumerable\":true,\"configurable\":true}"
        );
    }

    #[test]
    fn reflect_get_runs_a_getter_with_the_receiver_as_this() {
        assert_eq!(caught("const t = { get x() { return this.v; }, v: 1 }; return Reflect.get(t, 'x', { v: 2 }) + ':' + Reflect.get(t, 'x')"), "2:1");
        assert_eq!(caught("const t = Object.create({ get x() { return this.v; } }); return Reflect.get(t, 'x', { v: 3 })"), "3");
        assert_eq!(caught("return Reflect.get(new Proxy({ get x() { return this.v; } }, {}), 'x', { v: 4 })"), "4");
        assert_eq!(caught("let got; const r = {}; Reflect.get(new Proxy({}, { get(t, k, recv) { got = recv; } }), 'x', r); return got === r"), "true");
        assert_eq!(caught("Reflect.get(1, 'x')"), "TypeError");
    }
}

#[cfg(test)]
mod accessor_enumerability_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// Every reader of enumerability over `o`, joined: the descriptor,
    /// propertyIsEnumerable, Object.keys, for-in, spread, JSON and entries.
    const READERS: &str = "const d = Object.getOwnPropertyDescriptor(o, 'x'); const seen = []; for (const k in o) seen.push(k); \
        return [d.enumerable, o.propertyIsEnumerable('x'), Object.keys(o).join('/'), seen.join('/'), Object.keys({ ...o }).join('/'), \
        JSON.stringify(o), Object.entries(o).length, Object.assign({}, o).x].join()";

    #[test]
    fn a_defined_accessor_is_enumerable_only_when_the_descriptor_says_so() {
        assert_eq!(
            caught(&format!("const o = {{}}; Object.defineProperty(o, 'x', {{ get() {{ return 1; }} }}); {READERS}")),
            "false,false,,,,{},0,"
        );
        assert_eq!(
            caught(&format!("const o = {{}}; Object.defineProperty(o, 'x', {{ get() {{ return 1; }}, enumerable: true }}); {READERS}")),
            "true,true,x,x,x,{\"x\":1},1,1"
        );
        // A literal accessor is enumerable; a class accessor and a built-in
        // one are not.
        assert_eq!(caught(&format!("const o = {{ get x() {{ return 1; }} }}; {READERS}")), "true,true,x,x,x,{\"x\":1},1,1");
        assert_eq!(
            caught("class C { get x() { return 1; } static set y(v) {} } return [Object.getOwnPropertyDescriptor(C.prototype, 'x').enumerable, Object.getOwnPropertyDescriptor(C, 'y').enumerable, Object.keys(C.prototype).length].join()"),
            "false,false,0"
        );
        assert_eq!(
            caught("return [Object.getOwnPropertyDescriptor(RegExp.prototype, 'flags').enumerable, Object.getOwnPropertyDescriptor(Map.prototype, 'size').enumerable].join()"),
            "false,false"
        );
        // On an array index the accessor's own flag decides too: one that
        // replaces an element keeps the element's enumerability unless the
        // descriptor names it, and a new one past the end is not
        // enumerable.
        assert_eq!(
            caught("const a = [1, 2, 3]; Object.defineProperty(a, 1, { get() { return 9; }, enumerable: false }); return Object.keys(a).join() + ':' + JSON.stringify(Object.entries(a)) + ':' + a.propertyIsEnumerable(1)"),
            "0,2:[[\"0\",1],[\"2\",3]]:false"
        );
        assert_eq!(
            caught("const a = [1, 2]; Object.defineProperty(a, 1, { get() { return 9; } }); Object.defineProperty(a, 3, { get() { return 7; } }); return Object.keys(a).slice(0, 2).join() + ':' + Object.keys(a).includes('3') + ':' + a.propertyIsEnumerable(1) + a.propertyIsEnumerable(3) + ':' + a.length"),
            "0,1:false:truefalse:4"
        );
    }

    #[test]
    fn redefining_an_accessor_keeps_or_changes_its_enumerability() {
        // A later definition that names `enumerable` changes it; one that
        // does not keeps it, whatever else it replaces.
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { get() { return 1; }, configurable: true }); Object.defineProperty(o, 'x', { enumerable: true }); const a = Object.keys(o).join(); Object.defineProperty(o, 'x', { get() { return 2; } }); return a + ':' + Object.keys(o).join() + ':' + o.x"),
            "x:x:2"
        );
        assert_eq!(
            caught("const o = { get x() { return 1; } }; Object.defineProperty(o, 'x', { enumerable: false }); return Object.keys(o).length + ':' + o.x"),
            "0:1"
        );
        // A non-configurable accessor's enumerability is fixed.
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { get() { return 1; } }); Object.defineProperty(o, 'x', { enumerable: true })"),
            "TypeError"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { get() { return 1; }, enumerable: true }); return Reflect.defineProperty(o, 'x', { enumerable: true }) + ':' + Reflect.defineProperty(o, 'x', { enumerable: false })"),
            "true:false"
        );
    }
}

#[cfg(test)]
mod descriptor_kind_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// The own descriptor of `o.x` as JSON, a function field shown as its
    /// type (JSON drops undefined fields, so `get` and `set` are listed).
    const DESC: &str = "const d = Object.getOwnPropertyDescriptor(o, 'x'); \
        return JSON.stringify(d, (k, v) => typeof v === 'function' ? 'fn' : v) + ('get' in d ? ' get' : '') + ('set' in d ? ' set' : '')";

    #[test]
    fn a_data_descriptor_without_a_value_turns_an_accessor_into_undefined_data() {
        // ES 10.1.6.3 step 6.b: the accessor becomes a data property whose
        // value is undefined and writable false unless given, keeping its
        // configurable and enumerable attributes.
        assert_eq!(
            caught(&format!("const o = {{}}; Object.defineProperty(o, 'x', {{ get() {{ return 1; }}, configurable: true, enumerable: true }}); Object.defineProperty(o, 'x', {{ writable: true }}); {DESC}")),
            "{\"writable\":true,\"enumerable\":true,\"configurable\":true}"
        );
        assert_eq!(
            caught(&format!("const o = {{}}; Object.defineProperty(o, 'x', {{ set(v) {{}}, configurable: true }}); Object.defineProperty(o, 'x', {{ writable: false }}); o.x = 3; {DESC}")),
            "{\"writable\":false,\"enumerable\":false,\"configurable\":true}"
        );
        // It then behaves as data: a write lands, and Object.keys follows
        // its enumerability.
        assert_eq!(
            caught("const o = { get x() { return 1; } }; Object.defineProperty(o, 'x', { writable: true }); const before = o.x; o.x = 5; return before + ':' + o.x + ':' + Object.keys(o)"),
            "undefined:5:x"
        );
        // On an array index the table's accessor goes and the element reads
        // undefined.
        assert_eq!(
            caught("const a = [1, 2, 3]; Object.defineProperty(a, 1, { get() { return 9; }, configurable: true }); Object.defineProperty(a, 1, { writable: true }); a[2] = 4; return a[1] + ':' + a.join() + ':' + Object.keys(a)"),
            "undefined:1,,4:0,1,2"
        );
        // A non-configurable accessor cannot change kind.
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { get() { return 1; } }); Object.defineProperty(o, 'x', { writable: true })"),
            "TypeError"
        );
    }

    #[test]
    fn the_descriptor_fields_present_decide_the_kind_and_absent_ones_are_kept() {
        // An accessor descriptor whose functions are undefined is still an
        // accessor descriptor: it makes a new accessor, turns data into an
        // accessor, and clears just the function it names.
        assert_eq!(
            caught(&format!("const o = {{}}; Object.defineProperty(o, 'x', {{ get: undefined }}); {DESC}")),
            "{\"enumerable\":false,\"configurable\":false} get set"
        );
        assert_eq!(
            caught(&format!("const o = {{ x: 1 }}; Object.defineProperty(o, 'x', {{ set: undefined }}); {DESC}")),
            "{\"enumerable\":true,\"configurable\":true} get set"
        );
        assert_eq!(
            caught("let seen; const o = { get x() { return 1; }, set x(v) { seen = v; } }; Object.defineProperty(o, 'x', { get: undefined }); o.x = 7; return o.x + ':' + seen"),
            "undefined:7"
        );
        // A value-only redefinition keeps the property's enumerability.
        assert_eq!(
            caught("const o = { x: 1 }; Object.defineProperty(o, 'x', { value: 2 }); return Object.keys(o) + ':' + o.x"),
            "x:2"
        );
        assert_eq!(
            caught("const o = {}; Object.defineProperty(o, 'x', { value: 1, writable: true, configurable: true }); Object.defineProperty(o, 'x', { value: 2 }); return Object.keys(o).length + ':' + o.x"),
            "0:2"
        );
    }
}

#[cfg(test)]
mod get_prototype_of_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn every_prototype_read_calls_the_get_prototype_of_trap() {
        // Reflect.getPrototypeOf, Object.getPrototypeOf, instanceof and
        // isPrototypeOf all ask the trap, which runs with the handler as
        // `this` and the target as its argument.
        assert_eq!(
            caught("class C {} const t = {}; const calls = []; const h = { getPrototypeOf(tt) { calls.push(this === h && tt === t); return C.prototype; } }; const p = new Proxy(t, h); \
                    return [Reflect.getPrototypeOf(p) === C.prototype, Object.getPrototypeOf(p) === C.prototype, p instanceof C, C.prototype.isPrototypeOf(p), calls.join()].join()"),
            "true,true,true,true,true,true,true,true"
        );
        // The trap answers for a Proxy anywhere on the instanceof walk.
        assert_eq!(
            caught("class C {} const mid = new Proxy({}, { getPrototypeOf() { return C.prototype; } }); return Object.create(mid) instanceof C"),
            "true"
        );
        // Without a trap the target's current prototype is the answer, not
        // the one it had when the Proxy was made.
        assert_eq!(
            caught("const a = {}, b = {}; const t = Object.create(a); const p = new Proxy(t, {}); Object.setPrototypeOf(t, b); return (Object.getPrototypeOf(p) === b) + ':' + (Reflect.getPrototypeOf(p) === b) + ':' + b.isPrototypeOf(p)"),
            "true:true:true"
        );
    }

    #[test]
    fn the_trap_result_is_held_to_its_invariant() {
        // The result must be an object or null.
        assert_eq!(caught("return Object.getPrototypeOf(new Proxy({}, { getPrototypeOf() { return 1; } }))"), "TypeError");
        assert_eq!(caught("return Object.getPrototypeOf(new Proxy({}, { getPrototypeOf() { return null; } }))"), "null");
        // A non-extensible target's prototype cannot be misreported.
        assert_eq!(
            caught("const t = Object.preventExtensions({}); return Object.getPrototypeOf(new Proxy(t, { getPrototypeOf() { return Array.prototype; } }))"),
            "TypeError"
        );
        assert_eq!(
            caught("const t = Object.preventExtensions({}); return Reflect.getPrototypeOf(new Proxy(t, { getPrototypeOf() { return Object.prototype; } })) === Object.prototype"),
            "true"
        );
        // A trap that is neither callable nor undefined is a TypeError.
        assert_eq!(caught("return Object.getPrototypeOf(new Proxy({}, { getPrototypeOf: 1 }))"), "TypeError");
    }

    #[test]
    fn primitives_follow_each_entry_points_rule() {
        // Object.getPrototypeOf converts with ToObject; Reflect refuses.
        assert_eq!(
            caught("return [Object.getPrototypeOf('s') === String.prototype, Object.getPrototypeOf(1) === Number.prototype, Object.getPrototypeOf(true) === Boolean.prototype].join()"),
            "true,true,true"
        );
        assert_eq!(caught("return Object.getPrototypeOf(null)"), "TypeError");
        assert_eq!(caught("return Reflect.getPrototypeOf(1)"), "TypeError");
    }
}

#[cfg(test)]
mod string_wrapper_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_string_wrapper_owns_its_characters_and_length() {
        assert_eq!(
            caught("const s = new String('ab'); const fi = []; for (const k in s) fi.push(k); \
                    return [s[0], s[1], String(s[2]), s.length, Object(s) === s, 0 in s, s.hasOwnProperty(1), s.hasOwnProperty('length'), \
                            Object.keys(s).join('/'), Object.getOwnPropertyNames(s).join('/'), fi.join('/'), Object.entries(s).join('|'), Reflect.get(s, 'length', {})].join(' ')"),
            "a b undefined 2 true true true true 0/1 0/1/length 0/1 0,a|1,b 2"
        );
        assert_eq!(
            caught("const d = Object.getOwnPropertyDescriptor(new String('ab'), 1); const l = Object.getOwnPropertyDescriptor(new String('ab'), 'length'); \
                    return JSON.stringify(d) + ' ' + JSON.stringify(l)"),
            "{\"value\":\"b\",\"writable\":false,\"enumerable\":true,\"configurable\":false} {\"value\":2,\"writable\":false,\"enumerable\":false,\"configurable\":false}"
        );
        // Primitives reach the same properties through ToObject.
        assert_eq!(caught("return ['ab'.hasOwnProperty(0), Object.getOwnPropertyNames('ab').join('/'), Object.keys('ab').join('/')].join(' ')"), "true 0/1/length 0/1");
    }

    #[test]
    fn a_string_wrappers_characters_and_length_are_read_only() {
        assert_eq!(
            caught("const s = new String('ab'); s[0] = 'x'; s.length = 9; s[2] = 'c'; s.extra = 1; \
                    return [s[0], s.length, s[2], s.extra, delete s[0], delete s.length, Reflect.set(s, 0, 'y'), Reflect.defineProperty(s, 0, { value: 'z' }), Reflect.defineProperty(s, 0, { value: 'a' }), String(s)].join(' ')"),
            "a 2 c 1 false false false false true ab"
        );
        assert_eq!(caught("'use strict'; new String('ab')[1] = 'x'"), "TypeError");
        assert_eq!(caught("'use strict'; new String('ab').length = 0"), "TypeError");
    }
}

#[cfg(test)]
mod own_key_order_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn integer_keys_come_first_in_ascending_order() {
        // OrdinaryOwnPropertyKeys (ES 10.1.11.1): array indices ascending,
        // then string keys in creation order, then symbols.
        assert_eq!(
            caught("const s = Symbol('s'); const o = { b: 1, 10: 'x', a: 2, [s]: 0, 2: 'y', '01': 'z', 4294967295: 'big' }; const fi = []; for (const k in o) fi.push(k); \
                    return [Object.keys(o).join('/'), Object.getOwnPropertyNames(o).join('/'), Reflect.ownKeys(o).map(String).join('/'), fi.join('/'), JSON.stringify(o), Object.entries(o).map(e => e[0]).join('/')].join(' | ')"),
            "2/10/b/a/01/4294967295 | 2/10/b/a/01/4294967295 | 2/10/b/a/01/4294967295/Symbol(s) | 2/10/b/a/01/4294967295 | {\"2\":\"y\",\"10\":\"x\",\"b\":1,\"a\":2,\"01\":\"z\",\"4294967295\":\"big\"} | 2/10/b/a/01/4294967295"
        );
        // An Array's indices come before `length` and its named keys; a
        // String wrapper's characters before `length`.
        assert_eq!(caught("const a = [1]; a.x = 1; a[3] = 2; return Object.getOwnPropertyNames(a).join('/')"), "0/3/length/x");
        assert_eq!(caught("const s = new String('ab'); s.x = 1; s[5] = 2; return Object.getOwnPropertyNames(s).join('/')"), "0/1/5/length/x");
        assert_eq!(caught("return Object.keys(Object.assign({}, { z: 1, 3: 2, 1: 3 })).join('/')"), "1/3/z");
    }
}

#[cfg(test)]
mod proto_property_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_proto_entry_in_an_object_literal_sets_the_prototype() {
        // ES 13.2.5.5 PropertyDefinitionEvaluation: `__proto__: v` (not
        // computed, not shorthand) sets [[Prototype]] when v is an object
        // or null and creates no own property; any other value is ignored.
        assert_eq!(
            caught("const o = { __proto__: Array.prototype, a: 1 }; return [o instanceof Array, Object.keys(o).join(), o.hasOwnProperty('__proto__')].join()"),
            "true,a,false"
        );
        assert_eq!(caught("const o = { '__proto__': null }; return Object.getPrototypeOf(o) === null"), "true");
        assert_eq!(caught("const o = { __proto__: 1 }; return [Object.getPrototypeOf(o) === Object.prototype, Object.keys(o).length].join()"), "true,0");
        // A computed or shorthand `__proto__` is an ordinary own property.
        assert_eq!(
            caught("const __proto__ = Array.prototype; const a = { ['__proto__']: 1 }, b = { __proto__ }; return [Object.keys(a).join(), a instanceof Array, Object.keys(b).join(), b instanceof Array].join()"),
            "__proto__,false,__proto__,false"
        );
        assert_eq!(caught("const p = { greet() { return 'hi'; } }; return ({ __proto__: p }).greet()"), "hi");
    }

    #[test]
    fn object_prototype_proto_is_an_accessor_over_the_prototype() {
        assert_eq!(
            caught("const d = Object.getOwnPropertyDescriptor(Object.prototype, '__proto__'); return [typeof d.get, typeof d.set, d.enumerable, d.configurable, d.get.name, d.set.name].join()"),
            "function,function,false,true,get __proto__,set __proto__"
        );
        assert_eq!(caught("const o = {}; o.__proto__ = Array.prototype; return [o instanceof Array, [].__proto__ === Array.prototype, 'x'.__proto__ === String.prototype, Object.keys(o).length].join()"), "true,true,true,0");
        // A non-object value is ignored; a cycle or a non-extensible
        // object is a TypeError; null and undefined receivers are refused.
        assert_eq!(caught("const o = {}; o.__proto__ = 5; return Object.getPrototypeOf(o) === Object.prototype"), "true");
        assert_eq!(caught("const a = {}, b = Object.create(a); a.__proto__ = b"), "TypeError");
        assert_eq!(caught("const o = Object.preventExtensions({}); o.__proto__ = Array.prototype"), "TypeError");
        assert_eq!(caught("return Object.getOwnPropertyDescriptor(Object.prototype, '__proto__').get.call(null)"), "TypeError");
        // An object without Object.prototype on its chain has no accessor:
        // `__proto__` is an ordinary key there.
        assert_eq!(caught("const o = Object.create(null); o.__proto__ = Array.prototype; return [Object.getPrototypeOf(o) === null, Object.keys(o).join()].join()"), "true,__proto__");
        // JSON.parse creates an own property; it does not set the prototype.
        assert_eq!(caught("const o = JSON.parse('{\"__proto__\": []}'); return [Array.isArray(o), Object.keys(o).join()].join()"), "false,__proto__");
    }
}

#[cfg(test)]
mod property_is_enumerable_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn property_is_enumerable_asks_get_own_property() {
        // ES 20.1.3.4: ToPropertyKey, ToObject, then [[GetOwnProperty]],
        // which a Proxy answers with its trap.
        assert_eq!(
            caught("const log = []; const p = new Proxy({ a: 1 }, { getOwnPropertyDescriptor(t, k) { log.push(k); return { value: 1, enumerable: false, configurable: true }; } }); \
                    return [p.propertyIsEnumerable('a'), Object.prototype.propertyIsEnumerable.call(p, 'b'), log.join()].join()"),
            "false,false,a,b"
        );
        // The trap's invariants hold: a non-extensible target cannot gain
        // a property through it.
        assert_eq!(caught("const p = new Proxy(Object.preventExtensions({ a: 1 }), { getOwnPropertyDescriptor(t, k) { return { value: 1, enumerable: true, configurable: true }; } }); return p.propertyIsEnumerable('zz')"), "TypeError");
        assert_eq!(caught("const p = new Proxy({ a: 1 }, {}); return [p.propertyIsEnumerable('a'), p.propertyIsEnumerable('toString')].join()"), "true,false");
        // Primitives are converted; null and undefined are refused.
        assert_eq!(caught("return ['abc'.propertyIsEnumerable(0), 'abc'.propertyIsEnumerable('length'), [1].propertyIsEnumerable('length'), [1].propertyIsEnumerable(0)].join()"), "true,false,false,true");
        assert_eq!(caught("return Object.prototype.propertyIsEnumerable.call(null, 'a')"), "TypeError");
        assert_eq!(caught("const s = Symbol(); const o = { [s]: 1 }; Object.defineProperty(o, 'h', { value: 1 }); return [o.propertyIsEnumerable(s), o.propertyIsEnumerable('h')].join()"), "true,false");
    }
}

#[cfg(test)]
mod proxy_has_invariant_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_has_trap_cannot_hide_what_the_target_must_show() {
        // ES 10.5.7 steps 9-10: reporting false is refused for a
        // non-configurable own property of the target, and for any own
        // property of a non-extensible target.
        assert_eq!(caught("const t = {}; Object.defineProperty(t, 'x', { value: 1 }); return 'x' in new Proxy(t, { has() { return false; } })"), "TypeError");
        assert_eq!(caught("const t = Object.preventExtensions({ y: 1 }); return Reflect.has(new Proxy(t, { has() { return 0; } }), 'y')"), "TypeError");
        assert_eq!(caught("const t = Object.freeze([1]); return 0 in new Proxy(t, { has() { return false; } })"), "TypeError");
        // Hiding a configurable property of an extensible target, or one
        // the target does not have, is allowed; a true result is never
        // checked.
        assert_eq!(caught("const p = new Proxy({ x: 1 }, { has() { return false; } }); return ['x' in p, 'nope' in p].join()"), "false,false");
        assert_eq!(caught("const t = Object.preventExtensions({}); return 'z' in new Proxy(t, { has() { return true; } })"), "true");
        // A Proxy reached through the prototype chain is checked too.
        assert_eq!(caught("const t = {}; Object.defineProperty(t, 'x', { value: 1 }); const o = Object.create(new Proxy(t, { has() { return false; } })); return 'x' in o"), "TypeError");
    }
}
