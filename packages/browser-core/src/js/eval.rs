//! eval — the expression half of the interpreter: `Interp::eval`, property
//! get/set along prototype chains, operators, and calls.
//!
//! Split from `interp.rs` so each half stays reviewable; both are `impl`
//! blocks on the same `Interp` type. Panic-free: no indexing, no unwrap.

use std::rc::Rc;

use super::ast::{AssignOp, BinaryOp, Expr, LogicalOp, MemberKey, MethodKind, ObjectProp, PropKey, SpreadElem, TemplateElem, UnaryOp, UpdateOp};
use super::interp::{Interp, Scope, ScopeRef};
use super::value::{JsObject, JsValue, ObjKind, ObjRef, Prop, SYM_HAS_INSTANCE, SYM_TO_PRIMITIVE, array_index, is_symbol_key, symbol_key};

/// The largest dense array the engine materialises on an index or
/// `length` write. Indices at or beyond it live in the property table.
pub const MAX_DENSE: usize = 10_000_000;

impl<'h> Interp<'h> {
    /// Evaluate one expression.
    pub fn eval(&mut self, expr: &Expr, scope: &ScopeRef) -> Result<JsValue, JsValue> {
        self.charge_pub()?;
        match expr {
            Expr::Num(n) => Ok(JsValue::Num(*n)),
            Expr::Str(s) => Ok(JsValue::str(s.clone())),
            Expr::Bool(b) => Ok(JsValue::Bool(*b)),
            Expr::Null => Ok(JsValue::Null),
            Expr::Undefined => Ok(JsValue::Undefined),
            Expr::This => Ok(Scope::get(scope, "this").unwrap_or(JsValue::Undefined)),
            Expr::Ident(name) => match Scope::get(scope, name) {
                Some(v) => Ok(v),
                None => {
                    if name == "new.target" {
                        return Ok(JsValue::Undefined);
                    }
                    // Fall back to global object properties (window.foo).
                    let g = self.global_object.clone();
                    let has = g.borrow().own(name).is_some();
                    if has {
                        self.get_property(&JsValue::Object(g), name)
                    } else {
                        Err(Self::throw(format!(
                            "ReferenceError: {name} is not defined"
                        )))
                    }
                }
            },
            Expr::Template(parts) => {
                let mut out = String::new();
                for p in parts {
                    match p {
                        TemplateElem::Str(s) => out.push_str(s),
                        TemplateElem::Expr(e) => {
                            let v = self.eval(e, scope)?;
                            out.push_str(&self.to_string_value(&v)?);
                        }
                    }
                }
                Ok(JsValue::str(out))
            }
            Expr::Regex { source, flags } => {
                let obj = JsObject::new(
                    ObjKind::RegExp {
                        source: source.clone(),
                        flags: flags.clone(),
                    },
                    Some(self.regexp_proto.clone()),
                );
                Ok(JsValue::Object(obj))
            }
            Expr::Array(elems) => {
                // An elision leaves a hole (ES §13.2.4.1).
                let mut out = Vec::new();
                for e in elems {
                    match e {
                        None => out.push(None),
                        Some(se) => {
                            let v = self.eval(&se.expr, scope)?;
                            if se.spread {
                                out.extend(self.iterate(&v)?.into_iter().map(Some));
                            } else {
                                out.push(Some(v));
                            }
                        }
                    }
                }
                Ok(self.new_array_with_holes(out))
            }
            Expr::Object(props) => {
                let obj = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
                for p in props {
                    match p {
                        // `__proto__: v` sets the new object's prototype
                        // when v is an object or null and is otherwise
                        // ignored; it creates no own property (ES
                        // 13.2.5.5). A computed or shorthand `__proto__`
                        // is an ordinary key.
                        ObjectProp::KeyValue(PropKey::Static(k), value) if k == "__proto__" => {
                            match self.eval(value, scope)? {
                                JsValue::Object(p) => obj.borrow_mut().proto = Some(p),
                                JsValue::Null => obj.borrow_mut().proto = None,
                                _ => {}
                            }
                        }
                        ObjectProp::KeyValue(key, value) => {
                            let k = self.prop_key(key, scope)?;
                            let v = self.eval(value, scope)?;
                            if super::function_meta::is_anonymous_function_definition(value) {
                                let name = self.function_name_for_key(&k, None);
                                self.name_anonymous_function(&v, &name);
                            }
                            obj.borrow_mut().set_prop(&k, v, true);
                        }
                        ObjectProp::Shorthand(name) | ObjectProp::ShorthandDefault(name, _) => {
                            let v = match Scope::get(scope, name) {
                                Some(v) => v,
                                None => {
                                    let g = self.global_object.clone();
                                    if g.borrow().own(name).is_some() {
                                        self.get_property(&JsValue::Object(g), name)?
                                    } else {
                                        return Err(Self::throw(format!(
                                            "ReferenceError: {name} is not defined"
                                        )));
                                    }
                                }
                            };
                            obj.borrow_mut().set_prop(name, v, true);
                        }
                        ObjectProp::Method(key, def, kind) => {
                            let k = self.prop_key(key, scope)?;
                            let f = self.make_method(def.clone(), scope.clone());
                            let prefix = match kind {
                                MethodKind::Method => None,
                                MethodKind::Get => Some("get"),
                                MethodKind::Set => Some("set"),
                            };
                            let name = self.function_name_for_key(&k, prefix);
                            if let JsValue::Object(fo) = &f {
                                fo.borrow_mut().set_prop("name", JsValue::str(name), false);
                            }
                            match kind {
                                MethodKind::Method => obj.borrow_mut().set_prop(&k, f, true),
                                MethodKind::Get => {
                                    if let JsValue::Object(fo) = f {
                                        obj.borrow_mut().set_accessor(&k, Some(fo), None, true);
                                    }
                                }
                                MethodKind::Set => {
                                    if let JsValue::Object(fo) = f {
                                        obj.borrow_mut().set_accessor(&k, None, Some(fo), true);
                                    }
                                }
                            }
                        }
                        // CopyDataProperties (ES §7.3.25): every enumerable
                        // own key, string and symbol, read through [[Get]],
                        // so getters run and an array's elements come from
                        // wherever they live.
                        ObjectProp::Spread(e) => {
                            let v = self.eval(e, scope)?;
                            if let JsValue::Object(src) = &v {
                                for k in self.enumerable_own_keys(src, true)? {
                                    let value = self.get_property(&v, &k)?;
                                    obj.borrow_mut().set_prop(&k, value, true);
                                }
                            }
                        }
                    }
                }
                Ok(JsValue::Object(obj))
            }
            Expr::Function(def) => {
                let this = if def.arrow {
                    Scope::get(scope, "this")
                } else {
                    None
                };
                // A NAMED function expression (`var c = function e() { e() }`)
                // binds its own name in a scope of its own, visible to the
                // body and to nothing else (ES §15.2.5). Without it the name
                // resolves to whatever the enclosing scope calls `e` — three
                // corpus bundles (New Relic's event emitter, Prism's
                // `encode`, a Parcel runtime) called a module object that
                // way and died with "value is not callable".
                match (&def.name, def.arrow) {
                    (Some(name), false) => {
                        let own = Scope::new(Some(scope.clone()));
                        let f = self.make_function(def.clone(), own.clone(), this);
                        Scope::declare(&own, name, f.clone(), false);
                        Ok(f)
                    }
                    _ => Ok(self.make_function(def.clone(), scope.clone(), this)),
                }
            }
            Expr::Class(def) => self.make_class_pub(def, scope),
            Expr::Unary { op, expr } => self.eval_unary(*op, expr, scope),
            Expr::Update { op, prefix, target } => self.eval_update(*op, *prefix, target, scope),
            Expr::Binary { op, left, right } => {
                let l = self.eval(left, scope)?;
                let r = self.eval(right, scope)?;
                self.binary_op(*op, l, r)
            }
            Expr::Logical { op, left, right } => {
                let l = self.eval(left, scope)?;
                match op {
                    LogicalOp::And => {
                        if l.truthy() {
                            self.eval(right, scope)
                        } else {
                            Ok(l)
                        }
                    }
                    LogicalOp::Or => {
                        if l.truthy() {
                            Ok(l)
                        } else {
                            self.eval(right, scope)
                        }
                    }
                    LogicalOp::Nullish => {
                        if l.is_nullish() {
                            self.eval(right, scope)
                        } else {
                            Ok(l)
                        }
                    }
                }
            }
            Expr::Assign { op, target, value } => self.eval_assign(*op, target, value, scope),
            Expr::Cond { cond, then, alt } => {
                if self.eval(cond, scope)?.truthy() {
                    self.eval(then, scope)
                } else {
                    self.eval(alt, scope)
                }
            }
            Expr::Call {
                callee,
                args,
                optional,
            } => {
                // Evaluate callee, keeping `this` for method calls.
                let (f, this) = match callee.as_ref() {
                    // super(...) — invoke the parent constructor with the
                    // CURRENT `this` (bound in the class scope chain).
                    Expr::Ident(name) if name == "super" => {
                        let ctor = Scope::get(scope, "__super_ctor__").ok_or_else(|| {
                            Self::throw("SyntaxError: 'super' keyword unexpected here")
                        })?;
                        let this = Scope::get(scope, "this").unwrap_or(JsValue::Undefined);
                        let argv = self.eval_args(args, scope)?;
                        // The parent constructor runs as a CONSTRUCT, with
                        // `new.target` still the derived class: a class
                        // parent would reject a plain [[Call]], and a base
                        // class's field initialisers must run against the
                        // derived instance before the parent body does.
                        let nt = Scope::get(scope, "new.target")
                            .filter(|v| matches!(v, JsValue::Object(_)))
                            .unwrap_or_else(|| ctor.clone());
                        if let JsValue::Object(pc) = &ctor {
                            let is_derived = pc.borrow().get_prop("__super__").is_some();
                            if !is_derived {
                                let pc = pc.clone();
                                self.init_fields(&pc, &this)?;
                            }
                        }
                        let saved = self.new_target.replace(nt);
                        let r = self.call(ctor.clone(), this.clone(), &argv);
                        self.new_target = saved;
                        let r = r?;
                        // A base constructor that RETURNS an object makes it
                        // the instance (ES §10.2.2 [[Construct]] step 10):
                        // `this` is rebound for the rest of the derived
                        // constructor and the outer `new` answers with it.
                        // `HTMLElement` does exactly this for a custom
                        // element under construction.
                        let this = match (&r, &this) {
                            (JsValue::Object(ro), JsValue::Object(to)) if !Rc::ptr_eq(ro, to) => {
                                let _ = Scope::set(scope, "this", r.clone());
                                self.super_this = Some(ro.clone());
                                r.clone()
                            }
                            _ => this,
                        };
                        // This class's own fields initialise right after
                        // super() returns.
                        if let Some(JsValue::Object(me)) = Scope::get(scope, "__class_ctor__") {
                            self.init_fields(&me, &this)?;
                        }
                        return Ok(JsValue::Undefined);
                    }
                    // super.m(...) — look the method up on the parent
                    // prototype but keep the CURRENT `this`.
                    Expr::Member {
                        object,
                        property,
                        optional: mopt,
                    } if matches!(object.as_ref(), Expr::Ident(n) if n == "super") => {
                        let proto = Scope::get(scope, "__super_proto__").ok_or_else(|| {
                            Self::throw("SyntaxError: 'super' keyword unexpected here")
                        })?;
                        let _ = mopt;
                        let key = self.member_key(property, scope)?;
                        let f = self.get_property(&proto, &key)?;
                        let this = Scope::get(scope, "this").unwrap_or(JsValue::Undefined);
                        (f, this)
                    }
                    Expr::Member {
                        object,
                        property,
                        optional: mopt,
                    } => {
                        let obj = self.eval(object, scope)?;
                        if (*mopt || *optional) && obj.is_nullish() {
                            return Ok(JsValue::Undefined);
                        }
                        let key = self.member_key(property, scope)?;
                        let f = self.get_property(&obj, &key)?;
                        (f, obj)
                    }
                    Expr::Ident(name) if name == "eval" => {
                        // Indirect eval is not supported; treat as identity of
                        // its argument's completion where trivially safe.
                        (
                            Scope::get(scope, "eval").unwrap_or(JsValue::Undefined),
                            JsValue::Undefined,
                        )
                    }
                    other => (self.eval(other, scope)?, JsValue::Undefined),
                };
                if *optional && f.is_nullish() {
                    return Ok(JsValue::Undefined);
                }
                let argv = self.eval_args(args, scope)?;
                self.call(f, this, &argv)
            }
            Expr::New { callee, args } => {
                let f = self.eval(callee, scope)?;
                let argv = self.eval_args(args, scope)?;
                self.construct(f, &argv)
            }
            Expr::Member {
                object,
                property,
                optional,
            } => {
                let obj = self.eval(object, scope)?;
                if *optional && obj.is_nullish() {
                    return Ok(JsValue::Undefined);
                }
                let key = self.member_key(property, scope)?;
                self.get_property(&obj, &key)
            }
            Expr::Sequence(exprs) => {
                let mut last = JsValue::Undefined;
                for e in exprs {
                    last = self.eval(e, scope)?;
                }
                Ok(last)
            }
            Expr::Await(e) => {
                let v = self.eval(e, scope)?;
                match &v {
                    JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::Promise(_)) => {
                        let p = o.clone();
                        self.await_promise(&p)
                    }
                    _ => Ok(v), // await non-promise yields the value
                }
            }
            Expr::Spread(e) => self.eval(e, scope), // handled by callers; lone spread degrades
            Expr::Yield { .. } => {
                // Every `yield` a generator body contains is executed by the
                // coroutine executor (`coroutine.rs`), which suspends on it as
                // a statement (after `desugar.rs` lowered any expression
                // position). One reaching the plain evaluator is outside a
                // generator body, which the parser only admits for the
                // identifier `yield` in sloppy code (handled as an Ident).
                Err(Self::throw("SyntaxError: yield outside a generator"))
            }
        }
    }

    fn eval_args(
        &mut self,
        args: &[SpreadElem],
        scope: &ScopeRef,
    ) -> Result<Vec<JsValue>, JsValue> {
        let mut out = Vec::new();
        for a in args {
            let v = self.eval(&a.expr, scope)?;
            if a.spread {
                out.extend(self.iterate(&v)?);
            } else {
                out.push(v);
            }
        }
        Ok(out)
    }

    fn prop_key(&mut self, key: &PropKey, scope: &ScopeRef) -> Result<String, JsValue> {
        match key {
            PropKey::Static(s) => Ok(s.clone()),
            PropKey::Computed(e) => {
                let v = self.eval(e, scope)?;
                self.to_property_key(&v)
            }
        }
    }

    fn member_key(&mut self, key: &MemberKey, scope: &ScopeRef) -> Result<String, JsValue> {
        match key {
            MemberKey::Static(s) => Ok(s.clone()),
            MemberKey::Computed(e) => {
                let v = self.eval(e, scope)?;
                self.to_property_key(&v)
            }
        }
    }

    /// The JS value a property-table key stands for (a symbol key becomes
    /// the symbol, anything else the string), for trap arguments.
    pub fn key_value(&mut self, key: &str) -> JsValue {
        if is_symbol_key(key) {
            self.symbol_for_key(key)
        } else {
            JsValue::str(key)
        }
    }

    /// ToPropertyKey: symbols select their reserved table key, objects go
    /// through ToPrimitive (hint string), everything else through ToString.
    pub fn to_property_key(&mut self, v: &JsValue) -> Result<String, JsValue> {
        Ok(match v {
            JsValue::Symbol(_) => {
                self.note_symbol(v);
                v.to_property_key()
            }
            JsValue::Object(_) => {
                let p = self.to_primitive_hint(v, "string")?;
                self.note_symbol(&p);
                p.to_property_key()
            }
            other => other.to_js_string(),
        })
    }

    /// The `(target, handler)` pair of a Proxy object, or None for any
    /// other object.
    pub fn proxy_parts(o: &ObjRef) -> Option<(ObjRef, ObjRef)> {
        match &o.borrow().kind {
            ObjKind::Proxy { target, handler } => Some((target.clone(), handler.clone())),
            _ => None,
        }
    }

    /// The handler's trap named `name`: `None` when the handler has no such
    /// trap (undefined or null, per GetMethod), the callable otherwise. Any
    /// other value is a TypeError — `{ ownKeys: 1 }` must not read as "no
    /// trap".
    pub(super) fn proxy_trap(&mut self, handler: &ObjRef, name: &str) -> Result<Option<JsValue>, JsValue> {
        let trap = self.get_property(&JsValue::Object(handler.clone()), name)?;
        match &trap {
            JsValue::Undefined | JsValue::Null => Ok(None),
            JsValue::Object(t) if t.borrow().is_callable() => Ok(Some(trap)),
            _ => Err(Self::throw(format!(
                "TypeError: proxy handler's '{name}' trap is not a function"
            ))),
        }
    }

    /// [[Delete]]: a Proxy resolves its `deleteProperty` trap with
    /// GetMethod semantics (undefined or null means no trap, any other
    /// non-callable value is a TypeError) and otherwise forwards to its
    /// target; an ordinary object removes the own property and reports
    /// whether it could.
    pub fn delete_property(&mut self, o: &ObjRef, key: &str) -> Result<bool, JsValue> {
        if let Some((target, handler)) = Self::proxy_parts(o) {
            if let Some(trap) = self.proxy_trap(&handler, "deleteProperty")? {
                let kv = self.key_value(key);
                let out = self.call(trap, JsValue::Object(handler), &[JsValue::Object(target.clone()), kv])?;
                if !out.truthy() {
                    return Ok(false);
                }
                // Invariant (ES §10.5.10): a trap may not report a
                // non-configurable property of the target deleted.
                let t = target.borrow();
                if t.has_own_key(key) && !t.is_configurable(key) {
                    return Err(Self::throw(format!(
                        "TypeError: 'deleteProperty' on proxy: trap returned truish for property '{key}' which is non-configurable in the proxy target"
                    )));
                }
                return Ok(true);
            }
            return self.delete_property(&target, key);
        }
        Ok(o.borrow_mut().delete(key))
    }

    /// [[GetPrototypeOf]] (ES §10.1.1, §10.5.1 for a Proxy): an ordinary
    /// object's prototype; a Proxy calls its `getPrototypeOf` trap
    /// (resolved with GetMethod semantics) with the handler as `this` and
    /// the target, and otherwise asks its target. The trap must answer an
    /// object or null, and for a non-extensible target exactly the
    /// target's own prototype.
    pub fn get_prototype_of(&mut self, o: &ObjRef) -> Result<Option<ObjRef>, JsValue> {
        let Some((target, handler)) = Self::proxy_parts(o) else {
            return Ok(o.borrow().proto.clone());
        };
        let Some(trap) = self.proxy_trap(&handler, "getPrototypeOf")? else {
            self.charge_pub()?;
            return self.get_prototype_of(&target);
        };
        let reported = match self.call(trap, JsValue::Object(handler), &[JsValue::Object(target.clone())])? {
            JsValue::Object(p) => Some(p),
            JsValue::Null => None,
            _ => {
                return Err(Self::throw(
                    "TypeError: 'getPrototypeOf' on proxy: trap returned neither object nor null",
                ))
            }
        };
        if self.is_extensible(&target)? {
            return Ok(reported);
        }
        let actual = self.get_prototype_of(&target)?;
        let same = match (&reported, &actual) {
            (Some(a), Some(b)) => Rc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if !same {
            return Err(Self::throw(
                "TypeError: 'getPrototypeOf' on proxy: proxy target is non-extensible but the trap did not return its actual prototype",
            ));
        }
        Ok(reported)
    }

    /// [[SetPrototypeOf]] (ES §10.1.2 OrdinarySetPrototypeOf, §10.5.2 for
    /// a Proxy): `false` when the object is not extensible and the
    /// prototype would change, or when `proto`'s chain already reaches the
    /// object (a cycle). A Proxy consults its `setPrototypeOf` trap and
    /// otherwise forwards to its target.
    pub fn set_prototype_of(&mut self, o: &ObjRef, proto: Option<ObjRef>) -> Result<bool, JsValue> {
        if let Some((target, handler)) = Self::proxy_parts(o) {
            if let Some(trap) = self.proxy_trap(&handler, "setPrototypeOf")? {
                let p = proto.map(JsValue::Object).unwrap_or(JsValue::Null);
                let out = self.call(trap, JsValue::Object(handler), &[JsValue::Object(target), p])?;
                return Ok(out.truthy());
            }
            return self.set_prototype_of(&target, proto);
        }
        let current = o.borrow().proto.clone();
        let same = match (&current, &proto) {
            (Some(a), Some(b)) => Rc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if same {
            return Ok(true);
        }
        if o.borrow().non_extensible {
            return Ok(false);
        }
        // The chain stops at a Proxy, whose prototype is not ordinary.
        let mut p = proto.clone();
        while let Some(cur) = p {
            if Rc::ptr_eq(&cur, o) {
                return Ok(false);
            }
            if Self::proxy_parts(&cur).is_some() {
                break;
            }
            self.charge_pub()?;
            p = cur.borrow().proto.clone();
        }
        o.borrow_mut().proto = proto;
        Ok(true)
    }

    /// [[OwnPropertyKeys]]: every own key (string keys in insertion order,
    /// array indices first, then symbol keys as table keys) — through a
    /// Proxy's `ownKeys` trap when present, recursively through the target
    /// otherwise. Vue's component-instance proxy answers `Object.keys(this)`
    /// and `hasOwn` checks this way.
    pub fn own_property_keys(&mut self, o: &ObjRef) -> Result<Vec<String>, JsValue> {
        if let Some((target, handler)) = Self::proxy_parts(o) {
            if let Some(trap) = self.proxy_trap(&handler, "ownKeys")? {
                let list = self.call(
                    trap,
                    JsValue::Object(handler),
                    &[JsValue::Object(target.clone())],
                )?;
                if !matches!(list, JsValue::Object(_)) {
                    return Err(Self::throw(
                        "TypeError: ownKeys trap result must be an object",
                    ));
                }
                let items = self.iterate(&list)?;
                let mut out: Vec<String> = Vec::with_capacity(items.len());
                for k in items {
                    match &k {
                        JsValue::Str(_) | JsValue::Symbol(_) => {
                            let key = self.to_property_key(&k)?;
                            if out.contains(&key) {
                                return Err(Self::throw(
                                    "TypeError: ownKeys trap result contains duplicate entries",
                                ));
                            }
                            out.push(key);
                        }
                        _ => {
                            return Err(Self::throw(
                                "TypeError: ownKeys trap result must contain only strings and symbols",
                            ))
                        }
                    }
                }
                // Invariants (ES §10.5.11 steps 9-23): every
                // non-configurable key of the target must be reported, and
                // for a non-extensible target exactly its keys.
                let extensible = self.is_extensible(&target)?;
                let mut fixed = Vec::new();
                let mut configurable = Vec::new();
                for k in self.own_property_keys(&target)? {
                    match self.own_prop_desc(&target, &k)? {
                        Some(d) if d.configurable == Some(false) => fixed.push(k),
                        _ => configurable.push(k),
                    }
                }
                if !extensible || !fixed.is_empty() {
                    let mut unchecked: Vec<&String> = out.iter().collect();
                    let mut required: Vec<(&String, &str)> =
                        fixed.iter().map(|k| (k, "non-configurable")).collect();
                    if !extensible {
                        required.extend(configurable.iter().map(|k| (k, "existing")));
                    }
                    for (k, what) in required {
                        let Some(i) = unchecked.iter().position(|u| *u == k) else {
                            return Err(Self::throw(format!(
                                "TypeError: 'ownKeys' on proxy: trap result did not include the {what} key '{k}' of the proxy target"
                            )));
                        };
                        unchecked.remove(i);
                    }
                    if !extensible && !unchecked.is_empty() {
                        return Err(Self::throw(
                            "TypeError: 'ownKeys' on proxy: trap returned extra keys but the proxy target is non-extensible",
                        ));
                    }
                }
                return Ok(out);
            }
            return self.own_property_keys(&target);
        }
        let b = o.borrow();
        let mut keys = b.own_string_keys_all();
        keys.extend(b.own_symbol_keys());
        Ok(keys)
    }

    /// [[GetOwnProperty]] as a descriptor object (or None when absent),
    /// honouring a Proxy's `getOwnPropertyDescriptor` trap. The returned
    /// object carries `value`/`writable` or `get`/`set`, plus `enumerable`
    /// and `configurable`.
    pub fn own_property_descriptor(
        &mut self,
        o: &ObjRef,
        key: &str,
    ) -> Result<Option<ObjRef>, JsValue> {
        if let Some((target, handler)) = Self::proxy_parts(o) {
            let Some(trap) = self.proxy_trap(&handler, "getOwnPropertyDescriptor")? else {
                return self.own_property_descriptor(&target, key);
            };
            let kv = self.key_value(key);
            let result = self.call(trap, JsValue::Object(handler), &[JsValue::Object(target.clone()), kv])?;
            if !matches!(result, JsValue::Object(_) | JsValue::Undefined) {
                return Err(Self::throw(
                    "TypeError: getOwnPropertyDescriptor trap result must be an object or undefined",
                ));
            }
            // Invariants (ES §10.5.5): a trap may not hide a
            // non-configurable property, nor any property of a
            // non-extensible target; what it reports must be a descriptor
            // the target could hold, and it may report a property
            // non-configurable (or non-configurable and read-only) only
            // when the target's is.
            let target_desc = self.own_prop_desc(&target, key)?;
            if matches!(result, JsValue::Undefined) {
                if let Some(td) = &target_desc {
                    if td.configurable == Some(false) {
                        return Err(Self::throw(format!(
                            "TypeError: 'getOwnPropertyDescriptor' on proxy: trap returned undefined for property '{key}' which is non-configurable in the proxy target"
                        )));
                    }
                    if !self.is_extensible(&target)? {
                        return Err(Self::throw(format!(
                            "TypeError: 'getOwnPropertyDescriptor' on proxy: trap returned undefined for property '{key}' which exists in the non-extensible proxy target"
                        )));
                    }
                }
                return Ok(None);
            }
            let extensible = self.is_extensible(&target)?;
            let mut reported = self.read_property_descriptor(&result)?;
            reported.complete();
            let refused = !super::builtins_es::is_compatible_descriptor(extensible, &reported, target_desc.as_ref())
                || (reported.configurable == Some(false)
                    && match &target_desc {
                        None => true,
                        Some(td) => {
                            td.configurable == Some(true)
                                || (reported.writable == Some(false) && td.writable == Some(true))
                        }
                    });
            if refused {
                return Err(Self::throw(format!(
                    "TypeError: 'getOwnPropertyDescriptor' on proxy: trap reported a descriptor for property '{key}' that is incompatible with the proxy target"
                )));
            }
            return Ok(Some(reported.to_object(self)));
        }
        let desc = super::builtins_es::ordinary_own_desc(&o.borrow(), key);
        Ok(desc.map(|d| d.to_object(self)))
    }

    /// HasOwnProperty through a Proxy's `getOwnPropertyDescriptor` trap;
    /// an ordinary object's property table and its exotic own properties
    /// (array elements, typed-array elements, a String wrapper's
    /// characters and `length`).
    pub fn has_own_property(&mut self, o: &ObjRef, key: &str) -> Result<bool, JsValue> {
        if Self::proxy_parts(o).is_some() {
            return Ok(self.own_property_descriptor(o, key)?.is_some());
        }
        Ok(o.borrow().has_own_key(key))
    }

    /// EnumerableOwnProperties (the `Object.keys` list): own STRING keys
    /// whose descriptor is enumerable, through Proxy traps when present.
    pub fn enumerable_own_string_keys(&mut self, o: &ObjRef) -> Result<Vec<String>, JsValue> {
        self.enumerable_own_keys(o, false)
    }

    /// The enumerable own keys — string keys, plus symbol keys when
    /// `with_symbols` (the `Object.assign` / spread source list) — through
    /// Proxy traps when present.
    pub fn enumerable_own_keys(&mut self, o: &ObjRef, with_symbols: bool) -> Result<Vec<String>, JsValue> {
        // A live facet enumerates the attribute it mirrors.
        let facet = match &o.borrow().kind {
            ObjKind::DomFacet { handle, facet } => Some((*handle, *facet)),
            _ => None,
        };
        if let Some((h, f)) = facet {
            return Ok(super::dom_bindings::facet_keys(self, h, f));
        }
        if Self::proxy_parts(o).is_none() {
            let b = o.borrow();
            let mut keys = b.own_keys();
            if with_symbols {
                keys.extend(b.own_symbol_keys().into_iter().filter(|k| b.is_enumerable(k)));
            }
            return Ok(keys);
        }
        let keys = self.own_property_keys(o)?;
        let mut out = Vec::new();
        for k in keys {
            if !with_symbols && is_symbol_key(&k) {
                continue;
            }
            if let Some(d) = self.own_property_descriptor(o, &k)? {
                let enumerable = d
                    .borrow()
                    .get_prop("enumerable")
                    .map(|v| v.truthy())
                    .unwrap_or(false);
                if enumerable {
                    out.push(k);
                }
            }
        }
        Ok(out)
    }

    fn eval_unary(
        &mut self,
        op: UnaryOp,
        expr: &Expr,
        scope: &ScopeRef,
    ) -> Result<JsValue, JsValue> {
        // typeof of an unresolvable name is "undefined", not a throw.
        if op == UnaryOp::Typeof {
            if let Expr::Ident(name) = expr {
                if Scope::get(scope, name).is_none() {
                    let g = self.global_object.clone();
                    if g.borrow().own(name).is_none() {
                        return Ok(JsValue::str("undefined"));
                    }
                }
            }
        }
        if op == UnaryOp::Delete {
            if let Expr::Member {
                object, property, ..
            } = expr
            {
                let obj = self.eval(object, scope)?;
                let key = self.member_key(property, scope)?;
                let deleted = match &obj {
                    JsValue::Object(o) => self.delete_property(o, &key)?,
                    JsValue::Undefined | JsValue::Null => {
                        return Err(Self::throw(format!(
                            "TypeError: Cannot convert undefined or null to object (deleting '{key}')"
                        )))
                    }
                    // A string's length and indices are its own
                    // non-configurable properties; no other primitive
                    // owns any.
                    JsValue::Str(s) => {
                        let owns = key == "length"
                            || key.parse::<usize>().is_ok_and(|i| i < s.chars().count());
                        !owns
                    }
                    _ => true,
                };
                // Strict code may not ignore a refused delete (ES §13.5.1.2).
                if !deleted && self.is_strict(scope) {
                    return Err(Self::throw(format!(
                        "TypeError: Cannot delete property '{key}' of {}",
                        to_display_brief(&obj)
                    )));
                }
                return Ok(JsValue::Bool(deleted));
            }
            if !matches!(expr, Expr::Ident(_)) {
                // `delete f()` evaluates its operand for its effects.
                self.eval(expr, scope)?;
            }
            return Ok(JsValue::Bool(true));
        }
        let v = self.eval(expr, scope)?;
        Ok(match op {
            UnaryOp::Neg => JsValue::Num(-self.to_number_value(&v)?),
            UnaryOp::Plus => JsValue::Num(self.to_number_value(&v)?),
            UnaryOp::Not => JsValue::Bool(!v.truthy()),
            UnaryOp::BitNot => JsValue::Num(!(to_i32(self.to_number_value(&v)?)) as f64),
            UnaryOp::Typeof => JsValue::str(v.type_of()),
            UnaryOp::Void => JsValue::Undefined,
            UnaryOp::Delete => JsValue::Bool(true),
        })
    }

    fn eval_update(
        &mut self,
        op: UpdateOp,
        prefix: bool,
        target: &Expr,
        scope: &ScopeRef,
    ) -> Result<JsValue, JsValue> {
        // The reference (`o[k()]`) is evaluated once, read, then written.
        let Some(r) = self.eval_reference(target, scope)? else {
            return Err(Self::throw("SyntaxError: invalid update target"));
        };
        let old = self.get_reference(&r, scope)?;
        let old_n = self.to_number_value(&old)?;
        let new_n = match op {
            UpdateOp::Inc => old_n + 1.0,
            UpdateOp::Dec => old_n - 1.0,
        };
        self.put_reference(&r, JsValue::Num(new_n), scope)?;
        Ok(JsValue::Num(if prefix { new_n } else { old_n }))
    }

    /// Evaluate an assignment target to a reference: a binding name, or
    /// the object and property key of a member expression (its object and
    /// key expressions run here, once). `None` for a destructuring
    /// pattern.
    fn eval_reference(&mut self, target: &Expr, scope: &ScopeRef) -> Result<Option<Reference>, JsValue> {
        match target {
            Expr::Ident(name) => Ok(Some(Reference::Binding(name.clone()))),
            Expr::Member {
                object, property, ..
            } => {
                let obj = self.eval(object, scope)?;
                let key = self.member_key(property, scope)?;
                Ok(Some(Reference::Property(obj, key)))
            }
            _ => Ok(None),
        }
    }

    /// GetValue on an evaluated reference (getters run here).
    fn get_reference(&mut self, r: &Reference, scope: &ScopeRef) -> Result<JsValue, JsValue> {
        match r {
            Reference::Binding(name) => self.eval(&Expr::Ident(name.clone()), scope),
            Reference::Property(obj, key) => self.get_property(obj, key),
        }
    }

    /// PutValue on an evaluated reference (setters run here).
    fn put_reference(&mut self, r: &Reference, value: JsValue, scope: &ScopeRef) -> Result<(), JsValue> {
        match r {
            Reference::Binding(name) => self.set_binding(scope, name, value),
            Reference::Property(obj, key) => {
                let strict = self.is_strict(scope);
                self.put_value(obj, key, value, strict)
            }
        }
    }

    fn eval_assign(
        &mut self,
        op: AssignOp,
        target: &Expr,
        value: &Expr,
        scope: &ScopeRef,
    ) -> Result<JsValue, JsValue> {
        // The target REFERENCE (binding, or object and key) is evaluated
        // first and once, so `(b = o).x = b.y` sees the new binding when
        // the right-hand side runs and `o[k()] += 1` calls k once. A
        // compound or logical assignment then reads the target (running a
        // getter) BEFORE the right-hand side is evaluated (ES §13.15.2).
        let Some(r) = self.eval_reference(target, scope)? else {
            // Destructuring: only a plain `=` reaches here.
            let rhs = self.eval(value, scope)?;
            self.assign_to(target, rhs.clone(), scope)?;
            return Ok(rhs);
        };
        match op {
            AssignOp::Assign => {
                let rhs = match target {
                    Expr::Ident(name) => self.eval_named(value, scope, name)?,
                    _ => self.eval(value, scope)?,
                };
                self.put_reference(&r, rhs.clone(), scope)?;
                Ok(rhs)
            }
            AssignOp::And | AssignOp::Or | AssignOp::Nullish => {
                // Short-circuit: the right-hand side runs, and the target
                // is written, only when the current value calls for it.
                let cur = self.get_reference(&r, scope)?;
                let keep = match op {
                    AssignOp::And => !cur.truthy(),
                    AssignOp::Or => cur.truthy(),
                    _ => !cur.is_nullish(),
                };
                if keep {
                    return Ok(cur);
                }
                let v = match target {
                    Expr::Ident(name) => self.eval_named(value, scope, name)?,
                    _ => self.eval(value, scope)?,
                };
                self.put_reference(&r, v.clone(), scope)?;
                Ok(v)
            }
            _ => {
                let cur = self.get_reference(&r, scope)?;
                let rhs = self.eval(value, scope)?;
                let out = self.binary_op(compound_binary_op(op), cur, rhs)?;
                self.put_reference(&r, out.clone(), scope)?;
                Ok(out)
            }
        }
    }

    /// Assign a value to an expression target (identifier or member).
    pub fn assign_to(
        &mut self,
        target: &Expr,
        value: JsValue,
        scope: &ScopeRef,
    ) -> Result<(), JsValue> {
        match target {
            Expr::Ident(name) => self.set_binding(scope, name, value),
            Expr::Member {
                object, property, ..
            } => {
                let obj = self.eval(object, scope)?;
                let key = self.member_key(property, scope)?;
                let strict = self.is_strict(scope);
                self.put_value(&obj, &key, value, strict)
            }
            // Destructuring assignment: `[a, b] = ...`, `({x, y} = ...)`.
            Expr::Array(elems) => {
                let items = self.iterate(&value)?;
                let mut idx = 0usize;
                for elem in elems {
                    let Some(elem) = elem else {
                        idx = idx.saturating_add(1);
                        continue;
                    };
                    if elem.spread {
                        let rest: Vec<JsValue> =
                            items.get(idx..).map(|s| s.to_vec()).unwrap_or_default();
                        let arr = self.new_array(rest);
                        self.assign_to(&elem.expr, arr, scope)?;
                        break;
                    }
                    let v = items.get(idx).cloned().unwrap_or(JsValue::Undefined);
                    // `[a = 1] = [...]` arrives as an Assign target with a
                    // default value.
                    match &elem.expr {
                        Expr::Assign {
                            op: AssignOp::Assign,
                            target,
                            value: default,
                        } => {
                            let v = match (&v, target.as_ref()) {
                                (JsValue::Undefined, Expr::Ident(name)) => self.eval_named(default, scope, name)?,
                                (JsValue::Undefined, _) => self.eval(default, scope)?,
                                _ => v,
                            };
                            self.assign_to(target, v, scope)?;
                        }
                        other => self.assign_to(other, v, scope)?,
                    }
                    idx = idx.saturating_add(1);
                }
                Ok(())
            }
            Expr::Object(props) => {
                let mut taken: Vec<String> = Vec::new();
                for p in props {
                    match p {
                        ObjectProp::Shorthand(name) => {
                            taken.push(name.clone());
                            let v = self.get_property(&value, name)?;
                            self.set_binding(scope, name, v)?;
                        }
                        ObjectProp::ShorthandDefault(name, default) => {
                            taken.push(name.clone());
                            let mut v = self.get_property(&value, name)?;
                            if matches!(v, JsValue::Undefined) {
                                v = self.eval_named(default, scope, name)?;
                            }
                            self.set_binding(scope, name, v)?;
                        }
                        ObjectProp::KeyValue(key, target) => {
                            let k = self.prop_key(key, scope)?;
                            taken.push(k.clone());
                            let v = self.get_property(&value, &k)?;
                            match target {
                                Expr::Assign {
                                    op: AssignOp::Assign,
                                    target: inner,
                                    value: default,
                                } => {
                                    let v = match (&v, inner.as_ref()) {
                                        (JsValue::Undefined, Expr::Ident(name)) => self.eval_named(default, scope, name)?,
                                        (JsValue::Undefined, _) => self.eval(default, scope)?,
                                        _ => v,
                                    };
                                    self.assign_to(inner, v, scope)?;
                                }
                                other => self.assign_to(other, v, scope)?,
                            }
                        }
                        ObjectProp::Spread(target) => {
                            let rest = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
                            if let JsValue::Object(src) = &value {
                                let keys = src.borrow().own_keys();
                                for k in keys {
                                    if !taken.iter().any(|t| t == &k) {
                                        let v = self.get_property(&value, &k)?;
                                        rest.borrow_mut().set_prop(&k, v, true);
                                    }
                                }
                            }
                            self.assign_to(target, JsValue::Object(rest), scope)?;
                        }
                        ObjectProp::Method(..) => {
                            return Err(Self::throw("SyntaxError: invalid destructuring target"))
                        }
                    }
                }
                Ok(())
            }
            _ => Err(Self::throw("SyntaxError: invalid assignment target")),
        }
    }

    /// ToNumber (ES §7.1.4): objects go through ToPrimitive with hint
    /// number, a Symbol is a TypeError, and whatever the script's
    /// conversion methods throw propagates.
    pub fn to_number_value(&mut self, v: &JsValue) -> Result<f64, JsValue> {
        match v {
            JsValue::Symbol(_) => Err(Self::throw(
                "TypeError: Cannot convert a Symbol value to a number",
            )),
            JsValue::Object(_) => {
                let p = self.to_primitive_hint(v, "number")?;
                self.to_number_value(&p)
            }
            other => Ok(other.to_number()),
        }
    }

    /// ToIntegerOrInfinity (ES §7.1.5): ToNumber, then NaN is 0 and the
    /// rest truncates toward zero (infinities stay infinite).
    pub fn to_integer_or_infinity(&mut self, v: &JsValue) -> Result<f64, JsValue> {
        let n = self.to_number_value(v)?;
        Ok(if n.is_nan() { 0.0 } else { n.trunc() })
    }

    /// ToNumber of an optional argument: `absent` when the caller passed
    /// none, the converted value (or the conversion's throw) otherwise.
    pub fn number_arg(&mut self, v: Option<&JsValue>, absent: f64) -> Result<f64, JsValue> {
        match v {
            Some(v) => self.to_number_value(v),
            None => Ok(absent),
        }
    }

    /// ToNumber of an optional argument, `None` when the caller passed none.
    pub fn opt_number_arg(&mut self, v: Option<&JsValue>) -> Result<Option<f64>, JsValue> {
        v.map(|v| self.to_number_value(v)).transpose()
    }

    /// ToString of an optional argument: `absent` when the caller passed
    /// none, the converted value (or the conversion's throw) otherwise.
    pub fn string_arg(&mut self, v: Option<&JsValue>, absent: &str) -> Result<String, JsValue> {
        match v {
            Some(v) => self.to_string_value(v),
            None => Ok(absent.to_string()),
        }
    }

    /// ToString (ES §7.1.17): objects go through ToPrimitive with hint
    /// string, a Symbol is a TypeError, and whatever the script's
    /// conversion methods throw propagates.
    pub fn to_string_value(&mut self, v: &JsValue) -> Result<String, JsValue> {
        match v {
            JsValue::Symbol(_) => Err(Self::throw(
                "TypeError: Cannot convert a Symbol value to a string",
            )),
            JsValue::Object(_) => {
                let p = self.to_primitive_hint(v, "string")?;
                self.to_string_value(&p)
            }
            other => Ok(other.to_js_string()),
        }
    }

    pub fn binary_op(&mut self, op: BinaryOp, l: JsValue, r: JsValue) -> Result<JsValue, JsValue> {
        use super::ast::BinaryOp::{Add, Sub, Mul, Div, Rem, Pow, Eq, NotEq, StrictEq, StrictNotEq, Lt, Gt, LtEq, GtEq, BitAnd, BitOr, BitXor, Shl, Shr, UShr, In, Instanceof};
        Ok(match op {
            Add => {
                // String concatenation wins when either side is a string or
                // an object that stringifies (Date, Array, plain).
                let l_prim = self.to_primitive(&l)?;
                let r_prim = self.to_primitive(&r)?;
                match (&l_prim, &r_prim) {
                    (JsValue::Str(_), _) | (_, JsValue::Str(_)) => {
                        let ls = self.to_string_value(&l_prim)?;
                        let rs = self.to_string_value(&r_prim)?;
                        JsValue::str(format!("{ls}{rs}"))
                    }
                    _ => JsValue::Num(self.to_number_value(&l_prim)? + self.to_number_value(&r_prim)?),
                }
            }
            Sub => JsValue::Num(self.to_number_value(&l)? - self.to_number_value(&r)?),
            Mul => JsValue::Num(self.to_number_value(&l)? * self.to_number_value(&r)?),
            Div => JsValue::Num(self.to_number_value(&l)? / self.to_number_value(&r)?),
            Rem => JsValue::Num(self.to_number_value(&l)? % self.to_number_value(&r)?),
            Pow => JsValue::Num(self.to_number_value(&l)?.powf(self.to_number_value(&r)?)),
            Eq => JsValue::Bool(l.loose_eq(&r)),
            NotEq => JsValue::Bool(!l.loose_eq(&r)),
            StrictEq => JsValue::Bool(l.strict_eq(&r)),
            StrictNotEq => JsValue::Bool(!l.strict_eq(&r)),
            Lt | Gt | LtEq | GtEq => {
                let lp = self.to_primitive_hint(&l, "number")?;
                let rp = self.to_primitive_hint(&r, "number")?;
                if let (JsValue::Str(a), JsValue::Str(b)) = (&lp, &rp) {
                    let c = a.as_ref().cmp(b.as_ref());
                    JsValue::Bool(match op {
                        Lt => c.is_lt(),
                        Gt => c.is_gt(),
                        LtEq => c.is_le(),
                        _ => c.is_ge(),
                    })
                } else {
                    let a = self.to_number_value(&lp)?;
                    let b = self.to_number_value(&rp)?;
                    if a.is_nan() || b.is_nan() {
                        JsValue::Bool(false)
                    } else {
                        JsValue::Bool(match op {
                            Lt => a < b,
                            Gt => a > b,
                            LtEq => a <= b,
                            _ => a >= b,
                        })
                    }
                }
            }
            BitAnd => JsValue::Num(
                (to_i32(self.to_number_value(&l)?) & to_i32(self.to_number_value(&r)?)) as f64,
            ),
            BitOr => JsValue::Num(
                (to_i32(self.to_number_value(&l)?) | to_i32(self.to_number_value(&r)?)) as f64,
            ),
            BitXor => JsValue::Num(
                (to_i32(self.to_number_value(&l)?) ^ to_i32(self.to_number_value(&r)?)) as f64,
            ),
            Shl => JsValue::Num(
                ((to_i32(self.to_number_value(&l)?)) << (to_u32(self.to_number_value(&r)?) & 31))
                    as f64,
            ),
            Shr => JsValue::Num(
                ((to_i32(self.to_number_value(&l)?)) >> (to_u32(self.to_number_value(&r)?) & 31))
                    as f64,
            ),
            UShr => JsValue::Num(
                ((to_u32(self.to_number_value(&l)?)) >> (to_u32(self.to_number_value(&r)?) & 31))
                    as f64,
            ),
            In => match &r {
                JsValue::Object(o) => {
                    // The key converts once, before any trap lookup.
                    let key = self.to_property_key(&l)?;
                    JsValue::Bool(self.has_property(o, &key)?)
                }
                _ => return Err(Self::throw("TypeError: 'in' requires an object")),
            },
            Instanceof => JsValue::Bool(self.instance_of(&l, &r)?),
        })
    }

    /// ToPrimitive with default hint: valueOf then toString for objects.
    pub fn to_primitive(&mut self, v: &JsValue) -> Result<JsValue, JsValue> {
        self.to_primitive_hint(v, "default")
    }

    /// ToPrimitive (ES §7.1.1) with an explicit hint (`"string"`,
    /// `"number"`, or `"default"`). `Symbol.toPrimitive` is consulted
    /// first; then OrdinaryToPrimitive tries `toString` / `valueOf` in hint
    /// order (Date treats the default hint as string). Whatever those
    /// methods throw propagates; a non-callable `Symbol.toPrimitive`, an
    /// exotic result that is an object, or no method yielding a primitive
    /// is a TypeError.
    pub fn to_primitive_hint(&mut self, v: &JsValue, hint: &str) -> Result<JsValue, JsValue> {
        let JsValue::Object(o) = v else {
            return Ok(v.clone());
        };
        if let ObjKind::Primitive(p) = &o.borrow().kind {
            return Ok(p.as_ref().clone());
        }
        let exotic = self.get_property(v, &symbol_key(SYM_TO_PRIMITIVE))?;
        if !exotic.is_nullish() {
            let callable = matches!(&exotic, JsValue::Object(fo) if fo.borrow().is_callable());
            if !callable {
                return Err(Self::throw(
                    "TypeError: Symbol.toPrimitive is not a function",
                ));
            }
            let prim = self.call(exotic, v.clone(), &[JsValue::str(hint)])?;
            if matches!(prim, JsValue::Object(_)) {
                return Err(Self::throw(
                    "TypeError: Cannot convert object to primitive value",
                ));
            }
            return Ok(prim);
        }
        let is_date = matches!(o.borrow().kind, ObjKind::Date(_));
        let order: [&str; 2] = if hint == "string" || (is_date && hint == "default") {
            ["toString", "valueOf"]
        } else {
            ["valueOf", "toString"]
        };
        for m in order {
            let f = self.get_property(v, m)?;
            if matches!(&f, JsValue::Object(fo) if fo.borrow().is_callable()) {
                let prim = self.call(f, v.clone(), &[])?;
                if !matches!(prim, JsValue::Object(_)) {
                    return Ok(prim);
                }
            }
        }
        Err(Self::throw(
            "TypeError: Cannot convert object to primitive value",
        ))
    }

    /// InstanceofOperator (ES §13.10.2): the target's `Symbol.hasInstance`
    /// method decides when it has one (Function.prototype's is
    /// OrdinaryHasInstance, run here directly); otherwise the target must
    /// be callable and OrdinaryHasInstance answers.
    pub fn instance_of(&mut self, v: &JsValue, target: &JsValue) -> Result<bool, JsValue> {
        let JsValue::Object(t) = target else {
            return Err(Self::throw("TypeError: Right-hand side of 'instanceof' is not an object"));
        };
        let key = symbol_key(SYM_HAS_INSTANCE);
        // The common case: a function inheriting straight from
        // Function.prototype, whose @@hasInstance cannot be replaced
        // (non-writable, non-configurable), with no own one: the lookup
        // would find the intrinsic, which is OrdinaryHasInstance.
        let plain_function = {
            let b = t.borrow();
            matches!(b.kind, ObjKind::Function { .. } | ObjKind::Native(_) | ObjKind::Bound { .. })
                && b.proto.as_ref().is_some_and(|p| Rc::ptr_eq(p, &self.function_proto))
                && b.own(&key).is_none()
        };
        if plain_function {
            return self.ordinary_has_instance(target, v);
        }
        let handler = self.get_property(target, &key)?;
        match &handler {
            JsValue::Undefined | JsValue::Null => {}
            JsValue::Object(h) if h.borrow().is_callable() => {
                let intrinsic = matches!(
                    self.function_proto.borrow().own_slot(&key),
                    Some(Prop::Value { value: JsValue::Object(i), .. }) if Rc::ptr_eq(i, h)
                );
                if intrinsic {
                    return self.ordinary_has_instance(target, v);
                }
                return Ok(self.call(handler.clone(), target.clone(), std::slice::from_ref(v))?.truthy());
            }
            _ => return Err(Self::throw("TypeError: Symbol.hasInstance is not a function")),
        }
        if !t.borrow().is_callable() {
            return Err(Self::throw("TypeError: Right-hand side of 'instanceof' is not callable"));
        }
        self.ordinary_has_instance(target, v)
    }

    /// OrdinaryHasInstance (ES §7.3.21): false for a non-callable `c` or a
    /// primitive `o`; a bound function answers for its target (through
    /// InstanceofOperator); otherwise `c.prototype`, read through [[Get]]
    /// and required to be an object, is looked for on `o`'s chain, walked
    /// through [[GetPrototypeOf]] so a Proxy on it answers with its trap.
    pub fn ordinary_has_instance(&mut self, c: &JsValue, o: &JsValue) -> Result<bool, JsValue> {
        let JsValue::Object(co) = c else { return Ok(false) };
        if !co.borrow().is_callable() {
            return Ok(false);
        }
        let bound = match &co.borrow().kind {
            ObjKind::Bound { target, .. } => Some(target.clone()),
            _ => None,
        };
        if let Some(bt) = bound {
            self.charge_pub()?;
            return self.instance_of(o, &JsValue::Object(bt));
        }
        let JsValue::Object(obj) = o else { return Ok(false) };
        let JsValue::Object(p) = self.get_property(c, "prototype")? else {
            return Err(Self::throw("TypeError: Function has non-object prototype in instanceof check"));
        };
        let mut cur = self.get_prototype_of(obj)?;
        while let Some(x) = cur {
            if Rc::ptr_eq(&x, &p) {
                return Ok(true);
            }
            self.charge_pub()?;
            cur = self.get_prototype_of(&x)?;
        }
        Ok(false)
    }

    /// Get `base[key]`, walking prototypes, with string/array/DOM specials.
    pub fn get_property(&mut self, base: &JsValue, key: &str) -> Result<JsValue, JsValue> {
        match base {
            JsValue::Undefined | JsValue::Null => Err(Self::throw(format!(
                "TypeError: cannot read properties of {} (reading '{key}')",
                base.to_js_string()
            ))),
            JsValue::Str(s) => {
                if key == "length" {
                    return Ok(JsValue::Num(s.chars().count() as f64));
                }
                if let Ok(i) = key.parse::<usize>() {
                    return Ok(s
                        .chars()
                        .nth(i)
                        .map(|c| JsValue::str(c.to_string()))
                        .unwrap_or(JsValue::Undefined));
                }
                let proto = self.string_proto.clone();
                self.get_from_object(&proto, key, base, false)
            }
            JsValue::Num(_) => {
                let proto = self.number_proto.clone();
                self.get_from_object(&proto, key, base, false)
            }
            JsValue::Bool(_) => {
                let proto = self.boolean_proto.clone();
                self.get_from_object(&proto, key, base, false)
            }
            JsValue::Symbol(s) => {
                if key == "description" {
                    return Ok(match &s.description {
                        Some(d) => JsValue::str(d.clone()),
                        None => JsValue::Undefined,
                    });
                }
                let proto = self.symbol_proto.clone();
                self.get_from_object(&proto, key, base, false)
            }
            JsValue::Object(o) => {
                // Proxy: the `get` trap decides (receiver = the proxy); no
                // trap falls through to the target.
                let proxy = match &o.borrow().kind {
                    ObjKind::Proxy { target, handler } => Some((target.clone(), handler.clone())),
                    _ => None,
                };
                if let Some((target, handler)) = proxy {
                    if let Some(trap) = self.proxy_trap(&handler, "get")? {
                        let k = self.key_value(key);
                        return self.call(
                            trap,
                            JsValue::Object(handler),
                            &[JsValue::Object(target), k, base.clone()],
                        );
                    }
                    // No trap: target.[[Get]](key, receiver), the receiver
                    // being the Proxy (ES §10.5.8 step 6).
                    return self.get_with_receiver(&target, key, base);
                }
                if let Some(v) = self.host_get(o, key)? {
                    return Ok(v);
                }
                // Array fast paths.
                {
                    let b = o.borrow();
                    if matches!(b.kind, ObjKind::Array) {
                        if key == "length" {
                            return Ok(JsValue::Num(b.array_length() as f64));
                        }
                        // An index the property table holds (an accessor)
                        // is read through it below, and so is a hole,
                        // which the prototype chain may fill.
                        if let Some(v) = array_index(key).and_then(|i| b.elem(i)) {
                            return Ok(v.clone());
                        }
                    }
                    // Typed-array views: integer-indexed reads decode the
                    // buffer's bytes; `length` is the element count.
                    if let Some(v) = b.string_own(key) {
                        return Ok(v);
                    }
                    if let ObjKind::TypedArray(t) = &b.kind {
                        if key == "length" {
                            return Ok(JsValue::Num(t.length as f64));
                        }
                        // Every numeric key is the view's: an element, or
                        // undefined without asking the prototype (ES
                        // 10.4.5.4 IntegerIndexedElementGet).
                        if let Some(i) = t.index_of_key(key) {
                            return Ok(i.and_then(|i| t.get(i)).map_or(JsValue::Undefined, JsValue::Num));
                        }
                    }
                }
                let obj = o.clone();
                self.get_from_object(&obj, key, base, true)
            }
        }
    }

    /// The host's own reads on a DOM-backed object, which are not slots on
    /// the wrapper: a node's reflected properties (`tagName`,
    /// `textContent`, `children`, ...) from the arena Document, a live
    /// facet's (`el.style.x`, `el.dataset.x`) parsed from the attribute
    /// every time, and a DOM list's `length` and items. `None` when the
    /// key is not one the host answers for, and for every other object.
    fn host_get(&mut self, o: &ObjRef, key: &str) -> Result<Option<JsValue>, JsValue> {
        enum Host {
            Node(usize),
            Facet(usize, super::value::Facet),
            List(Option<usize>, usize),
            None,
        }
        let host = {
            let b = o.borrow();
            match &b.kind {
                ObjKind::DomNode(h) => Host::Node(*h),
                ObjKind::DomFacet { handle, facet } if b.own(key).is_none() => Host::Facet(*handle, *facet),
                ObjKind::DomList(handles) => match key.parse::<usize>() {
                    Ok(i) => Host::List(handles.get(i).copied(), handles.len()),
                    Err(_) if key == "length" => Host::List(None, handles.len()),
                    Err(_) => Host::None,
                },
                _ => Host::None,
            }
        };
        Ok(match host {
            Host::Node(h) => super::dom_bindings::get_dom_property(self, h, key)?,
            Host::Facet(h, f) => super::dom_bindings::get_facet_property(self, h, f, key),
            Host::List(_, n) if key == "length" => Some(JsValue::Num(n as f64)),
            Host::List(Some(h), _) => Some(self.wrap_dom_node(h)),
            Host::List(None, _) => Some(JsValue::Undefined),
            Host::None => None,
        })
    }

    /// Walk an object + prototype chain for `key`, running accessors with
    /// `this` as the receiver (OrdinaryGet, ES §10.1.8.1, one level at a
    /// time). A Proxy on the chain is asked through its [[Get]] (its `get`
    /// trap, handed the receiver, or its target's), and an exotic object
    /// (an Array, a typed array, a String wrapper, a DOM-backed object)
    /// answers with its own exotic properties before its parent is
    /// consulted. `start_is_base` says `start` is the object the read began
    /// at, whose exotic properties `get_property` has already answered for.
    fn get_from_object(
        &mut self,
        start: &ObjRef,
        key: &str,
        this: &JsValue,
        start_is_base: bool,
    ) -> Result<JsValue, JsValue> {
        enum Step {
            Value(JsValue),
            Getter(Option<ObjRef>),
            Delegate,
            Next(Option<ObjRef>),
        }
        let mut cur = Some(start.clone());
        let mut first = start_is_base;
        while let Some(o) = cur {
            let step = {
                let b = o.borrow();
                match b.own(key).and_then(|i| b.props.get(i)) {
                    Some((_, Prop::Value { value, .. })) => Step::Value(value.clone()),
                    Some((_, Prop::Accessor { get, .. })) => Step::Getter(get.clone()),
                    None => match &b.kind {
                        ObjKind::Proxy { .. } => Step::Delegate,
                        ObjKind::Array
                        | ObjKind::TypedArray(_)
                        | ObjKind::Primitive(_)
                        | ObjKind::DomNode(_)
                        | ObjKind::DomList(_)
                        | ObjKind::DomFacet { .. }
                            if !first =>
                        {
                            Step::Delegate
                        }
                        _ => Step::Next(b.proto.clone()),
                    },
                }
            };
            match step {
                Step::Value(v) => return Ok(v),
                Step::Getter(Some(getter)) => return self.call(JsValue::Object(getter), this.clone(), &[]),
                Step::Getter(None) => return Ok(JsValue::Undefined),
                Step::Delegate => return self.get_with_receiver(&o, key, this),
                Step::Next(next) => cur = next,
            }
            first = false;
        }
        Ok(JsValue::Undefined)
    }

    /// PutValue for a property reference (ES §6.2.5.6): a null or
    /// undefined base is a TypeError; on a primitive base a setter found
    /// on its prototype chain runs with the primitive as `this`, and
    /// otherwise the write has nowhere to land; an object goes through
    /// [[Set]]. A write that does not land is a TypeError in strict code
    /// and ignored in sloppy code.
    pub fn put_value(&mut self, base: &JsValue, key: &str, value: JsValue, strict: bool) -> Result<(), JsValue> {
        let proto = match base {
            JsValue::Object(_) => {
                if !self.try_set_property(base, key, value)? && strict {
                    return Err(Self::throw(format!(
                        "TypeError: Cannot assign to read only property '{key}' of object"
                    )));
                }
                return Ok(());
            }
            JsValue::Undefined | JsValue::Null => {
                return Err(Self::throw(format!(
                    "TypeError: Cannot set properties of {} (setting '{key}')",
                    base.to_js_string()
                )))
            }
            JsValue::Str(_) => self.string_proto.clone(),
            JsValue::Num(_) => self.number_proto.clone(),
            JsValue::Bool(_) => self.boolean_proto.clone(),
            JsValue::Symbol(_) => self.symbol_proto.clone(),
        };
        let mut cur = Some(proto);
        while let Some(o) = cur {
            let slot = {
                let b = o.borrow();
                match b.own_slot(key) {
                    Some(Prop::Accessor { set, .. }) => Some(set.clone()),
                    Some(Prop::Value { .. }) => Some(None),
                    None => None,
                }
            };
            match slot {
                Some(Some(setter)) => {
                    self.call(JsValue::Object(setter), base.clone(), &[value])?;
                    return Ok(());
                }
                Some(None) => break,
                None => {
                    self.charge_pub()?;
                    let next = o.borrow().proto.clone();
                    cur = next;
                }
            }
        }
        if strict {
            return Err(Self::throw(format!(
                "TypeError: Cannot create property '{key}' on {} '{}'",
                base.type_of(),
                base.to_js_string()
            )));
        }
        Ok(())
    }

    /// Set `base[key] = value` where a refused write is ignored, as sloppy
    /// code and the engine's own callers want (see `try_set_property`).
    pub fn set_property(
        &mut self,
        base: &JsValue,
        key: &str,
        value: JsValue,
    ) -> Result<(), JsValue> {
        self.try_set_property(base, key, value).map(|_| ())
    }

    /// [[Set]] (ES §10.1.9 OrdinarySet, §10.5.9 for a Proxy): write
    /// `base[key] = value` and report whether the write took effect. A
    /// Proxy's `set` trap decides by its result's truthiness. It is
    /// refused (false) for a non-writable data property, own or inherited,
    /// an accessor without a setter, a new key on a non-extensible object,
    /// a typed array's `length`, and an array element or `length` that the
    /// array's integrity level protects. Setters run; a primitive base
    /// writes nothing (`put_value` handles primitives).
    pub fn try_set_property(
        &mut self,
        base: &JsValue,
        key: &str,
        value: JsValue,
    ) -> Result<bool, JsValue> {
        let JsValue::Object(o) = base else {
            return Ok(false);
        };
        // Proxy: the `set` trap decides; without one the target's [[Set]]
        // runs with the Proxy as the receiver (ES §10.5.9 step 6).
        if let Some((target, handler)) = Self::proxy_parts(o) {
            if let Some(ok) = self.proxy_set_trap(&target, &handler, key, value.clone(), base)? {
                return Ok(ok);
            }
            return self.set_with_receiver(&target, key, value, base);
        }
        // A String wrapper's characters and `length` are read-only.
        if o.borrow().string_own(key).is_some() {
            return Ok(false);
        }
        // Typed-array views: an integer-indexed write encodes into the
        // buffer's bytes (out of range: no effect); `length` is an
        // accessor without a setter.
        let typed = match &o.borrow().kind {
            ObjKind::TypedArray(t) => Some(t.clone()),
            _ => None,
        };
        if let Some(t) = typed {
            if key == "length" {
                return Ok(false);
            }
            // TypedArraySetElement (ES 10.4.5.16): the value converts
            // whatever the key, and lands only at a valid index; a write to
            // any other numeric key is ignored, successfully.
            if let Some(i) = t.index_of_key(key) {
                let n = self.to_number_value(&value)?;
                if let Some(i) = i {
                    t.set(i, n);
                }
                return Ok(true);
            }
        }
        // Array index / length writes. An index that `defineProperty`
        // turned into an accessor lives in the property table and goes the
        // ordinary way below.
        {
            let mut b = o.borrow_mut();
            if matches!(b.kind, ObjKind::Array) && !b.index.contains_key(key) {
                // OrdinarySet refuses a read-only `length` before anything
                // converts; a writable one takes the value through
                // ArraySetLength, whose RangeError holds in any mode.
                if key == "length" {
                    if !b.is_writable("length") {
                        return Ok(false);
                    }
                    drop(b);
                    let n = self.array_length_value(&value)?;
                    return Ok(o.borrow_mut().set_array_length(n));
                }
                // A present element is overwritten in place; a hole or an
                // index past the end is created below, after the
                // prototype chain has had its say.
                if let Some(i) = array_index(key).filter(|i| b.elem(*i).is_some()) {
                    if !b.is_writable(key) {
                        return Ok(false);
                    }
                    if let Some(slot) = b.elems.get_mut(i) {
                        *slot = Some(value);
                    }
                    return Ok(true);
                }
            }
        }
        // The nearest property on the chain decides: a setter runs, an
        // accessor without one refuses, a non-writable data property
        // refuses (even an inherited one: it may not be shadowed by
        // assignment), and a writable one lets the receiver take the value.
        // A Proxy or an exotic object further up decides through its own
        // [[Set]] with this receiver (OrdinarySet's step 2: the parent's
        // [[Set]]), so a `set` trap runs and an inherited array element,
        // typed-array element or string character counts.
        enum Found {
            Setter(Option<ObjRef>),
            Data(bool),
            Delegate,
            Next(Option<ObjRef>),
        }
        let mut cur = Some(o.clone());
        let mut first = true;
        while let Some(c) = cur {
            let found = {
                let b = c.borrow();
                match b.own_slot(key) {
                    Some(Prop::Accessor { set, .. }) => Found::Setter(set.clone()),
                    Some(Prop::Value { .. }) => Found::Data(b.is_writable(key)),
                    None => match &b.kind {
                        ObjKind::Proxy { .. }
                        | ObjKind::Array
                        | ObjKind::TypedArray(_)
                        | ObjKind::Primitive(_)
                        | ObjKind::DomNode(_)
                        | ObjKind::DomList(_)
                        | ObjKind::DomFacet { .. }
                            if !first =>
                        {
                            Found::Delegate
                        }
                        _ => Found::Next(b.proto.clone()),
                    },
                }
            };
            match found {
                Found::Setter(Some(setter)) => {
                    self.call(JsValue::Object(setter), base.clone(), &[value])?;
                    return Ok(true);
                }
                Found::Setter(None) | Found::Data(false) => return Ok(false),
                Found::Data(true) => break,
                Found::Delegate => return self.set_with_receiver(&c, key, value, base),
                Found::Next(next) => cur = next,
            }
            first = false;
        }
        if self.host_set(o, key, &value)? {
            return Ok(true);
        }
        let mut b = o.borrow_mut();
        if matches!(b.kind, ObjKind::Array) && !b.index.contains_key(key) {
            if let Some(i) = array_index(key) {
                return Ok(b.create_index(i, key, value));
            }
        }
        Ok(b.write_prop(key, value))
    }

    /// The host's own property writes on a DOM-backed object, run when no
    /// script-visible property on its chain decided the write: a node's
    /// reflected properties (`textContent`, `id`, `className`, ...) and a
    /// live facet's (`el.style.color = "red"` lands on the style
    /// attribute, `el.dataset.k = v` on `data-k`). False when the key is
    /// not one the host handles.
    fn host_set(&mut self, o: &ObjRef, key: &str, value: &JsValue) -> Result<bool, JsValue> {
        if super::dom_bindings::set_dom_property(self, o, key, value)? {
            return Ok(true);
        }
        let facet = match &o.borrow().kind {
            ObjKind::DomFacet { handle, facet } => Some((*handle, *facet)),
            _ => None,
        };
        Ok(match facet {
            Some((h, f)) => {
                o.borrow().own(key).is_none() && super::dom_bindings::set_facet_property(self, h, f, key, value)
            }
            None => false,
        })
    }

    /// The DOM-backed object a receiver stands for: the receiver itself, or
    /// the object at the end of a chain of Proxies over it.
    fn host_behind(receiver: &JsValue) -> Option<ObjRef> {
        let JsValue::Object(mut cur) = receiver.clone() else {
            return None;
        };
        for _ in 0..64 {
            let next = match &cur.borrow().kind {
                ObjKind::DomNode(_) | ObjKind::DomFacet { .. } => return Some(cur.clone()),
                ObjKind::Proxy { target, .. } => target.clone(),
                _ => return None,
            };
            cur = next;
        }
        None
    }

    /// The new length an Array takes from `v` (ES §10.4.2.4 ArraySetLength
    /// steps 3-5): ToUint32(v), which must equal ToNumber(v) (converted a
    /// second time, as the spec does), or a RangeError.
    pub fn array_length_value(&mut self, v: &JsValue) -> Result<usize, JsValue> {
        let first = self.to_number_value(v)?;
        let new_len = to_u32(first);
        let number_len = self.to_number_value(v)?;
        if f64::from(new_len) != number_len {
            return Err(Self::throw("RangeError: Invalid array length"));
        }
        Ok(new_len as usize)
    }

    /// A Proxy's `set` trap (ES §10.5.9): `None` when the handler has
    /// none, otherwise whether the trap reported the write done, after the
    /// invariant checks: a trap may not report a write to a
    /// non-configurable, non-writable data property of the target that
    /// changes its value, nor to a non-configurable accessor without a
    /// setter.
    fn proxy_set_trap(
        &mut self,
        target: &ObjRef,
        handler: &ObjRef,
        key: &str,
        value: JsValue,
        receiver: &JsValue,
    ) -> Result<Option<bool>, JsValue> {
        let Some(trap) = self.proxy_trap(handler, "set")? else {
            return Ok(None);
        };
        let k = self.key_value(key);
        let ok = self
            .call(
                trap,
                JsValue::Object(handler.clone()),
                &[JsValue::Object(target.clone()), k, value.clone(), receiver.clone()],
            )?
            .truthy();
        if ok {
            let t = target.borrow();
            if t.has_own_key(key) && !t.is_configurable(key) {
                let refused = match t.own_slot(key) {
                    Some(Prop::Accessor { set, .. }) => set.is_none(),
                    _ => {
                        !t.is_writable(key)
                            && !super::builtins_es::own_data_value(&t, key)
                                .is_some_and(|cur| super::builtins_es::same_value(&cur, &value))
                    }
                };
                if refused {
                    return Err(Self::throw(format!(
                        "TypeError: 'set' on proxy: trap returned truish for property '{key}' which exists in the proxy target as a non-configurable and non-writable property"
                    )));
                }
            }
        }
        Ok(Some(ok))
    }

    /// [[Set]] with an explicit receiver (ES §10.1.9, `Reflect.set`'s
    /// fourth argument): the property found on `o`'s chain decides as in
    /// OrdinarySetWithOwnDescriptor, a setter runs with `receiver` as
    /// `this`, and a data write lands on the receiver: its own writable
    /// data property takes the value (through its [[DefineOwnProperty]],
    /// so a Proxy receiver's trap sees it), an absent one is created, and
    /// anything else (a primitive receiver, an accessor or read-only
    /// property on it) refuses. A receiver that is `o` itself takes the
    /// ordinary path.
    pub fn set_with_receiver(
        &mut self,
        o: &ObjRef,
        key: &str,
        value: JsValue,
        receiver: &JsValue,
    ) -> Result<bool, JsValue> {
        if matches!(receiver, JsValue::Object(r) if Rc::ptr_eq(r, o)) {
            return self.try_set_property(receiver, key, value);
        }
        self.charge_pub()?;
        if let Some((target, handler)) = Self::proxy_parts(o) {
            if let Some(ok) = self.proxy_set_trap(&target, &handler, key, value.clone(), receiver)? {
                return Ok(ok);
            }
            return self.set_with_receiver(&target, key, value, receiver);
        }
        use super::builtins_es::{ordinary_own_desc, PropDesc};
        // A DOM-backed object's reflected properties are the host's, not
        // slots on the wrapper: when no script-visible property on its
        // chain decides the write (an accessor, or a read-only property),
        // the host writes the node behind the receiver, which a Proxy over
        // the node resolves to. Defining the key on the receiver instead
        // would leave an expando on the wrapper and the document unchanged.
        if matches!(o.borrow().kind, ObjKind::DomNode(_) | ObjKind::DomFacet { .. }) {
            if let Some(node) = Self::host_behind(receiver) {
                let mut cur = Some(o.clone());
                let mut decided = false;
                while let Some(c) = cur {
                    if let Some(d) = ordinary_own_desc(&c.borrow(), key) {
                        decided = d.is_accessor() || d.writable == Some(false);
                        break;
                    }
                    self.charge_pub()?;
                    cur = c.borrow().proto.clone();
                }
                if !decided && self.host_set(&node, key, &value)? {
                    return Ok(true);
                }
            }
        }
        // A typed array's integer index (ES §10.4.5.5): one outside the
        // view is ignored, as a write the receiver need not see.
        let outside = match &o.borrow().kind {
            ObjKind::TypedArray(t) => t.index_of_key(key) == Some(None),
            _ => false,
        };
        if outside {
            return Ok(true);
        }
        let own = ordinary_own_desc(&o.borrow(), key);
        let own = match own {
            Some(d) => d,
            None => {
                let parent = o.borrow().proto.clone();
                if let Some(p) = parent {
                    return self.set_with_receiver(&p, key, value, receiver);
                }
                PropDesc {
                    writable: Some(true),
                    ..PropDesc::default()
                }
            }
        };
        if own.is_accessor() {
            let Some(setter @ JsValue::Object(_)) = own.set else {
                return Ok(false);
            };
            self.call(setter, receiver.clone(), &[value])?;
            return Ok(true);
        }
        if own.writable == Some(false) {
            return Ok(false);
        }
        let JsValue::Object(r) = receiver else {
            return Ok(false);
        };
        // A DOM-backed receiver whose chain had no say: the host takes its
        // own properties, as an ordinary write to it would.
        if !matches!(o.borrow().kind, ObjKind::DomNode(_) | ObjKind::DomFacet { .. })
            && matches!(r.borrow().kind, ObjKind::DomNode(_) | ObjKind::DomFacet { .. })
            && self.host_set(r, key, &value)?
        {
            return Ok(true);
        }
        let desc = match self.own_prop_desc(r, key)? {
            Some(existing) => {
                if existing.is_accessor() || existing.writable == Some(false) {
                    return Ok(false);
                }
                PropDesc {
                    value: Some(value),
                    ..PropDesc::default()
                }
            }
            None => PropDesc {
                value: Some(value),
                writable: Some(true),
                enumerable: Some(true),
                configurable: Some(true),
                ..PropDesc::default()
            },
        };
        let d = desc.to_object(self);
        self.define_own_property(r, key, &d)
    }

    /// [[Get]] with an explicit receiver (ES §10.1.8, `Reflect.get`'s third
    /// argument, and a trap-less Proxy's forwarded read): a getter found on
    /// `o`'s chain runs with `receiver` as `this`, and a Proxy's `get` trap
    /// is handed it. A DOM-backed object's host properties answer first,
    /// whatever the receiver. A receiver that is `o` itself takes the
    /// ordinary path.
    pub fn get_with_receiver(&mut self, o: &ObjRef, key: &str, receiver: &JsValue) -> Result<JsValue, JsValue> {
        if matches!(receiver, JsValue::Object(r) if Rc::ptr_eq(r, o)) {
            return self.get_property(receiver, key);
        }
        self.charge_pub()?;
        if let Some(v) = self.host_get(o, key)? {
            return Ok(v);
        }
        // A typed array answers a numeric key itself (ES §10.4.5.4): its
        // element, or undefined outside the view.
        let typed = match &o.borrow().kind {
            ObjKind::TypedArray(t) => t
                .index_of_key(key)
                .map(|i| i.and_then(|i| t.get(i)).map_or(JsValue::Undefined, JsValue::Num)),
            _ => None,
        };
        if let Some(v) = typed {
            return Ok(v);
        }
        if let Some((target, handler)) = Self::proxy_parts(o) {
            if let Some(trap) = self.proxy_trap(&handler, "get")? {
                let k = self.key_value(key);
                return self.call(trap, JsValue::Object(handler), &[JsValue::Object(target), k, receiver.clone()]);
            }
            return self.get_with_receiver(&target, key, receiver);
        }
        let own = super::builtins_es::ordinary_own_desc(&o.borrow(), key);
        match own {
            None => {
                let parent = o.borrow().proto.clone();
                match parent {
                    Some(p) => self.get_with_receiver(&p, key, receiver),
                    None => Ok(JsValue::Undefined),
                }
            }
            Some(d) if d.is_accessor() => match d.get {
                Some(getter @ JsValue::Object(_)) => self.call(getter, receiver.clone(), &[]),
                _ => Ok(JsValue::Undefined),
            },
            Some(d) => Ok(d.value.unwrap_or(JsValue::Undefined)),
        }
    }
}

/// A short rendering of a value for an error message.
fn to_display_brief(v: &JsValue) -> String {
    match v {
        JsValue::Object(_) => "#<Object>".to_string(),
        JsValue::Str(s) => format!("string '{}'", s.as_ref()),
        other => other.to_js_string(),
    }
}

/// An evaluated assignment target.
enum Reference {
    /// A binding resolved through the scope chain when read or written.
    Binding(String),
    /// A property: the evaluated base and its property key.
    Property(JsValue, String),
}

/// The binary operator a compound assignment lowers onto.
pub(super) fn compound_binary_op(op: AssignOp) -> BinaryOp {
    match op {
        AssignOp::Sub => BinaryOp::Sub,
        AssignOp::Mul => BinaryOp::Mul,
        AssignOp::Div => BinaryOp::Div,
        AssignOp::Rem => BinaryOp::Rem,
        AssignOp::Pow => BinaryOp::Pow,
        AssignOp::BitAnd => BinaryOp::BitAnd,
        AssignOp::BitOr => BinaryOp::BitOr,
        AssignOp::BitXor => BinaryOp::BitXor,
        AssignOp::Shl => BinaryOp::Shl,
        AssignOp::Shr => BinaryOp::Shr,
        AssignOp::UShr => BinaryOp::UShr,
        _ => BinaryOp::Add,
    }
}

/// f64 → i32 with JS ToInt32 wrapping.
pub fn to_i32(n: f64) -> i32 {
    if !n.is_finite() {
        return 0;
    }
    (n as i64 & 0xffff_ffff) as u32 as i32
}

/// f64 → u32 with JS ToUint32 wrapping.
pub fn to_u32(n: f64) -> u32 {
    if !n.is_finite() {
        return 0;
    }
    (n as i64 & 0xffff_ffff) as u32
}

#[cfg(test)]
mod conversion_tests {
    use super::super::interp::test_support::eval_js;

    /// The error name a script caught, whether the engine threw a string or
    /// an Error object.
    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ {body}; }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn to_number_propagates_what_value_of_throws() {
        assert_eq!(caught("+{ valueOf() { throw 'boom'; } }"), "boom");
        assert_eq!(caught("1 - { valueOf() { throw 'sub'; } }"), "sub");
        assert_eq!(caught("let x = { valueOf() { throw 'inc'; } }; x++"), "inc");
        assert_eq!(caught("Number({ valueOf() { throw 'ctor'; } })"), "ctor");
    }

    #[test]
    fn to_number_falls_back_to_to_string_and_refuses_what_has_no_primitive() {
        assert_eq!(eval_js("+{ toString() { return '7'; } }"), "7");
        assert_eq!(eval_js("+{ valueOf() { return {}; }, toString() { return '8'; } }"), "8");
        assert_eq!(caught("+Object.create(null)"), "TypeError");
        assert_eq!(caught("+Symbol('s')"), "TypeError");
        assert_eq!(caught("+{ [Symbol.toPrimitive]() { return {}; } }"), "TypeError");
    }

    #[test]
    fn to_string_runs_the_objects_conversion_and_propagates_its_throw() {
        assert_eq!(eval_js("`a${{ toString() { return 'b'; } }}c`"), "abc");
        assert_eq!(caught("`${{ toString() { throw 'tpl'; } }}`"), "tpl");
        assert_eq!(caught("'' + { toString() { throw 'cat'; }, valueOf() { throw 'cat2'; } }"), "cat2");
        assert_eq!(caught("String({ toString() { throw 'str'; } })"), "str");
        assert_eq!(caught("`${Symbol('s')}`"), "TypeError");
    }

    #[test]
    fn to_property_key_propagates_what_to_string_throws() {
        assert_eq!(caught("({})[{ toString() { throw 'get'; } }]"), "get");
        assert_eq!(caught("const o = {}; o[{ toString() { throw 'set'; } }] = 1"), "set");
        assert_eq!(caught("({ [{ toString() { throw 'lit'; } }]: 1 })"), "lit");
        assert_eq!(caught("({ toString() { throw 'in'; } }) in {}"), "in");
    }
}

#[cfg(test)]
mod assignment_order_tests {
    use super::super::interp::test_support::eval_js;

    const LOGGED: &str = "const log = [];
        const o = { get x() { log.push('get'); return 1; }, set x(v) { log.push('set' + v); } };";

    #[test]
    fn compound_assignment_reads_the_target_before_the_right_hand_side() {
        assert_eq!(
            eval_js(&format!("{LOGGED} o.x += (log.push('rhs'), 1); log.join()")),
            "get,rhs,set2"
        );
        assert_eq!(
            eval_js(&format!("{LOGGED} o[(log.push('key'), 'x')] *= (log.push('rhs'), 3); log.join()")),
            "key,get,rhs,set3"
        );
        assert_eq!(eval_js("let x = 1; x += (x = 5, 1); x"), "2");
        assert_eq!(eval_js("let s = 'a'; s += (s = 'z', 'b'); s"), "ab");
        // A suspending right-hand side (lowered by desugar.rs) keeps the
        // order: the getter runs before the yield.
        assert_eq!(
            eval_js(&format!(
                "{LOGGED} function* g() {{ o.x += yield (log.push('rhs'), 0); }}
                 const it = g(); it.next(); it.next(1); log.join()"
            )),
            "get,rhs,set2"
        );
    }

    #[test]
    fn update_and_logical_assignment_evaluate_the_reference_once() {
        assert_eq!(eval_js("let n = 0; const o = { a: 1 }; o[(n++, 'a')]++; n + ':' + o.a"), "1:2");
        assert_eq!(eval_js("let n = 0; const o = {}; o[(n++, 'a')] ||= 7; n + ':' + o.a"), "1:7");
        assert_eq!(eval_js("let n = 0; const o = {}; o[(n++, 'a')] ??= 7; n + ':' + o.a"), "1:7");
        assert_eq!(eval_js("let n = 0; const o = { a: 1 }; o[(n++, 'a')] &&= 7; n + ':' + o.a"), "1:7");
        assert_eq!(
            eval_js(&format!("{LOGGED} o.x++; log.join()")),
            "get,set2"
        );
    }
}

#[cfg(test)]
mod proxy_delete_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String({body}); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_non_callable_delete_property_trap_is_a_type_error() {
        assert_eq!(caught("delete new Proxy({ a: 1 }, { deleteProperty: 1 }).a"), "TypeError");
        assert_eq!(caught("delete new Proxy({ a: 1 }, { deleteProperty: {} })['a']"), "TypeError");
        assert_eq!(caught("Reflect.deleteProperty(new Proxy({ a: 1 }, { deleteProperty: 'x' }), 'a')"), "TypeError");
    }

    #[test]
    fn every_trap_uses_get_method_semantics() {
        assert_eq!(caught("new Proxy({ a: 1 }, { get: 1 }).a"), "TypeError");
        assert_eq!(caught("(() => { new Proxy({}, { set: true }).a = 1; })()"), "TypeError");
        assert_eq!(caught("'a' in new Proxy({ a: 1 }, { has: 'yes' })"), "TypeError");
        assert_eq!(caught("new Proxy(function () { return 1; }, { apply: 1 })()"), "TypeError");
        assert_eq!(caught("new (new Proxy(function () {}, { construct: {} }))()"), "TypeError");
        assert_eq!(caught("new Proxy({ a: 1 }, { get: null, has: undefined }).a"), "1");
        assert_eq!(
            caught("new Proxy(function () { return 1; }, { get apply() { return (t, self, args) => 2; } })()"),
            "2"
        );
    }

    #[test]
    fn an_absent_trap_deletes_from_the_target_and_a_present_one_decides() {
        assert_eq!(
            caught("(() => { const t = { a: 1 }; const ok = delete new Proxy(t, { deleteProperty: null }).a; return ok + ':' + ('a' in t); })()"),
            "true:false"
        );
        assert_eq!(
            caught("(() => { const t = { a: 1 }; return Reflect.deleteProperty(new Proxy(t, {}), 'a') + ':' + ('a' in t); })()"),
            "true:false"
        );
        assert_eq!(
            caught("(() => { const seen = []; const p = new Proxy({ a: 1 }, { deleteProperty(t, k) { seen.push(k); return false; } }); return Reflect.deleteProperty(p, 'a') + ':' + seen; })()"),
            "false:a"
        );
    }
}

#[cfg(test)]
mod strict_refusal_tests {
    use super::super::interp::test_support::eval_js;

    /// Run `body` and render its result or the caught error's name.
    fn caught(prologue: &str, body: &str) -> String {
        eval_js(&format!(
            "{prologue} let r; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    const FIXED: &str = "const fixed = {}; Object.defineProperty(fixed, 'x', { value: 1 });";

    #[test]
    fn strict_code_throws_for_a_refused_delete() {
        assert_eq!(caught("'use strict';", &format!("{FIXED} delete fixed.x")), "TypeError");
        assert_eq!(caught("'use strict';", "const a = Object.freeze([1]); delete a[0]"), "TypeError");
        assert_eq!(caught("'use strict';", "delete [1].length"), "TypeError");
        assert_eq!(caught("'use strict';", "delete 'abc'.length"), "TypeError");
        assert_eq!(caught("'use strict';", "const o = { a: 1 }; return delete o.a"), "true");
        // A strict function in sloppy script, and a sloppy one.
        assert_eq!(
            caught("", &format!("{FIXED} return (function () {{ 'use strict'; return delete fixed.x; }})()")),
            "TypeError"
        );
        assert_eq!(caught("", &format!("{FIXED} return delete fixed.x")), "false");
        assert_eq!(caught("", "return delete 'abc'.length"), "false");
        assert_eq!(caught("", "return delete 'abc'.foo"), "true");
    }

    #[test]
    fn strict_code_throws_for_a_write_to_a_primitive() {
        assert_eq!(caught("'use strict';", "'abc'.x = 1"), "TypeError");
        assert_eq!(caught("'use strict';", "const n = 5; n.x = 1"), "TypeError");
        assert_eq!(caught("'use strict';", "true.x += 1"), "TypeError");
        assert_eq!(caught("'use strict';", "class C { m() { (1).y = 2; } } new C().m()"), "TypeError");
        assert_eq!(caught("", "'abc'.x = 1; return 'ignored'"), "ignored");
        // A setter on the primitive's prototype still runs, with the
        // primitive as `this`.
        assert_eq!(
            caught(
                "'use strict';",
                "let seen; Object.defineProperty(Number.prototype, 'tag', { set(v) { seen = typeof this + v; }, configurable: true }); (7).tag = '!'; delete Number.prototype.tag; return seen"
            ),
            "number!"
        );
    }

    #[test]
    fn a_write_to_null_or_undefined_throws_in_any_mode() {
        assert_eq!(caught("", "let u; u.x = 1"), "TypeError");
        assert_eq!(caught("", "const n = null; n['x'] = 1"), "TypeError");
    }
}

#[cfg(test)]
mod proxy_refusal_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(prologue: &str, body: &str) -> String {
        eval_js(&format!(
            "{prologue} let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    const STRICT: &str = "'use strict';";
    const REFUSING_SET: &str = "const t = {}; const p = new Proxy(t, { set() { return false; } });";

    #[test]
    fn a_set_trap_returning_false_throws_in_strict_code() {
        assert_eq!(caught(STRICT, &format!("{REFUSING_SET} p.x = 1")), "TypeError");
        assert_eq!(caught(STRICT, &format!("{REFUSING_SET} p['y'] += 1")), "TypeError");
        // A trap that returns nothing returns undefined: falsish.
        assert_eq!(caught(STRICT, "const p = new Proxy({}, { set(t, k, v) { t[k] = v; } }); p.x = 1"), "TypeError");
        assert_eq!(
            caught("", "return (function () { 'use strict'; const p = new Proxy({}, { set() { return 0; } }); p.x = 1; })()"),
            "TypeError"
        );
        // Sloppy code ignores the refusal; Reflect.set reports it; Array
        // methods write with throw = true.
        assert_eq!(caught("", &format!("{REFUSING_SET} p.x = 1; return 'x' in t")), "false");
        assert_eq!(caught("", &format!("{REFUSING_SET} return Reflect.set(p, 'x', 1)")), "false");
        assert_eq!(caught("", "return Reflect.set(new Proxy({}, { set() { return 1; } }), 'x', 1)"), "true");
        assert_eq!(caught("", "new Proxy([], { set() { return false; } }).push(1)"), "TypeError");
        assert_eq!(caught(STRICT, "const p = new Proxy({}, { set(t, k, v) { t[k] = v; return true; } }); p.x = 1; return p.x"), "1");
    }

    #[test]
    fn a_set_trap_cannot_report_a_read_only_property_changed() {
        assert_eq!(
            caught("", "const t = {}; Object.defineProperty(t, 'x', { value: 1 }); new Proxy(t, { set() { return true; } }).x = 2"),
            "TypeError"
        );
        assert_eq!(
            caught("", "const t = {}; Object.defineProperty(t, 'x', { value: 1 }); new Proxy(t, { set() { return true; } }).x = 1; return 'same'"),
            "same"
        );
    }

    #[test]
    fn a_define_property_trap_decides_and_its_refusal_is_reported() {
        assert_eq!(
            caught("", "Object.defineProperty(new Proxy({}, { defineProperty() { return false; } }), 'x', { value: 1 })"),
            "TypeError"
        );
        assert_eq!(
            caught("", "return Reflect.defineProperty(new Proxy({}, { defineProperty() { return false; } }), 'x', { value: 1 })"),
            "false"
        );
        assert_eq!(
            caught("", "Object.defineProperties(new Proxy({}, { defineProperty() { return false; } }), { x: { value: 1 } })"),
            "TypeError"
        );
        // The trap sees the target, key and descriptor; no trap forwards
        // to the target.
        assert_eq!(
            caught("", "const t = {}; let seen; const p = new Proxy(t, { defineProperty(tt, k, d) { seen = (tt === t) + k + d.value; return Reflect.defineProperty(tt, k, d); } }); Object.defineProperty(p, 'x', { value: 7 }); return seen + ':' + t.x"),
            "truex7:7"
        );
        assert_eq!(
            caught("", "const t = {}; Object.defineProperty(new Proxy(t, {}), 'x', { value: 1, enumerable: true }); return JSON.stringify(Object.getOwnPropertyDescriptor(t, 'x'))"),
            "{\"value\":1,\"writable\":false,\"enumerable\":true,\"configurable\":false}"
        );
        // Invariant: a trap may not report a property added to a
        // non-extensible target.
        assert_eq!(
            caught("", "Object.defineProperty(new Proxy(Object.preventExtensions({}), { defineProperty() { return true; } }), 'x', { value: 1 })"),
            "TypeError"
        );
    }

    #[test]
    fn a_delete_property_trap_returning_false_throws_in_strict_code() {
        assert_eq!(
            caught(STRICT, "delete new Proxy({ a: 1 }, { deleteProperty() { return false; } }).a"),
            "TypeError"
        );
        assert_eq!(
            caught("", "return delete new Proxy({ a: 1 }, { deleteProperty() { return false; } }).a"),
            "false"
        );
        assert_eq!(
            caught("", "return Reflect.deleteProperty(new Proxy({ a: 1 }, { deleteProperty() { return false; } }), 'a')"),
            "false"
        );
    }
}

#[cfg(test)]
mod proxy_receiver_tests {
    use super::super::interp::test_support::{eval_in_page, eval_js};

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_trap_less_proxy_forwards_a_write_with_itself_as_the_receiver() {
        // ES 10.5.9 step 6: target.[[Set]](P, V, Receiver), the receiver
        // being the Proxy, so a setter runs with the Proxy as `this`.
        assert_eq!(
            caught("let self; const t = { set x(v) { self = this; } }; const p = new Proxy(t, {}); p.x = 1; return (self === p) + ':' + (self === t)"),
            "true:false"
        );
        assert_eq!(
            caught("let self; const t = Object.create({ set x(v) { self = this; } }); const p = new Proxy(t, {}); p.x = 1; return self === p"),
            "true"
        );
        // A data write lands through the receiver's own [[GetOwnProperty]]
        // and [[DefineOwnProperty]], so traps for those run even without a
        // set trap.
        assert_eq!(
            caught("const log = []; const p = new Proxy({ z: 0 }, { \
                    getOwnPropertyDescriptor(t, k) { log.push('gopd ' + k); return Reflect.getOwnPropertyDescriptor(t, k); }, \
                    defineProperty(t, k, d) { log.push('define ' + k + JSON.stringify(d)); return Reflect.defineProperty(t, k, d); } }); \
                    p.y = 5; p.z = 6; return log.join('; ') + ' | ' + p.y + p.z"),
            "gopd y; define y{\"value\":5,\"writable\":true,\"enumerable\":true,\"configurable\":true}; gopd z; define z{\"value\":6} | 56"
        );
        // A refusal still reaches the caller: strict code throws.
        assert_eq!(caught("'use strict'; const p = new Proxy(Object.freeze({ a: 1 }), {}); p.a = 2"), "TypeError");
        assert_eq!(
            caught("const p = new Proxy({}, { defineProperty() { return false; } }); return Reflect.set(p, 'q', 1) + ':' + ('q' in p)"),
            "false:false"
        );
    }

    #[test]
    fn exotic_targets_keep_their_write_semantics_behind_a_proxy() {
        // An Array's elements and length, through the generic methods too.
        assert_eq!(
            caught("const a = [1]; const p = new Proxy(a, {}); p.push(2); p[3] = 4; const mid = a.length; p.length = 2; return mid + ':' + a.join() + ':' + a.length"),
            "4:1,2:2"
        );
        assert_eq!(caught("const p = new Proxy([], {}); p.length = -1"), "RangeError");
        // A typed array's in-range element lands in its buffer and an
        // out-of-range one is dropped.
        assert_eq!(
            caught("const u = new Uint8Array(2); const p = new Proxy(u, {}); p[0] = 300; p[5] = 1; return u[0] + ':' + Object.keys(u).join() + ':' + (5 in u)"),
            "44:0,1:false"
        );
    }

    #[test]
    fn a_trap_less_proxy_over_a_dom_node_still_writes_the_node() {
        assert_eq!(
            eval_in_page(
                "<p id=a>old</p>",
                "const el = document.getElementById('a'); const p = new Proxy(el, {}); \
                 p.textContent = 'new'; p.className = 'c'; p.title = 't'; p.custom = 7; \
                 new Proxy(el.style, {}).color = 'red'; new Proxy(el.dataset, {}).k = 'v'; \
                 return [el.textContent, el.getAttribute('class'), el.getAttribute('title'), el.custom, el.style.color, el.getAttribute('data-k'), document.getElementById('a') === el].join()"
            ),
            "new,c,t,7,red,v,true"
        );
        // The node's own setter path still runs for the node itself and
        // for a Proxy whose target is another Proxy over it.
        assert_eq!(
            eval_in_page(
                "<p id=a></p>",
                "const el = document.getElementById('a'); new Proxy(new Proxy(el, {}), {}).id = 'b'; return el.id + ':' + (document.getElementById('b') === el)"
            ),
            "b:true"
        );
    }
}

#[cfg(test)]
mod proxy_read_receiver_tests {
    use super::super::interp::test_support::{eval_in_page, eval_js};

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_trap_less_proxy_forwards_a_read_with_itself_as_the_receiver() {
        // ES 10.5.8 step 6: target.[[Get]](P, Receiver), the receiver
        // being the Proxy, so a getter runs with the Proxy as `this`.
        assert_eq!(
            caught("const t = { get me() { return this; } }; const p = new Proxy(t, {}); return (p.me === p) + ':' + (Reflect.get(p, 'me') === p) + ':' + (t.me === t)"),
            "true:true:true"
        );
        assert_eq!(caught("const p = new Proxy(Object.create({ get me() { return this; } }), {}); return p.me === p"), "true");
        // Through a chain of Proxies the outermost is the receiver, down
        // to a get trap further in.
        assert_eq!(
            caught("const inner = new Proxy({}, { get(t, k, r) { return r; } }); const outer = new Proxy(inner, {}); return (outer.x === outer) + ':' + (inner.x === inner)"),
            "true:true"
        );
        assert_eq!(caught("const t = { get me() { return this; } }; const p = new Proxy(new Proxy(t, {}), {}); return p.me === p"), "true");
        // A built-in getter checks its receiver, as in every engine.
        assert_eq!(caught("return new Proxy(new Map([[1, 2]]), {}).size"), "TypeError");
        assert_eq!(caught("return new Proxy(new Uint8Array([1, 2]), {}).length"), "TypeError");
    }

    #[test]
    fn exotic_targets_keep_their_own_reads_behind_a_proxy() {
        assert_eq!(
            caught("const p = new Proxy([1, , 3], {}); return [p.length, p[0], String(p[1]), p[2], 1 in p, p.join(), [...p].length, Array.prototype.map.call(p, x => x * 2).join()].join(' ')"),
            "3 1 undefined 3 false 1,,3 3 2,,6"
        );
        assert_eq!(caught("const p = new Proxy(new Uint8Array([7, 8]), {}); return p[1] + ':' + p[5] + ':' + (1 in p)"), "8:undefined:true");
        assert_eq!(
            eval_in_page(
                "<p id=a class=c>text</p><p>two</p>",
                "const el = document.getElementById('a'); const p = new Proxy(el, {}); \
                 const l = new Proxy(document.querySelectorAll('p'), {}); \
                 Object.defineProperty(Object.getPrototypeOf(el), 'me', { get() { return this; }, configurable: true }); \
                 return [p.tagName, p.textContent, p.className, p.id, p.children.length, new Proxy(el.style, {}).color === '', new Proxy(el.dataset, {}).k, \
                         l.length, l[1].textContent, p.me === p, el.me === el].join()"
            ),
            "P,text,c,a,0,true,,2,two,true,true"
        );
    }
}

#[cfg(test)]
mod prototype_chain_exotic_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_proxy_on_the_chain_is_asked_for_writes() {
        // OrdinarySet walks to the parent's [[Set]] with the original
        // receiver (ES 10.1.9.2 step 2): the trap runs, sees the receiver,
        // and Reflect.set with it creates the property on the receiver.
        assert_eq!(
            caught("const log = []; const t = {}; const proxy = new Proxy(t, { set(tt, k, v, r) { log.push(k + ':' + (r === o)); return Reflect.set(tt, k, v, r); } }); \
                    const o = Object.create(proxy); o.x = 1; o.x = 2; \
                    return [log.join(), o.hasOwnProperty('x'), o.x, 'x' in t].join(' ')"),
            "x:true true 2 false"
        );
        // A trap that writes nothing leaves nothing; one that refuses makes
        // strict code throw.
        assert_eq!(caught("const o = Object.create(new Proxy({}, { set() { return true; } })); o.y = 1; return o.hasOwnProperty('y')"), "false");
        assert_eq!(caught("'use strict'; const o = Object.create(new Proxy({}, { set() { return false; } })); o.y = 1"), "TypeError");
        // Without a trap the target's chain decides with the receiver: a
        // setter runs with it as `this`, a read-only property refuses.
        assert_eq!(
            caught("let self; const o = Object.create(new Proxy({ set s(v) { self = this; } }, {})); o.s = 1; o.d = 2; return (self === o) + ':' + o.hasOwnProperty('d')"),
            "true:true"
        );
        assert_eq!(caught("'use strict'; const o = Object.create(new Proxy(Object.freeze({ k: 1 }), {})); o.k = 2"), "TypeError");
    }

    #[test]
    fn a_proxy_on_the_chain_is_asked_for_reads_and_has() {
        assert_eq!(
            caught("const proxy = new Proxy({ a: 1 }, { get(t, k, r) { return typeof k === 'string' ? k + (r === o) : undefined; }, has(t, k) { return k === 'z'; } }); \
                    const o = Object.create(proxy); o.own = 'mine'; \
                    return [o.foo, o.own, 'z' in o, 'a' in o, 'own' in o, Reflect.has(o, 'z')].join(' ')"),
            "footrue mine true false true true"
        );
        assert_eq!(
            caught("const o = Object.create(new Proxy({ a: 1, get me() { return this; } }, {})); return [o.a, o.me === o, 'a' in o, 'b' in o].join(' ')"),
            "1 true true false"
        );
        // An object two levels below the Proxy.
        assert_eq!(caught("const o = Object.create(Object.create(new Proxy({}, { get(t, k) { return 'deep ' + String(k); } }))); return o.q"), "deep q");
    }

    #[test]
    fn exotic_objects_on_the_chain_answer_with_their_own_properties() {
        // An Array: its elements and length read through, and a write
        // creates the property on the receiver.
        assert_eq!(
            caught("const a = [5, 6]; const o = Object.create(a); o[0] = 9; return [o[1], o.length, 1 in o, o[0], a[0], o.hasOwnProperty(0), a.length].join(' ')"),
            "6 2 true 9 5 true 2"
        );
        // A typed array: an index reads its element and stops there, and a
        // write in range lands on the receiver.
        assert_eq!(
            caught("const u = new Uint8Array([1, 2]); const o = Object.create(u); Object.getPrototypeOf(u)[5] = 'proto'; o[0] = 7; \
                    return [o[1], String(o[5]), 1 in o, 5 in o, o[0], u[0], o.hasOwnProperty(0)].join(' ')"),
            "2 undefined true false 7 1 true"
        );
        // A String wrapper: its characters and length are read-only.
        assert_eq!(
            caught("const o = Object.create(new String('ab')); o[0] = 'x'; return [o[1], o.length, 0 in o, o[0], o.hasOwnProperty(0)].join(' ')"),
            "b 2 true a false"
        );
        assert_eq!(caught("'use strict'; Object.create(new String('ab'))[0] = 'x'"), "TypeError");
    }
}

#[cfg(test)]
mod instanceof_tests {
    use super::super::interp::test_support::{eval_in_page, eval_js};

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn symbol_has_instance_decides() {
        // InstanceofOperator (ES 13.10.2): the target's @@hasInstance is
        // called with it as `this` and the value, and its result converted.
        assert_eq!(
            caught("let seen; const T = { [Symbol.hasInstance](v) { seen = [this === T, v]; return 1; } }; const r = ({}) instanceof T; return r + ':' + seen[0] + ':' + typeof seen[1]"),
            "true:true:object"
        );
        assert_eq!(caught("class Even { static [Symbol.hasInstance](n) { return n % 2 === 0; } } return [2 instanceof Even, 3 instanceof Even].join()"), "true,false");
        assert_eq!(caught("function F() {} Object.defineProperty(F, Symbol.hasInstance, { value: () => true }); return 5 instanceof F"), "true");
        // A non-callable @@hasInstance is a TypeError; null or undefined
        // falls back to OrdinaryHasInstance.
        assert_eq!(caught("return ({}) instanceof { [Symbol.hasInstance]: 1 }"), "TypeError");
        assert_eq!(caught("function F() {} Object.defineProperty(F, Symbol.hasInstance, { value: undefined }); return new F() instanceof F"), "true");
    }

    #[test]
    fn function_prototype_has_instance_is_ordinary_has_instance() {
        assert_eq!(
            caught("const h = Function.prototype[Symbol.hasInstance]; const d = Object.getOwnPropertyDescriptor(Function.prototype, Symbol.hasInstance); \
                    function F() {} const o = new F(); \
                    return [typeof h, d.writable, d.enumerable, d.configurable, h.call(F, o), h.call(F, {}), h.call({}, o), h.call(F, 1), h.name].join()"),
            "function,false,false,false,true,false,false,false,[Symbol.hasInstance]"
        );
    }

    #[test]
    fn ordinary_has_instance_follows_the_spec() {
        // A bound function answers for its target.
        assert_eq!(caught("function F() {} const o = new F(); const G = F.bind(null).bind(null); return [o instanceof G, ({}) instanceof G].join()"), "true,false");
        // `prototype` is read through [[Get]]: a Proxy's get trap answers.
        assert_eq!(
            caught("const P = new Proxy(function () {}, { get(t, k) { return k === 'prototype' ? Array.prototype : Reflect.get(t, k); } }); return [[] instanceof P, ({}) instanceof P].join()"),
            "true,false"
        );
        // A primitive is never an instance (and the prototype is not read);
        // a non-object prototype is a TypeError for an object.
        assert_eq!(caught("function F() {} F.prototype = 1; return 1 instanceof F"), "false");
        assert_eq!(caught("function F() {} F.prototype = 1; return ({}) instanceof F"), "TypeError");
        // The right-hand side must be an object, and callable when it has
        // no @@hasInstance.
        assert_eq!(caught("return ({}) instanceof {}"), "TypeError");
        assert_eq!(caught("return ({}) instanceof 1"), "TypeError");
        assert_eq!(caught("return 1 instanceof undefined"), "TypeError");
        assert_eq!(caught("return [[] instanceof Array, [] instanceof Object, (() => {}) instanceof Function, new Map() instanceof Map, null instanceof Object].join()"), "true,true,true,true,false");
    }

    #[test]
    fn host_interfaces_keep_answering() {
        assert_eq!(
            eval_in_page(
                "<p>x</p>",
                "const p = document.querySelector('p'); \
                 const bad = Object.getOwnPropertyNames(window).filter((k) => { let v; try { v = window[k]; } catch (e) { return false; } \
                   return typeof v === 'function' && /^[A-Z]/.test(k) && k !== 'Proxy' && !(v.prototype && (typeof v.prototype === 'object' || typeof v.prototype === 'function')); }); \
                 return [p instanceof HTMLElement, p instanceof Element, p instanceof Node, document.querySelectorAll('p') instanceof NodeList, p instanceof Array, bad.join(' ')].join()"
            ),
            "true,true,true,true,false,"
        );
    }
}
