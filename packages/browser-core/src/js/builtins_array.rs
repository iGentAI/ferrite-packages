//! builtins_array — `Array.prototype` as the spec writes it: GENERIC over
//! the receiver. Every method reads the receiver's `length` and indices
//! through [[Get]] and writes through [[Set]], so it works on a dense
//! `Array` (the fast path), on a `Proxy` over an array (Vue 3's reactive
//! arrays call `Array.prototype.push.apply(proxy, args)` and depend on the
//! `set` trap seeing every index write), on `arguments`, and on a NodeList.
//!
//! These are the realm's only `Array.prototype` methods and its
//! `Array.isArray`. Same rules as the rest of the engine: std-only,
//! panic-free, no indexing, every failure a thrown `JsValue`.

use std::rc::Rc;

use super::interp::Interp;
use super::value::{JsObject, JsValue, NativeFn, ObjKind, ObjRef, SYM_IS_CONCAT_SPREADABLE, SYM_SPECIES, array_index, iterator_key, symbol_key};

/// Clamp a ToIntegerOrInfinity result to a relative index into `len`:
/// negatives count from the end, the infinities clamp to the ends.
fn clamp_relative(n: f64, len: usize) -> usize {
    let len_f = len as f64;
    if n < 0.0 {
        (len_f + n).max(0.0) as usize
    } else {
        n.min(len_f) as usize
    }
}

/// SameValueZero (the `includes` comparison): NaN equals NaN.
fn same_value_zero(a: &JsValue, b: &JsValue) -> bool {
    match (a, b) {
        (JsValue::Num(x), JsValue::Num(y)) if x.is_nan() && y.is_nan() => true,
        _ => a.strict_eq(b),
    }
}

/// Whether `v` is an Array, seeing through Proxies (the spec's IsArray).
pub fn is_array_value(v: &JsValue) -> bool {
    let JsValue::Object(o) = v else {
        return false;
    };
    let mut cur = o.clone();
    for _ in 0..64 {
        let next = match &cur.borrow().kind {
            ObjKind::Array => return true,
            ObjKind::Proxy { target, .. } => target.clone(),
            _ => return false,
        };
        cur = next;
    }
    false
}

impl<'h> Interp<'h> {
    /// A relative index argument (`slice`, `splice`, `fill`, the
    /// typed-array methods) through ToIntegerOrInfinity, so a `valueOf`
    /// runs and its throw propagates: negatives count from the end, the
    /// infinities clamp, and a missing OR `undefined` argument takes
    /// `default` (the spec reads `slice(1, undefined)` as "to the end", not
    /// as index 0).
    pub(super) fn relative_index(
        &mut self,
        v: Option<&JsValue>,
        len: usize,
        default: usize,
    ) -> Result<usize, JsValue> {
        match v.filter(|v| !matches!(v, JsValue::Undefined)) {
            Some(v) => {
                let n = self.to_integer_or_infinity(v)?;
                Ok(clamp_relative(n, len))
            }
            None => Ok(default.min(len)),
        }
    }

    /// The last index a backwards search (`lastIndexOf`) starts from: `len -
    /// 1` when the argument is absent, the clamped argument otherwise
    /// (negatives count from the end). Unlike the end arguments of `slice` /
    /// `fill`, an EXPLICIT `undefined` is "present" here and goes through
    /// ToIntegerOrInfinity to 0 (ES §23.1.3.20: `[1,2,3].lastIndexOf(3,
    /// undefined)` is -1 in every engine). `None` when the search is empty:
    /// an empty receiver, whose `fromIndex` is never converted, or a
    /// `fromIndex` before the first element.
    pub(super) fn last_from_index(
        &mut self,
        v: Option<&JsValue>,
        len: usize,
    ) -> Result<Option<usize>, JsValue> {
        if len == 0 {
            return Ok(None);
        }
        let Some(v) = v else {
            return Ok(Some(len - 1));
        };
        let n = self.to_integer_or_infinity(v)?;
        let k = if n < 0.0 { len as f64 + n } else { n.min((len - 1) as f64) };
        Ok(if k < 0.0 { None } else { Some(k as usize) })
    }

    /// The start of a forward search (`indexOf`, `includes`), `None` when
    /// it is past the end. Callers answer an empty receiver first, so
    /// `fromIndex` is not converted then (ES §23.1.3.16 step 4).
    pub(super) fn search_from(
        &mut self,
        v: Option<&JsValue>,
        len: usize,
    ) -> Result<Option<usize>, JsValue> {
        let n = match v {
            Some(v) => self.to_integer_or_infinity(v)?,
            None => 0.0,
        };
        let k = clamp_relative(n, len);
        Ok(if k < len { Some(k) } else { None })
    }

    /// LengthOfArrayLike (ES §7.3.18): the receiver's `length` read ONCE
    /// through [[Get]] and ToLength, after ToObject refused null and
    /// undefined. A dense Array, a typed array and a DOM list answer from
    /// their own storage, which no script can observe.
    pub(super) fn length_of_array_like(&mut self, v: &JsValue) -> Result<usize, JsValue> {
        if v.is_nullish() {
            return Err(Interp::throw(
                "TypeError: Array.prototype method called on null or undefined",
            ));
        }
        if let JsValue::Object(o) = v {
            let b = o.borrow();
            match &b.kind {
                ObjKind::Array => return Ok(b.array_length()),
                ObjKind::TypedArray(t) => return Ok(t.length),
                ObjKind::DomList(h) => return Ok(h.len()),
                _ => {}
            }
        }
        let len = self.get_property(v, "length")?;
        let n = self.to_integer_or_infinity(&len)?;
        // ToLength clamps to 2^53 - 1; the step budget bounds any walk.
        Ok(if n <= 0.0 { 0 } else { n.min(9_007_199_254_740_991.0) as usize })
    }

    /// The receiver's element `k` through [[Get]].
    fn element(&mut self, v: &JsValue, k: usize) -> Result<JsValue, JsValue> {
        self.charge_pub()?;
        self.get_property(v, &k.to_string())
    }

    /// Step `k` of a method that skips holes: HasProperty(O, k) and, when
    /// the property exists, Get(O, k); `None` for a hole. A dense Array's
    /// stored element and a typed array's in-bounds element answer from
    /// their storage, which no script can observe; anything else (a Proxy,
    /// whose `has` trap runs, an array-like, a hole in an Array, an
    /// accessor on an index) goes through [[HasProperty]], so an inherited
    /// index counts as present.
    fn present_element(&mut self, v: &JsValue, k: usize) -> Result<Option<JsValue>, JsValue> {
        self.charge_pub()?;
        let key = k.to_string();
        let stored = match v {
            JsValue::Object(o) => {
                let b = o.borrow();
                match &b.kind {
                    ObjKind::Array if !b.index.contains_key(&key) => b.elem(k).cloned(),
                    ObjKind::TypedArray(t) => t.get(k).map(JsValue::Num),
                    _ => None,
                }
            }
            _ => None,
        };
        if stored.is_some() {
            return Ok(stored);
        }
        let JsValue::Object(o) = self.to_object(v) else {
            return Ok(None);
        };
        if !self.has_property(&o, &key)? {
            return Ok(None);
        }
        Ok(Some(self.get_property(v, &key)?))
    }

    /// The receiver's indices `start..end` as `present_element` reads
    /// them, a hole as `None`. A dense Array whose holes nothing on its
    /// prototype chain can fill is copied from its store, a typed array
    /// from its buffer.
    fn element_slots(&mut self, v: &JsValue, start: usize, end: usize) -> Result<Vec<Option<JsValue>>, JsValue> {
        if let JsValue::Object(o) = v {
            let fast = {
                let b = o.borrow();
                match &b.kind {
                    ObjKind::Array if !b.has_element_slots() && end <= super::eval::MAX_DENSE => {
                        let n = b.elems.len();
                        let stored = b.elems.get(start.min(n)..end.min(n)).unwrap_or_default();
                        let holes = end > n || stored.iter().any(Option::is_none);
                        (!holes || holes_are_absent(&b)).then(|| {
                            let mut out = stored.to_vec();
                            out.resize(end.saturating_sub(start), None);
                            out
                        })
                    }
                    ObjKind::TypedArray(t) => Some((start..end).map(|i| t.get(i).map(JsValue::Num)).collect()),
                    _ => None,
                }
            };
            if let Some(slots) = fast {
                return Ok(slots);
            }
        }
        let mut out = Vec::with_capacity(end.saturating_sub(start).min(1 << 16));
        for k in start..end {
            out.push(self.present_element(v, k)?);
        }
        Ok(out)
    }

    /// CreateListFromArrayLike through [[Get]]: a dense `Array` is read
    /// directly (a hole as `undefined` when nothing on its prototype chain
    /// can hold an index), a DOM list wraps its handles, anything else (an
    /// Array with an accessor on an index included) goes through `length`
    /// and its indices so Proxy traps, accessors and inherited indices run.
    pub fn array_like_items(&mut self, v: &JsValue) -> Result<Vec<JsValue>, JsValue> {
        let JsValue::Object(o) = v else {
            if let JsValue::Str(s) = v {
                return Ok(s.chars().map(|c| JsValue::str(c.to_string())).collect());
            }
            return Err(Interp::throw(
                "TypeError: Array.prototype method called on a non-object",
            ));
        };
        enum Fast {
            Elems(Vec<JsValue>),
            Dom(Vec<usize>),
            Generic,
        }
        let fast = {
            let b = o.borrow();
            match &b.kind {
                ObjKind::Array if !b.has_element_slots() && (!b.has_holes() || holes_are_absent(&b)) => {
                    Fast::Elems(b.array_values())
                }
                ObjKind::DomList(h) => Fast::Dom(h.clone()),
                ObjKind::TypedArray(t) => {
                    Fast::Elems(t.values().into_iter().map(JsValue::Num).collect())
                }
                _ => Fast::Generic,
            }
        };
        match fast {
            Fast::Elems(e) => Ok(e),
            Fast::Dom(hs) => Ok(hs.iter().map(|h| self.wrap_dom_node(*h)).collect()),
            Fast::Generic => {
                let len = self.get_property(v, "length")?.to_number();
                let len = if len.is_finite() && len > 0.0 {
                    (len as usize).min(10_000_000)
                } else {
                    0
                };
                let mut out = Vec::with_capacity(len.min(1 << 16));
                for i in 0..len {
                    self.charge_pub()?;
                    out.push(self.get_property(v, &i.to_string())?);
                }
                Ok(out)
            }
        }
    }

    /// The receiver as an Array a method may rewrite through its store:
    /// a dense Array with no integrity level, no read-only,
    /// non-configurable or non-enumerable element and no accessor on an
    /// index (attributes belong to the index, not the value), so every
    /// [[Set]] and [[Delete]] the spec's steps make would land in the
    /// store unrefused, and whose `length` is within the dense cap. With
    /// `holes`, also one whose holes nothing on its prototype chain can
    /// fill, so [[HasProperty]] and [[Get]] read the store too.
    fn rewritable_array(v: &JsValue, holes: bool) -> Option<ObjRef> {
        let JsValue::Object(o) = v else { return None };
        let b = o.borrow();
        let ok = matches!(b.kind, ObjKind::Array)
            && !b.frozen
            && !b.sealed
            && !b.non_extensible
            && b.non_writable.is_empty()
            && b.non_configurable.is_empty()
            && b.non_enumerable_elems.is_empty()
            && b.array_length() <= super::eval::MAX_DENSE
            && !b.has_element_slots()
            && (!holes || !b.has_holes() || holes_are_absent(&b));
        ok.then(|| o.clone())
    }

    /// DeletePropertyOrThrow (ES §7.3.10) on the receiver's index or key.
    fn delete_or_throw(&mut self, v: &JsValue, key: &str) -> Result<(), JsValue> {
        let JsValue::Object(o) = self.to_object(v) else {
            return Ok(());
        };
        if self.delete_property(&o, key)? {
            return Ok(());
        }
        Err(Interp::throw(format!("TypeError: Cannot delete property '{key}' of object")))
    }

    /// Move element `from` to `to` the way shift, unshift and splice do:
    /// Set when `from` is present, DeletePropertyOrThrow otherwise.
    fn move_element(&mut self, v: &JsValue, from: usize, to: usize) -> Result<(), JsValue> {
        match self.present_element(v, from)? {
            Some(x) => self.set_or_throw(v, &to.to_string(), x),
            None => self.delete_or_throw(v, &to.to_string()),
        }
    }

    /// The receiver's present elements in index order, holes skipped
    /// (what `flat` and `flatMap` spread).
    fn present_items(&mut self, v: &JsValue) -> Result<Vec<JsValue>, JsValue> {
        let len = self.length_of_array_like(v)?;
        Ok(self.element_slots(v, 0, len)?.into_iter().flatten().collect())
    }

    /// Set(O, P, V, true) (ES §7.3.4): [[Set]], and a TypeError when the
    /// write is refused.
    pub(super) fn set_or_throw(&mut self, v: &JsValue, key: &str, value: JsValue) -> Result<(), JsValue> {
        if self.try_set_property(v, key, value)? {
            return Ok(());
        }
        Err(Interp::throw(format!(
            "TypeError: Cannot assign to read only property '{key}' of object"
        )))
    }

    /// `get [Symbol.species]() { return this; }` on the constructors whose
    /// methods consult it (ES 23.1.2.5, 24.1.2.2, 24.2.2.2, 27.2.4.8,
    /// 22.2.5.2, 25.1.5.3, and 23.2.2.4 for each typed array, the realm
    /// having no shared %TypedArray% constructor), each its own function.
    /// Array's is recorded for `array_species_create`.
    pub(super) fn install_species_getters(&mut self) {
        let key = symbol_key(SYM_SPECIES);
        let mut names = vec!["Array", "Map", "Set", "Promise", "RegExp", "ArrayBuffer"];
        names.extend(super::value::TypedKind::ALL.iter().map(|k| k.name()));
        for name in names {
            let ctor = match self.global_object.borrow().get_prop(name) {
                Some(JsValue::Object(c)) => c,
                _ => continue,
            };
            let getter: NativeFn = Rc::new(|_i, this, _a| Ok(this));
            let JsValue::Object(g) = self.native(getter) else { continue };
            ctor.borrow_mut().set_accessor(&key, Some(g.clone()), None, false);
            if name == "Array" {
                self.array_species = Some((ctor, g));
            }
        }
    }

    /// ArraySpeciesCreate (ES 10.4.2.3): `None` when the result is a plain
    /// Array (the original is not an Array, or its species is undefined
    /// or the realm's Array), otherwise the object
    /// `new (original.constructor[@@species])(length)` returned. An Array
    /// on the realm's Array.prototype whose constructor and species are
    /// still the installed ones answers without a lookup.
    pub(super) fn array_species_create(&mut self, original: &JsValue, length: usize) -> Result<Option<JsValue>, JsValue> {
        if !is_array_value(original) {
            return Ok(None);
        }
        if let (JsValue::Object(o), Some((array, getter))) = (original, &self.array_species) {
            let b = o.borrow();
            let intrinsic = matches!(b.kind, ObjKind::Array)
                && !b.index.contains_key("constructor")
                && b.proto.as_ref().is_some_and(|p| Rc::ptr_eq(p, &self.array_proto))
                && matches!(self.array_proto.borrow().get_prop("constructor"), Some(JsValue::Object(c)) if Rc::ptr_eq(&c, array))
                && matches!(
                    array.borrow().own_slot(&symbol_key(SYM_SPECIES)),
                    Some(super::value::Prop::Accessor { get: Some(g), .. }) if Rc::ptr_eq(g, getter)
                );
            if intrinsic {
                return Ok(None);
            }
        }
        let mut c = self.get_property(original, "constructor")?;
        if matches!(c, JsValue::Object(_)) {
            c = self.get_property(&c, &symbol_key(SYM_SPECIES))?;
            if matches!(c, JsValue::Null) {
                c = JsValue::Undefined;
            }
        }
        match &c {
            JsValue::Undefined => Ok(None),
            JsValue::Object(f) if self.array_species.as_ref().is_some_and(|(a, _)| Rc::ptr_eq(a, f)) => Ok(None),
            JsValue::Object(f) if f.borrow().is_callable() && !f.borrow().is_arrow() => {
                Ok(Some(self.construct(c.clone(), &[JsValue::Num(length as f64)])?))
            }
            _ => Err(Interp::throw("TypeError: object.constructor[Symbol.species] is not a constructor")),
        }
    }

    /// The result of `flat` / `flatMap`: `items` as a fresh Array, or
    /// defined at indices 0.. on the species result (whose length the
    /// spec leaves to its constructor).
    fn species_result(&mut self, species: Option<JsValue>, items: Vec<JsValue>) -> Result<JsValue, JsValue> {
        let Some(a) = species else {
            return Ok(self.new_array(items));
        };
        for (k, v) in items.into_iter().enumerate() {
            self.create_data_property_or_throw(&a, &k.to_string(), v)?;
        }
        Ok(a)
    }

    /// CreateDataPropertyOrThrow (ES 7.3.7) of `key` on the object a
    /// species constructor returned.
    fn create_data_property_or_throw(&mut self, target: &JsValue, key: &str, value: JsValue) -> Result<(), JsValue> {
        let JsValue::Object(o) = target else {
            return Err(Interp::throw("TypeError: species constructor returned a non-object"));
        };
        let desc = super::builtins_es::PropDesc {
            value: Some(value),
            writable: Some(true),
            enumerable: Some(true),
            configurable: Some(true),
            ..super::builtins_es::PropDesc::default()
        }
        .to_object(self);
        if self.define_own_property(o, key, &desc)? {
            return Ok(());
        }
        Err(Interp::throw(format!("TypeError: Cannot define property '{key}' on the species result")))
    }

    /// The receiver half of `splice` (ES 23.1.3.31 steps 15-21), generic
    /// over array-likes: shift the elements after the deleted range by
    /// the difference, write the items, set the length.
    fn splice_receiver(&mut self, this: &JsValue, len: usize, start: usize, delete_count: usize, items: Vec<JsValue>) -> Result<(), JsValue> {
        let new_len = len - delete_count + items.len();
        if items.len() < delete_count {
            for k in start..len - delete_count {
                self.move_element(this, k + delete_count, k + items.len())?;
            }
            for k in (new_len..len).rev() {
                self.delete_or_throw(this, &k.to_string())?;
            }
        } else if items.len() > delete_count {
            for k in (start..len - delete_count).rev() {
                self.move_element(this, k + delete_count, k + items.len())?;
            }
        }
        for (j, item) in items.into_iter().enumerate() {
            self.set_or_throw(this, &(start + j).to_string(), item)?;
        }
        self.set_or_throw(this, "length", JsValue::Num(new_len as f64))
    }

    /// IsConcatSpreadable (ES 23.1.3.2.1): an object's
    /// @@isConcatSpreadable through ToBoolean when it is not undefined,
    /// IsArray otherwise; a primitive is never spread. `key` is the
    /// symbol's property-table key.
    fn is_concat_spreadable(&mut self, v: &JsValue, key: &str) -> Result<bool, JsValue> {
        if !matches!(v, JsValue::Object(_)) {
            return Ok(false);
        }
        match self.get_property(v, key)? {
            JsValue::Undefined => Ok(is_array_value(v)),
            s => Ok(s.truthy()),
        }
    }

    /// Install the generic `Array.prototype` methods and `Array.isArray`.
    pub(super) fn install_array_generic(&mut self) {
        let mut methods: Vec<(&str, NativeFn)> = Vec::new();

        methods.push((
            "push",
            Rc::new(|interp, this, args| {
                // ES §23.1.3.23: Set each argument at the end, then
                // `length`; nothing already there is read or rewritten.
                let len = interp.length_of_array_like(&this)?;
                let n = len.saturating_add(args.len());
                if n <= super::eval::MAX_DENSE {
                    if let Some(o) = Self::rewritable_array(&this, false) {
                        let mut b = o.borrow_mut();
                        b.elems.resize(len, None);
                        b.elems.extend(args.iter().cloned().map(Some));
                        b.trailing_holes = 0;
                        return Ok(JsValue::Num(n as f64));
                    }
                }
                for (i, a) in args.iter().enumerate() {
                    interp.set_or_throw(&this, &len.saturating_add(i).to_string(), a.clone())?;
                }
                interp.set_or_throw(&this, "length", JsValue::Num(n as f64))?;
                Ok(JsValue::Num(n as f64))
            }),
        ));
        methods.push((
            "pop",
            Rc::new(|interp, this, _a| {
                // ES §23.1.3.22: Get the last index, delete it, shorten.
                let len = interp.length_of_array_like(&this)?;
                if len == 0 {
                    interp.set_or_throw(&this, "length", JsValue::Num(0.0))?;
                    return Ok(JsValue::Undefined);
                }
                if let Some(o) = Self::rewritable_array(&this, false) {
                    let mut b = o.borrow_mut();
                    if b.trailing_holes == 0 && matches!(b.elems.last(), Some(Some(_))) {
                        return Ok(b.elems.pop().flatten().unwrap_or(JsValue::Undefined));
                    }
                }
                let last = (len - 1).to_string();
                let out = interp.get_property(&this, &last)?;
                interp.delete_or_throw(&this, &last)?;
                interp.set_or_throw(&this, "length", JsValue::Num((len - 1) as f64))?;
                Ok(out)
            }),
        ));
        methods.push((
            "shift",
            Rc::new(|interp, this, _a| {
                // ES §23.1.3.27: every element moves down one, a hole
                // moving as a hole; the last index is deleted.
                let len = interp.length_of_array_like(&this)?;
                if len == 0 {
                    interp.set_or_throw(&this, "length", JsValue::Num(0.0))?;
                    return Ok(JsValue::Undefined);
                }
                if let Some(o) = Self::rewritable_array(&this, true) {
                    let mut b = o.borrow_mut();
                    b.elems.resize(len, None);
                    b.trailing_holes = 0;
                    return Ok(b.elems.remove(0).unwrap_or(JsValue::Undefined));
                }
                let first = interp.get_property(&this, "0")?;
                for k in 1..len {
                    interp.move_element(&this, k, k - 1)?;
                }
                interp.delete_or_throw(&this, &(len - 1).to_string())?;
                interp.set_or_throw(&this, "length", JsValue::Num((len - 1) as f64))?;
                Ok(first)
            }),
        ));
        methods.push((
            "unshift",
            Rc::new(|interp, this, args| {
                // ES §23.1.3.32: every element moves up by the argument
                // count, from the end down, then the arguments are set.
                let len = interp.length_of_array_like(&this)?;
                let n = len.saturating_add(args.len());
                if n <= super::eval::MAX_DENSE {
                    if let Some(o) = Self::rewritable_array(&this, true) {
                        let mut b = o.borrow_mut();
                        b.elems.resize(len, None);
                        b.trailing_holes = 0;
                        b.elems.splice(0..0, args.iter().cloned().map(Some));
                        return Ok(JsValue::Num(n as f64));
                    }
                }
                if !args.is_empty() {
                    for k in (0..len).rev() {
                        interp.move_element(&this, k, k.saturating_add(args.len()))?;
                    }
                    for (j, a) in args.iter().enumerate() {
                        interp.set_or_throw(&this, &j.to_string(), a.clone())?;
                    }
                }
                interp.set_or_throw(&this, "length", JsValue::Num(n as f64))?;
                Ok(JsValue::Num(n as f64))
            }),
        ));
        methods.push((
            "slice",
            Rc::new(|interp, this, args| {
                // Length once, then the arguments, then the elements: a
                // `valueOf` that changes the receiver is seen by the read.
                // A hole stays a hole in the result, whose length is the
                // count taken (ES §23.1.3.28).
                let len = interp.length_of_array_like(&this)?;
                let start = interp.relative_index(args.first(), len, 0)?;
                let end = interp.relative_index(args.get(1), len, len)?;
                let count = end.saturating_sub(start);
                if let Some(a) = interp.array_species_create(&this, count)? {
                    for k in 0..count {
                        if let Some(v) = interp.present_element(&this, start + k)? {
                            interp.create_data_property_or_throw(&a, &k.to_string(), v)?;
                        }
                    }
                    interp.set_or_throw(&a, "length", JsValue::Num(count as f64))?;
                    return Ok(a);
                }
                let slots = interp.element_slots(&this, start, end.max(start))?;
                Ok(interp.new_array_with_holes(slots))
            }),
        ));
        methods.push((
            "splice",
            Rc::new(|interp, this, args| {
                let len = interp.length_of_array_like(&this)?;
                let start = interp.relative_index(args.first(), len, 0)?;
                let delete_count = match args.get(1) {
                    Some(v) => {
                        let n = interp.to_integer_or_infinity(v)?;
                        if n <= 0.0 {
                            0
                        } else {
                            n.min(len.saturating_sub(start) as f64) as usize
                        }
                    }
                    None if args.is_empty() => 0,
                    None => len.saturating_sub(start),
                };
                let items: Vec<JsValue> = args.get(2..).unwrap_or_default().to_vec();
                let new_len = len - delete_count + items.len();
                // The result is created (step 11) before the removed
                // elements, which keep their holes, are read (step 12).
                let species = interp.array_species_create(&this, delete_count)?;
                let removed = interp.element_slots(&this, start, start + delete_count)?;
                if let Some(a) = species {
                    for (k, v) in removed.iter().enumerate() {
                        if let Some(v) = v {
                            interp.create_data_property_or_throw(&a, &k.to_string(), v.clone())?;
                        }
                    }
                    interp.set_or_throw(&a, "length", JsValue::Num(delete_count as f64))?;
                    interp.splice_receiver(&this, len, start, delete_count, items)?;
                    return Ok(a);
                }
                if new_len <= super::eval::MAX_DENSE {
                    if let Some(o) = Self::rewritable_array(&this, true) {
                        {
                            let mut b = o.borrow_mut();
                            b.elems.resize(len, None);
                            b.trailing_holes = 0;
                            b.elems.splice(start..start + delete_count, items.into_iter().map(Some));
                        }
                        return Ok(interp.new_array_with_holes(removed));
                    }
                }
                let out = interp.new_array_with_holes(removed);
                interp.splice_receiver(&this, len, start, delete_count, items)?;
                Ok(out)
            }),
        ));
        methods.push((
            "indexOf",
            Rc::new(|interp, this, args| {
                let len = interp.length_of_array_like(&this)?;
                if len == 0 {
                    return Ok(JsValue::Num(-1.0));
                }
                let target = args.first().cloned().unwrap_or(JsValue::Undefined);
                let Some(from) = interp.search_from(args.get(1), len)? else {
                    return Ok(JsValue::Num(-1.0));
                };
                for k in from..len {
                    if interp.present_element(&this, k)?.is_some_and(|v| v.strict_eq(&target)) {
                        return Ok(JsValue::Num(k as f64));
                    }
                }
                Ok(JsValue::Num(-1.0))
            }),
        ));
        methods.push((
            "lastIndexOf",
            Rc::new(|interp, this, args| {
                let len = interp.length_of_array_like(&this)?;
                let target = args.first().cloned().unwrap_or(JsValue::Undefined);
                // fromIndex: the search runs backwards from it (inclusive);
                // a negative value counts from the end, an absent one is
                // the last element (ES §23.1.3.20).
                let Some(from) = interp.last_from_index(args.get(1), len)? else {
                    return Ok(JsValue::Num(-1.0));
                };
                for k in (0..=from).rev() {
                    if interp.present_element(&this, k)?.is_some_and(|v| v.strict_eq(&target)) {
                        return Ok(JsValue::Num(k as f64));
                    }
                }
                Ok(JsValue::Num(-1.0))
            }),
        ));
        methods.push((
            "includes",
            Rc::new(|interp, this, args| {
                let len = interp.length_of_array_like(&this)?;
                if len == 0 {
                    return Ok(JsValue::Bool(false));
                }
                let target = args.first().cloned().unwrap_or(JsValue::Undefined);
                let Some(from) = interp.search_from(args.get(1), len)? else {
                    return Ok(JsValue::Bool(false));
                };
                for k in from..len {
                    if same_value_zero(&interp.element(&this, k)?, &target) {
                        return Ok(JsValue::Bool(true));
                    }
                }
                Ok(JsValue::Bool(false))
            }),
        ));
        methods.push((
            "join",
            Rc::new(|interp, this, args| {
                let len = interp.length_of_array_like(&this)?;
                let sep = match args.first() {
                    Some(v) if !matches!(v, JsValue::Undefined) => interp.to_string_value(v)?,
                    _ => ",".to_string(),
                };
                let mut parts: Vec<String> = Vec::with_capacity(len.min(1 << 16));
                for k in 0..len {
                    let v = interp.element(&this, k)?;
                    parts.push(if v.is_nullish() {
                        String::new()
                    } else {
                        interp.to_string_value(&v)?
                    });
                }
                Ok(JsValue::str(parts.join(&sep)))
            }),
        ));
        methods.push((
            "reverse",
            Rc::new(|interp, this, _a| {
                // ES §23.1.3.26: swap the pairs from the ends inward; a
                // hole swaps as a hole, and the middle index is untouched.
                let len = interp.length_of_array_like(&this)?;
                if let Some(o) = Self::rewritable_array(&this, true) {
                    let mut b = o.borrow_mut();
                    b.elems.resize(len, None);
                    b.trailing_holes = 0;
                    b.elems.reverse();
                    return Ok(this);
                }
                let mut lower = 0usize;
                while lower < len / 2 {
                    let upper = len - 1 - lower;
                    let (lk, uk) = (lower.to_string(), upper.to_string());
                    let lv = interp.present_element(&this, lower)?;
                    let uv = interp.present_element(&this, upper)?;
                    match (lv, uv) {
                        (Some(l), Some(u)) => {
                            interp.set_or_throw(&this, &lk, u)?;
                            interp.set_or_throw(&this, &uk, l)?;
                        }
                        (None, Some(u)) => {
                            interp.set_or_throw(&this, &lk, u)?;
                            interp.delete_or_throw(&this, &uk)?;
                        }
                        (Some(l), None) => {
                            interp.delete_or_throw(&this, &lk)?;
                            interp.set_or_throw(&this, &uk, l)?;
                        }
                        (None, None) => {}
                    }
                    lower += 1;
                }
                Ok(this)
            }),
        ));
        methods.push((
            "fill",
            Rc::new(|interp, this, args| {
                // Only the selected range is written, one [[Set]] each, so
                // an element a `valueOf` changed outside it keeps its value.
                let len = interp.length_of_array_like(&this)?;
                let value = args.first().cloned().unwrap_or(JsValue::Undefined);
                let start = interp.relative_index(args.get(1), len, 0)?;
                let end = interp.relative_index(args.get(2), len, len)?;
                for k in start..end {
                    interp.charge_pub()?;
                    interp.set_or_throw(&this, &k.to_string(), value.clone())?;
                }
                Ok(this)
            }),
        ));
        methods.push((
            "copyWithin",
            Rc::new(|interp, this, args| {
                // ES 23.1.3.4: copy [start, end) to target as if through a
                // temporary (an overlapping move runs backwards), a hole
                // deleting its target index; the length never changes.
                if this.is_nullish() {
                    return Err(Interp::throw("TypeError: Array.prototype.copyWithin called on null or undefined"));
                }
                let o = interp.to_object(&this);
                let len = interp.length_of_array_like(&o)?;
                let to = interp.relative_index(args.first(), len, 0)?;
                let from = interp.relative_index(args.get(1), len, 0)?;
                let end = interp.relative_index(args.get(2), len, len)?;
                let count = end.saturating_sub(from).min(len - to);
                if count == 0 {
                    return Ok(o);
                }
                if let Some(arr) = Self::rewritable_array(&o, true) {
                    let mut b = arr.borrow_mut();
                    b.elems.resize(len, None);
                    b.trailing_holes = 0;
                    let moved: Vec<Option<JsValue>> = b.elems.get(from..from + count).unwrap_or_default().to_vec();
                    if let Some(dest) = b.elems.get_mut(to..to + count) {
                        dest.clone_from_slice(&moved);
                    }
                    return Ok(o);
                }
                let steps: Box<dyn Iterator<Item = usize>> =
                    if from < to && to < from + count { Box::new((0..count).rev()) } else { Box::new(0..count) };
                for k in steps {
                    interp.charge_pub()?;
                    interp.move_element(&o, from + k, to + k)?;
                }
                Ok(o)
            }),
        ));
        methods.push((
            "at",
            Rc::new(|interp, this, args| {
                let len = interp.length_of_array_like(&this)?;
                let n = match args.first() {
                    Some(v) => interp.to_integer_or_infinity(v)?,
                    None => 0.0,
                };
                let k = if n < 0.0 { len as f64 + n } else { n };
                if k < 0.0 || k >= len as f64 {
                    return Ok(JsValue::Undefined);
                }
                interp.element(&this, k as usize)
            }),
        ));
        methods.push((
            "concat",
            Rc::new(|interp, this, args| {
                // ES §23.1.3.2: a spreadable item contributes its indices,
                // a hole leaving a hole in the result.
                if this.is_nullish() {
                    return Err(Interp::throw("TypeError: Array.prototype.concat called on null or undefined"));
                }
                let mut out: Vec<Option<JsValue>> = Vec::new();
                let receiver = interp.to_object(&this);
                let species = interp.array_species_create(&receiver, 0)?;
                let spreadable_key = symbol_key(SYM_IS_CONCAT_SPREADABLE);
                for a in std::iter::once(&receiver).chain(args.iter()) {
                    if interp.is_concat_spreadable(a, &spreadable_key)? {
                        let len = interp.length_of_array_like(a)?;
                        out.extend(interp.element_slots(a, 0, len)?);
                    } else {
                        out.push(Some(a.clone()));
                    }
                }
                if let Some(a) = species {
                    let n = out.len();
                    for (k, v) in out.into_iter().enumerate() {
                        if let Some(v) = v {
                            interp.create_data_property_or_throw(&a, &k.to_string(), v)?;
                        }
                    }
                    interp.set_or_throw(&a, "length", JsValue::Num(n as f64))?;
                    return Ok(a);
                }
                Ok(interp.new_array_with_holes(out))
            }),
        ));
        methods.push((
            "flat",
            Rc::new(|interp, this, args| {
                let depth = match args.first() {
                    Some(v) if !v.is_nullish() => {
                        let d = v.to_number();
                        if d.is_nan() || d < 0.0 {
                            0
                        } else {
                            d.min(1000.0) as usize
                        }
                    }
                    _ => 1,
                };
                let species = interp.array_species_create(&this, 0)?;
                let items = interp.present_items(&this)?;
                let mut out = Vec::new();
                let mut budget = 1_000_000usize;
                flatten_into(interp, items, depth, &mut out, &mut budget)?;
                interp.species_result(species, out)
            }),
        ));
        methods.push((
            "forEach",
            Rc::new(|interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let t = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let len = interp.length_of_array_like(&this)?;
                for k in 0..len {
                    if let Some(v) = interp.present_element(&this, k)? {
                        interp.call(cb.clone(), t.clone(), &[v, JsValue::Num(k as f64), this.clone()])?;
                    }
                }
                Ok(JsValue::Undefined)
            }),
        ));
        methods.push((
            "map",
            Rc::new(|interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let t = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let len = interp.length_of_array_like(&this)?;
                let species = interp.array_species_create(&this, len)?;
                // The result has the receiver's length and a hole where
                // the receiver has one.
                let mut out = Vec::with_capacity(len.min(1 << 16));
                for k in 0..len {
                    let mapped = match interp.present_element(&this, k)? {
                        Some(v) => Some(interp.call(cb.clone(), t.clone(), &[v, JsValue::Num(k as f64), this.clone()])?),
                        None => None,
                    };
                    match (&species, mapped) {
                        (Some(a), Some(m)) => interp.create_data_property_or_throw(a, &k.to_string(), m)?,
                        (Some(_), None) => {}
                        (None, m) => out.push(m),
                    }
                }
                Ok(match species {
                    Some(a) => a,
                    None => interp.new_array_with_holes(out),
                })
            }),
        ));
        methods.push((
            "filter",
            Rc::new(|interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let t = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let len = interp.length_of_array_like(&this)?;
                let species = interp.array_species_create(&this, 0)?;
                let mut out = Vec::new();
                let mut to = 0usize;
                for k in 0..len {
                    let Some(v) = interp.present_element(&this, k)? else { continue };
                    if interp
                        .call(cb.clone(), t.clone(), &[v.clone(), JsValue::Num(k as f64), this.clone()])?
                        .truthy()
                    {
                        match &species {
                            Some(a) => interp.create_data_property_or_throw(a, &to.to_string(), v)?,
                            None => out.push(v),
                        }
                        to += 1;
                    }
                }
                Ok(match species {
                    Some(a) => a,
                    None => interp.new_array(out),
                })
            }),
        ));
        methods.push((
            "flatMap",
            Rc::new(|interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let t = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let len = interp.length_of_array_like(&this)?;
                let species = interp.array_species_create(&this, 0)?;
                let mut out = Vec::new();
                for i in 0..len {
                    let Some(v) = interp.present_element(&this, i)? else { continue };
                    let r = interp.call(cb.clone(), t.clone(), &[v, JsValue::Num(i as f64), this.clone()])?;
                    if is_array_value(&r) {
                        out.extend(interp.present_items(&r)?);
                    } else {
                        out.push(r);
                    }
                }
                interp.species_result(species, out)
            }),
        ));
        for (name, from_end, want_index) in [
            ("find", false, false),
            ("findIndex", false, true),
            ("findLast", true, false),
            ("findLastIndex", true, true),
        ] {
            let f: NativeFn = Rc::new(move |interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let t = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let items = interp.array_like_items(&this)?;
                let order: Vec<(usize, JsValue)> = if from_end {
                    items.into_iter().enumerate().rev().collect()
                } else {
                    items.into_iter().enumerate().collect()
                };
                for (i, v) in order {
                    if interp
                        .call(cb.clone(), t.clone(), &[v.clone(), JsValue::Num(i as f64), this.clone()])?
                        .truthy()
                    {
                        return Ok(if want_index { JsValue::Num(i as f64) } else { v });
                    }
                }
                Ok(if want_index { JsValue::Num(-1.0) } else { JsValue::Undefined })
            });
            methods.push((name, f));
        }
        // some / every: the first present element whose callback result
        // decides ends the walk; holes are skipped.
        for (name, want) in [("some", true), ("every", false)] {
            let f: NativeFn = Rc::new(move |interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let t = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let len = interp.length_of_array_like(&this)?;
                for k in 0..len {
                    let Some(v) = interp.present_element(&this, k)? else { continue };
                    if interp.call(cb.clone(), t.clone(), &[v, JsValue::Num(k as f64), this.clone()])?.truthy() == want {
                        return Ok(JsValue::Bool(want));
                    }
                }
                Ok(JsValue::Bool(!want))
            });
            methods.push((name, f));
        }
        // reduce / reduceRight: without an initial value the accumulator is
        // the first present element in walk order; holes are skipped, and
        // a receiver with none is a TypeError (ES §23.1.3.24-25).
        for (name, from_end) in [("reduce", false), ("reduceRight", true)] {
            let f: NativeFn = Rc::new(move |interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let len = interp.length_of_array_like(&this)?;
                let order: Box<dyn Iterator<Item = usize>> =
                    if from_end { Box::new((0..len).rev()) } else { Box::new(0..len) };
                let mut acc = args.get(1).cloned();
                for k in order {
                    let Some(v) = interp.present_element(&this, k)? else { continue };
                    acc = Some(match acc {
                        None => v,
                        Some(a) => interp.call(
                            cb.clone(),
                            JsValue::Undefined,
                            &[a, v, JsValue::Num(k as f64), this.clone()],
                        )?,
                    });
                }
                acc.ok_or_else(|| Interp::throw("TypeError: Reduce of empty array with no initial value"))
            });
            methods.push((name, f));
        }
        methods.push((
            "sort",
            Rc::new(|interp, this, args| {
                let cmp = sort_comparator(args)?;
                // SortIndexedProperties (ES §23.1.3.30.1) skipping holes:
                // the present values are sorted, undefined ones after the
                // rest without consulting the comparator, written back
                // from index 0, and every index after them is deleted, so
                // the holes end up at the end.
                let len = interp.length_of_array_like(&this)?;
                let items: Vec<JsValue> = interp.element_slots(&this, 0, len)?.into_iter().flatten().collect();
                let mut undef = 0usize;
                let mut elems: Vec<JsValue> = Vec::with_capacity(items.len());
                for v in items {
                    if matches!(v, JsValue::Undefined) {
                        undef = undef.saturating_add(1);
                    } else {
                        elems.push(v);
                    }
                }
                // Stable insertion sort so the comparator can call back into
                // script (and throw) without an unwinding panic path.
                for i in 1..elems.len() {
                    let mut j = i;
                    while j > 0 {
                        let swap = {
                            let (Some(a), Some(b)) = (elems.get(j - 1), elems.get(j)) else { break };
                            match &cmp {
                                Some(f @ JsValue::Object(fo)) if fo.borrow().is_callable() => {
                                    let r = interp.call(
                                        f.clone(),
                                        JsValue::Undefined,
                                        &[a.clone(), b.clone()],
                                    )?;
                                    interp.to_number_value(&r)? > 0.0
                                }
                                _ => interp.to_string_value(a)? > interp.to_string_value(b)?,
                            }
                        };
                        if swap {
                            elems.swap(j - 1, j);
                            j -= 1;
                        } else {
                            break;
                        }
                    }
                }
                elems.extend(std::iter::repeat_n(JsValue::Undefined, undef));
                let n = elems.len();
                if let Some(o) = Self::rewritable_array(&this, false) {
                    let mut b = o.borrow_mut();
                    if b.array_length() == len {
                        b.set_elems(elems.into_iter().map(Some).collect());
                        b.trailing_holes = len - n;
                        return Ok(this);
                    }
                }
                for (i, v) in elems.into_iter().enumerate() {
                    interp.charge_pub()?;
                    interp.set_or_throw(&this, &i.to_string(), v)?;
                }
                for k in n..len {
                    interp.charge_pub()?;
                    interp.delete_or_throw(&this, &k.to_string())?;
                }
                Ok(this)
            }),
        ));
        methods.push((
            "keys",
            Rc::new(|interp, this, _a| {
                let n = interp.array_like_items(&this)?.len();
                let out: Vec<JsValue> = (0..n).map(|i| JsValue::Num(i as f64)).collect();
                Ok(interp.make_list_iterator(out))
            }),
        ));
        methods.push((
            "entries",
            Rc::new(|interp, this, _a| {
                let items = interp.array_like_items(&this)?;
                let out: Vec<JsValue> = items
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| interp.new_array(vec![JsValue::Num(i as f64), v]))
                    .collect();
                Ok(interp.make_list_iterator(out))
            }),
        ));
        methods.push((
            "values",
            Rc::new(|interp, this, _a| {
                let items = interp.array_like_items(&this)?;
                Ok(interp.make_list_iterator(items))
            }),
        ));
        methods.push((
            "toString",
            Rc::new(|interp, this, _a| {
                let join = interp.get_property(&this, "join")?;
                match &join {
                    JsValue::Object(f) if f.borrow().is_callable() => interp.call(join.clone(), this, &[]),
                    _ => Ok(JsValue::str("[object Array]")),
                }
            }),
        ));

        for (name, f) in methods {
            let fv = self.native(f);
            self.array_proto.borrow_mut().set_prop(name, fv, false);
        }
        // `values` is also the array iterator.
        let values = self.array_proto.borrow().get_prop("values");
        if let Some(v) = values {
            self.array_proto
                .borrow_mut()
                .set_prop(&iterator_key(), v, false);
        }

        // Array.isArray sees through Proxies (IsArray, ES §7.2.2).
        if let Some(JsValue::Object(ctor)) = self.global_object.borrow().get_prop("Array") {
            let is_array: NativeFn = Rc::new(|_i, _t, args| {
                Ok(JsValue::Bool(
                    args.first().map(is_array_value).unwrap_or(false),
                ))
            });
            let f = JsValue::Object(JsObject::new(
                ObjKind::Native(is_array),
                Some(self.function_proto.clone()),
            ));
            ctor.borrow_mut().set_prop("isArray", f, false);
        }
    }
}

/// The comparator argument of `sort` (ES 23.1.3.30 step 1, 23.2.3.29
/// step 1): undefined or absent selects the default order, a callable
/// is used, and anything else is a TypeError before the receiver is
/// touched.
pub(super) fn sort_comparator(args: &[JsValue]) -> Result<Option<JsValue>, JsValue> {
    match args.first() {
        None | Some(JsValue::Undefined) => Ok(None),
        Some(f @ JsValue::Object(o)) if o.borrow().is_callable() => Ok(Some(f.clone())),
        Some(_) => Err(Interp::throw(
            "TypeError: The comparison function must be either a function or undefined",
        )),
    }
}

/// Whether a hole in an Array with this object's prototype chain is
/// simply absent: no object on the chain can hold an index (an ordinary
/// object without index keys, or an Array with no elements, is fine; a
/// Proxy, a typed array, a DOM list or a String wrapper may answer for
/// one), so [[HasProperty]] is false and [[Get]] undefined for it.
fn holes_are_absent(b: &JsObject) -> bool {
    let mut cur = b.proto.clone();
    for _ in 0..64 {
        let Some(p) = cur else { return true };
        let next = {
            let pb = p.borrow();
            let exotic = match &pb.kind {
                ObjKind::Array => !pb.elems.is_empty() || pb.trailing_holes > 0,
                ObjKind::Proxy { .. }
                | ObjKind::TypedArray(_)
                | ObjKind::DomList(_)
                | ObjKind::DomNode(_)
                | ObjKind::DomFacet { .. }
                | ObjKind::Primitive(_) => true,
                _ => false,
            };
            if exotic || pb.props.iter().any(|(k, _)| array_index(k).is_some()) {
                return false;
            }
            pb.proto.clone()
        };
        cur = next;
    }
    false
}

/// FlattenIntoArray: `depth` levels, arrays (and Proxies over arrays)
/// spread, everything else copied. `budget` bounds hostile self-nesting.
fn flatten_into(
    interp: &mut Interp,
    items: Vec<JsValue>,
    depth: usize,
    out: &mut Vec<JsValue>,
    budget: &mut usize,
) -> Result<(), JsValue> {
    for e in items {
        if *budget == 0 {
            return Err(Interp::throw("RangeError: flat produced too many elements"));
        }
        *budget -= 1;
        if depth > 0 && is_array_value(&e) {
            let inner = interp.present_items(&e)?;
            flatten_into(interp, inner, depth - 1, out, budget)?;
        } else {
            out.push(e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod order_tests {
    use super::super::interp::test_support::eval_js;

    /// Call `Array.prototype[method]` on a Proxy over [10, 20, 30, 40] with
    /// arguments whose conversions log their tag, and return the method's
    /// result followed by every string-keyed read the Proxy saw, in order.
    fn trace(method: &str, args: &str) -> String {
        eval_js(&format!(
            "const log = [];
             const p = new Proxy([10, 20, 30, 40], {{
               get(t, k) {{ if (typeof k === 'string') log.push(k); return t[k]; }}
             }});
             const arg = (v, tag) => ({{
               valueOf() {{ log.push(tag); return v; }},
               toString() {{ log.push(tag); return String(v); }}
             }});
             const out = Array.prototype.{method}.apply(p, [{args}]);
             const seen = log.join(',');
             String(out) + ' | ' + seen"
        ))
    }

    #[test]
    fn length_is_read_once_and_arguments_convert_before_any_element() {
        // ArraySpeciesCreate reads the Proxy's `constructor` after the
        // arguments and before any element (ES 23.1.3.28 step 8).
        assert_eq!(trace("slice", "arg(1, 's'), arg(3, 'e')"), "20,30 | length,s,e,constructor,1,2");
        assert_eq!(trace("indexOf", "40, arg(1, 'f')"), "3 | length,f,1,2,3");
        assert_eq!(trace("lastIndexOf", "10, arg(2, 'f')"), "0 | length,f,2,1,0");
        assert_eq!(trace("includes", "30, arg(1, 'f')"), "true | length,f,1,2");
        assert_eq!(trace("at", "arg(-1, 'i')"), "40 | length,i,3");
        assert_eq!(trace("join", "arg('-', 'sep')"), "10-20-30-40 | length,sep,0,1,2,3");
        assert_eq!(trace("fill", "0, arg(1, 's'), arg(3, 'e')"), "10,0,0,40 | length,s,e");
        let spliced = trace("splice", "arg(1, 's'), arg(2, 'd')");
        assert!(spliced.starts_with("20,30 | length,s,d,constructor,1,2"), "{spliced}");
        assert_eq!(spliced.matches("length").count(), 1, "{spliced}");
    }

    #[test]
    fn elements_are_read_after_the_arguments_convert() {
        assert_eq!(
            eval_js("const a = [1]; String(a.slice({ valueOf() { a[0] = 2; return 0; } }))"),
            "2"
        );
        assert_eq!(
            eval_js("const a = [1, 2, 3]; a.fill(0, { valueOf() { a[0] = 9; return 1; } }); a.join()"),
            "9,0,0"
        );
        assert_eq!(
            eval_js("const a = [1, 2]; a.indexOf(3, { valueOf() { a[1] = 3; return 0; } })"),
            "1"
        );
    }

    #[test]
    fn an_empty_receiver_answers_before_converting_from_index() {
        assert_eq!(eval_js("[].indexOf(1, Symbol())"), "-1");
        assert_eq!(eval_js("[].lastIndexOf(1, Symbol())"), "-1");
        assert_eq!(eval_js("[].includes(1, { valueOf() { throw 'converted'; } })"), "false");
    }

    #[test]
    fn arguments_and_generic_lengths_use_the_throwing_conversions() {
        assert_eq!(eval_js("[1, 2, 3].at({ valueOf() { return -1; } })"), "3");
        let one = "{ valueOf() { return 1; } }";
        assert_eq!(eval_js(&format!("new Uint8Array([1, 2, 3]).subarray({one}).length")), "2");
        assert_eq!(eval_js(&format!("new Uint8Array([1, 2, 3]).indexOf(1, {one})")), "-1");
        assert_eq!(eval_js(&format!("new Uint8Array([1, 2, 3]).lastIndexOf(2, {one})")), "1");
        assert_eq!(eval_js("[1, 2].join({ toString() { return '-'; } })"), "1-2");
        assert_eq!(
            eval_js("Array.prototype.indexOf.call({ length: { valueOf() { return 2; } }, 0: 'a', 1: 'b' }, 'b')"),
            "1"
        );
        assert_eq!(
            eval_js("let r = ''; try { [1].slice({ valueOf() { throw 'arg'; } }); } catch (e) { r = e; } r"),
            "arg"
        );
        assert_eq!(
            eval_js("let r = ''; try { Array.prototype.slice.call(null); } catch (e) { r = String(e).split(':')[0]; } r"),
            "TypeError"
        );
    }
}

#[cfg(test)]
mod length_write_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn methods_that_set_length_throw_on_a_frozen_array_even_when_it_is_unchanged() {
        for call in ["push()", "pop()", "shift()", "unshift()", "splice(0, 0)"] {
            assert_eq!(caught(&format!("return Object.freeze([]).{call}")), "TypeError", "[].{call}");
            assert_eq!(caught(&format!("return Object.freeze([1]).{call}")), "TypeError", "[1].{call}");
        }
        assert_eq!(
            caught("const a = [1]; Object.defineProperty(a, 'length', { writable: false }); a.push()"),
            "TypeError"
        );
        // A writable length takes the unchanged value without complaint.
        assert_eq!(caught("return [].push() + ':' + Object.seal([]).push() + ':' + Object.preventExtensions([]).pop()"), "0:0:undefined");
        // reverse and sort write no length at all.
        assert_eq!(caught("return Object.freeze([]).reverse().length + ':' + Object.freeze([]).sort().length"), "0:0");
    }

    #[test]
    fn a_proxy_sees_exactly_the_length_writes_the_spec_makes() {
        assert_eq!(
            caught("const log = []; const p = new Proxy([], { set(t, k, v) { log.push(k); t[k] = v; return true; } }); p.push(); p.pop(); p.shift(); p.unshift(); return log.join()"),
            "length,length,length,length"
        );
        assert_eq!(
            caught("const log = []; const p = new Proxy([2, 1], { set(t, k, v) { log.push(k); t[k] = v; return true; } }); p.reverse(); p.sort(); return log.join()"),
            "0,1,0,1"
        );
    }
}

#[cfg(test)]
mod array_length_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(prologue: &str, body: &str) -> String {
        eval_js(&format!(
            "{prologue} let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn an_invalid_length_is_a_range_error_in_any_mode() {
        for bad in ["-1", "1.5", "NaN", "Infinity", "4294967296", "'x'", "{ valueOf() { return -2; } }"] {
            for prologue in ["", "'use strict';"] {
                assert_eq!(
                    caught(prologue, &format!("const a = [1, 2]; try {{ a.length = {bad}; }} catch (e) {{ return String(e).split(':')[0] + ':' + a.length; }} return 'set'")),
                    "RangeError:2",
                    "{prologue} length = {bad}"
                );
            }
            assert_eq!(caught("", &format!("Object.defineProperty([1], 'length', {{ value: {bad} }})")), "RangeError", "defineProperty {bad}");
            assert_eq!(caught("", &format!("Reflect.set([1], 'length', {bad})")), "RangeError", "Reflect.set {bad}");
        }
        // Valid values convert, and the value converts twice as the spec says.
        assert_eq!(caught("", "const a = [1, 2, 3]; a.length = '2'; return a.length"), "2");
        assert_eq!(caught("", "let n = 0; const a = [1, 2, 3]; a.length = { valueOf() { n++; return 1; } }; return a.length + ':' + n"), "1:2");
        assert_eq!(caught("", "const a = [1]; a.length = -0; return a.length"), "0");
        // A read-only length refuses before converting; defineProperty
        // converts first.
        assert_eq!(caught("", "const a = Object.freeze([1]); a.length = -1; return a.length"), "1");
        assert_eq!(caught("'use strict';", "Object.freeze([1]).length = -1"), "TypeError");
        assert_eq!(caught("", "Object.defineProperty(Object.freeze([1]), 'length', { value: -1 })"), "RangeError");
    }

    #[test]
    fn growing_a_non_extensible_array_adds_no_elements() {
        for lock in ["Object.seal(a)", "Object.preventExtensions(a)"] {
            assert_eq!(
                caught("", &format!("const a = [1]; {lock}; a.length = 3; return [a.length, 1 in a, 2 in a, Object.keys(a), JSON.stringify(a), a.join('-'), [...a].length, Object.getOwnPropertyDescriptor(a, 'length').value].join(' ')")),
                "3 false false 0 [1,null,null] 1-- 3 3",
                "{lock}"
            );
            assert_eq!(
                caught("", &format!("const a = [1]; {lock}; Object.defineProperty(a, 'length', {{ value: 4 }}); a[1] = 5; return a.length + ':' + (1 in a) + ':' + Object.keys(a)")),
                "4:false:0",
                "{lock}"
            );
            assert_eq!(caught("'use strict';", &format!("const a = [1]; {lock}; a.length = 3; a[1] = 5")), "TypeError", "{lock}");
            assert_eq!(
                caught("", &format!("const a = [1, 2]; {lock}; a.length = 4; a.length = 2; return a.length + ':' + a.join()")),
                "2:1,2",
                "{lock}"
            );
            assert_eq!(
                caught("", &format!("const a = [1]; {lock}; a.length = 3; return (function () {{ return arguments.length; }}).apply(null, a)")),
                "3",
                "{lock}"
            );
        }
        // pop and shrink on a non-extensible (not sealed) array with holes
        // at the end.
        assert_eq!(
            caught("", "const a = [1]; Object.preventExtensions(a); a.length = 3; const v = a.pop(); return v + ':' + a.length + ':' + Object.keys(a)"),
            "undefined:2:0"
        );
        assert_eq!(
            caught("", "const a = [1, 2]; Object.preventExtensions(a); a.length = 4; a.length = 1; return a.length + ':' + a.join()"),
            "1:1"
        );
    }

    #[test]
    fn define_property_reports_a_length_shrink_that_stopped_early() {
        assert_eq!(
            caught("", "const a = [1, 2]; Object.defineProperty(a, 1, { value: 2, writable: true, configurable: false }); try { Object.defineProperty(a, 'length', { value: 0 }); } catch (e) { return String(e).split(':')[0] + ':' + a.length; } return 'shrunk'"),
            "TypeError:2"
        );
        assert_eq!(
            caught("", "const a = [1, 2]; Object.defineProperty(a, 1, { value: 2, writable: true, configurable: false }); return Reflect.defineProperty(a, 'length', { value: 0 }) + ':' + a.length"),
            "false:2"
        );
    }
}

#[cfg(test)]
mod index_accessor_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// `a = [1, 2, 3]` with index 1 turned into an accessor reading 9 and
    /// logging what is written to it.
    const ACCESSOR: &str = "const writes = []; const a = [1, 2, 3]; Object.defineProperty(a, 1, { get() { return 9; }, set(v) { writes.push(v); }, configurable: true, enumerable: true });";

    #[test]
    fn every_read_of_the_index_goes_through_the_accessor() {
        assert_eq!(
            caught(&format!("{ACCESSOR} return [a[1], a.join(), a.indexOf(9), a.includes(2), a.slice(1, 2), [...a], a.map(x => x), Array.from(a), JSON.stringify(a), a.length].join(' ')")),
            "9 1,9,3 1 false 9 1,9,3 1,9,3 1,9,3 [1,9,3] 3"
        );
        assert_eq!(caught(&format!("{ACCESSOR} let s = []; for (const x of a) s.push(x); return s.join()")), "1,9,3");
        assert_eq!(caught(&format!("{ACCESSOR} return (function () {{ return [...arguments].join(); }}).apply(null, a)")), "1,9,3");
        assert_eq!(caught(&format!("{ACCESSOR} return JSON.stringify({{ ...a }})")), "{\"0\":1,\"1\":9,\"2\":3}");
        assert_eq!(caught(&format!("{ACCESSOR} return String(a) + ':' + (a + '')")), "1,9,3:1,9,3");
    }

    #[test]
    fn the_index_is_listed_once() {
        assert_eq!(
            caught(&format!("{ACCESSOR} return [Object.keys(a), Object.getOwnPropertyNames(a), Reflect.ownKeys(a)].join(' | ')")),
            "0,1,2 | 0,1,2,length | 0,1,2,length"
        );
        assert_eq!(caught(&format!("{ACCESSOR} const ks = []; for (const k in a) ks.push(k); return ks.join()")), "0,1,2");
        assert_eq!(caught(&format!("{ACCESSOR} return Object.entries(a).join(' ')")), "0,1 1,9 2,3");
    }

    #[test]
    fn writes_run_the_setter_and_methods_go_through_it() {
        assert_eq!(caught(&format!("{ACCESSOR} a[1] = 5; return writes.join() + ':' + a[1]")), "5:9");
        // reverse leaves the middle index alone, so its setter does not run.
        assert_eq!(caught(&format!("{ACCESSOR} a.reverse(); return writes.join() + ':' + a.join()")), ":3,9,1");
        assert_eq!(caught(&format!("{ACCESSOR} a.fill(0); return writes.join() + ':' + a.join()")), "0:0,9,0");
        assert_eq!(caught(&format!("{ACCESSOR} a.push(4); return writes.join() + ':' + a.join() + ':' + a.length")), ":1,9,3,4:4");
        assert_eq!(caught(&format!("{ACCESSOR} a.shift(); return writes.join() + ':' + a.length")), "3:2");
    }

    #[test]
    fn redefining_or_removing_the_index_leaves_no_stale_value() {
        // Back to data: the new value, not the one the accessor shadowed.
        assert_eq!(caught(&format!("{ACCESSOR} Object.defineProperty(a, 1, {{ value: 7 }}); return a[1] + ':' + a.join() + ':' + Object.keys(a)")), "7:1,7,3:0,1,2");
        assert_eq!(caught(&format!("{ACCESSOR} delete a[1]; return a[1] + ':' + a.join()")), "undefined:1,,3");
        assert_eq!(caught(&format!("{ACCESSOR} a.length = 1; a.length = 3; return a[1] + ':' + Object.getOwnPropertyDescriptor(a, 1) + ':' + writes.length")), "undefined:undefined:0");
        // An accessor past the end extends the array.
        assert_eq!(
            caught("const a = [1]; Object.defineProperty(a, 3, { get() { return 'g'; }, configurable: true }); return a.length + ':' + a[3] + ':' + a.join()"),
            "4:g:1,,,g"
        );
    }
}

#[cfg(test)]
mod hole_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// An array-like with holes at 0 and 2: `length` 4, index 1 holding
    /// undefined and index 3 holding 'd'.
    const HOLEY: &str = "const o = { length: 4, 1: undefined, 3: 'd' };";

    #[test]
    fn the_searches_skip_holes_and_includes_reads_them_as_undefined() {
        assert_eq!(
            caught(&format!("{HOLEY} const A = Array.prototype; return [A.indexOf.call(o, undefined), A.lastIndexOf.call(o, undefined), A.includes.call(o, undefined), A.indexOf.call({{ length: 2 }}, undefined), A.includes.call({{ length: 2 }}, undefined)].join()")),
            "1,1,true,-1,true"
        );
        // An inherited index is a property, not a hole.
        assert_eq!(
            caught("const o = Object.create({ 1: 'p' }); o.length = 2; return Array.prototype.indexOf.call(o, 'p')"),
            "1"
        );
        // A grown non-extensible array has holes at the end.
        assert_eq!(
            caught("const a = Object.preventExtensions([1]); a.length = 3; return [a.indexOf(undefined), a.lastIndexOf(undefined), a.includes(undefined)].join()"),
            "-1,-1,true"
        );
    }

    #[test]
    fn the_callback_methods_skip_holes_and_find_visits_them() {
        let visits = |method: &str| {
            caught(&format!("{HOLEY} const seen = []; Array.prototype.{method}.call(o, (v, i) => {{ seen.push(i + '=' + v); }}); return seen.join()"))
        };
        for method in ["forEach", "map", "filter", "some", "every"] {
            let expected = if method == "every" { "1=undefined" } else { "1=undefined,3=d" };
            assert_eq!(visits(method), expected, "{method}");
        }
        assert_eq!(visits("find"), "0=undefined,1=undefined,2=undefined,3=d");
        assert_eq!(visits("findIndex"), "0=undefined,1=undefined,2=undefined,3=d");
        // map keeps the result's length and filter keeps only what it saw.
        assert_eq!(
            caught(&format!("{HOLEY} const m = Array.prototype.map.call(o, (v) => String(v)); const f = Array.prototype.filter.call(o, () => true); return m.length + ':' + m[1] + ':' + m[3] + ':' + f.length")),
            "4:undefined:d:2"
        );
        assert_eq!(caught("return [Array.prototype.every.call({ length: 2 }, () => false), Array.prototype.some.call({ length: 2 }, () => true)].join()"), "true,false");
    }

    #[test]
    fn reduce_starts_from_the_first_present_element() {
        assert_eq!(caught(&format!("{HOLEY} return Array.prototype.reduce.call(o, (a, v, i) => a + '|' + i + v)")), "undefined|3d");
        assert_eq!(caught(&format!("{HOLEY} return Array.prototype.reduceRight.call(o, (a, v, i) => a + '|' + i + v)")), "d|1undefined");
        assert_eq!(caught("return Array.prototype.reduce.call({ length: 3, 1: 5 }, (a, b) => a + b)"), "5");
        assert_eq!(caught("return Array.prototype.reduce.call({ length: 2 }, (a, b) => a + b)"), "TypeError");
        assert_eq!(caught("return Array.prototype.reduceRight.call({ length: 2 }, (a, b) => a + b, 'init')"), "init");
    }

    #[test]
    fn has_property_runs_before_each_read_through_a_proxy() {
        assert_eq!(
            caught("const log = []; const p = new Proxy([7, 8], { has(t, k) { log.push('has ' + k); return k in t; }, get(t, k) { if (typeof k === 'string') log.push('get ' + k); return t[k]; } }); \
                    Array.prototype.forEach.call(p, () => {}); return log.join()"),
            "get length,has 0,get 0,has 1,get 1"
        );
        // A trap that hides an index makes it a hole.
        assert_eq!(
            caught("const p = new Proxy([7, 8, 9], { has(t, k) { return k !== '1'; } }); return Array.prototype.map.call(p, (v) => v).join('/') + ':' + Array.prototype.indexOf.call(p, 8)"),
            "7//9:-1"
        );
        // The callback sees writes made during the walk, as the spec's
        // per-step reads do.
        assert_eq!(caught("const a = [1, 2, 3]; const seen = []; a.forEach((v, i) => { seen.push(v); if (i === 0) a[2] = 9; }); return seen.join()"), "1,2,9");
    }

    #[test]
    fn host_and_primitive_receivers_have_their_indices() {
        // HasProperty must see a DOM list's items and a string's characters,
        // or the generic methods would skip every one of them.
        assert_eq!(
            super::super::interp::test_support::eval_in_page(
                "<p>a</p><p>b</p>",
                "const l = document.querySelectorAll('p'); const out = []; [].forEach.call(l, (p, i) => out.push(i + p.textContent)); \
                 return [out.join(), [].map.call(document.getElementsByTagName('p'), (p) => p.textContent).join(), [].indexOf.call(l, l[1]), 0 in l, 1 in l, 2 in l].join('|')"
            ),
            "0a,1b|a,b|1|true|true|false"
        );
        assert_eq!(
            caught("return [Array.prototype.indexOf.call('abc', 'b'), Array.prototype.map.call('ab', (c) => c + c).join(), 1 in new String('ab'), 2 in new String('ab')].join('|')"),
            "1|aa,bb|true|false"
        );
        assert_eq!(
            caught("return [(function () { return [].map.call(arguments, (x) => x * 2).join(); })(1, 2), Array.prototype.indexOf.call(new Uint8Array([5, 6]), 6)].join('|')"),
            "2,4|1"
        );
    }
}

#[cfg(test)]
mod dense_hole_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// What every reader of own properties says about index 1 of `a` and
    /// about the array as a whole.
    fn report(setup: &str) -> String {
        caught(&format!(
            "{setup} const fi = []; for (const k in a) fi.push(k); \
             return [a.length, 1 in a, a.hasOwnProperty(1), Object.getOwnPropertyDescriptor(a, 1) === undefined, \
                     Object.keys(a).join('/'), Object.getOwnPropertyNames(a).join('/'), Reflect.ownKeys(a).join('/'), fi.join('/'), \
                     JSON.stringify(a), a[1], a.indexOf(undefined)].join(' ')"
        ))
    }

    #[test]
    fn every_way_of_making_a_hole_leaves_the_index_absent() {
        assert_eq!(report("const a = [1, , 3];"), "3 false false true 0/2 0/2/length 0/2/length 0/2 [1,null,3]  -1");
        assert_eq!(report("const a = [1, 2, 3]; delete a[1];"), "3 false false true 0/2 0/2/length 0/2/length 0/2 [1,null,3]  -1");
        assert_eq!(report("const a = new Array(3); a[0] = 1; a[2] = 3;"), "3 false false true 0/2 0/2/length 0/2/length 0/2 [1,null,3]  -1");
        assert_eq!(report("const a = [1]; a[2] = 3;"), "3 false false true 0/2 0/2/length 0/2/length 0/2 [1,null,3]  -1");
        assert_eq!(report("const a = [1]; a.length = 3; a[2] = 3;"), "3 false false true 0/2 0/2/length 0/2/length 0/2 [1,null,3]  -1");
        assert_eq!(caught("return [[, ].length, [, , ].length, 0 in [, 1], Array(2).length, 0 in Array(2), Object.keys(new Array(4)).length].join()"), "1,2,false,2,false,0");
        // A present undefined is not a hole.
        assert_eq!(report("const a = [1, undefined, 3];"), "3 true true false 0/1/2 0/1/2/length 0/1/2/length 0/1/2 [1,null,3]  1");
    }

    #[test]
    fn a_hole_reads_through_the_prototype_chain() {
        assert_eq!(
            caught("Array.prototype[1] = 'p'; const a = [0, , 2]; const r = [a[1], 1 in a, a.hasOwnProperty(1), a.indexOf('p'), a.join()].join(' '); delete Array.prototype[1]; return r"),
            "p true false 1 0,p,2"
        );
        assert_eq!(caught("const a = [0, , 2]; const p = Object.create(Array.prototype); p[1] = 'q'; Object.setPrototypeOf(a, p); return a[1] + a.map(x => x).join()"), "q0,q,2");
    }

    #[test]
    fn methods_follow_the_spec_on_holes() {
        let has = |expr: &str| caught(&format!("const r = {expr}; return r.length + ':' + Object.keys(r).join('/') + ':' + r.join()"));
        assert_eq!(has("[1, , 3].map(x => x * 2)"), "3:0/2:2,,6");
        assert_eq!(has("[1, , 3].filter(() => true)"), "2:0/1:1,3");
        assert_eq!(has("[1, , 3].concat([4, , 6], 7)"), "7:0/2/3/5/6:1,,3,4,,6,7");
        assert_eq!(has("[1, , 3, 4].slice(1)"), "3:1/2:,3,4");
        assert_eq!(has("[1, , 3, 4].reverse()"), "4:0/1/3:4,3,,1");
        assert_eq!(has("[3, , undefined, 1].sort()"), "4:0/1/2:1,3,,");
        assert_eq!(has("(() => { const a = [1, , 3]; a.shift(); return a; })()"), "2:1:,3");
        assert_eq!(has("(() => { const a = [1, , 3]; a.unshift(0); return a; })()"), "4:0/1/3:0,1,,3");
        assert_eq!(has("(() => { const a = [, 1]; a.push(2); return a; })()"), "3:1/2:,1,2");
        assert_eq!(has("(() => { const a = [1, , 3, 4]; return a.splice(0, 2); })()"), "2:0:1,");
        assert_eq!(has("(() => { const a = [1, , 3, 4]; a.splice(0, 1, 'x', 'y'); return a; })()"), "5:0/1/3/4:x,y,,3,4");
        assert_eq!(has("[1, , [2, , 3]].flat()"), "3:0/1/2:1,2,3");
        assert_eq!(has("[1, , 3].flatMap(x => [x])"), "2:0/1:1,3");
        assert_eq!(has("new Array(3).fill(0)"), "3:0/1/2:0,0,0");
        assert_eq!(has("[...[1, , 3]]"), "3:0/1/2:1,,3");
        assert_eq!(has("Array.from([1, , 3])"), "3:0/1/2:1,,3");
        assert_eq!(has("[...[1, , 3].keys()]"), "3:0/1/2:0,1,2");
        assert_eq!(caught("const a = [1, , ]; return [a.pop(), a.length, a.pop(), a.length].join()"), ",1,1,0");
        assert_eq!(caught("return [Object.values([1, , 3]).join(), Object.entries([1, , 3]).join('|'), Object.keys(Object.assign({}, [1, , 3])).join(), Object.keys({ ...[1, , 3] }).join()].join(' ')"), "1,3 0,1|2,3 0,2 0,2");
        assert_eq!(caught("const seen = []; [1, , 3].forEach((v, i) => seen.push(i)); [1, , 3].find((v, i) => { seen.push('f' + i); }); return seen.join()"), "0,2,f0,f1,f2");
        assert_eq!(caught("return [[1, , 3].includes(undefined), [1, , 3].lastIndexOf(undefined), [, 'a'].reduce((x, y) => x + y), [1, , 3].some(v => v === undefined)].join()"), "true,-1,a,false");
        assert_eq!(caught("return String([1, , 3]) + '|' + [1, , 3].toString() + '|' + [, ].join('-')"), "1,,3|1,,3|");
    }

    #[test]
    fn length_writes_add_and_remove_holes() {
        assert_eq!(caught("const a = [1, 2, 3]; a.length = 5; const k1 = Object.keys(a).join('/'); a.length = 1; a.length = 3; return k1 + ':' + Object.keys(a).join('/') + ':' + a.length"), "0/1/2:0:3");
        assert_eq!(caught("const a = []; a[4] = 'e'; a.length = 2; return a.length + ':' + Object.keys(a).length + ':' + a[4]"), "2:0:undefined");
        // A large length allocates nothing and reads back exactly.
        assert_eq!(caught("const a = []; a.length = 4294967295; return a.length + ':' + Object.keys(a).length + ':' + (5 in a)"), "4294967295:0:false");
        assert_eq!(caught("const a = new Array(4294967295); return a.length"), "4294967295");
        // A sealed array keeps its elements but its holes are not properties.
        assert_eq!(caught("const a = [1, , 3, , ]; Object.seal(a); a.length = 0; return a.length + ':' + Object.keys(a).join('/')"), "3:0/2");
        // A non-extensible array cannot fill a hole.
        assert_eq!(caught("const a = [1, , 3]; Object.preventExtensions(a); a[1] = 2; return (1 in a) + ':' + Reflect.set(a, 1, 2) + ':' + Reflect.defineProperty(a, 1, { value: 2 })"), "false:false:false");
    }

    #[test]
    fn host_lists_strings_and_typed_arrays_keep_their_indices() {
        assert_eq!(
            super::super::interp::test_support::eval_in_page(
                "<p>a</p><p>b</p>",
                "const l = document.querySelectorAll('p'); const out = []; [].forEach.call(l, (p, i) => out.push(i + p.textContent)); \
                 return [out.join(), [].slice.call(l).length, Array.from(l).length, [...l].length, [].concat.call([], l).length].join('|')"
            ),
            "0a,1b|2|2|2|1"
        );
        assert_eq!(
            caught("return [[].slice.call('ab').join(), [].map.call(new Uint8Array([1, 2]), x => x * 2).join(), [].reverse.call(new Uint8Array([1, 2])).join()].join('|')"),
            "a,b|2,4|2,1"
        );
    }
}

#[cfg(test)]
mod index_attribute_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    /// Every reader of index 0's attributes, then the value.
    fn report(setup: &str) -> String {
        caught(&format!(
            "{setup} const d = Object.getOwnPropertyDescriptor(a, 0); const fi = []; for (const k in a) fi.push(k); \
             return [d.enumerable, d.writable, d.configurable, a.propertyIsEnumerable(0), Object.keys(a).join('/'), fi.join('/'), \
                     Object.keys({{ ...a }}).join('/'), Object.keys(Object.assign({{}}, a)).join('/'), Object.entries(a).length, JSON.stringify(a), a[0]].join(' ')"
        ))
    }

    #[test]
    fn an_index_can_be_made_non_enumerable() {
        assert_eq!(report("const a = [1, 2]; Object.defineProperty(a, 0, { enumerable: false });"), "false true true false 1 1 1 1 1 [1,2] 1");
        assert_eq!(
            report("const a = [1, 2]; Object.defineProperty(a, 0, { value: 5, enumerable: false, writable: false, configurable: false }); a[0] = 9; delete a[0];"),
            "false false false false 1 1 1 1 1 [5,2] 5"
        );
        // A new index defined with no attributes is non-enumerable,
        // non-writable and non-configurable.
        assert_eq!(report("const a = []; Object.defineProperty(a, 0, { value: 7 }); a[1] = 2; a[0] = 8;"), "false false false false 1 1 1 1 1 [7,2] 7");
        // A generic descriptor or a value-only one keeps the others.
        assert_eq!(
            report("const a = [1, 2]; Object.defineProperty(a, 0, { enumerable: false }); Object.defineProperty(a, 0, { value: 3 }); Object.defineProperty(a, 0, { enumerable: true });"),
            "true true true true 0/1 0/1 0/1 0/1 2 [3,2] 3"
        );
    }

    #[test]
    fn the_attribute_belongs_to_the_index_not_the_value() {
        // Deleted, cut off by length, or recreated: a fresh index is enumerable.
        assert_eq!(report("const a = [1, 2]; Object.defineProperty(a, 0, { enumerable: false }); delete a[0]; a[0] = 4;"), "true true true true 0/1 0/1 0/1 0/1 2 [4,2] 4");
        assert_eq!(report("const a = [1, 2]; Object.defineProperty(a, 0, { enumerable: false }); a.length = 0; a.push(6, 2);"), "true true true true 0/1 0/1 0/1 0/1 2 [6,2] 6");
        // shift, reverse and sort Set index 0, which keeps its attributes.
        for call in ["a.unshift(0); a.shift()", "a.reverse()", "a.sort((x, y) => y - x)"] {
            assert_eq!(
                caught(&format!("const a = [1, 2]; Object.defineProperty(a, 0, {{ enumerable: false }}); {call}; return Object.keys(a).join('/') + ':' + a.propertyIsEnumerable(0) + ':' + a.join()")),
                if call == "a.unshift(0); a.shift()" { "1:false:1,2" } else { "1:false:2,1" },
                "{call}"
            );
        }
        // Freezing keeps enumerability and fixes the rest.
        assert_eq!(report("const a = [1, 2]; Object.defineProperty(a, 0, { enumerable: false }); Object.freeze(a);"), "false false false false 1 1 1 1 1 [1,2] 1");
    }
}

#[cfg(test)]
mod copy_within_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn copy_within_moves_a_range_inside_the_array() {
        // ES 23.1.3.4: target, start and end are relative indices; the
        // copy is made as if through a temporary, so overlapping ranges
        // come out right in both directions; the length never changes.
        assert_eq!(caught("return [1, 2, 3, 4, 5].copyWithin(0, 3).join()"), "4,5,3,4,5");
        assert_eq!(caught("return [1, 2, 3, 4, 5].copyWithin(1, 0).join()"), "1,1,2,3,4");
        assert_eq!(caught("return [1, 2, 3, 4, 5].copyWithin(0, 1).join()"), "2,3,4,5,5");
        assert_eq!(caught("return [1, 2, 3, 4, 5].copyWithin(-2, -4, -3).join()"), "1,2,3,2,5");
        assert_eq!(caught("return [1, 2, 3, 4, 5].copyWithin(0, 3, 4).join()"), "4,2,3,4,5");
        assert_eq!(caught("const a = [1, 2, 3]; return [a.copyWithin(1) === a, a.join(), a.length, Array.prototype.copyWithin.length].join()"), "true,1,1,2,3,2");
        // A hole is copied as a hole (the target index is deleted).
        assert_eq!(caught("const a = [1, , 3, 4]; a.copyWithin(2, 0); return [2 in a, 3 in a, a[2], a.length].join()"), "true,false,1,4");
        // Generic over array-likes; a frozen array refuses the write.
        assert_eq!(caught("const o = { length: 3, 0: 'a', 2: 'c' }; Array.prototype.copyWithin.call(o, 0, 2); return [o[0], 1 in o, o[2]].join()"), "c,false,c");
        assert_eq!(caught("Object.freeze([1, 2]).copyWithin(0, 1)"), "TypeError");
        assert_eq!(caught("Array.prototype.copyWithin.call(null, 0)"), "TypeError");
    }
}

#[cfg(test)]
mod sort_comparator_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_comparator_that_is_neither_callable_nor_undefined_is_a_type_error() {
        // ES 23.1.3.30 step 1 and 23.2.3.29 step 1: checked before the
        // receiver is read, so nothing is sorted and no getter runs.
        for bad in ["1", "null", "'x'", "{}", "true"] {
            assert_eq!(caught(&format!("[2, 1].sort({bad})")), "TypeError", "Array sort({bad})");
            assert_eq!(caught(&format!("new Uint8Array([2, 1]).sort({bad})")), "TypeError", "Uint8Array sort({bad})");
        }
        assert_eq!(caught("let read = false; const o = { get length() { read = true; return 0; } }; try { Array.prototype.sort.call(o, 1); } catch (e) {} return read"), "false");
        assert_eq!(caught("const a = [2, 1]; try { a.sort(1); } catch (e) {} return a.join()"), "2,1");
        // undefined (or no argument) is the default order.
        assert_eq!(caught("return [[10, 9, 1].sort(undefined).join(), [10, 9, 1].sort().join(), [3, 1, 2].sort((a, b) => a - b).join(), new Uint8Array([3, 1]).sort(undefined).join()].join(' ')"), "1,10,9 1,10,9 1,2,3 1,3");
    }
}

#[cfg(test)]
mod concat_spreadable_tests {
    use super::super::interp::test_support::{eval_in_page, eval_js};

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn symbol_is_concat_spreadable_decides_what_is_spread() {
        // ES 23.1.3.2.1 IsConcatSpreadable: @@isConcatSpreadable when it
        // is not undefined (through ToBoolean), IsArray otherwise.
        assert_eq!(
            caught("const o = { length: 2, 0: 'a', 1: 'b', [Symbol.isConcatSpreadable]: true }; return JSON.stringify([1].concat(o))"),
            "[1,\"a\",\"b\"]"
        );
        assert_eq!(caught("const a = [2, 3]; a[Symbol.isConcatSpreadable] = false; const r = [1].concat(a); return [r.length, r[1] === a].join()"), "2,true");
        assert_eq!(caught("const a = [2, 3]; a[Symbol.isConcatSpreadable] = 0; return [1].concat(a).length"), "2");
        assert_eq!(caught("const o = { length: 1, 0: 'x', [Symbol.isConcatSpreadable]: 'yes' }; return [].concat(o).join()"), "x");
        // The receiver is tested too; a getter runs once per item; a
        // spreadable object's holes stay holes.
        assert_eq!(caught("const o = { length: 2, 0: 'p', [Symbol.isConcatSpreadable]: true }; const r = Array.prototype.concat.call(o, 'q'); return [r.length, 1 in r, r[2]].join()"), "3,false,q");
        assert_eq!(caught("let n = 0; const o = { get [Symbol.isConcatSpreadable]() { n++; return true; }, length: 0 }; [].concat(o, o); return n"), "2");
        // Spreadable through a Proxy and a String wrapper; primitives never.
        assert_eq!(caught("const p = new Proxy([1, 2], {}); return [0].concat(p).length"), "3");
        assert_eq!(caught("const s = new String('ab'); s[Symbol.isConcatSpreadable] = true; return [].concat(s, 'cd').join('|')"), "a|b|cd");
        assert_eq!(caught("Array.prototype[Symbol.isConcatSpreadable] = false; const r = [1].concat([2]); delete Array.prototype[Symbol.isConcatSpreadable]; return [r.length, Array.isArray(r[0]), Array.isArray(r[1])].join()"), "2,true,true");
    }

    #[test]
    fn node_lists_are_not_spread_unless_marked() {
        assert_eq!(
            eval_in_page(
                "<p>a</p><p>b</p>",
                "const l = document.querySelectorAll('p'); const n = [].concat(l).length; const seen = []; [].forEach.call(l, (p) => seen.push(p.textContent)); \
                 l[Symbol.isConcatSpreadable] = true; return [n, [].concat(l).length, seen.join('')].join()"
            ),
            "1,2,ab"
        );
    }
}

#[cfg(test)]
mod species_tests {
    use super::super::interp::test_support::{eval_in_page, eval_js};

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn an_array_subclass_constructs_instances_of_itself() {
        assert_eq!(
            caught("class A extends Array {} const a = new A(1, 2, 3); return [a instanceof A, a instanceof Array, Array.isArray(a), a.length, a.constructor === A, new A(4).length].join()"),
            "true,true,true,3,true,4"
        );
        assert_eq!(caught("class A extends Array { sum() { return this.reduce((s, x) => s + x, 0); } } return new A(1, 2, 3).sum()"), "6");
    }

    #[test]
    fn methods_create_their_result_through_the_species_constructor() {
        // ES 23.1.3.x ArraySpeciesCreate: map, filter, slice, splice,
        // concat, flat and flatMap build their result with
        // `this.constructor[Symbol.species]`.
        assert_eq!(
            caught("class A extends Array {} const a = new A(1, 2, 3); \
                    const r = [a.map((x) => x), a.filter(() => true), a.slice(1), a.concat([4]), a.flat(), a.flatMap((x) => [x]), new A(1, 2, 3).splice(0, 1)]; \
                    return r.map((x) => (x instanceof A) + ':' + x.join('')).join(' ')"),
            "true:123 true:123 true:23 true:1234 true:123 true:123 true:1"
        );
        // A species getter returning another constructor, or undefined /
        // null (a plain Array), decides; a non-constructor is a TypeError.
        assert_eq!(
            caught("class B extends Array {} class A extends Array { static get [Symbol.species]() { return B; } } return new A(1, 2).map((x) => x) instanceof B"),
            "true"
        );
        assert_eq!(
            caught("class A extends Array { static get [Symbol.species]() { return undefined; } } const m = new A(1, 2).map((x) => x); return [m instanceof A, Array.isArray(m), m.constructor === Array].join()"),
            "false,true,true"
        );
        assert_eq!(caught("const a = [1]; a.constructor = { [Symbol.species]: null }; return a.map((x) => x).constructor === Array"), "true");
        assert_eq!(caught("const a = [1]; a.constructor = { [Symbol.species]: 1 }; return a.map((x) => x)"), "TypeError");
        assert_eq!(caught("const a = [1]; a.constructor = 5; return a.slice()"), "TypeError");
        // A non-array receiver always gets a plain Array.
        assert_eq!(caught("const o = { length: 1, 0: 'x', constructor: { [Symbol.species]: function () { throw 1; } } }; return Array.prototype.map.call(o, (x) => x).join()"), "x");
        // The species constructor is called with the length, and the
        // elements are defined on what it returns.
        assert_eq!(
            caught("let args; function C(n) { args = [...arguments]; this.length = 0; } const a = [1, 2, 3]; a.constructor = { [Symbol.species]: C }; \
                    const m = a.map((x) => x * 2), s = a.slice(1); return [args.join(), m instanceof C, m[2], s.length, s[0]].join()"),
            "2,true,6,2,2"
        );
    }

    #[test]
    fn the_constructors_expose_species_getters() {
        assert_eq!(
            caught("const names = [Array, Map, Set, Promise, RegExp, ArrayBuffer].map((C) => { const d = Object.getOwnPropertyDescriptor(C, Symbol.species); return [C[Symbol.species] === C, typeof d.get, d.set, d.configurable, d.enumerable, d.get.name].join('/'); }); return names.join(' ')"),
            ["true/function//true/false/get [Symbol.species]"; 6].join(" ")
        );
        assert_eq!(caught("return [Uint8Array[Symbol.species] === Uint8Array, Float64Array[Symbol.species] === Float64Array].join()"), "true,true");
        assert_eq!(caught("class M extends Map {} return M[Symbol.species] === M"), "true");
    }

    #[test]
    fn plain_arrays_and_node_lists_keep_their_results() {
        assert_eq!(caught("const r = [1, , 3].map((x) => x); return [r.length, 1 in r, r.constructor === Array, [1, 2].concat([3]).constructor === Array].join()"), "3,false,true,true");
        assert_eq!(
            eval_in_page(
                "<p>a</p><p>b</p>",
                "const l = document.querySelectorAll('p'); const seen = []; [].forEach.call(l, (p) => seen.push(p.textContent)); \
                 const m = Array.prototype.map.call(l, (p) => p.textContent); return [seen.join(''), m.join(''), Array.isArray(m), Array.prototype.slice.call(l).length].join()"
            ),
            "ab,ab,true,2"
        );
    }
}
