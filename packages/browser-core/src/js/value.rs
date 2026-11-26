//! value — the JavaScript value model: primitives, heap objects, prototype
//! chains, and the ECMAScript coercions the interpreter needs.
//!
//! Objects live behind `Rc<RefCell<JsObject>>` so closures, the DOM glue, and
//! the interpreter can share them; cycles are tolerated because a `Page` (and
//! its whole JS heap) is dropped as one unit at the end of a render — the
//! engine is stateless across requests, so leaked cycles cannot accumulate.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;

use super::ast::FnDef;

/// A JavaScript value.
#[derive(Clone)]
pub enum JsValue {
    Undefined,
    Null,
    Bool(bool),
    Num(f64),
    Str(Rc<String>),
    Symbol(Rc<SymbolData>),
    Object(ObjRef),
}

/// A symbol: unique identity plus an optional description. Well-known
/// symbols use fixed ids below `WELL_KNOWN_SYMBOLS`; `Symbol()` allocates
/// from the realm's counter above that.
pub struct SymbolData {
    pub id: u64,
    pub description: Option<String>,
}

/// Ids reserved for well-known symbols (see [`well_known_symbol`]).
pub const WELL_KNOWN_SYMBOLS: u64 = 64;

/// The fixed ids of the well-known symbols the engine understands.
pub const SYM_ITERATOR: u64 = 1;
pub const SYM_ASYNC_ITERATOR: u64 = 2;
pub const SYM_HAS_INSTANCE: u64 = 3;
pub const SYM_TO_PRIMITIVE: u64 = 4;
pub const SYM_TO_STRING_TAG: u64 = 5;
pub const SYM_SPECIES: u64 = 6;
pub const SYM_UNSCOPABLES: u64 = 7;
pub const SYM_IS_CONCAT_SPREADABLE: u64 = 8;
pub const SYM_MATCH: u64 = 9;
pub const SYM_REPLACE: u64 = 10;
pub const SYM_SEARCH: u64 = 11;
pub const SYM_SPLIT: u64 = 12;
pub const SYM_MATCH_ALL: u64 = 13;

/// Build a well-known symbol value by id.
pub fn well_known_symbol(id: u64) -> JsValue {
    let name = match id {
        SYM_ITERATOR => "Symbol.iterator",
        SYM_ASYNC_ITERATOR => "Symbol.asyncIterator",
        SYM_HAS_INSTANCE => "Symbol.hasInstance",
        SYM_TO_PRIMITIVE => "Symbol.toPrimitive",
        SYM_TO_STRING_TAG => "Symbol.toStringTag",
        SYM_SPECIES => "Symbol.species",
        SYM_UNSCOPABLES => "Symbol.unscopables",
        SYM_IS_CONCAT_SPREADABLE => "Symbol.isConcatSpreadable",
        SYM_MATCH => "Symbol.match",
        SYM_REPLACE => "Symbol.replace",
        SYM_SEARCH => "Symbol.search",
        SYM_SPLIT => "Symbol.split",
        SYM_MATCH_ALL => "Symbol.matchAll",
        _ => "Symbol",
    };
    JsValue::Symbol(Rc::new(SymbolData {
        id,
        description: Some(name.to_string()),
    }))
}

/// The property-table key of a symbol: symbols live in the same ordered
/// table as string keys under an un-typeable prefix, and every key-listing
/// API filters them out.
pub fn symbol_key(id: u64) -> String {
    format!("@@sym:{id}")
}

/// Whether a property-table key is a symbol key.
pub fn is_symbol_key(key: &str) -> bool {
    key.starts_with("@@sym:")
}

/// Whether a property key is a CanonicalNumericIndexString (ES §7.1.21):
/// the ToString of its own ToNumber, or "-0". A typed array answers every
/// such key itself, in range or not, and never asks its prototype.
pub fn is_canonical_numeric(key: &str) -> bool {
    key == "-0" || (!key.is_empty() && format_number(string_to_number(key)) == key)
}

/// How a typed array reads property key `key` (ES 10.4.5): `None` for a
/// key that is not a CanonicalNumericIndexString, an ordinary property;
/// `Some(Some(i))` for the integer index `i`; `Some(None)` for a numeric
/// key that is not a valid index anywhere (`-1`, `1.5`, `-0`,
/// `Infinity`, `NaN`), which the view answers as absent. `+1` and `01`
/// are not canonical and stay ordinary keys.
pub fn typed_index_key(key: &str) -> Option<Option<usize>> {
    if let Some(i) = array_index(key) {
        return Some(Some(i));
    }
    let numeric_start = key
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'-' | b'I' | b'N'));
    (numeric_start && is_canonical_numeric(key)).then_some(None)
}

/// The array index a property key names (ES §6.1.7: a canonical numeric
/// string for an integer below 2^32 - 1), `None` for any other key.
pub fn array_index(key: &str) -> Option<usize> {
    let b = key.as_bytes();
    if b.is_empty() || b.len() > 10 || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b.first() == Some(&b'0')) {
        return None;
    }
    key.parse::<u64>().ok().filter(|n| *n < 4_294_967_295).map(|n| n as usize)
}

/// The well-known-symbol key for `Symbol.iterator`.
pub fn iterator_key() -> String {
    symbol_key(SYM_ITERATOR)
}

/// `JsObject::fn_meta_readonly` bits.
const FN_META_LENGTH: u8 = 1;
const FN_META_NAME: u8 = 2;

/// The `fn_meta_readonly` bit for a property key (0 for any other key).
fn fn_meta_bit(key: &str) -> u8 {
    match key {
        "length" => FN_META_LENGTH,
        "name" => FN_META_NAME,
        _ => 0,
    }
}

/// Shared mutable reference to a heap object.
pub type ObjRef = Rc<RefCell<JsObject>>;

/// A Map/Set key: SameValueZero identity over JS values.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum MapKey {
    Undefined,
    Null,
    Bool(bool),
    /// Canonicalized bits: -0 folds into +0 and every NaN into one NaN.
    Num(u64),
    Str(String),
    Sym(u64),
    Obj(usize),
}

impl MapKey {
    pub fn of(v: &JsValue) -> MapKey {
        match v {
            JsValue::Undefined => MapKey::Undefined,
            JsValue::Null => MapKey::Null,
            JsValue::Bool(b) => MapKey::Bool(*b),
            JsValue::Num(n) => {
                let n = if *n == 0.0 { 0.0 } else { *n };
                let n = if n.is_nan() { f64::NAN } else { n };
                MapKey::Num(n.to_bits())
            }
            JsValue::Str(s) => MapKey::Str(s.as_ref().clone()),
            JsValue::Symbol(s) => MapKey::Sym(s.id),
            JsValue::Object(o) => MapKey::Obj(Rc::as_ptr(o) as *const () as usize),
        }
    }
}

/// Insertion-ordered Map/Set storage: entries plus a key index. Deleted
/// entries become tombstones (`None`) so live iteration stays stable.
#[derive(Default)]
pub struct MapData {
    pub entries: Vec<Option<(JsValue, JsValue)>>,
    pub index: HashMap<MapKey, usize>,
    pub live: usize,
}

impl MapData {
    pub fn get(&self, k: &JsValue) -> Option<JsValue> {
        let i = *self.index.get(&MapKey::of(k))?;
        match self.entries.get(i) {
            Some(Some((_, v))) => Some(v.clone()),
            _ => None,
        }
    }
    pub fn has(&self, k: &JsValue) -> bool {
        self.index.contains_key(&MapKey::of(k))
    }
    pub fn set(&mut self, k: JsValue, v: JsValue) {
        let mk = MapKey::of(&k);
        if let Some(i) = self.index.get(&mk) {
            if let Some(Some(slot)) = self.entries.get_mut(*i) {
                slot.1 = v;
                return;
            }
        }
        // Map keys normalise -0 to +0.
        let mut k = k;
        if let JsValue::Num(n) = &mut k {
            if *n == 0.0 {
                *n = 0.0;
            }
        }
        self.index.insert(mk, self.entries.len());
        self.entries.push(Some((k, v)));
        self.live = self.live.saturating_add(1);
    }
    pub fn delete(&mut self, k: &JsValue) -> bool {
        match self.index.remove(&MapKey::of(k)) {
            Some(i) => {
                if let Some(slot) = self.entries.get_mut(i) {
                    *slot = None;
                }
                self.live = self.live.saturating_sub(1);
                true
            }
            None => false,
        }
    }
    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
        self.live = 0;
    }
    /// Live entries in insertion order.
    pub fn items(&self) -> Vec<(JsValue, JsValue)> {
        self.entries.iter().flatten().cloned().collect()
    }
}

/// Which DOM-backed facet a live facet object exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Facet {
    /// `element.style`: reads and writes go to the `style` attribute.
    Style,
    /// `element.dataset`: reads and writes go to `data-*` attributes.
    Dataset,
    /// `element.classList`: `length` and indices over the class attribute.
    ClassList,
}

/// What kind of exotic object this is (affects call/construct/coercion).
pub enum ObjKind {
    Plain,
    Array,
    /// Interpreted function: definition + captured scope chain.
    Function {
        def: Rc<FnDef>,
        scope: super::interp::ScopeRef,
        /// `this` binding captured by arrow functions.
        captured_this: Option<Box<JsValue>>,
    },
    /// Host function implemented in Rust.
    Native(NativeFn),
    /// Bound function produced by `Function.prototype.bind`.
    Bound {
        target: ObjRef,
        this_arg: Box<JsValue>,
        bound_args: Vec<JsValue>,
    },
    /// A promise with its state and reaction queues.
    Promise(PromiseState),
    Date(f64),
    RegExp {
        source: String,
        flags: String,
    },
    Error,
    /// DOM node handle: index into the document arena held by the realm.
    DomNode(usize),
    /// Live NodeList/HTMLCollection-ish snapshot of DOM handles.
    DomList(Vec<usize>),
    /// A live view over one element's attribute-backed facet.
    DomFacet { handle: usize, facet: Facet },
    /// `Map` / `WeakMap` (weak semantics are strong here: the realm dies
    /// with the page).
    Map(MapData),
    /// `Set` / `WeakSet`; values are stored as keys with an undefined value.
    Set(MapData),
    /// `Proxy`: every fundamental operation consults `handler`'s trap when
    /// present and falls through to `target` otherwise.
    Proxy { target: ObjRef, handler: ObjRef },
    /// A primitive wrapper (`new String("x")`, `Object(1)`).
    Primitive(Box<JsValue>),
    /// A generator object (see `Interp::generator_next`).
    Generator(GeneratorState),
    /// `ArrayBuffer`: the byte storage every view over it shares.
    ArrayBuffer(Bytes),
    /// A typed-array view (`Uint8Array`, `Float64Array`, …) over a slice
    /// of an ArrayBuffer's bytes; reads and writes go to the bytes, so two
    /// views over one buffer observe each other's writes.
    TypedArray(TypedArrayData),
    /// A `DataView` over a slice of an ArrayBuffer's bytes.
    DataView {
        buffer_obj: ObjRef,
        bytes: Bytes,
        byte_offset: usize,
        byte_length: usize,
    },
}

/// Shared, fixed-length byte storage behind an `ArrayBuffer` and every
/// view over it.
pub type Bytes = Rc<RefCell<Vec<u8>>>;

/// The element type of a typed array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypedKind {
    Int8,
    Uint8,
    Uint8Clamped,
    Int16,
    Uint16,
    Int32,
    Uint32,
    Float32,
    Float64,
}

impl TypedKind {
    /// Every kind, in the order the constructors are installed.
    pub const ALL: [TypedKind; 9] = [
        TypedKind::Int8,
        TypedKind::Uint8,
        TypedKind::Uint8Clamped,
        TypedKind::Int16,
        TypedKind::Uint16,
        TypedKind::Int32,
        TypedKind::Uint32,
        TypedKind::Float32,
        TypedKind::Float64,
    ];

    /// The constructor's global name (also the `class_name`).
    pub fn name(self) -> &'static str {
        match self {
            TypedKind::Int8 => "Int8Array",
            TypedKind::Uint8 => "Uint8Array",
            TypedKind::Uint8Clamped => "Uint8ClampedArray",
            TypedKind::Int16 => "Int16Array",
            TypedKind::Uint16 => "Uint16Array",
            TypedKind::Int32 => "Int32Array",
            TypedKind::Uint32 => "Uint32Array",
            TypedKind::Float32 => "Float32Array",
            TypedKind::Float64 => "Float64Array",
        }
    }

    /// Bytes per element.
    pub fn size(self) -> usize {
        match self {
            TypedKind::Int8 | TypedKind::Uint8 | TypedKind::Uint8Clamped => 1,
            TypedKind::Int16 | TypedKind::Uint16 => 2,
            TypedKind::Int32 | TypedKind::Uint32 | TypedKind::Float32 => 4,
            TypedKind::Float64 => 8,
        }
    }

    /// The element domain a write lands in (ToInt8 … ToUint8Clamp,
    /// float rounding), as the number the read then returns.
    pub fn coerce(self, n: f64) -> f64 {
        match self {
            TypedKind::Float64 => n,
            TypedKind::Float32 => n as f32 as f64,
            TypedKind::Uint8Clamped => {
                if n.is_nan() {
                    return 0.0;
                }
                let c = n.clamp(0.0, 255.0);
                // Round half to even (ToUint8Clamp).
                let f = c.floor();
                let d = c - f;
                if d < 0.5 {
                    f
                } else if d > 0.5 || f % 2.0 != 0.0 {
                    f + 1.0
                } else {
                    f
                }
            }
            _ => {
                if !n.is_finite() {
                    return 0.0;
                }
                let bits = (self.size() as u32).saturating_mul(8);
                let modulus = 2f64.powi(bits as i32);
                let wrapped = n.trunc().rem_euclid(modulus);
                let signed = matches!(self, TypedKind::Int8 | TypedKind::Int16 | TypedKind::Int32);
                if signed && wrapped >= modulus / 2.0 {
                    wrapped - modulus
                } else {
                    wrapped
                }
            }
        }
    }

    /// Decode one element from `bytes` at byte offset `at` (little-endian,
    /// the platform order every typed array uses). `None` when the slice
    /// does not hold a whole element.
    pub fn read(self, bytes: &[u8], at: usize) -> Option<f64> {
        let raw = bytes.get(at..at.checked_add(self.size())?)?;
        let mut v: u64 = 0;
        for (i, b) in raw.iter().enumerate() {
            v |= (*b as u64) << (8 * i as u32);
        }
        Some(match self {
            TypedKind::Int8 => (v as u8 as i8) as f64,
            TypedKind::Uint8 | TypedKind::Uint8Clamped => (v as u8) as f64,
            TypedKind::Int16 => (v as u16 as i16) as f64,
            TypedKind::Uint16 => (v as u16) as f64,
            TypedKind::Int32 => (v as u32 as i32) as f64,
            TypedKind::Uint32 => (v as u32) as f64,
            TypedKind::Float32 => f32::from_bits(v as u32) as f64,
            TypedKind::Float64 => f64::from_bits(v),
        })
    }

    /// Encode `n` into `bytes` at byte offset `at` (little-endian). Returns
    /// whether the slice held a whole element.
    pub fn write(self, bytes: &mut [u8], at: usize, n: f64) -> bool {
        let Some(end) = at.checked_add(self.size()) else {
            return false;
        };
        let Some(raw) = bytes.get_mut(at..end) else {
            return false;
        };
        let v: u64 = match self {
            TypedKind::Float32 => (n as f32).to_bits() as u64,
            TypedKind::Float64 => n.to_bits(),
            other => {
                let c = other.coerce(n);
                // Two's complement through the unsigned width.
                let bits = (other.size() as u32).saturating_mul(8);
                let modulus = 2f64.powi(bits as i32);
                c.rem_euclid(modulus) as u64
            }
        };
        for (i, b) in raw.iter_mut().enumerate() {
            *b = ((v >> (8 * i as u32)) & 0xff) as u8;
        }
        true
    }
}

/// A typed-array view: `length` elements of `kind` starting `byte_offset`
/// bytes into `bytes` (the ArrayBuffer object `buffer_obj` owns them).
#[derive(Clone)]
pub struct TypedArrayData {
    pub buffer_obj: ObjRef,
    pub bytes: Bytes,
    pub byte_offset: usize,
    pub length: usize,
    pub kind: TypedKind,
}

impl TypedArrayData {
    /// The element index property key `key` selects (see
    /// [`typed_index_key`]): `Some(Some(i))` inside the view,
    /// `Some(None)` for any other numeric key, `None` for an ordinary key.
    pub fn index_of_key(&self, key: &str) -> Option<Option<usize>> {
        typed_index_key(key).map(|i| i.filter(|i| *i < self.length))
    }

    /// The element at `i`, or `None` out of range.
    pub fn get(&self, i: usize) -> Option<f64> {
        if i >= self.length {
            return None;
        }
        let at = self.byte_offset.checked_add(i.checked_mul(self.kind.size())?)?;
        self.kind.read(&self.bytes.borrow(), at)
    }

    /// Write `n` at `i`; out-of-range writes are ignored (spec: no effect).
    pub fn set(&self, i: usize, n: f64) -> bool {
        if i >= self.length {
            return false;
        }
        let Some(at) = i.checked_mul(self.kind.size()).and_then(|o| self.byte_offset.checked_add(o)) else {
            return false;
        };
        self.kind.write(&mut self.bytes.borrow_mut(), at, n)
    }

    /// Every element, in order.
    pub fn values(&self) -> Vec<f64> {
        (0..self.length).filter_map(|i| self.get(i)).collect()
    }

    /// The view's byte length.
    pub fn byte_len(&self) -> usize {
        self.length.saturating_mul(self.kind.size())
    }

    /// A copy of the bytes the view covers.
    pub fn byte_copy(&self) -> Vec<u8> {
        let b = self.bytes.borrow();
        b.get(self.byte_offset..self.byte_offset.saturating_add(self.byte_len()))
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }
}

/// The state of a generator object (see `Interp::generator_resume`). A
/// generator function's body is a suspended [`super::coroutine::Coroutine`]
/// that `next()` / `throw()` / `return()` resume at its last `yield`. The
/// engine's own list iterators (`Array.prototype.values()`, Map entries)
/// share the shape with `co` absent: `buffer` holds their items.
pub struct GeneratorState {
    /// The suspended body; `None` for a list iterator and while the body
    /// is running (`running`), so a re-entrant `next()` is a TypeError.
    pub co: Option<Box<super::coroutine::Coroutine>>,
    pub running: bool,
    pub buffer: Vec<JsValue>,
    pub pos: usize,
    pub done: bool,
    pub return_value: Box<JsValue>,
}

/// A native (Rust-implemented) function: (interp, this, args) -> result or
/// thrown value. Receiving the interpreter lets natives (Array.prototype.map,
/// Promise.all, JSON.stringify with toJSON…) call back into script.
pub type NativeFn = Rc<
    dyn for<'a, 'h> Fn(
        &'a mut super::interp::Interp<'h>,
        JsValue,
        &[JsValue],
    ) -> Result<JsValue, JsValue>,
>;

/// Promise internal state.
pub enum PromiseState {
    Pending {
        on_fulfilled: Vec<Reaction>,
        on_rejected: Vec<Reaction>,
    },
    Fulfilled(Box<JsValue>),
    Rejected(Box<JsValue>),
}

/// A queued promise reaction: the handler (may be None for pass-through) and
/// the derived promise to settle with its result.
pub struct Reaction {
    pub handler: Option<ObjRef>,
    pub derived: ObjRef,
}

/// One property slot: value or accessor pair.
pub enum Prop {
    Value {
        value: JsValue,
        enumerable: bool,
    },
    Accessor {
        get: Option<ObjRef>,
        set: Option<ObjRef>,
        enumerable: bool,
    },
}

/// A heap object: ordered property map + prototype + exotic kind.
pub struct JsObject {
    /// Insertion-ordered property table (JS object key order for string keys).
    pub props: Vec<(String, Prop)>,
    /// Fast lookup index into `props`.
    pub index: HashMap<String, usize>,
    pub proto: Option<ObjRef>,
    pub kind: ObjKind,
    /// Array elements when kind == Array (dense representation): `None`
    /// is a hole, an index the array does not have as a property (an
    /// elision, a deleted element, the gap a write past the end leaves).
    pub elems: Vec<Option<JsValue>>,
    /// An Array's `length` beyond `elems`: absent indices (holes) at the
    /// end, which take no storage. `new Array(n)` and a `length` write
    /// that grows the array record the new length here; a write past the
    /// end extends `elems` to reach the index.
    pub trailing_holes: usize,
    /// Class name for Object.prototype.toString / diagnostics.
    pub class_name: &'static str,
    /// `Object.freeze`: every own property is non-configurable and every
    /// own data property non-writable (the object is also non-extensible).
    pub frozen: bool,
    /// `Object.preventExtensions` / `seal`: no new properties.
    pub non_extensible: bool,
    /// `Object.seal`: existing properties are non-configurable (deletes are
    /// ignored) while values stay writable.
    pub sealed: bool,
    /// A `class` constructor: calling it without `new` throws.
    pub is_class: bool,
    /// Own keys (property-table keys or array indices) whose
    /// [[Configurable]] attribute is false: `Object.defineProperty` without
    /// `configurable: true` makes one, and it cannot be deleted or made
    /// configurable again. Properties created by assignment or literals
    /// are configurable and never listed. `sealed` / `frozen` make every
    /// existing property non-configurable without listing it.
    pub non_configurable: HashSet<String>,
    /// Own data-property keys (property-table keys, array indices, or an
    /// array's `length`) whose [[Writable]] attribute is false:
    /// `Object.defineProperty` without `writable: true` makes one. Writes
    /// to it are refused. Properties created by assignment or literals are
    /// writable and never listed; `frozen` makes every existing data
    /// property non-writable without listing it.
    pub non_writable: HashSet<String>,
    /// A function's `length` (bit 0) and `name` (bit 1) are read-only:
    /// every function is created that way (`define_function_meta`), so
    /// the flags live here instead of costing `non_writable` two entries
    /// per function. Cleared when the property is made writable or
    /// deleted.
    pub fn_meta_readonly: u8,
    /// Array indices held in the dense store whose [[Enumerable]]
    /// attribute is false (`Object.defineProperty` without `enumerable:
    /// true` makes one). A property-table entry carries its own flag;
    /// store elements are enumerable unless listed here.
    pub non_enumerable_elems: HashSet<usize>,
}

impl JsObject {
    pub fn new(kind: ObjKind, proto: Option<ObjRef>) -> ObjRef {
        let class_name = match &kind {
            ObjKind::Array => "Array",
            ObjKind::Function { .. } | ObjKind::Native(_) | ObjKind::Bound { .. } => "Function",
            ObjKind::Promise(_) => "Promise",
            ObjKind::Date(_) => "Date",
            ObjKind::RegExp { .. } => "RegExp",
            ObjKind::Error => "Error",
            ObjKind::Map(_) => "Map",
            ObjKind::Set(_) => "Set",
            ObjKind::DomNode(_) => "HTMLElement",
            ObjKind::DomList(_) => "NodeList",
            ObjKind::DomFacet { .. } => "CSSStyleDeclaration",
            ObjKind::Generator(_) => "Generator",
            ObjKind::ArrayBuffer(_) => "ArrayBuffer",
            ObjKind::TypedArray(t) => t.kind.name(),
            ObjKind::DataView { .. } => "DataView",
            ObjKind::Primitive(p) => match p.as_ref() {
                JsValue::Str(_) => "String",
                JsValue::Num(_) => "Number",
                JsValue::Bool(_) => "Boolean",
                JsValue::Symbol(_) => "Symbol",
                _ => "Object",
            },
            _ => "Object",
        };
        Rc::new(RefCell::new(JsObject {
            props: Vec::new(),
            index: HashMap::new(),
            proto,
            kind,
            elems: Vec::new(),
            trailing_holes: 0,
            class_name,
            frozen: false,
            non_extensible: false,
            sealed: false,
            is_class: false,
            non_configurable: HashSet::new(),
            non_writable: HashSet::new(),
            fn_meta_readonly: 0,
            non_enumerable_elems: HashSet::new(),
        }))
    }

    /// The element count of a typed-array view (its integer-indexed own
    /// properties), `None` for every other object.
    pub fn typed_len(&self) -> Option<usize> {
        match &self.kind {
            ObjKind::TypedArray(t) => Some(t.length),
            _ => None,
        }
    }

    /// A String wrapper's own character or `length` (String exotic
    /// objects, ES §10.4.3): the character at an index below the length,
    /// or the length, both read-only and non-configurable. `None` for any
    /// other key and any other object.
    pub fn string_own(&self, key: &str) -> Option<JsValue> {
        let ObjKind::Primitive(p) = &self.kind else { return None };
        let JsValue::Str(s) = p.as_ref() else { return None };
        if key == "length" {
            return Some(JsValue::Num(s.chars().count() as f64));
        }
        let i = array_index(key)?;
        s.chars().nth(i).map(|c| JsValue::str(c.to_string()))
    }

    /// Define a function's `length` and `name` (ES §10.2.9, §10.2.10):
    /// non-writable, non-enumerable, configurable data properties that
    /// lead its own keys, ahead of `prototype` and any static. An existing
    /// one is overwritten in place.
    pub fn define_function_meta(&mut self, length: f64, name: JsValue) {
        let fresh = !self.index.contains_key("length") && !self.index.contains_key("name");
        if fresh && !self.props.is_empty() {
            self.props.splice(
                0..0,
                [
                    ("length".to_string(), Prop::Value { value: JsValue::Num(length), enumerable: false }),
                    ("name".to_string(), Prop::Value { value: name, enumerable: false }),
                ],
            );
            self.index.clear();
            for (n, (k, _)) in self.props.iter().enumerate() {
                self.index.insert(k.clone(), n);
            }
        } else {
            self.set_prop("length", JsValue::Num(length), false);
            self.set_prop("name", name, false);
        }
        self.fn_meta_readonly = FN_META_LENGTH | FN_META_NAME;
    }

    /// Set an own data property's [[Writable]] attribute.
    pub fn set_writable(&mut self, key: &str, writable: bool) {
        if writable {
            self.fn_meta_readonly &= !fn_meta_bit(key);
            self.non_writable.remove(key);
        } else {
            self.non_writable.insert(key.to_string());
        }
    }

    /// Read an own property slot (value or accessor).
    pub fn own_slot(&self, key: &str) -> Option<&Prop> {
        let i = self.own(key)?;
        self.props.get(i).map(|(_, p)| p)
    }

    /// Whether an own property is enumerable (missing → false).
    pub fn is_enumerable(&self, key: &str) -> bool {
        match self.own_slot(key) {
            Some(Prop::Value { enumerable, .. } | Prop::Accessor { enumerable, .. }) => *enumerable,
            None => false,
        }
    }

    /// Every own string key (enumerable or not), symbol keys excluded, in
    /// [[OwnPropertyKeys]] order: array indices ascending, then an Array's
    /// or String wrapper's `length` (it is created with the object), then
    /// the other keys in creation order.
    pub fn own_string_keys_all(&self) -> Vec<String> {
        let mut keys = Vec::new();
        if matches!(self.kind, ObjKind::Array) {
            for (i, e) in self.elems.iter().enumerate() {
                if e.is_some() || self.index.contains_key(&i.to_string()) {
                    keys.push(i.to_string());
                }
            }
        }
        if let Some(n) = self.typed_len().or_else(|| self.string_len()) {
            keys.extend((0..n).map(|i| i.to_string()));
        }
        let (indices, named) = self.table_string_keys(false);
        keys.extend(indices);
        // `length` is created with an Array or String wrapper, so it is
        // the first of the named keys.
        if matches!(self.kind, ObjKind::Array) || self.string_len().is_some() {
            keys.push("length".to_string());
        }
        keys.extend(named);
        keys
    }

    /// The property table's string keys (symbols and the Array indices
    /// the dense store owns left out), split as OrdinaryOwnPropertyKeys
    /// (ES §10.1.11.1) orders them: array indices in ascending order, then
    /// the other keys in creation order. With `enumerable_only`, only the
    /// enumerable ones.
    fn table_string_keys(&self, enumerable_only: bool) -> (Vec<String>, Vec<String>) {
        let mut indices: Vec<(usize, String)> = Vec::new();
        let mut named = Vec::new();
        for (k, p) in &self.props {
            if is_symbol_key(k) || self.is_element_slot(k) {
                continue;
            }
            if enumerable_only && !matches!(p, Prop::Value { enumerable: true, .. } | Prop::Accessor { enumerable: true, .. }) {
                continue;
            }
            match array_index(k) {
                Some(i) => indices.push((i, k.clone())),
                None => named.push(k.clone()),
            }
        }
        indices.sort_by_key(|(i, _)| *i);
        (indices.into_iter().map(|(_, k)| k).collect(), named)
    }

    /// A String wrapper's length (its character count), `None` for every
    /// other object.
    pub fn string_len(&self) -> Option<usize> {
        match &self.kind {
            ObjKind::Primitive(p) => match p.as_ref() {
                JsValue::Str(s) => Some(s.chars().count()),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether `key` is an Array index inside the dense store that the
    /// property table holds instead (an accessor `defineProperty` put
    /// there): the table entry is the property, and the store keeps a
    /// hole in its place.
    pub fn is_element_slot(&self, key: &str) -> bool {
        matches!(self.kind, ObjKind::Array)
            && key.parse::<usize>().is_ok_and(|i| i < self.elems.len())
            && self.index.contains_key(key)
    }

    /// Whether any Array index is held by the property table (see
    /// `is_element_slot`): the dense store alone no longer gives the
    /// elements, so readers must go through [[Get]].
    pub fn has_element_slots(&self) -> bool {
        matches!(self.kind, ObjKind::Array)
            && self
                .props
                .iter()
                .any(|(k, _)| k.parse::<usize>().is_ok_and(|i| i < self.elems.len()))
    }

    /// Remove a property-table entry, keeping the index in step.
    pub fn remove_slot(&mut self, key: &str) {
        if let Some(i) = self.index.remove(key) {
            self.props.remove(i);
            self.index.clear();
            for (n, (k, _)) in self.props.iter().enumerate() {
                self.index.insert(k.clone(), n);
            }
        }
    }

    /// Own symbol keys (as table keys), in insertion order.
    pub fn own_symbol_keys(&self) -> Vec<String> {
        self.props
            .iter()
            .filter(|(k, _)| is_symbol_key(k))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Get an own property slot index.
    pub fn own(&self, key: &str) -> Option<usize> {
        self.index.get(key).copied()
    }

    /// Read an own data property's value (accessors and misses return None).
    pub fn get_prop(&self, key: &str) -> Option<JsValue> {
        let i = self.own(key)?;
        match self.props.get(i) {
            Some((_, Prop::Value { value, .. })) => Some(value.clone()),
            _ => None,
        }
    }

    /// Define/overwrite a data property.
    pub fn set_prop(&mut self, key: &str, value: JsValue, enumerable: bool) {
        if let Some(i) = self.index.get(key) {
            if let Some(slot) = self.props.get_mut(*i) {
                slot.1 = Prop::Value { value, enumerable };
                return;
            }
        }
        self.index.insert(key.to_string(), self.props.len());
        self.props
            .push((key.to_string(), Prop::Value { value, enumerable }));
    }

    /// The last step of ordinary [[Set]] on the receiver itself (ES
    /// §10.1.9.2 OrdinarySetWithOwnDescriptor): overwrite an existing
    /// writable data property keeping its enumerability, or create an
    /// enumerable one. Returns false, writing nothing, for a non-writable
    /// property, an accessor (its setter, if any, was the caller's to
    /// run), or a new key on a non-extensible object.
    pub fn write_prop(&mut self, key: &str, value: JsValue) -> bool {
        if let Some(i) = self.index.get(key).copied() {
            if !self.is_writable(key) {
                return false;
            }
            return match self.props.get_mut(i) {
                Some((_, Prop::Value { value: slot, .. })) => {
                    *slot = value;
                    true
                }
                _ => false,
            };
        }
        if self.non_extensible {
            return false;
        }
        self.index.insert(key.to_string(), self.props.len());
        self.props.push((
            key.to_string(),
            Prop::Value {
                value,
                enumerable: true,
            },
        ));
        true
    }

    /// An Array's `length`: its stored elements and any holes after them.
    pub fn array_length(&self) -> usize {
        self.elems.len().saturating_add(self.trailing_holes)
    }

    /// An Array's element at `i` when the dense store holds one (`None`
    /// for a hole, an index past the store, or an accessor the property
    /// table holds).
    pub fn elem(&self, i: usize) -> Option<&JsValue> {
        self.elems.get(i).and_then(Option::as_ref)
    }

    /// Whether the dense store has a hole anywhere below `length`.
    pub fn has_holes(&self) -> bool {
        self.trailing_holes > 0 || self.elems.iter().any(Option::is_none)
    }

    /// Store `v` as the Array element at `i` (below the dense cap),
    /// extending the store with holes to reach it; `length` grows to
    /// `i + 1` when it was shorter. The caller has decided the write is
    /// allowed.
    pub fn put_elem(&mut self, i: usize, v: JsValue) {
        if i >= self.elems.len() {
            let len = self.array_length();
            self.elems.resize(i.saturating_add(1), None);
            self.trailing_holes = len.saturating_sub(i.saturating_add(1));
        }
        if let Some(slot) = self.elems.get_mut(i) {
            *slot = Some(v);
        }
    }

    /// Create the Array index `i` (key `key`) holding `v`, as
    /// ArrayDefineOwnProperty does for a new data property (ES §10.4.2.1):
    /// refused on a non-extensible array, and at or past `length` when
    /// `length` is read-only; `length` grows to cover it. Below the dense
    /// cap the element goes into the store (a write to `a[4294967294]`, a
    /// sparse-key idiom bundles use for "not found" sentinels, must not
    /// allocate four billion slots, so beyond it the index is a
    /// property-table entry).
    pub fn create_index(&mut self, i: usize, key: &str, v: JsValue) -> bool {
        let len = self.array_length();
        if self.non_extensible || (i >= len && !self.is_writable("length")) {
            return false;
        }
        if i < super::eval::MAX_DENSE {
            self.put_elem(i, v);
            return true;
        }
        self.set_prop(key, v, true);
        if i >= len {
            self.trailing_holes = i.saturating_add(1).saturating_sub(self.elems.len());
        }
        true
    }

    /// Replace an Array's elements with `items` (holes as `None`) and
    /// make its length theirs.
    pub fn set_elems(&mut self, items: Vec<Option<JsValue>>) {
        self.elems = items;
        self.trailing_holes = 0;
    }

    /// An Array's elements `0..length` in order, a hole reading as
    /// `undefined` (the padding stops at the dense cap). Only for readers
    /// for which a hole and `undefined` are the same: [[Get]] of a hole
    /// reads the prototype chain.
    pub fn array_values(&self) -> Vec<JsValue> {
        let mut out: Vec<JsValue> = self
            .elems
            .iter()
            .map(|e| e.clone().unwrap_or(JsValue::Undefined))
            .collect();
        let len = self.array_length().min(super::eval::MAX_DENSE.max(out.len()));
        out.resize(len, JsValue::Undefined);
        out
    }

    /// Set an Array's `length` (ES §10.4.2.4 ArraySetLength, after the
    /// value is converted): growing adds holes at the end, which take no
    /// storage (a non-extensible array may grow this way too: holes are
    /// not properties); shrinking deletes from the end and stops above
    /// the highest element that cannot be deleted, which on a sealed or
    /// frozen array is its highest present element. Returns false when
    /// `length` is not writable or the shrink stopped early.
    pub fn set_array_length(&mut self, n: usize) -> bool {
        if !self.is_writable("length") {
            return false;
        }
        let stored = self.elems.len();
        if n >= self.array_length() {
            self.trailing_holes = n - stored;
            return true;
        }
        let index_keys = || self.props.iter().filter_map(|(k, _)| array_index(k));
        let floor = if self.sealed || self.frozen {
            let last_elem = self.elems.iter().rposition(Option::is_some).map(|i| i.saturating_add(1));
            last_elem.into_iter().chain(index_keys().map(|i| i.saturating_add(1))).max().unwrap_or(0)
        } else {
            self.non_configurable
                .iter()
                .filter_map(|k| array_index(k))
                .map(|i| i.saturating_add(1))
                .max()
                .unwrap_or(0)
        };
        let target = n.max(floor);
        if target < stored {
            self.elems.truncate(target);
            self.trailing_holes = 0;
        } else {
            self.trailing_holes = target - stored;
        }
        self.non_writable.retain(|k| array_index(k).is_none_or(|i| i < target));
        self.non_enumerable_elems.retain(|i| *i < target);
        let gone: Vec<String> = self
            .props
            .iter()
            .filter(|(k, _)| array_index(k).is_some_and(|i| i >= target))
            .map(|(k, _)| k.clone())
            .collect();
        for k in gone {
            self.remove_slot(&k);
        }
        target == n
    }

    /// Define an accessor property the way an object literal or a class
    /// body does (getter/setter may each be absent): `get x` and `set x`
    /// compose into one accessor, which keeps the enumerability it was
    /// first given; over a data property the accessor replaces it.
    pub fn set_accessor(&mut self, key: &str, get: Option<ObjRef>, set: Option<ObjRef>, enumerable: bool) {
        if let Some(Prop::Accessor { get: g0, set: s0, .. }) = self.own(key).and_then(|i| self.props.get_mut(i)).map(|(_, p)| p) {
            if get.is_some() {
                *g0 = get;
            }
            if set.is_some() {
                *s0 = set;
            }
            return;
        }
        self.put_accessor(key, get, set, enumerable);
    }

    /// Make `key` an accessor with exactly these fields, replacing whatever
    /// slot it had (the caller has already merged any fields to keep).
    pub fn put_accessor(&mut self, key: &str, get: Option<ObjRef>, set: Option<ObjRef>, enumerable: bool) {
        let prop = Prop::Accessor { get, set, enumerable };
        if let Some(slot) = self.own(key).and_then(|i| self.props.get_mut(i)) {
            slot.1 = prop;
            return;
        }
        self.index.insert(key.to_string(), self.props.len());
        self.props.push((key.to_string(), prop));
    }

    /// Whether `key` is an own property: a property-table entry, a dense
    /// array element or `length`, or a typed-array element.
    pub fn has_own_key(&self, key: &str) -> bool {
        if self.index.contains_key(key) {
            return true;
        }
        if matches!(self.kind, ObjKind::Array) {
            if key == "length" {
                return true;
            }
            if let Some(i) = array_index(key) {
                return self.elem(i).is_some();
            }
        }
        if let ObjKind::TypedArray(t) = &self.kind {
            if let Some(i) = t.index_of_key(key) {
                return i.is_some();
            }
        }
        self.string_own(key).is_some()
    }

    /// An own property's [[Configurable]] attribute (only meaningful for a
    /// key the object owns).
    pub fn is_configurable(&self, key: &str) -> bool {
        if matches!(self.kind, ObjKind::Array) && key == "length" {
            return false;
        }
        if self.string_own(key).is_some() {
            return false;
        }
        !(self.sealed || self.frozen || self.non_configurable.contains(key))
    }

    /// An own data property's [[Writable]] attribute (only meaningful for
    /// a data property the object owns).
    pub fn is_writable(&self, key: &str) -> bool {
        !self.frozen
            && self.fn_meta_readonly & fn_meta_bit(key) == 0
            && !self.non_writable.contains(key)
            && self.string_own(key).is_none()
    }

    /// TestIntegrityLevel (ES §7.3.16): non-extensible, every own property
    /// non-configurable and, for `frozen`, every own data property
    /// non-writable.
    pub fn test_integrity(&self, frozen: bool) -> bool {
        if !self.non_extensible {
            return false;
        }
        if self.frozen || (self.sealed && !frozen) {
            return true;
        }
        let mut keys = self.own_string_keys_all();
        keys.extend(self.own_symbol_keys());
        keys.iter().all(|k| {
            let accessor = matches!(self.own_slot(k), Some(Prop::Accessor { .. }));
            !self.is_configurable(k) && (!frozen || accessor || !self.is_writable(k))
        })
    }

    /// [[Delete]] on an ordinary object (ES §10.1.10): `true` when the
    /// property is gone afterwards (an absent key included), `false` when
    /// it is non-configurable, which a sealed or frozen object makes every
    /// property, and which an array's `length` always is. Deletability is
    /// decided before anything is touched: a dense array element that may
    /// go leaves a hole (the length is unchanged).
    pub fn delete(&mut self, key: &str) -> bool {
        if matches!(self.kind, ObjKind::Array) && !self.index.contains_key(key) {
            if key == "length" {
                return false;
            }
            if let Some(i) = array_index(key) {
                if self.elem(i).is_some() {
                    if !self.is_configurable(key) {
                        return false;
                    }
                    if let Some(slot) = self.elems.get_mut(i) {
                        *slot = None;
                    }
                    self.non_writable.remove(key);
                    self.non_configurable.remove(key);
                    self.non_enumerable_elems.remove(&i);
                }
                return true;
            }
        }
        if let ObjKind::TypedArray(t) = &self.kind {
            // A typed array's in-bounds elements cannot be deleted; any
            // other numeric key is absent, so its delete succeeds.
            if let Some(i) = t.index_of_key(key) {
                return i.is_none();
            }
        }
        if self.string_own(key).is_some() {
            return false;
        }
        if !self.index.contains_key(key) {
            return true;
        }
        if !self.is_configurable(key) {
            return false;
        }
        self.set_writable(key, true);
        self.remove_slot(key);
        true
    }

    /// Enumerable own string keys in [[OwnPropertyKeys]] order: array
    /// indices ascending (an Array's, a typed array's or a String
    /// wrapper's, then the property table's), then the other keys in
    /// creation order. Symbol keys are excluded, as `Object.keys` and
    /// `for-in` require. An index the property table holds (an accessor)
    /// is listed when that entry is enumerable.
    pub fn own_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        if matches!(self.kind, ObjKind::Array) {
            for (i, e) in self.elems.iter().enumerate() {
                let k = i.to_string();
                let listed = if self.index.contains_key(&k) {
                    self.is_enumerable(&k)
                } else {
                    e.is_some() && !self.non_enumerable_elems.contains(&i)
                };
                if listed {
                    keys.push(k);
                }
            }
        }
        if let Some(n) = self.typed_len().or_else(|| self.string_len()) {
            for i in 0..n {
                keys.push(i.to_string());
            }
        }
        let (indices, named) = self.table_string_keys(true);
        keys.extend(indices);
        keys.extend(named);
        keys
    }

    pub fn is_callable(&self) -> bool {
        match &self.kind {
            ObjKind::Function { .. } | ObjKind::Native(_) | ObjKind::Bound { .. } => true,
            ObjKind::Proxy { target, .. } => target.borrow().is_callable(),
            _ => false,
        }
    }

    /// Whether this function object is a class constructor, an arrow, or a
    /// method (none of which may be `new`ed the sloppy way). Used by
    /// `construct` to reject arrows.
    pub fn is_arrow(&self) -> bool {
        matches!(&self.kind, ObjKind::Function { def, .. } if def.arrow)
    }
}

impl JsValue {
    pub fn str(s: impl Into<String>) -> JsValue {
        JsValue::Str(Rc::new(s.into()))
    }

    /// The property-table key this value selects: strings and numbers
    /// through ToString, symbols through their reserved key form.
    pub fn to_property_key(&self) -> String {
        match self {
            JsValue::Symbol(s) => symbol_key(s.id),
            other => other.to_js_string(),
        }
    }

    pub fn type_of(&self) -> &'static str {
        match self {
            JsValue::Undefined => "undefined",
            JsValue::Null => "object",
            JsValue::Bool(_) => "boolean",
            JsValue::Num(_) => "number",
            JsValue::Str(_) => "string",
            JsValue::Symbol(_) => "symbol",
            JsValue::Object(o) => {
                if o.borrow().is_callable() {
                    "function"
                } else {
                    "object"
                }
            }
        }
    }

    pub fn is_nullish(&self) -> bool {
        matches!(self, JsValue::Undefined | JsValue::Null)
    }

    /// ToBoolean.
    pub fn truthy(&self) -> bool {
        match self {
            JsValue::Undefined | JsValue::Null => false,
            JsValue::Bool(b) => *b,
            JsValue::Num(n) => *n != 0.0 && !n.is_nan(),
            JsValue::Str(s) => !s.is_empty(),
            JsValue::Symbol(_) => true,
            JsValue::Object(_) => true,
        }
    }

    /// ToNumber (objects via ToPrimitive-ish valueOf/toString handled by caller;
    /// here plain objects coerce to NaN, arrays via join like real engines'
    /// ToPrimitive fallback).
    pub fn to_number(&self) -> f64 {
        match self {
            JsValue::Undefined => f64::NAN,
            JsValue::Null => 0.0,
            JsValue::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            JsValue::Num(n) => *n,
            JsValue::Str(s) => string_to_number(s),
            JsValue::Symbol(_) => f64::NAN,
            JsValue::Object(o) => {
                let b = o.borrow();
                match &b.kind {
                    ObjKind::Date(t) => *t,
                    ObjKind::Primitive(p) => p.to_number(),
                    ObjKind::Array => match b.array_length() {
                        0 => 0.0,
                        1 => b.elem(0).filter(|v| !v.is_nullish()).map(|v| v.to_number()).unwrap_or(0.0),
                        _ => f64::NAN,
                    },
                    _ => f64::NAN,
                }
            }
        }
    }

    /// ToString for display/concatenation. Function sources are elided.
    pub fn to_js_string(&self) -> String {
        match self {
            JsValue::Undefined => "undefined".into(),
            JsValue::Null => "null".into(),
            JsValue::Bool(b) => b.to_string(),
            JsValue::Num(n) => format_number(*n),
            JsValue::Str(s) => s.as_ref().clone(),
            JsValue::Symbol(s) => {
                format!("Symbol({})", s.description.clone().unwrap_or_default())
            }
            JsValue::Object(o) => {
                let b = o.borrow();
                match &b.kind {
                    ObjKind::Primitive(p) => p.to_js_string(),
                    ObjKind::Proxy { target, .. } => JsValue::Object(target.clone()).to_js_string(),
                    ObjKind::Date(ms) => format_date_string(*ms),
                    ObjKind::Array => {
                        let mut out = String::new();
                        for (i, v) in b.array_values().iter().enumerate() {
                            if i > 0 {
                                out.push(',');
                            }
                            if !v.is_nullish() {
                                out.push_str(&v.to_js_string());
                            }
                        }
                        out
                    }
                    ObjKind::Function { def, .. } => {
                        format!(
                            "function {}() {{ [source elided] }}",
                            def.name.clone().unwrap_or_default()
                        )
                    }
                    ObjKind::Native(_) | ObjKind::Bound { .. } => {
                        "function () { [native code] }".into()
                    }
                    ObjKind::RegExp { source, flags } => format!("/{source}/{flags}"),
                    ObjKind::TypedArray(t) => t
                        .values()
                        .iter()
                        .map(|n| format_number(*n))
                        .collect::<Vec<_>>()
                        .join(","),
                    ObjKind::Error => {
                        let name = b
                            .own("name")
                            .and_then(|i| b.props.get(i))
                            .and_then(|(_, p)| match p {
                                Prop::Value { value, .. } => Some(value.to_js_string()),
                                _ => None,
                            })
                            .unwrap_or_else(|| "Error".into());
                        let msg = b
                            .own("message")
                            .and_then(|i| b.props.get(i))
                            .and_then(|(_, p)| match p {
                                Prop::Value { value, .. } => Some(value.to_js_string()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        if msg.is_empty() {
                            name
                        } else {
                            format!("{name}: {msg}")
                        }
                    }
                    _ => "[object Object]".into(),
                }
            }
        }
    }

    /// Display form used in error messages and console output.
    pub fn to_display_string(&self) -> String {
        self.to_js_string()
    }

    /// Loose equality (==) per the abstract equality algorithm, minus exotic
    /// document.all cases.
    pub fn loose_eq(&self, other: &JsValue) -> bool {
        use self::JsValue::*;
        match (self, other) {
            (Undefined | Null, Undefined | Null) => true,
            (Num(a), Num(b)) => a == b,
            (Str(a), Str(b)) => a == b,
            (Symbol(a), Symbol(b)) => a.id == b.id,
            (Symbol(_), _) | (_, Symbol(_)) => false,
            (Bool(_), _) => JsValue::Num(self.to_number()).loose_eq(other),
            (_, Bool(_)) => self.loose_eq(&JsValue::Num(other.to_number())),
            (Num(_), Str(_)) => self.to_number() == other.to_number(),
            (Str(_), Num(_)) => self.to_number() == other.to_number(),
            (Object(a), Object(b)) => Rc::ptr_eq(a, b),
            (Object(_), Num(_) | Str(_)) => {
                JsValue::str(self.to_js_string()).loose_eq(other)
                    || self.to_number() == other.to_number()
            }
            (Num(_) | Str(_), Object(_)) => other.loose_eq(self),
            _ => false,
        }
    }

    /// Strict equality (===).
    pub fn strict_eq(&self, other: &JsValue) -> bool {
        use self::JsValue::*;
        match (self, other) {
            (Undefined, Undefined) | (Null, Null) => true,
            (Bool(a), Bool(b)) => a == b,
            (Num(a), Num(b)) => a == b,
            (Str(a), Str(b)) => a == b,
            (Symbol(a), Symbol(b)) => a.id == b.id,
            (Object(a), Object(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// StringToNumber: whitespace-trimmed decimal, hex/octal/binary prefixes,
/// `Infinity`, and the empty string as 0.
pub fn string_to_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let v = if body == "Infinity" {
        f64::INFINITY
    } else if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        if neg {
            return f64::NAN;
        }
        u64::from_str_radix(hex, 16).map(|v| v as f64).unwrap_or(f64::NAN)
    } else if let Some(oct) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
        if neg {
            return f64::NAN;
        }
        u64::from_str_radix(oct, 8).map(|v| v as f64).unwrap_or(f64::NAN)
    } else if let Some(bin) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
        if neg {
            return f64::NAN;
        }
        u64::from_str_radix(bin, 2).map(|v| v as f64).unwrap_or(f64::NAN)
    } else if body.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
        && !body.contains("inf")
        && !body.contains("nan")
    {
        body.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    };
    if neg {
        -v
    } else {
        v
    }
}

/// `Date.prototype.toString` rendering on the virtual clock (UTC).
pub fn format_date_string(ms: f64) -> String {
    if !ms.is_finite() {
        return "Invalid Date".into();
    }
    let (y, mo, d, h, mi, s, _, dow) = civil_from_ms(ms);
    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let dn = days.get(dow as usize).copied().unwrap_or("Thu");
    let mn = months
        .get((mo - 1).clamp(0, 11) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{dn} {mn} {d:02} {y:04} {h:02}:{mi:02}:{s:02} GMT+0000 (Coordinated Universal Time)")
}

/// (year, month 1-12, day, hour, minute, second, millisecond, weekday 0=Sun)
/// for a millisecond timestamp, UTC. Integer-only civil-from-days.
pub fn civil_from_ms(ms: f64) -> (i64, i64, i64, i64, i64, i64, i64, i64) {
    let total_s = (ms / 1000.0).floor() as i64;
    let (days, rem) = (total_s.div_euclid(86_400), total_s.rem_euclid(86_400));
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    let dow = (days + 4).rem_euclid(7);
    (y, mo, d, h, mi, s, (ms as i64).rem_euclid(1000), dow)
}

/// Days from civil date (Howard Hinnant), inverse of [`civil_from_ms`].
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Number → string following JS conventions (integers without decimal point,
/// NaN/Infinity spelled out).
pub fn format_number(n: f64) -> String {
    if n.is_nan() {
        return "NaN".into();
    }
    if n.is_infinite() {
        return if n > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    if n == 0.0 {
        return "0".into();
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        let mut s = String::new();
        let _ = write!(s, "{}", n as i64);
        return s;
    }
    let mut s = format!("{n}");
    // Rust prints 1e21 as 1e21, JS as 1e+21; normalize the exponent sign.
    if let Some(pos) = s.find('e') {
        if s.get(pos + 1..pos + 2) != Some("-") && s.get(pos + 1..pos + 2) != Some("+") {
            s.insert(pos + 1, '+');
        }
    }
    s
}
