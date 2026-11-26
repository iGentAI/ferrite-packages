//! builtins_web — the web-platform globals a real page's scripts reach for
//! beyond ECMAScript: `location` (seeded from the page URL), `localStorage` /
//! `sessionStorage` (in-memory, per page), the URI-encoding functions,
//! `URL` / `URLSearchParams`, `atob` / `btoa`, `performance`, `screen`,
//! `history`, `crypto`, `TextEncoder` / `TextDecoder`, typed arrays, and the
//! `Headers` / `Response` / `Request` / `AbortController` shapes bundles
//! feature-detect.
//!
//! Same rules as the rest of the engine: std-only, panic-free, no indexing,
//! every failure a thrown `JsValue`. Nothing here performs I/O: `fetch`
//! still travels through [`super::interp::HostHooks`].

use std::cell::RefCell;
use std::rc::Rc;

use super::interp::Interp;
use super::value::{Bytes, JsObject, JsValue, NativeFn, ObjKind, ObjRef, Prop, TypedArrayData, TypedKind, format_number, iterator_key};

/// The most bytes one `ArrayBuffer` may hold. Wasm-style bundles allocate
/// tens of megabytes; a hostile `new Uint8Array(1e9)` must fail with a
/// RangeError instead of taking the process past its memory cap.
pub const MAX_ARRAY_BUFFER_BYTES: usize = 128 * 1024 * 1024;

/// The most bytes one `crypto.getRandomValues` call fills (Web Crypto's
/// quota; a larger view throws `QuotaExceededError`).
const MAX_RANDOM_VALUES_BYTES: usize = 65_536;

impl<'h> Interp<'h> {
    /// Install the web-platform globals. Called from `install_globals`
    /// after the ECMAScript surface so these definitions win where they
    /// overlap (`location`, `navigator`).
    pub(super) fn install_web_builtins(&mut self) {
        self.install_uri_encoding();
        self.install_location_and_history();
        self.install_storage();
        self.install_url();
        self.install_base64();
        self.install_typed_arrays();
        self.install_text_codecs();
        self.install_perf_screen_crypto();
        self.install_fetch_shapes();
        self.install_bigint();
    }

    /// `BigInt`: this engine has ONE numeric representation (f64), so a
    /// BigInt is the integral number it converts to. That covers what
    /// bundles actually use it for — feature detection
    /// (`typeof BigInt !== "undefined"`), integer ids, and the
    /// `asIntN`/`asUintN` wrapping helpers — and it is honest about its
    /// limit: a non-integral argument is a RangeError exactly as the real
    /// constructor throws, and values past 2^53 lose precision rather than
    /// carrying arbitrary width.
    fn install_bigint(&mut self) {
        let ctor: NativeFn = Rc::new(|interp, _t, args| {
            // `BigInt()` / `BigInt(undefined)` is a TypeError (undefined
            // has no BigInt conversion), as in Chrome.
            let v = match args.first() {
                Some(v) if !matches!(v, JsValue::Undefined) => v.clone(),
                _ => {
                    return Err(Interp::throw(
                        "TypeError: Cannot convert undefined to a BigInt",
                    ))
                }
            };
            let n = interp.to_number_value(&v)?;
            if !n.is_finite() || n.fract() != 0.0 {
                return Err(Interp::throw(format!(
                    "RangeError: The number {n} cannot be converted to a BigInt because it is not an integer"
                )));
            }
            Ok(JsValue::Num(n))
        });
        let f = self.native(ctor);
        // `BigInt.asIntN(bits, v)` / `asUintN(bits, v)`: wrap to the two's
        // complement / unsigned range of `bits` (up to the 53 bits an f64
        // holds exactly; a wider request returns the value unchanged).
        let as_int_n: NativeFn = Rc::new(|interp, _t, args| {
            // ToIndex on the width: NaN is 0, a negative or non-finite
            // width is a RangeError. Width 0 wraps everything to 0; a width
            // past the 53 bits an f64 holds exactly leaves a representable
            // value unchanged (it already fits).
            let bits = to_index(interp.number_arg(args.first(), 0.0)?)
                .ok_or_else(|| Interp::throw("RangeError: Invalid value: not (convertible to) a safe integer"))?;
            let n = interp.number_arg(args.get(1), 0.0)?;
            if bits == 0 {
                return Ok(JsValue::Num(0.0));
            }
            let bits = bits as f64;
            if bits > 53.0 || !n.is_finite() {
                return Ok(JsValue::Num(n));
            }
            let m = 2f64.powf(bits);
            let mut r = n.rem_euclid(m);
            if r >= m / 2.0 {
                r -= m;
            }
            Ok(JsValue::Num(r))
        });
        let as_uint_n: NativeFn = Rc::new(|interp, _t, args| {
            let bits = to_index(interp.number_arg(args.first(), 0.0)?)
                .ok_or_else(|| Interp::throw("RangeError: Invalid value: not (convertible to) a safe integer"))?;
            let n = interp.number_arg(args.get(1), 0.0)?;
            if bits == 0 {
                return Ok(JsValue::Num(0.0));
            }
            let bits = bits as f64;
            if bits > 53.0 || !n.is_finite() {
                return Ok(JsValue::Num(n));
            }
            Ok(JsValue::Num(n.rem_euclid(2f64.powf(bits))))
        });
        let int_n = self.native(as_int_n);
        let uint_n = self.native(as_uint_n);
        if let JsValue::Object(o) = &f {
            let mut b = o.borrow_mut();
            b.set_prop("asIntN", int_n, false);
            b.set_prop("asUintN", uint_n, false);
            b.set_prop("prototype", JsValue::Object(self.number_proto.clone()), false);
        }
        self.set_global("BigInt", f);
    }

    /// `encodeURIComponent` / `decodeURIComponent` / `encodeURI` / `decodeURI`
    /// / `escape` / `unescape`.
    fn install_uri_encoding(&mut self) {
        // (name, unreserved set beyond ALPHA DIGIT - _ . ! ~ * ' ( ))
        let component: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            Ok(JsValue::str(uri_encode(&s, "-_.!~*'()")))
        });
        let f = self.native(component);
        self.set_global("encodeURIComponent", f);
        let full: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            Ok(JsValue::str(uri_encode(&s, "-_.!~*'();/?:@&=+$,#")))
        });
        let f = self.native(full);
        self.set_global("encodeURI", f);
        let decode: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            match uri_decode(&s) {
                Some(d) => Ok(JsValue::str(d)),
                None => Err(Interp::throw("URIError: URI malformed")),
            }
        });
        let f = self.native(decode);
        self.set_global("decodeURIComponent", f);
        // decodeURI keeps the reserved set escaped (`%2F` stays `%2F`).
        let decode_uri: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            match uri_decode_keeping(&s, ";/?:@&=+$,#") {
                Some(d) => Ok(JsValue::str(d)),
                None => Err(Interp::throw("URIError: URI malformed")),
            }
        });
        let f = self.native(decode_uri);
        self.set_global("decodeURI", f);
        let escape_fn: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            Ok(JsValue::str(uri_encode(&s, "@*_+-./")))
        });
        let f = self.native(escape_fn);
        self.set_global("escape", f);
        let unescape_fn: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            Ok(JsValue::str(uri_decode(&s).unwrap_or(s)))
        });
        let f = self.native(unescape_fn);
        self.set_global("unescape", f);
    }

    /// `location` with its parsed parts, `history` with pushState /
    /// replaceState (which update `location` without navigating).
    fn install_location_and_history(&mut self) {
        let loc = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        set_location_parts(&loc, "about:blank");
        let assign: NativeFn = Rc::new(|interp, this, args| {
            let url = interp.string_arg(args.first(), "")?;
            if let JsValue::Object(o) = &this {
                set_location_parts(o, &url);
            }
            // The embedder owns navigation; record the intent like a link.
            interp
                .global_object
                .borrow_mut()
                .set_prop("__pendingNavigation", JsValue::str(url), false);
            Ok(JsValue::Undefined)
        });
        for name in ["assign", "replace"] {
            let f = self.native(assign.clone());
            loc.borrow_mut().set_prop(name, f, false);
        }
        let reload: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
        let f = self.native(reload);
        loc.borrow_mut().set_prop("reload", f, false);
        let to_string: NativeFn = Rc::new(|_i, this, _a| {
            Ok(match &this {
                JsValue::Object(o) => o
                    .borrow()
                    .get_prop("href")
                    .unwrap_or(JsValue::str("about:blank")),
                _ => JsValue::str("about:blank"),
            })
        });
        let f = self.native(to_string);
        loc.borrow_mut().set_prop("toString", f, false);
        self.set_global("location", JsValue::Object(loc.clone()));
        // `document.location` is the same object.
        self.global_object
            .borrow_mut()
            .set_prop("__location", JsValue::Object(loc.clone()), false);

        let history = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        history
            .borrow_mut()
            .set_prop("length", JsValue::Num(1.0), true);
        history.borrow_mut().set_prop("state", JsValue::Null, true);
        history
            .borrow_mut()
            .set_prop("scrollRestoration", JsValue::str("auto"), true);
        let make_push = |adds_entry: bool| -> NativeFn {
            Rc::new(move |interp, this: JsValue, args: &[JsValue]| {
            let state = args.first().cloned().unwrap_or(JsValue::Null);
            if let JsValue::Object(h) = &this {
                let mut b = h.borrow_mut();
                b.set_prop("state", state, true);
                if adds_entry {
                    let n = b.get_prop("length").map(|v| v.to_number()).unwrap_or(1.0);
                    b.set_prop("length", JsValue::Num(n + 1.0), true);
                }
            }
            // A same-document URL change: `location` follows, no navigation.
            if let Some(url) = args.get(2).filter(|v| !v.is_nullish()) {
                let url = url.to_js_string();
                let base = interp
                    .global_object
                    .borrow()
                    .get_prop("location")
                    .and_then(|l| match l {
                        JsValue::Object(o) => o.borrow().get_prop("href"),
                        _ => None,
                    })
                    .map(|v| v.to_js_string())
                    .unwrap_or_default();
                let abs = super::super::cdp::resolve_url(&base, &url).unwrap_or(url);
                // Read `location` under a borrow that ends here: a script can
                // set `location = globalThis`, and set_location_parts then
                // mutably borrows that same object.
                let loc = interp.global_object.borrow().get_prop("location");
                if let Some(JsValue::Object(l)) = loc {
                    set_location_parts(&l, &abs);
                }
            }
            Ok(JsValue::Undefined)
            })
        };
        let f = self.native(make_push(true));
        history.borrow_mut().set_prop("pushState", f, false);
        let f = self.native(make_push(false));
        history.borrow_mut().set_prop("replaceState", f, false);
        let noop: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
        for name in ["back", "forward", "go"] {
            let f = self.native(noop.clone());
            history.borrow_mut().set_prop(name, f, false);
        }
        self.set_global("history", JsValue::Object(history));
    }

    /// `localStorage` / `sessionStorage`: an in-memory Storage per page.
    fn install_storage(&mut self) {
        for name in ["localStorage", "sessionStorage"] {
            let store = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
            // Values live in a hidden backing object so `length` and the
            // methods agree and enumeration sees only stored keys.
            let data = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
            store
                .borrow_mut()
                .set_prop("__data", JsValue::Object(data), false);
            let get_item: NativeFn = Rc::new(|interp, this, args| {
                let k = interp.string_arg(args.first(), "")?;
                let Some(d) = storage_data(&this) else {
                    return Ok(JsValue::Null);
                };
                let v = d.borrow().get_prop(&k);
                Ok(v.unwrap_or(JsValue::Null))
            });
            let f = self.native(get_item);
            store.borrow_mut().set_prop("getItem", f, false);
            let set_item: NativeFn = Rc::new(|interp, this, args| {
                let k = interp.string_arg(args.first(), "")?;
                let v = interp.string_arg(args.get(1), "")?;
                if let Some(d) = storage_data(&this) {
                    d.borrow_mut().set_prop(&k, JsValue::str(v), true);
                    let n = d.borrow().own_keys().len() as f64;
                    if let JsValue::Object(s) = &this {
                        s.borrow_mut().set_prop("length", JsValue::Num(n), true);
                    }
                }
                Ok(JsValue::Undefined)
            });
            let f = self.native(set_item);
            store.borrow_mut().set_prop("setItem", f, false);
            let remove_item: NativeFn = Rc::new(|interp, this, args| {
                let k = interp.string_arg(args.first(), "")?;
                if let Some(d) = storage_data(&this) {
                    d.borrow_mut().delete(&k);
                    let n = d.borrow().own_keys().len() as f64;
                    if let JsValue::Object(s) = &this {
                        s.borrow_mut().set_prop("length", JsValue::Num(n), true);
                    }
                }
                Ok(JsValue::Undefined)
            });
            let f = self.native(remove_item);
            store.borrow_mut().set_prop("removeItem", f, false);
            let clear: NativeFn = Rc::new(|interp, this, _a| {
                if let JsValue::Object(s) = &this {
                    let fresh = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                    s.borrow_mut()
                        .set_prop("__data", JsValue::Object(fresh), false);
                    s.borrow_mut().set_prop("length", JsValue::Num(0.0), true);
                }
                Ok(JsValue::Undefined)
            });
            let f = self.native(clear);
            store.borrow_mut().set_prop("clear", f, false);
            let key: NativeFn = Rc::new(|interp, this, args| {
                let i = interp.number_arg(args.first(), 0.0)?;
                let Some(d) = storage_data(&this) else {
                    return Ok(JsValue::Null);
                };
                let keys = d.borrow().own_keys();
                if i < 0.0 || !i.is_finite() {
                    return Ok(JsValue::Null);
                }
                Ok(keys
                    .get(i as usize)
                    .map(|k| JsValue::str(k.clone()))
                    .unwrap_or(JsValue::Null))
            });
            let f = self.native(key);
            store.borrow_mut().set_prop("key", f, false);
            store
                .borrow_mut()
                .set_prop("length", JsValue::Num(0.0), true);
            self.set_global(name, JsValue::Object(store));
        }
    }

    /// `URL` and `URLSearchParams`.
    fn install_url(&mut self) {
        let object_proto = self.object_proto.clone();
        let url_ctor: NativeFn = Rc::new(move |interp, this, args| {
            // ToString through ToPrimitive: `new URL(document.location)` and
            // `new URL(anotherUrl)` hand over OBJECTS whose `toString` is the
            // href; a raw `to_js_string` would see `[object Object]`.
            let raw = match args.first() {
                Some(v) => interp.to_string_value(v)?,
                None => String::new(),
            };
            let base = match args.get(1) {
                Some(v) if !v.is_nullish() => {
                    Some(interp.to_string_value(v)?)
                }
                _ => None,
            };
            let abs = match &base {
                Some(b) => super::super::cdp::resolve_url(b, &raw).unwrap_or_else(|| raw.clone()),
                None => raw.clone(),
            };
            if !abs.contains("://") {
                return Err(Interp::throw(format!("TypeError: Invalid URL: {raw}")));
            }
            let obj = match &this {
                JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                _ => JsObject::new(ObjKind::Plain, Some(object_proto.clone())),
            };
            set_location_parts(&obj, &abs);
            // searchParams: a live-enough params object over the query.
            let query = obj
                .borrow()
                .get_prop("search")
                .map(|v| v.to_js_string())
                .unwrap_or_default();
            let params = interp.make_search_params(&query);
            obj.borrow_mut().set_prop("searchParams", params, true);
            let to_string: NativeFn = Rc::new(|_i, this, _a| {
                Ok(match &this {
                    JsValue::Object(o) => o.borrow().get_prop("href").unwrap_or(JsValue::str("")),
                    _ => JsValue::str(""),
                })
            });
            let f = interp.native(to_string);
            obj.borrow_mut().set_prop("toString", f.clone(), false);
            obj.borrow_mut().set_prop("toJSON", f, false);
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(ObjKind::Native(url_ctor), Some(self.function_proto.clone()));
        let proto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        ctor.borrow_mut()
            .set_prop("prototype", JsValue::Object(proto), false);
        // URL.createObjectURL / revokeObjectURL: no blob store, but bundles
        // feature-detect them.
        let create_obj: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::str("blob:agent-browser/0")));
        let f = self.native(create_obj);
        ctor.borrow_mut().set_prop("createObjectURL", f, false);
        let revoke: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
        let f = self.native(revoke);
        ctor.borrow_mut().set_prop("revokeObjectURL", f, false);
        self.set_global("URL", JsValue::Object(ctor));

        let params_ctor: NativeFn = Rc::new(|interp, _this, args| {
            let init = args
                .first()
                .filter(|v| !v.is_nullish())
                .map(|v| v.to_js_string())
                .unwrap_or_default();
            Ok(interp.make_search_params(&init))
        });
        let ctor = JsObject::new(
            ObjKind::Native(params_ctor),
            Some(self.function_proto.clone()),
        );
        let proto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        ctor.borrow_mut()
            .set_prop("prototype", JsValue::Object(proto), false);
        self.set_global("URLSearchParams", JsValue::Object(ctor));
    }

    /// A `URLSearchParams` object over `query` (`?a=1&b=2` or `a=1&b=2`).
    pub fn make_search_params(&mut self, query: &str) -> JsValue {
        let obj = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        let pairs: Vec<(String, String)> = query
            .trim_start_matches('?')
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (
                    uri_decode(&k.replace('+', " ")).unwrap_or_else(|| k.to_string()),
                    uri_decode(&v.replace('+', " ")).unwrap_or_else(|| v.to_string()),
                ),
                None => (
                    uri_decode(&p.replace('+', " ")).unwrap_or_else(|| p.to_string()),
                    String::new(),
                ),
            })
            .collect();
        let list: Vec<JsValue> = pairs
            .iter()
            .map(|(k, v)| self.new_array(vec![JsValue::str(k.clone()), JsValue::str(v.clone())]))
            .collect();
        let entries = self.new_array(list);
        obj.borrow_mut().set_prop("__pairs", entries, false);
        let get: NativeFn = Rc::new(|interp, this, args| {
            let k = interp.string_arg(args.first(), "")?;
            Ok(params_pairs(&this)
                .into_iter()
                .find(|(pk, _)| *pk == k)
                .map(|(_, v)| JsValue::str(v))
                .unwrap_or(JsValue::Null))
        });
        let f = self.native(get);
        obj.borrow_mut().set_prop("get", f, false);
        let get_all: NativeFn = Rc::new(|interp, this, args| {
            let k = interp.string_arg(args.first(), "")?;
            let out: Vec<JsValue> = params_pairs(&this)
                .into_iter()
                .filter(|(pk, _)| *pk == k)
                .map(|(_, v)| JsValue::str(v))
                .collect();
            Ok(interp.new_array(out))
        });
        let f = self.native(get_all);
        obj.borrow_mut().set_prop("getAll", f, false);
        let has: NativeFn = Rc::new(|interp, this, args| {
            let k = interp.string_arg(args.first(), "")?;
            Ok(JsValue::Bool(
                params_pairs(&this).iter().any(|(pk, _)| *pk == k),
            ))
        });
        let f = self.native(has);
        obj.borrow_mut().set_prop("has", f, false);
        let set_fn: NativeFn = Rc::new(|interp, this, args| {
            let k = interp.string_arg(args.first(), "")?;
            let v = interp.string_arg(args.get(1), "")?;
            // The first matching pair is replaced in place; later duplicates
            // are removed; a missing key appends.
            let mut pairs = params_pairs(&this);
            match pairs.iter().position(|(pk, _)| *pk == k) {
                Some(first) => {
                    if let Some(slot) = pairs.get_mut(first) {
                        slot.1 = v;
                    }
                    let mut idx = 0usize;
                    pairs.retain(|(pk, _)| {
                        let keep = idx == first || *pk != k;
                        idx = idx.saturating_add(1);
                        keep
                    });
                }
                None => pairs.push((k, v)),
            }
            set_params_pairs(interp, &this, pairs);
            Ok(JsValue::Undefined)
        });
        let f = self.native(set_fn);
        obj.borrow_mut().set_prop("set", f, false);
        let append: NativeFn = Rc::new(|interp, this, args| {
            let k = interp.string_arg(args.first(), "")?;
            let v = interp.string_arg(args.get(1), "")?;
            let mut pairs = params_pairs(&this);
            pairs.push((k, v));
            set_params_pairs(interp, &this, pairs);
            Ok(JsValue::Undefined)
        });
        let f = self.native(append);
        obj.borrow_mut().set_prop("append", f, false);
        let delete: NativeFn = Rc::new(|interp, this, args| {
            let k = interp.string_arg(args.first(), "")?;
            let mut pairs = params_pairs(&this);
            pairs.retain(|(pk, _)| *pk != k);
            set_params_pairs(interp, &this, pairs);
            Ok(JsValue::Undefined)
        });
        let f = self.native(delete);
        obj.borrow_mut().set_prop("delete", f, false);
        let for_each: NativeFn = Rc::new(|interp, this, args| {
            let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
            for (k, v) in params_pairs(&this) {
                interp.call(
                    cb.clone(),
                    JsValue::Undefined,
                    &[JsValue::str(v), JsValue::str(k), this.clone()],
                )?;
            }
            Ok(JsValue::Undefined)
        });
        let f = self.native(for_each);
        obj.borrow_mut().set_prop("forEach", f, false);
        let to_string: NativeFn = Rc::new(|_i, this, _a| {
            Ok(JsValue::str(
                params_pairs(&this)
                    .iter()
                    .map(|(k, v)| format!("{}={}", uri_encode(k, "-_.!~*'()"), uri_encode(v, "-_.!~*'()")))
                    .collect::<Vec<_>>()
                    .join("&"),
            ))
        });
        let f = self.native(to_string);
        obj.borrow_mut().set_prop("toString", f, false);
        // Iteration: entries/keys/values plus [Symbol.iterator].
        let entries_fn: NativeFn = Rc::new(|interp, this, _a| {
            let items: Vec<JsValue> = params_pairs(&this)
                .into_iter()
                .map(|(k, v)| interp.new_array(vec![JsValue::str(k), JsValue::str(v)]))
                .collect();
            Ok(interp.make_list_iterator(items))
        });
        let f = self.native(entries_fn.clone());
        obj.borrow_mut().set_prop("entries", f, false);
        let f = self.native(entries_fn);
        obj.borrow_mut().set_prop(&iterator_key(), f, false);
        let keys_fn: NativeFn = Rc::new(|interp, this, _a| {
            let items: Vec<JsValue> = params_pairs(&this)
                .into_iter()
                .map(|(k, _)| JsValue::str(k))
                .collect();
            Ok(interp.make_list_iterator(items))
        });
        let f = self.native(keys_fn);
        obj.borrow_mut().set_prop("keys", f, false);
        let values_fn: NativeFn = Rc::new(|interp, this, _a| {
            let items: Vec<JsValue> = params_pairs(&this)
                .into_iter()
                .map(|(_, v)| JsValue::str(v))
                .collect();
            Ok(interp.make_list_iterator(items))
        });
        let f = self.native(values_fn);
        obj.borrow_mut().set_prop("values", f, false);
        JsValue::Object(obj)
    }

    /// `atob` / `btoa`.
    fn install_base64(&mut self) {
        let btoa: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            // btoa operates on latin-1: a code point above 255 is an error.
            let mut bytes = Vec::with_capacity(s.len());
            for c in s.chars() {
                let n = c as u32;
                if n > 255 {
                    return Err(Interp::throw(
                        "InvalidCharacterError: btoa argument is not latin-1",
                    ));
                }
                bytes.push(n as u8);
            }
            Ok(JsValue::str(base64_encode(&bytes)))
        });
        let f = self.native(btoa);
        self.set_global("btoa", f);
        let atob: NativeFn = Rc::new(|interp, _t, args| {
            let s = interp.string_arg(args.first(), "")?;
            match base64_decode(&s) {
                Some(bytes) => Ok(JsValue::str(
                    bytes.iter().map(|b| *b as char).collect::<String>(),
                )),
                None => Err(Interp::throw(
                    "InvalidCharacterError: atob argument is not base64",
                )),
            }
        });
        let f = self.native(atob);
        self.set_global("atob", f);
    }

    /// `ArrayBuffer`, the nine typed-array views and `DataView`, over SHARED
    /// byte storage: a view reads and writes its buffer's bytes, so two
    /// views over one buffer observe each other — the wasm-loader, hashing
    /// and UTF-8 idioms bundles use (`new Uint32Array(buf)` beside a
    /// `Uint8Array` over the same memory, `new DataView(buf).getUint32`).
    /// Allocation is bounded by [`MAX_ARRAY_BUFFER_BYTES`].
    fn install_typed_arrays(&mut self) {
        let ab_proto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        let ab_proto_for_ctor = ab_proto.clone();
        let buffer_ctor: NativeFn = Rc::new(move |interp, _this, args| {
            // ToIndex: NaN is 0; a negative, non-finite or oversize length
            // is a RangeError.
            let n = interp.number_arg(args.first(), 0.0)?;
            let len = to_index(n)
                .filter(|l| *l <= MAX_ARRAY_BUFFER_BYTES)
                .ok_or_else(|| Interp::throw("RangeError: Array buffer allocation failed"))?;
            let obj = JsObject::new(
                ObjKind::ArrayBuffer(Rc::new(RefCell::new(vec![0u8; len]))),
                Some(ab_proto_for_ctor.clone()),
            );
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(ObjKind::Native(buffer_ctor), Some(self.function_proto.clone()));
        ctor.borrow_mut()
            .set_prop("prototype", JsValue::Object(ab_proto.clone()), false);
        ab_proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor.clone()), false);
        let byte_length: NativeFn = Rc::new(|_i, this, _a| {
            Ok(JsValue::Num(
                buffer_bytes(&this).map(|b| b.borrow().len() as f64).unwrap_or(0.0),
            ))
        });
        if let JsValue::Object(g) = self.native(byte_length) {
            ab_proto.borrow_mut().set_accessor("byteLength", Some(g), None, false);
        }
        let slice: NativeFn = Rc::new(|interp, this, args| {
            let Some(bytes) = buffer_bytes(&this) else {
                return Err(Interp::throw(
                    "TypeError: ArrayBuffer.prototype.slice called on incompatible receiver",
                ));
            };
            let data = bytes.borrow().clone();
            let len = data.len();
            let start = interp.relative_index(args.first(), len, 0)?;
            let end = interp.relative_index(args.get(1), len, len)?.max(start);
            let out = data.get(start..end).map(<[u8]>::to_vec).unwrap_or_default();
            Ok(interp.new_array_buffer(out))
        });
        let f = self.native(slice);
        ab_proto.borrow_mut().set_prop("slice", f, false);
        let is_view: NativeFn = Rc::new(|_i, _t, args| {
            Ok(JsValue::Bool(matches!(
                args.first(),
                Some(JsValue::Object(o))
                    if matches!(o.borrow().kind, ObjKind::TypedArray(_) | ObjKind::DataView { .. })
            )))
        });
        let f = self.native(is_view);
        ctor.borrow_mut().set_prop("isView", f, false);
        self.set_global("ArrayBuffer", JsValue::Object(ctor));
        let ta_proto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        self.install_typed_array_proto(&ta_proto);
        for kind in TypedKind::ALL {
            let proto = JsObject::new(ObjKind::Plain, Some(ta_proto.clone()));
            let size = kind.size() as f64;
            proto
                .borrow_mut()
                .set_prop("BYTES_PER_ELEMENT", JsValue::Num(size), false);
            let proto_for_ctor = proto.clone();
            let ctor_fn: NativeFn = Rc::new(move |interp, _this, args| {
                interp.construct_typed_array(kind, &proto_for_ctor, args)
            });
            let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
            ctor.borrow_mut()
                .set_prop("prototype", JsValue::Object(proto.clone()), false);
            ctor.borrow_mut()
                .set_prop("BYTES_PER_ELEMENT", JsValue::Num(size), false);
            proto
                .borrow_mut()
                .set_prop("constructor", JsValue::Object(ctor.clone()), false);
            let proto_for_from = proto.clone();
            let from: NativeFn = Rc::new(move |interp, _t, args| {
                let src = args.first().cloned().unwrap_or(JsValue::Undefined);
                let items = interp.iterate(&src)?;
                let mapped = match args.get(1) {
                    Some(f @ JsValue::Object(fo)) if fo.borrow().is_callable() => {
                        let mut out = Vec::with_capacity(items.len());
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
                let mut vals = Vec::with_capacity(mapped.len());
                for v in &mapped {
                    vals.push(interp.to_number_value(v)?);
                }
                interp.typed_array_from_values(kind, &proto_for_from, &vals)
            });
            let f = self.native(from);
            ctor.borrow_mut().set_prop("from", f, false);
            let proto_for_of = proto.clone();
            let of: NativeFn = Rc::new(move |interp, _t, args| {
                let mut vals = Vec::with_capacity(args.len());
                for v in args {
                    vals.push(interp.to_number_value(v)?);
                }
                interp.typed_array_from_values(kind, &proto_for_of, &vals)
            });
            let f = self.native(of);
            ctor.borrow_mut().set_prop("of", f, false);
            self.set_global(kind.name(), JsValue::Object(ctor));
        }
        let dv_proto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        let dv_proto_for_ctor = dv_proto.clone();
        let dv_ctor: NativeFn = Rc::new(move |interp, _this, args| {
            let (buffer_obj, bytes) = match args.first() {
                Some(JsValue::Object(o)) => match &o.borrow().kind {
                    ObjKind::ArrayBuffer(b) => (o.clone(), b.clone()),
                    _ => {
                        return Err(Interp::throw(
                            "TypeError: First argument to DataView constructor must be an ArrayBuffer",
                        ))
                    }
                },
                _ => {
                    return Err(Interp::throw(
                        "TypeError: First argument to DataView constructor must be an ArrayBuffer",
                    ))
                }
            };
            let buf_len = bytes.borrow().len();
            let byte_offset = match args.get(1).filter(|v| !v.is_nullish()) {
                Some(v) => {
                    let n = interp.to_number_value(v)?;
                    to_index(n).filter(|o| *o <= buf_len).ok_or_else(|| {
                        Interp::throw("RangeError: Start offset is outside the bounds of the buffer")
                    })?
                }
                None => 0,
            };
            let byte_length = match args.get(2).filter(|v| !v.is_nullish()) {
                Some(v) => {
                    let n = interp.to_number_value(v)?;
                    to_index(n)
                        .filter(|l| byte_offset.saturating_add(*l) <= buf_len)
                        .ok_or_else(|| Interp::throw("RangeError: Invalid DataView length"))?
                }
                None => buf_len.saturating_sub(byte_offset),
            };
            let obj = JsObject::new(
                ObjKind::DataView {
                    buffer_obj,
                    bytes,
                    byte_offset,
                    byte_length,
                },
                Some(dv_proto_for_ctor.clone()),
            );
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(ObjKind::Native(dv_ctor), Some(self.function_proto.clone()));
        ctor.borrow_mut()
            .set_prop("prototype", JsValue::Object(dv_proto.clone()), false);
        dv_proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor.clone()), false);
        type DvPick = fn(&DvParts) -> JsValue;
        let accessors: [(&str, DvPick); 3] = [
            ("buffer", |p| JsValue::Object(p.0.clone())),
            ("byteLength", |p| JsValue::Num(p.3 as f64)),
            ("byteOffset", |p| JsValue::Num(p.2 as f64)),
        ];
        for (name, pick) in accessors {
            let g: NativeFn = Rc::new(move |_i, this, _a| Ok(pick(&dv(&this)?)));
            if let JsValue::Object(go) = self.native(g) {
                dv_proto.borrow_mut().set_accessor(name, Some(go), None, false);
            }
        }
        for kind in TypedKind::ALL {
            if kind == TypedKind::Uint8Clamped {
                continue;
            }
            let short = kind.name().trim_end_matches("Array").to_string();
            let get: NativeFn = Rc::new(move |interp, this, args| {
                let (_, bytes, off, len) = dv(&this)?;
                let idx = dv_index(interp, args.first(), kind.size(), len)?;
                let little = args.get(1).map(|v| v.truthy()).unwrap_or(false);
                let mut tmp: Vec<u8> = bytes
                    .borrow()
                    .get(off + idx..off + idx + kind.size())
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default();
                if !little {
                    tmp.reverse();
                }
                Ok(kind.read(&tmp, 0).map(JsValue::Num).unwrap_or(JsValue::Num(f64::NAN)))
            });
            let f = self.native(get);
            dv_proto.borrow_mut().set_prop(&format!("get{short}"), f, false);
            let set: NativeFn = Rc::new(move |interp, this, args| {
                let (_, bytes, off, len) = dv(&this)?;
                let idx = dv_index(interp, args.first(), kind.size(), len)?;
                let n = interp.number_arg(args.get(1), f64::NAN)?;
                let little = args.get(2).map(|v| v.truthy()).unwrap_or(false);
                let mut tmp = vec![0u8; kind.size()];
                kind.write(&mut tmp, 0, n);
                if !little {
                    tmp.reverse();
                }
                let mut b = bytes.borrow_mut();
                if let Some(dst) = b.get_mut(off + idx..off + idx + kind.size()) {
                    dst.copy_from_slice(&tmp);
                }
                Ok(JsValue::Undefined)
            });
            let f = self.native(set);
            dv_proto.borrow_mut().set_prop(&format!("set{short}"), f, false);
        }
        self.set_global("DataView", JsValue::Object(ctor));
    }

    /// The `ArrayBuffer.prototype` the realm installed (for buffers the
    /// engine allocates on a script's behalf).
    fn array_buffer_proto(&self) -> ObjRef {
        self.global_ctor_proto("ArrayBuffer")
    }

    /// The prototype of the typed-array constructor for `kind`.
    fn typed_array_proto(&self, kind: TypedKind) -> ObjRef {
        self.global_ctor_proto(kind.name())
    }

    fn global_ctor_proto(&self, ctor: &str) -> ObjRef {
        let ctor = self.global_object.borrow().get_prop(ctor);
        match ctor {
            Some(JsValue::Object(c)) => match c.borrow().get_prop("prototype") {
                Some(JsValue::Object(p)) => p,
                _ => self.object_proto.clone(),
            },
            _ => self.object_proto.clone(),
        }
    }

    /// Allocate a zero-filled buffer of `len` bytes: the object and its
    /// storage. A length past the cap is a RangeError.
    fn fresh_buffer(&mut self, len: usize) -> Result<(ObjRef, Bytes), JsValue> {
        if len > MAX_ARRAY_BUFFER_BYTES {
            return Err(Interp::throw("RangeError: Array buffer allocation failed"));
        }
        let bytes: Bytes = Rc::new(RefCell::new(vec![0u8; len]));
        let obj = JsObject::new(ObjKind::ArrayBuffer(bytes.clone()), Some(self.array_buffer_proto()));
        Ok((obj, bytes))
    }

    /// An `ArrayBuffer` holding `data` (the bytes a host answered with).
    /// Oversized data is truncated to the cap rather than refused: the
    /// embedder already bounded the transfer.
    pub fn new_array_buffer(&mut self, mut data: Vec<u8>) -> JsValue {
        data.truncate(MAX_ARRAY_BUFFER_BYTES);
        let bytes: Bytes = Rc::new(RefCell::new(data));
        let obj = JsObject::new(ObjKind::ArrayBuffer(bytes), Some(self.array_buffer_proto()));
        JsValue::Object(obj)
    }

    /// A `Uint8Array` over a fresh buffer holding `data` (`TextEncoder`,
    /// response bodies).
    pub fn new_uint8_array(&mut self, mut data: Vec<u8>) -> JsValue {
        data.truncate(MAX_ARRAY_BUFFER_BYTES);
        let length = data.len();
        let bytes: Bytes = Rc::new(RefCell::new(data));
        let buffer_obj = JsObject::new(ObjKind::ArrayBuffer(bytes.clone()), Some(self.array_buffer_proto()));
        let proto = self.typed_array_proto(TypedKind::Uint8);
        let view = JsObject::new(
            ObjKind::TypedArray(TypedArrayData {
                buffer_obj,
                bytes,
                byte_offset: 0,
                length,
                kind: TypedKind::Uint8,
            }),
            Some(proto),
        );
        JsValue::Object(view)
    }

    /// A typed array of `kind` over a fresh buffer holding `vals` (each
    /// coerced to the element type).
    pub fn typed_array_from_values(
        &mut self,
        kind: TypedKind,
        proto: &ObjRef,
        vals: &[f64],
    ) -> Result<JsValue, JsValue> {
        let size = kind.size();
        let total = vals
            .len()
            .checked_mul(size)
            .ok_or_else(|| Interp::throw("RangeError: Array buffer allocation failed"))?;
        let (buffer_obj, bytes) = self.fresh_buffer(total)?;
        {
            let mut b = bytes.borrow_mut();
            for (i, v) in vals.iter().enumerate() {
                kind.write(&mut b, i.saturating_mul(size), *v);
            }
        }
        let view = JsObject::new(
            ObjKind::TypedArray(TypedArrayData {
                buffer_obj,
                bytes,
                byte_offset: 0,
                length: vals.len(),
                kind,
            }),
            Some(proto.clone()),
        );
        Ok(JsValue::Object(view))
    }

    /// `new <Kind>Array(...)` (ES §23.2.5.1): no argument, a length, an
    /// `ArrayBuffer` (with optional byteOffset / length), another typed
    /// array, or any iterable / array-like.
    pub fn construct_typed_array(
        &mut self,
        kind: TypedKind,
        proto: &ObjRef,
        args: &[JsValue],
    ) -> Result<JsValue, JsValue> {
        let size = kind.size();
        let name = kind.name();
        let first = args.first().cloned().unwrap_or(JsValue::Undefined);
        enum Src {
            Len(usize),
            Buffer(ObjRef, Bytes),
            Values(Vec<f64>),
        }
        let src = match &first {
            JsValue::Undefined => Src::Len(0),
            JsValue::Object(o) => {
                let direct = {
                    let b = o.borrow();
                    match &b.kind {
                        ObjKind::ArrayBuffer(bytes) => Some(Src::Buffer(o.clone(), bytes.clone())),
                        ObjKind::TypedArray(t) => Some(Src::Values(t.values())),
                        _ => None,
                    }
                };
                match direct {
                    Some(s) => s,
                    None => {
                        let items = self.iterate(&first)?;
                        let mut vals = Vec::with_capacity(items.len());
                        for v in &items {
                            vals.push(self.to_number_value(v)?);
                        }
                        Src::Values(vals)
                    }
                }
            }
            other => {
                let n = self.to_number_value(other)?;
                Src::Len(to_index(n).ok_or_else(|| {
                    Interp::throw(format!(
                        "RangeError: Invalid typed array length: {}",
                        format_number(n)
                    ))
                })?)
            }
        };
        let (buffer_obj, bytes, byte_offset, length) = match src {
            Src::Len(n) => {
                let total = n
                    .checked_mul(size)
                    .ok_or_else(|| Interp::throw("RangeError: Array buffer allocation failed"))?;
                let (obj, bytes) = self.fresh_buffer(total)?;
                (obj, bytes, 0, n)
            }
            Src::Values(vals) => {
                return self.typed_array_from_values(kind, proto, &vals);
            }
            Src::Buffer(obj, bytes) => {
                let buf_len = bytes.borrow().len();
                let offset = match args.get(1).filter(|v| !v.is_nullish()) {
                    Some(v) => {
                        let n = self.to_number_value(v)?;
                        to_index(n).ok_or_else(|| {
                            Interp::throw("RangeError: Start offset is outside the bounds of the buffer")
                        })?
                    }
                    None => 0,
                };
                if offset % size != 0 {
                    return Err(Interp::throw(format!(
                        "RangeError: start offset of {name} should be a multiple of {size}"
                    )));
                }
                let length = match args.get(2).filter(|v| !v.is_nullish()) {
                    Some(v) => {
                        let n = self.to_number_value(v)?;
                        to_index(n).ok_or_else(|| {
                            Interp::throw(format!(
                                "RangeError: Invalid typed array length: {}",
                                format_number(n)
                            ))
                        })?
                    }
                    None => {
                        let rest = buf_len.checked_sub(offset).ok_or_else(|| {
                            Interp::throw(format!(
                                "RangeError: Start offset {offset} is outside the bounds of the buffer"
                            ))
                        })?;
                        if rest % size != 0 {
                            return Err(Interp::throw(format!(
                                "RangeError: byte length of {name} should be a multiple of {size}"
                            )));
                        }
                        rest / size
                    }
                };
                let end = length
                    .checked_mul(size)
                    .and_then(|b| offset.checked_add(b))
                    .unwrap_or(usize::MAX);
                if end > buf_len {
                    return Err(Interp::throw(format!(
                        "RangeError: Invalid typed array length: {length}"
                    )));
                }
                (obj, bytes, offset, length)
            }
        };
        let view = JsObject::new(
            ObjKind::TypedArray(TypedArrayData {
                buffer_obj,
                bytes,
                byte_offset,
                length,
                kind,
            }),
            Some(proto.clone()),
        );
        Ok(JsValue::Object(view))
    }

    /// `%TypedArray%.prototype`: the accessors and methods every view kind
    /// shares. Element reads and writes go through [`TypedArrayData`], so
    /// every method observes (and makes) the same bytes the buffer holds.
    fn install_typed_array_proto(&mut self, proto: &ObjRef) {
        type TaPick = fn(&TypedArrayData) -> JsValue;
        let accessors: [(&str, TaPick); 4] = [
            ("buffer", |t| JsValue::Object(t.buffer_obj.clone())),
            ("byteLength", |t| JsValue::Num(t.byte_len() as f64)),
            ("byteOffset", |t| JsValue::Num(t.byte_offset as f64)),
            ("length", |t| JsValue::Num(t.length as f64)),
        ];
        for (name, pick) in accessors {
            let g: NativeFn = Rc::new(move |_i, this, _a| Ok(pick(&ta(&this)?)));
            if let JsValue::Object(go) = self.native(g) {
                proto.borrow_mut().set_accessor(name, Some(go), None, false);
            }
        }
        let mut methods: Vec<(&str, NativeFn)> = Vec::new();
        methods.push((
            "set",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let src = args.first().cloned().unwrap_or(JsValue::Undefined);
                let vals: Vec<f64> = match &src {
                    JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::TypedArray(_)) => {
                        match &o.borrow().kind {
                            ObjKind::TypedArray(s) => s.values(),
                            _ => Vec::new(),
                        }
                    }
                    _ => {
                        let items = interp.iterate(&src)?;
                        let mut out = Vec::with_capacity(items.len());
                        for v in &items {
                            out.push(interp.to_number_value(v)?);
                        }
                        out
                    }
                };
                let offset = match args.get(1) {
                    Some(v) => {
                        let n = interp.to_number_value(v)?;
                        to_index(n).ok_or_else(|| Interp::throw("RangeError: offset is out of bounds"))?
                    }
                    None => 0,
                };
                if offset.saturating_add(vals.len()) > t.length {
                    return Err(Interp::throw("RangeError: offset is out of bounds"));
                }
                for (i, v) in vals.iter().enumerate() {
                    t.set(offset.saturating_add(i), *v);
                }
                Ok(JsValue::Undefined)
            }),
        ));
        methods.push((
            "subarray",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let start = interp.relative_index(args.first(), t.length, 0)?;
                let end = interp.relative_index(args.get(1), t.length, t.length)?.max(start);
                let proto = interp.typed_array_proto(t.kind);
                let view = JsObject::new(
                    ObjKind::TypedArray(TypedArrayData {
                        buffer_obj: t.buffer_obj.clone(),
                        bytes: t.bytes.clone(),
                        byte_offset: t.byte_offset.saturating_add(start.saturating_mul(t.kind.size())),
                        length: end - start,
                        kind: t.kind,
                    }),
                    Some(proto),
                );
                Ok(JsValue::Object(view))
            }),
        ));
        methods.push((
            "slice",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let vals = t.values();
                let start = interp.relative_index(args.first(), vals.len(), 0)?;
                let end = interp.relative_index(args.get(1), vals.len(), vals.len())?.max(start);
                let out: Vec<f64> = vals.get(start..end).map(<[f64]>::to_vec).unwrap_or_default();
                let proto = interp.typed_array_proto(t.kind);
                interp.typed_array_from_values(t.kind, &proto, &out)
            }),
        ));
        methods.push((
            "fill",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let v = interp.number_arg(args.first(), f64::NAN)?;
                let start = interp.relative_index(args.get(1), t.length, 0)?;
                let end = interp.relative_index(args.get(2), t.length, t.length)?;
                for i in start..end {
                    t.set(i, v);
                }
                Ok(this)
            }),
        ));
        methods.push((
            "copyWithin",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let vals = t.values();
                let target = interp.relative_index(args.first(), t.length, 0)?;
                let start = interp.relative_index(args.get(1), t.length, 0)?;
                let end = interp.relative_index(args.get(2), t.length, t.length)?.max(start);
                for (k, i) in (start..end).enumerate() {
                    if let Some(v) = vals.get(i) {
                        t.set(target.saturating_add(k), *v);
                    }
                }
                Ok(this)
            }),
        ));
        methods.push((
            "indexOf",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let target = interp.number_arg(args.first(), f64::NAN)?;
                let from = interp.relative_index(args.get(1), t.length, 0)?;
                let idx = t.values().iter().enumerate().skip(from).find(|(_, v)| **v == target).map(|(i, _)| i);
                Ok(JsValue::Num(idx.map(|i| i as f64).unwrap_or(-1.0)))
            }),
        ));
        methods.push((
            "lastIndexOf",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let target = interp.number_arg(args.first(), f64::NAN)?;
                let from = interp.last_from_index(args.get(1), t.length)?;
                let idx = t
                    .values()
                    .iter()
                    .enumerate()
                    .take(from.map(|f| f.saturating_add(1)).unwrap_or(0))
                    .rev()
                    .find(|(_, v)| **v == target)
                    .map(|(i, _)| i);
                Ok(JsValue::Num(idx.map(|i| i as f64).unwrap_or(-1.0)))
            }),
        ));
        methods.push((
            "includes",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let target = interp.number_arg(args.first(), f64::NAN)?;
                let from = interp.relative_index(args.get(1), t.length, 0)?;
                Ok(JsValue::Bool(t.values().iter().skip(from).any(|v| {
                    *v == target || (v.is_nan() && target.is_nan())
                })))
            }),
        ));
        methods.push((
            "at",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let n = interp.number_arg(args.first(), 0.0)?;
                let len = t.length as i64;
                let mut idx = if n.is_nan() { 0 } else { n.trunc() as i64 };
                if idx < 0 {
                    idx += len;
                }
                if idx < 0 || idx >= len {
                    return Ok(JsValue::Undefined);
                }
                Ok(t.get(idx as usize).map(JsValue::Num).unwrap_or(JsValue::Undefined))
            }),
        ));
        methods.push((
            "join",
            Rc::new(|_i, this, args| {
                let t = ta(&this)?;
                let sep = match args.first() {
                    Some(v) if !matches!(v, JsValue::Undefined) => v.to_js_string(),
                    _ => ",".to_string(),
                };
                Ok(JsValue::str(
                    t.values().iter().map(|n| format_number(*n)).collect::<Vec<_>>().join(&sep),
                ))
            }),
        ));
        let to_string: NativeFn = Rc::new(|_i, this, _a| {
            let t = ta(&this)?;
            Ok(JsValue::str(
                t.values().iter().map(|n| format_number(*n)).collect::<Vec<_>>().join(","),
            ))
        });
        methods.push(("toString", to_string.clone()));
        methods.push(("toLocaleString", to_string));
        methods.push((
            "reverse",
            Rc::new(|_i, this, _a| {
                let t = ta(&this)?;
                let mut vals = t.values();
                vals.reverse();
                for (i, v) in vals.iter().enumerate() {
                    t.set(i, *v);
                }
                Ok(this)
            }),
        ));
        methods.push((
            "sort",
            Rc::new(|interp, this, args| {
                let cmp = super::builtins_array::sort_comparator(args)?;
                let t = ta(&this)?;
                let mut vals = t.values();
                // Insertion sort so a comparator can call back into script;
                // the default order is numeric with NaN last (ES §23.2.3.29).
                for i in 1..vals.len() {
                    let mut j = i;
                    while j > 0 {
                        let swap = {
                            let (Some(a), Some(b)) = (vals.get(j - 1), vals.get(j)) else { break };
                            match &cmp {
                                Some(f @ JsValue::Object(fo)) if fo.borrow().is_callable() => {
                                    let r = interp.call(
                                        f.clone(),
                                        JsValue::Undefined,
                                        &[JsValue::Num(*a), JsValue::Num(*b)],
                                    )?;
                                    interp.to_number_value(&r)? > 0.0
                                }
                                _ => match (a.is_nan(), b.is_nan()) {
                                    (true, false) => true,
                                    (false, true) | (true, true) => false,
                                    _ => a > b,
                                },
                            }
                        };
                        if swap {
                            vals.swap(j - 1, j);
                            j -= 1;
                        } else {
                            break;
                        }
                    }
                }
                for (i, v) in vals.iter().enumerate() {
                    t.set(i, *v);
                }
                Ok(this)
            }),
        ));
        // Callback methods: (value, index, view) with an optional thisArg.
        methods.push((
            "forEach",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let ta_this = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                for (i, v) in t.values().into_iter().enumerate() {
                    interp.call(cb.clone(), ta_this.clone(), &[JsValue::Num(v), JsValue::Num(i as f64), this.clone()])?;
                }
                Ok(JsValue::Undefined)
            }),
        ));
        methods.push((
            "map",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let ta_this = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let mut out = Vec::with_capacity(t.length);
                for (i, v) in t.values().into_iter().enumerate() {
                    let r = interp.call(cb.clone(), ta_this.clone(), &[JsValue::Num(v), JsValue::Num(i as f64), this.clone()])?;
                    out.push(interp.to_number_value(&r)?);
                }
                let proto = interp.typed_array_proto(t.kind);
                interp.typed_array_from_values(t.kind, &proto, &out)
            }),
        ));
        methods.push((
            "filter",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let ta_this = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let mut out = Vec::new();
                for (i, v) in t.values().into_iter().enumerate() {
                    if interp
                        .call(cb.clone(), ta_this.clone(), &[JsValue::Num(v), JsValue::Num(i as f64), this.clone()])?
                        .truthy()
                    {
                        out.push(v);
                    }
                }
                let proto = interp.typed_array_proto(t.kind);
                interp.typed_array_from_values(t.kind, &proto, &out)
            }),
        ));
        for (name, from_end, want_index) in [
            ("find", false, false),
            ("findIndex", false, true),
            ("findLast", true, false),
            ("findLastIndex", true, true),
        ] {
            let f: NativeFn = Rc::new(move |interp, this, args| {
                let t = ta(&this)?;
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let ta_this = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                let order: Vec<(usize, f64)> = if from_end {
                    t.values().into_iter().enumerate().rev().collect()
                } else {
                    t.values().into_iter().enumerate().collect()
                };
                for (i, v) in order {
                    if interp
                        .call(cb.clone(), ta_this.clone(), &[JsValue::Num(v), JsValue::Num(i as f64), this.clone()])?
                        .truthy()
                    {
                        return Ok(if want_index { JsValue::Num(i as f64) } else { JsValue::Num(v) });
                    }
                }
                Ok(if want_index { JsValue::Num(-1.0) } else { JsValue::Undefined })
            });
            methods.push((name, f));
        }
        methods.push((
            "some",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let ta_this = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                for (i, v) in t.values().into_iter().enumerate() {
                    if interp.call(cb.clone(), ta_this.clone(), &[JsValue::Num(v), JsValue::Num(i as f64), this.clone()])?.truthy() {
                        return Ok(JsValue::Bool(true));
                    }
                }
                Ok(JsValue::Bool(false))
            }),
        ));
        methods.push((
            "every",
            Rc::new(|interp, this, args| {
                let t = ta(&this)?;
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let ta_this = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                for (i, v) in t.values().into_iter().enumerate() {
                    if !interp.call(cb.clone(), ta_this.clone(), &[JsValue::Num(v), JsValue::Num(i as f64), this.clone()])?.truthy() {
                        return Ok(JsValue::Bool(false));
                    }
                }
                Ok(JsValue::Bool(true))
            }),
        ));
        for (name, from_end) in [("reduce", false), ("reduceRight", true)] {
            let f: NativeFn = Rc::new(move |interp, this, args| {
                let t = ta(&this)?;
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let mut order: Vec<(usize, f64)> = t.values().into_iter().enumerate().collect();
                if from_end {
                    order.reverse();
                }
                let mut iter = order.into_iter();
                let mut acc = match args.get(1) {
                    Some(v) => v.clone(),
                    None => match iter.next() {
                        Some((_, v)) => JsValue::Num(v),
                        None => {
                            return Err(Interp::throw(
                                "TypeError: Reduce of empty array with no initial value",
                            ))
                        }
                    },
                };
                for (i, v) in iter {
                    acc = interp.call(
                        cb.clone(),
                        JsValue::Undefined,
                        &[acc, JsValue::Num(v), JsValue::Num(i as f64), this.clone()],
                    )?;
                }
                Ok(acc)
            });
            methods.push((name, f));
        }
        methods.push((
            "keys",
            Rc::new(|interp, this, _a| {
                let t = ta(&this)?;
                let out: Vec<JsValue> = (0..t.length).map(|i| JsValue::Num(i as f64)).collect();
                Ok(interp.make_list_iterator(out))
            }),
        ));
        methods.push((
            "entries",
            Rc::new(|interp, this, _a| {
                let t = ta(&this)?;
                let out: Vec<JsValue> = t
                    .values()
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| interp.new_array(vec![JsValue::Num(i as f64), JsValue::Num(v)]))
                    .collect();
                Ok(interp.make_list_iterator(out))
            }),
        ));
        let values: NativeFn = Rc::new(|interp, this, _a| {
            let t = ta(&this)?;
            let out: Vec<JsValue> = t.values().into_iter().map(JsValue::Num).collect();
            Ok(interp.make_list_iterator(out))
        });
        methods.push(("values", values.clone()));
        for (name, f) in methods {
            let fv = self.native(f);
            proto.borrow_mut().set_prop(name, fv, false);
        }
        let fv = self.native(values);
        proto.borrow_mut().set_prop(&iterator_key(), fv, false);
    }

    /// `TextEncoder` / `TextDecoder` over UTF-8.
    fn install_text_codecs(&mut self) {
        let enc_ctor: NativeFn = Rc::new(|interp, this, _args| {
            let obj = match &this {
                JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
            };
            obj.borrow_mut()
                .set_prop("encoding", JsValue::str("utf-8"), true);
            let encode: NativeFn = Rc::new(|interp, _t, args| {
                let s = interp.string_arg(args.first(), "")?;
                Ok(interp.new_uint8_array(s.into_bytes()))
            });
            let f = interp.native(encode);
            obj.borrow_mut().set_prop("encode", f, false);
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(ObjKind::Native(enc_ctor), Some(self.function_proto.clone()));
        self.set_global("TextEncoder", JsValue::Object(ctor));

        let dec_ctor: NativeFn = Rc::new(|interp, this, _args| {
            let obj = match &this {
                JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
            };
            obj.borrow_mut()
                .set_prop("encoding", JsValue::str("utf-8"), true);
            let decode: NativeFn = Rc::new(|interp, _t, args| {
                // A typed array, ArrayBuffer or DataView decodes its bytes;
                // any other array-like is read element by element.
                let src = args.first().cloned().unwrap_or(JsValue::Undefined);
                // Nothing to decode (`decode()`) is the empty string; an
                // iteration or element conversion that throws propagates.
                let bytes: Vec<u8> = match byte_source(&src) {
                    Some(b) => b,
                    None if matches!(src, JsValue::Undefined) => Vec::new(),
                    None => {
                        let items = interp.iterate(&src)?;
                        let mut out = Vec::with_capacity(items.len());
                        for v in &items {
                            let n = interp.to_number_value(v)?;
                            out.push(if n.is_finite() {
                                (n as i64).rem_euclid(256) as u8
                            } else {
                                0
                            });
                        }
                        out
                    }
                };
                Ok(JsValue::str(String::from_utf8_lossy(&bytes).into_owned()))
            });
            let f = interp.native(decode);
            obj.borrow_mut().set_prop("decode", f, false);
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(ObjKind::Native(dec_ctor), Some(self.function_proto.clone()));
        self.set_global("TextDecoder", JsValue::Object(ctor));
    }

    /// `performance`, `screen`, `crypto`, `structuredClone`.
    fn install_perf_screen_crypto(&mut self) {
        let perf = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        let now: NativeFn = Rc::new(|interp, _t, _a| Ok(JsValue::Num(interp.now_ms)));
        let f = self.native(now);
        perf.borrow_mut().set_prop("now", f, false);
        perf.borrow_mut()
            .set_prop("timeOrigin", JsValue::Num(0.0), true);
        let entries: NativeFn = Rc::new(|interp, _t, _a| Ok(interp.new_array(Vec::new())));
        for name in ["getEntries", "getEntriesByType", "getEntriesByName"] {
            let f = self.native(entries.clone());
            perf.borrow_mut().set_prop(name, f, false);
        }
        let noop: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
        for name in ["mark", "measure", "clearMarks", "clearMeasures"] {
            let f = self.native(noop.clone());
            perf.borrow_mut().set_prop(name, f, false);
        }
        // performance.timing: the legacy navigation-timing shape.
        let timing = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        for k in [
            "navigationStart",
            "domLoading",
            "domInteractive",
            "domContentLoadedEventStart",
            "domContentLoadedEventEnd",
            "domComplete",
            "loadEventStart",
            "loadEventEnd",
            "responseStart",
            "responseEnd",
            "requestStart",
            "fetchStart",
        ] {
            timing.borrow_mut().set_prop(k, JsValue::Num(0.0), true);
        }
        perf.borrow_mut()
            .set_prop("timing", JsValue::Object(timing), true);
        self.set_global("performance", JsValue::Object(perf));

        let screen = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        for (k, v) in [
            ("width", 1280.0),
            ("height", 720.0),
            ("availWidth", 1280.0),
            ("availHeight", 720.0),
            ("colorDepth", 24.0),
            ("pixelDepth", 24.0),
        ] {
            screen.borrow_mut().set_prop(k, JsValue::Num(v), true);
        }
        self.set_global("screen", JsValue::Object(screen));

        let crypto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        // Web Crypto randomness comes from the embedder's secure generator
        // (HostHooks::random_fill), never from the deterministic render
        // contract Math.random follows.
        let get_random: NativeFn = Rc::new(|interp, _t, args| {
            // Fills the typed array's bytes, so
            // `crypto.getRandomValues(new Uint32Array(4))` and a Uint8Array
            // view over the same buffer agree.
            let Some(v) = args.first() else {
                return Err(Interp::throw(
                    "TypeError: crypto.getRandomValues requires a typed array",
                ));
            };
            let mismatch = || {
                Interp::throw("TypeMismatchError: crypto.getRandomValues requires an integer typed array")
            };
            let t = ta(v).map_err(|_| mismatch())?;
            if matches!(t.kind, TypedKind::Float32 | TypedKind::Float64) {
                return Err(mismatch());
            }
            let len = t.length.saturating_mul(t.kind.size());
            if len > MAX_RANDOM_VALUES_BYTES {
                return Err(Interp::throw(
                    "QuotaExceededError: crypto.getRandomValues accepts at most 65536 bytes",
                ));
            }
            let mut fresh = vec![0u8; len];
            interp
                .hooks
                .random_fill(&mut fresh)
                .map_err(|e| Interp::throw(format!("OperationError: {e}")))?;
            let mut bytes = t.bytes.borrow_mut();
            let end = t.byte_offset.saturating_add(len);
            let Some(dst) = bytes.get_mut(t.byte_offset..end) else {
                return Err(Interp::throw(
                    "TypeError: crypto.getRandomValues: the view is outside its buffer",
                ));
            };
            dst.copy_from_slice(&fresh);
            Ok(v.clone())
        });
        let f = self.native(get_random);
        crypto.borrow_mut().set_prop("getRandomValues", f, false);
        let uuid: NativeFn = Rc::new(|interp, _t, _a| {
            let mut b = [0u8; 16];
            interp
                .hooks
                .random_fill(&mut b)
                .map_err(|e| Interp::throw(format!("OperationError: {e}")))?;
            // RFC 9562 version 4: version nibble 4, variant bits 10.
            if let Some(x) = b.get_mut(6) {
                *x = (*x & 0x0f) | 0x40;
            }
            if let Some(x) = b.get_mut(8) {
                *x = (*x & 0x3f) | 0x80;
            }
            let mut out = String::with_capacity(36);
            for (i, x) in b.iter().enumerate() {
                if matches!(i, 4 | 6 | 8 | 10) {
                    out.push('-');
                }
                out.push_str(&format!("{x:02x}"));
            }
            Ok(JsValue::str(out))
        });
        let f = self.native(uuid);
        crypto.borrow_mut().set_prop("randomUUID", f, false);
        self.set_global("crypto", JsValue::Object(crypto));

        // structuredClone: a deep copy through the JSON value model.
        let clone: NativeFn = Rc::new(|interp, _t, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            match super::json::stringify(interp, &v)? {
                Some(s) => super::json::parse(interp, &s),
                None => Ok(JsValue::Undefined),
            }
        });
        let f = self.native(clone);
        self.set_global("structuredClone", f);
    }

    /// `Headers`, `Request`, `Response`, `AbortController`, `FormData`: the
    /// shapes bundles construct and feature-detect around `fetch`.
    fn install_fetch_shapes(&mut self) {
        let headers_ctor: NativeFn = Rc::new(|interp, this, args| {
            let obj = match &this {
                JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
            };
            let data = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            if let Some(JsValue::Object(init)) = args.first() {
                let entries: Vec<(String, JsValue)> = init
                    .borrow()
                    .props
                    .iter()
                    .filter_map(|(k, p)| match p {
                        Prop::Value { value, .. } => Some((k.clone(), value.clone())),
                        _ => None,
                    })
                    .collect();
                for (k, v) in entries {
                    let v = interp.to_string_value(&v)?;
                    data.borrow_mut()
                        .set_prop(&k.to_ascii_lowercase(), JsValue::str(v), true);
                }
            }
            obj.borrow_mut()
                .set_prop("__data", JsValue::Object(data), false);
            let get: NativeFn = Rc::new(|interp, this, args| {
                let k = interp.string_arg(args.first(), "")?.to_ascii_lowercase();
                let Some(d) = storage_data(&this) else {
                    return Ok(JsValue::Null);
                };
                let v = d.borrow().get_prop(&k);
                Ok(v.unwrap_or(JsValue::Null))
            });
            let f = interp.native(get);
            obj.borrow_mut().set_prop("get", f, false);
            let set_fn: NativeFn = Rc::new(|interp, this, args| {
                let k = interp.string_arg(args.first(), "")?.to_ascii_lowercase();
                let v = interp.string_arg(args.get(1), "")?;
                if let Some(d) = storage_data(&this) {
                    d.borrow_mut().set_prop(&k, JsValue::str(v), true);
                }
                Ok(JsValue::Undefined)
            });
            let f = interp.native(set_fn.clone());
            obj.borrow_mut().set_prop("set", f, false);
            let f = interp.native(set_fn);
            obj.borrow_mut().set_prop("append", f, false);
            let has: NativeFn = Rc::new(|interp, this, args| {
                let k = interp.string_arg(args.first(), "")?.to_ascii_lowercase();
                Ok(JsValue::Bool(
                    storage_data(&this)
                        .map(|d| d.borrow().get_prop(&k).is_some())
                        .unwrap_or(false),
                ))
            });
            let f = interp.native(has);
            obj.borrow_mut().set_prop("has", f, false);
            let for_each: NativeFn = Rc::new(|interp, this, args| {
                let cb = args.first().cloned().unwrap_or(JsValue::Undefined);
                let Some(d) = storage_data(&this) else {
                    return Ok(JsValue::Undefined);
                };
                let entries: Vec<(String, JsValue)> = d
                    .borrow()
                    .props
                    .iter()
                    .filter_map(|(k, p)| match p {
                        Prop::Value { value, .. } => Some((k.clone(), value.clone())),
                        _ => None,
                    })
                    .collect();
                for (k, v) in entries {
                    interp.call(
                        cb.clone(),
                        JsValue::Undefined,
                        &[v, JsValue::str(k), this.clone()],
                    )?;
                }
                Ok(JsValue::Undefined)
            });
            let f = interp.native(for_each);
            obj.borrow_mut().set_prop("forEach", f, false);
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(
            ObjKind::Native(headers_ctor),
            Some(self.function_proto.clone()),
        );
        self.set_global("Headers", JsValue::Object(ctor));

        // Response: the same shape `fetch` resolves with, constructible.
        let response_ctor: NativeFn = Rc::new(|interp, _this, args| {
            let body = match args.first().filter(|v| !v.is_nullish()) {
                Some(v) => interp.to_string_value(v)?,
                None => String::new(),
            };
            let status = match args.get(1) {
                Some(init @ JsValue::Object(_)) => {
                    let v = interp.get_property(init, "status")?;
                    if matches!(v, JsValue::Undefined) {
                        200.0
                    } else {
                        let n = interp.to_number_value(&v)?;
                        if n.is_finite() { n } else { 200.0 }
                    }
                }
                _ => 200.0,
            };
            Ok(interp.make_response(status as u16, &[], body.into_bytes()))
        });
        let ctor = JsObject::new(
            ObjKind::Native(response_ctor),
            Some(self.function_proto.clone()),
        );
        let json_static: NativeFn = Rc::new(|interp, _t, args| {
            let v = args.first().cloned().unwrap_or(JsValue::Undefined);
            let body = super::json::stringify(interp, &v)?.unwrap_or_else(|| "null".to_string());
            Ok(interp.make_response(200, &[], body.into_bytes()))
        });
        let f = self.native(json_static);
        ctor.borrow_mut().set_prop("json", f, false);
        self.set_global("Response", JsValue::Object(ctor));

        let request_ctor: NativeFn = Rc::new(|interp, _this, args| {
            let url = interp.string_arg(args.first(), "")?;
            let obj = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            obj.borrow_mut().set_prop("url", JsValue::str(url), true);
            let method = match args.get(1) {
                Some(JsValue::Object(init)) => init
                    .borrow()
                    .get_prop("method")
                    .map(|v| v.to_js_string())
                    .unwrap_or_else(|| "GET".to_string()),
                _ => "GET".to_string(),
            };
            obj.borrow_mut()
                .set_prop("method", JsValue::str(method), true);
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(
            ObjKind::Native(request_ctor),
            Some(self.function_proto.clone()),
        );
        self.set_global("Request", JsValue::Object(ctor));

        let abort_ctor: NativeFn = Rc::new(|interp, this, _args| {
            let obj = match &this {
                JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                _ => JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone())),
            };
            let signal = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
            signal
                .borrow_mut()
                .set_prop("aborted", JsValue::Bool(false), true);
            let noop: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Undefined));
            for name in ["addEventListener", "removeEventListener"] {
                let f = interp.native(noop.clone());
                signal.borrow_mut().set_prop(name, f, false);
            }
            obj.borrow_mut()
                .set_prop("signal", JsValue::Object(signal), true);
            let abort: NativeFn = Rc::new(|_i, this, _a| {
                if let JsValue::Object(o) = &this {
                    // Read the signal under a borrow that ends here: the
                    // script-writable `signal` may be the controller itself.
                    let signal = o.borrow().get_prop("signal");
                    if let Some(JsValue::Object(s)) = signal {
                        s.borrow_mut()
                            .set_prop("aborted", JsValue::Bool(true), true);
                    }
                }
                Ok(JsValue::Undefined)
            });
            let f = interp.native(abort);
            obj.borrow_mut().set_prop("abort", f, false);
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(
            ObjKind::Native(abort_ctor),
            Some(self.function_proto.clone()),
        );
        self.set_global("AbortController", JsValue::Object(ctor));

        let form_ctor: NativeFn = Rc::new(|interp, _this, _args| {
            Ok(interp.make_search_params(""))
        });
        let ctor = JsObject::new(
            ObjKind::Native(form_ctor),
            Some(self.function_proto.clone()),
        );
        self.set_global("FormData", JsValue::Object(ctor));
    }

    /// Point `location` (and `document.URL`) at the page being rendered.
    /// The embedder calls this before running scripts so `location.href`,
    /// `.hostname`, `.pathname` and friends are the real page's.
    pub fn set_location(&mut self, url: &str) {
        let loc = self.global_object.borrow().get_prop("location");
        if let Some(JsValue::Object(o)) = loc {
            set_location_parts(&o, url);
            let query = o
                .borrow()
                .get_prop("search")
                .map(|v| v.to_js_string())
                .unwrap_or_default();
            let params = self.make_search_params(&query);
            o.borrow_mut().set_prop("searchParams", params, true);
        }
    }
}

/// The hidden `__data` backing object of a Storage/Headers-like object.
fn storage_data(this: &JsValue) -> Option<ObjRef> {
    match this {
        JsValue::Object(o) => match o.borrow().get_prop("__data") {
            Some(JsValue::Object(d)) => Some(d),
            _ => None,
        },
        _ => None,
    }
}

/// The (key, value) pairs of a URLSearchParams object.
fn params_pairs(this: &JsValue) -> Vec<(String, String)> {
    let JsValue::Object(o) = this else {
        return Vec::new();
    };
    let Some(JsValue::Object(list)) = o.borrow().get_prop("__pairs") else {
        return Vec::new();
    };
    let items = list.borrow().array_values();
    items
        .iter()
        .filter_map(|pair| match pair {
            JsValue::Object(p) => {
                let b = p.borrow();
                Some((
                    b.elem(0)?.to_js_string(),
                    b.elem(1).map(|v| v.to_js_string()).unwrap_or_default(),
                ))
            }
            _ => None,
        })
        .collect()
}

/// Replace a URLSearchParams object's pairs.
fn set_params_pairs(interp: &mut Interp, this: &JsValue, pairs: Vec<(String, String)>) {
    let JsValue::Object(o) = this else { return };
    let list: Vec<JsValue> = pairs
        .into_iter()
        .map(|(k, v)| interp.new_array(vec![JsValue::str(k), JsValue::str(v)]))
        .collect();
    let arr = interp.new_array(list);
    o.borrow_mut().set_prop("__pairs", arr, false);
}

/// Fill a location-like object's parts from an absolute URL.
fn set_location_parts(obj: &ObjRef, url: &str) {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (format!("{s}:"), r.to_string()),
        None => ("about:".to_string(), url.trim_start_matches("about:").to_string()),
    };
    let (hostport, path_q) = match rest.find('/') {
        Some(i) => (
            rest.get(..i).unwrap_or("").to_string(),
            rest.get(i..).unwrap_or("/").to_string(),
        ),
        None => (rest.clone(), "/".to_string()),
    };
    let (path_only, hash) = match path_q.split_once('#') {
        Some((p, h)) => (p.to_string(), format!("#{h}")),
        None => (path_q.clone(), String::new()),
    };
    let (pathname, search) = match path_only.split_once('?') {
        Some((p, q)) => (p.to_string(), format!("?{q}")),
        None => (path_only.clone(), String::new()),
    };
    let (hostname, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.to_string())
        }
        _ => (hostport.clone(), String::new()),
    };
    let mut b = obj.borrow_mut();
    b.set_prop("href", JsValue::str(url), true);
    b.set_prop("protocol", JsValue::str(scheme.clone()), true);
    b.set_prop("host", JsValue::str(hostport), true);
    b.set_prop("hostname", JsValue::str(hostname), true);
    b.set_prop("port", JsValue::str(port), true);
    b.set_prop(
        "pathname",
        JsValue::str(if pathname.is_empty() {
            "/".to_string()
        } else {
            pathname
        }),
        true,
    );
    b.set_prop("search", JsValue::str(search), true);
    b.set_prop("hash", JsValue::str(hash), true);
    let origin = match url.split_once("://") {
        Some((s, r)) => format!(
            "{s}://{}",
            r.split('/').next().unwrap_or("")
        ),
        None => "null".to_string(),
    };
    b.set_prop("origin", JsValue::str(origin), true);
}

/// Percent-encode everything outside ALPHA / DIGIT / `unreserved`.
fn uri_encode(s: &str, unreserved: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || unreserved.contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `decodeURI`: like [`uri_decode`] but an escape that decodes to one of
/// the `keep` characters (the URI reserved set) is left encoded.
fn uri_decode_keeping(s: &str, keep: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'%') => {
                let h = bytes.get(i + 1).and_then(|c| (*c as char).to_digit(16))?;
                let l = bytes.get(i + 2).and_then(|c| (*c as char).to_digit(16))?;
                let v = (h * 16 + l) as u8;
                if v < 0x80 && keep.contains(v as char) {
                    out.extend_from_slice(bytes.get(i..i + 3)?);
                } else {
                    out.push(v);
                }
                i += 3;
            }
            Some(b) => {
                out.push(*b);
                i += 1;
            }
            None => break,
        }
    }
    // A decoded byte sequence that is not UTF-8 (`%FF`, a lone
    // continuation byte) is a URIError, not a replacement character.
    String::from_utf8(out).ok()
}

/// Decode `%XX` escapes as UTF-8; None when the input is malformed.
fn uri_decode(s: &str) -> Option<String> {
    uri_decode_keeping(s, "")
}

/// Standard base64 encoding.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0) as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let idx = |shift: u32| {
            T.get(((n >> shift) & 0x3f) as usize)
                .copied()
                .unwrap_or(b'A') as char
        };
        out.push(idx(18));
        out.push(idx(12));
        out.push(if chunk.len() > 1 { idx(6) } else { '=' });
        out.push(if chunk.len() > 2 { idx(0) } else { '=' });
    }
    out
}

/// Standard base64 decoding; None on an invalid character.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c == '=' {
            // Padding ends the stream; the partial group's low bits are
            // discarded (they are the encoder's zero fill).
            break;
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// ToIndex (ES §7.1.22): NaN is 0; a negative, non-finite or > 2^53-1
/// value is `None` (the caller's RangeError).
fn to_index(n: f64) -> Option<usize> {
    if n.is_nan() {
        return Some(0);
    }
    let t = n.trunc();
    if !t.is_finite() || !(0.0..=9_007_199_254_740_991.0).contains(&t) {
        None
    } else {
        Some(t as usize)
    }
}

/// The typed-array view behind `this`, or a TypeError.
fn ta(this: &JsValue) -> Result<TypedArrayData, JsValue> {
    if let JsValue::Object(o) = this {
        if let ObjKind::TypedArray(t) = &o.borrow().kind {
            return Ok(t.clone());
        }
    }
    Err(Interp::throw("TypeError: this is not a typed array"))
}

/// The byte storage of an `ArrayBuffer` receiver.
fn buffer_bytes(this: &JsValue) -> Option<Bytes> {
    match this {
        JsValue::Object(o) => match &o.borrow().kind {
            ObjKind::ArrayBuffer(b) => Some(b.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// (buffer object, bytes, byte offset, byte length) of a DataView receiver.
type DvParts = (ObjRef, Bytes, usize, usize);

fn dv(this: &JsValue) -> Result<DvParts, JsValue> {
    if let JsValue::Object(o) = this {
        if let ObjKind::DataView {
            buffer_obj,
            bytes,
            byte_offset,
            byte_length,
        } = &o.borrow().kind
        {
            return Ok((buffer_obj.clone(), bytes.clone(), *byte_offset, *byte_length));
        }
    }
    Err(Interp::throw("TypeError: this is not a DataView"))
}

/// A DataView access index: ToIndex of the argument, in bounds for an
/// element of `size` bytes inside a view of `len` bytes.
fn dv_index(interp: &mut Interp, v: Option<&JsValue>, size: usize, len: usize) -> Result<usize, JsValue> {
    let n = interp.number_arg(v, 0.0)?;
    to_index(n)
        .filter(|i| i.saturating_add(size) <= len)
        .ok_or_else(|| Interp::throw("RangeError: Offset is outside the bounds of the DataView"))
}

/// The bytes a typed array, ArrayBuffer or DataView value covers.
fn byte_source(v: &JsValue) -> Option<Vec<u8>> {
    let JsValue::Object(o) = v else {
        return None;
    };
    let b = o.borrow();
    match &b.kind {
        ObjKind::TypedArray(t) => Some(t.byte_copy()),
        ObjKind::ArrayBuffer(bytes) => Some(bytes.borrow().clone()),
        ObjKind::DataView {
            bytes,
            byte_offset,
            byte_length,
            ..
        } => Some(
            bytes
                .borrow()
                .get(*byte_offset..byte_offset.saturating_add(*byte_length))
                .map(<[u8]>::to_vec)
                .unwrap_or_default(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod crypto_tests {
    use super::super::interp::{to_display, HostHooks, Interp};
    use super::super::parser;

    /// An embedder that supplies no random source (the trait default).
    struct NoSource;
    impl HostHooks for NoSource {
        fn fetch(
            &mut self,
            _url: &str,
            _method: &str,
            _headers: &[(String, String)],
            _body: Option<&[u8]>,
        ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
            Err("no network".to_string())
        }
        fn console(&mut self, _level: &str, _message: &str) {}
    }

    /// An embedder source that walks a counter, standing in for the
    /// operating system's generator only to show which bytes the engine
    /// hands the page.
    struct Counter(u8);
    impl HostHooks for Counter {
        fn fetch(
            &mut self,
            _url: &str,
            _method: &str,
            _headers: &[(String, String)],
            _body: Option<&[u8]>,
        ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
            Err("no network".to_string())
        }
        fn console(&mut self, _level: &str, _message: &str) {}
        fn random_fill(&mut self, dest: &mut [u8]) -> Result<(), String> {
            for b in dest.iter_mut() {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
            Ok(())
        }
    }

    fn run(hooks: &mut dyn HostHooks, src: &str) -> String {
        let prog = parser::parse(src).unwrap();
        let mut interp = Interp::new(hooks);
        match interp.run_program(&prog) {
            Ok(v) => v.to_js_string(),
            Err(e) => format!("uncaught {}", to_display(&e)),
        }
    }

    #[test]
    fn without_a_secure_source_both_calls_throw_and_write_nothing() {
        let filled = run(
            &mut NoSource,
            "let m = ''; const u = new Uint8Array(4); \
             try { crypto.getRandomValues(u); m = 'filled'; } catch (e) { m = String(e); } \
             m + '|' + Array.from(u).join(',')",
        );
        assert!(filled.contains("no secure random source"), "{filled}");
        assert!(filled.ends_with("|0,0,0,0"), "{filled}");
        let uuid = run(
            &mut NoSource,
            "let m = ''; try { m = crypto.randomUUID(); } catch (e) { m = String(e); } m",
        );
        assert!(uuid.contains("no secure random source"), "{uuid}");
    }

    #[test]
    fn get_random_values_fills_the_view_with_the_source_bytes() {
        let mut source = Counter(0);
        let bytes = run(
            &mut source,
            "const u = new Uint8Array(4); \
             const same = crypto.getRandomValues(u) === u; \
             same + '|' + Array.from(u).join(',')",
        );
        assert_eq!(bytes, "true|1,2,3,4");
        // A wider element type is filled through its bytes: 5,6,7,8
        // little-endian is 0x08070605.
        let wide = run(&mut source, "String(crypto.getRandomValues(new Uint32Array(1))[0])");
        assert_eq!(wide, "134678021");
    }

    #[test]
    fn get_random_values_keeps_the_web_crypto_contract() {
        let mut source = Counter(0);
        let float = run(
            &mut source,
            "let m = ''; try { crypto.getRandomValues(new Float64Array(2)); } catch (e) { m = String(e); } m",
        );
        assert!(float.contains("TypeMismatchError"), "{float}");
        let quota = run(
            &mut source,
            "let m = ''; try { crypto.getRandomValues(new Uint8Array(65537)); } catch (e) { m = String(e); } m",
        );
        assert!(quota.contains("QuotaExceededError"), "{quota}");
        let max = run(&mut source, "String(crypto.getRandomValues(new Uint8Array(65536)).length)");
        assert_eq!(max, "65536");
    }

    #[test]
    fn random_uuid_is_version_4_built_from_the_source() {
        let mut source = Counter(0);
        // Bytes 1..=16, with byte 6 (0x07) forced to 0x47 and byte 8 (0x09)
        // to 0x89.
        assert_eq!(
            run(&mut source, "crypto.randomUUID()"),
            "01020304-0506-4708-890a-0b0c0d0e0f10"
        );
        let next = run(&mut source, "crypto.randomUUID()");
        assert_ne!(next, "01020304-0506-4708-890a-0b0c0d0e0f10");
        assert_eq!(next.get(14..15), Some("4"), "{next}");
    }
}

#[cfg(test)]
mod web_conversion_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ {body}; }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    const NAMED: &str = "const named = (s) => ({ toString() { return s; } });";

    #[test]
    fn storage_converts_keys_and_values_with_to_string() {
        assert_eq!(
            eval_js(&format!(
                "{NAMED} localStorage.setItem(named('k'), named('v')); localStorage.getItem('k')"
            )),
            "v"
        );
        assert_eq!(caught("localStorage.setItem({ toString() { throw 'key'; } }, 1)"), "key");
        assert_eq!(caught("localStorage.getItem(Symbol('s'))"), "TypeError");
        assert_eq!(caught("localStorage.key({ valueOf() { throw 'idx'; } })"), "idx");
    }

    #[test]
    fn url_search_params_and_headers_convert_with_to_string() {
        assert_eq!(
            eval_js(&format!(
                "{NAMED} const p = new URLSearchParams('a=1'); p.append(named('b'), named('2')); p.toString()"
            )),
            "a=1&b=2"
        );
        assert_eq!(caught("new URLSearchParams().set('a', { toString() { throw 'val'; } })"), "val");
        assert_eq!(
            eval_js(&format!(
                "{NAMED} const h = new Headers(); h.set(named('X-A'), named('one')); h.get('x-a')"
            )),
            "one"
        );
        assert_eq!(caught("new Headers().append('x', { toString() { throw 'hdr'; } })"), "hdr");
    }

    #[test]
    fn uri_and_text_codecs_convert_with_to_string_and_to_number() {
        assert_eq!(eval_js("encodeURIComponent({ toString() { return 'a b'; } })"), "a%20b");
        assert_eq!(caught("decodeURIComponent({ toString() { throw 'uri'; } })"), "uri");
        assert_eq!(
            eval_js("new TextEncoder().encode({ toString() { return 'hi'; } }).length"),
            "2"
        );
        assert_eq!(
            eval_js("new TextDecoder().decode([{ valueOf() { return 65; } }, 66])"),
            "AB"
        );
        assert_eq!(caught("new TextDecoder().decode([{ valueOf() { throw 'byte'; } }])"), "byte");
        assert_eq!(
            caught("new TextDecoder().decode({ [Symbol.iterator]() { throw 'iter'; } })"),
            "iter"
        );
    }
}

#[cfg(test)]
mod typed_array_numeric_key_tests {
    use super::super::interp::test_support::eval_js;

    fn caught(body: &str) -> String {
        eval_js(&format!(
            "let r = 'no throw'; try {{ r = String((() => {{ {body} }})()); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn a_numeric_key_outside_the_view_is_absent_and_never_inherited() {
        // ES 10.4.5: every CanonicalNumericIndexString is the typed
        // array's own business; one that is not a valid integer index
        // reads undefined without consulting the prototype chain.
        assert_eq!(
            caught("for (const k of ['-1', '1.5', '-0', 'Infinity', 'NaN', '2', '+1', '01']) Object.prototype[k] = 'proto:' + k; \
                    const ta = new Uint8Array(2); const out = ['-1', '1.5', '-0', 'Infinity', 'NaN', '2', '+1', '01'].map((k) => String(ta[k])); \
                    for (const k of ['-1', '1.5', '-0', 'Infinity', 'NaN', '2', '+1', '01']) delete Object.prototype[k]; return out.join()"),
            "undefined,undefined,undefined,undefined,undefined,undefined,proto:+1,proto:01"
        );
        assert_eq!(caught("Object.prototype['-1'] = 'p'; const v = Object.create(new Int8Array(1))['-1']; delete Object.prototype['-1']; return String(v)"), "undefined");
        assert_eq!(caught("Object.prototype['-1'] = 'p'; const v = Reflect.get(new Int8Array(1), '-1', {}); delete Object.prototype['-1']; return String(v)"), "undefined");
        assert_eq!(caught("const ta = new Float64Array(2); return ['-1' in ta, '1.5' in ta, '1' in ta, '+1' in ta, ta.hasOwnProperty('-0'), Object.getOwnPropertyDescriptor(ta, '-1') === undefined].join()"), "false,false,true,false,false,true");
    }

    #[test]
    fn writes_to_an_invalid_numeric_key_are_ignored() {
        assert_eq!(
            caught("'use strict'; const ta = new Uint8Array(2); let n = 0; ta['-1'] = { valueOf() { n++; return 7; } }; ta['1.5'] = 1; ta[5] = 1; ta['-0'] = 1; \
                    return [Object.keys(ta).join('/'), n, ta.hasOwnProperty('-1'), 5 in ta, ta[0]].join()"),
            "0/1,1,false,false,0"
        );
        // A non-canonical numeric string is an ordinary property.
        assert_eq!(caught("const ta = new Uint8Array(2); ta['+1'] = 9; ta['01'] = 8; return [ta['+1'], ta['01'], ta[1], Object.keys(ta).join('/')].join()"), "9,8,0,0/1/+1/01");
        assert_eq!(caught("Object.defineProperty(new Uint8Array(2), '1.5', { value: 1 })"), "TypeError");
        assert_eq!(caught("return [Reflect.defineProperty(new Uint8Array(2), '-1', { value: 1 }), Reflect.defineProperty(new Uint8Array(2), '+1', { value: 1 })].join()"), "false,true");
        assert_eq!(caught("const ta = new Uint8Array(2); return [delete ta['-1'], delete ta['1.5'], delete ta[0], delete ta[7]].join()"), "true,true,false,true");
    }
}
