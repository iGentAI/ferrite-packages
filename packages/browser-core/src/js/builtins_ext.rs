//! builtins_ext — the capability-report gap closers: Date (virtual clock),
//! Promise.race, Object.prototype.hasOwnProperty, Array.prototype
//! flat/fill/keys/at, String.prototype match/at, global + Number.isFinite,
//! and String.replace with capture-group substitutions ($1..$9, $&, $$).
//!
//! Same rules as the rest of the engine: std-only, panic-free, no indexing.

use std::rc::Rc;

use super::interp::Interp;
use super::value::{JsObject, JsValue, NativeFn, ObjKind, SYM_TO_PRIMITIVE, days_from_civil, format_date_string, symbol_key};

impl<'h> Interp<'h> {
    /// Install the extended builtins. Called from `install_globals`.
    pub(super) fn install_gap_builtins(&mut self) {
        self.install_date();
        self.install_promise_race();
        self.install_has_own_property();
        self.install_string_extras();
        self.install_is_finite();
    }

    /// Date on the VIRTUAL clock: `Date.now()`, `new Date()`, `new Date(ms)`,
    /// `new Date(string)`, `new Date(y, m, d, …)`, `Date.parse`, `Date.UTC`,
    /// the component getters AND setters, and the string formatters pages
    /// read (`toISOString`, `toString`, `toUTCString`, `toDateString`,
    /// `toLocale*String`, `toJSON`). The epoch starts at 0 at navigation
    /// (deterministic renders — same contract as Math.random), and the
    /// realm has no timezone: local time IS UTC (`getTimezoneOffset` is 0),
    /// so the local and UTC accessors agree by construction.
    fn install_date(&mut self) {
        let date_proto = self.date_proto.clone();
        let ctor_fn: NativeFn = Rc::new(move |interp, this, args| {
            // `Date()` as a plain call returns the string form.
            let constructing = matches!(&this, JsValue::Object(o) if !o.borrow().is_callable());
            let ms = match args.len() {
                0 => interp.now_ms,
                1 => match args.first() {
                    Some(JsValue::Str(s)) => parse_date(s),
                    Some(JsValue::Object(o)) if matches!(o.borrow().kind, ObjKind::Date(_)) => {
                        match o.borrow().kind {
                            ObjKind::Date(ms) => ms,
                            _ => f64::NAN,
                        }
                    }
                    Some(v) => {
                        let p = interp.to_primitive(v)?;
                        match p {
                            JsValue::Str(s) => parse_date(&s),
                            other => time_clip(interp.to_number_value(&other)?),
                        }
                    }
                    None => interp.now_ms,
                },
                _ => {
                    let n = |i: usize, d: f64| args.get(i).map(interp_num).unwrap_or(d);
                    let mut y = n(0, f64::NAN);
                    if (0.0..=99.0).contains(&y) && y.fract() == 0.0 {
                        y += 1900.0;
                    }
                    make_time(y, n(1, 0.0), n(2, 1.0), n(3, 0.0), n(4, 0.0), n(5, 0.0), n(6, 0.0))
                }
            };
            if !constructing {
                return Ok(JsValue::str(format_date_string(ms)));
            }
            let obj = match &this {
                JsValue::Object(o) if !o.borrow().is_callable() => o.clone(),
                _ => JsObject::new(ObjKind::Date(ms), Some(interp.date_proto.clone())),
            };
            {
                let mut b = obj.borrow_mut();
                b.kind = ObjKind::Date(ms);
                b.class_name = "Date";
            }
            Ok(JsValue::Object(obj))
        });
        let ctor = JsObject::new(ObjKind::Native(ctor_fn), Some(self.function_proto.clone()));
        ctor.borrow_mut()
            .set_prop("prototype", JsValue::Object(date_proto.clone()), false);
        date_proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(ctor.clone()), false);
        let now: NativeFn = Rc::new(|interp, _t, _a| Ok(JsValue::Num(interp.now_ms)));
        let f = self.native(now);
        ctor.borrow_mut().set_prop("now", f, false);
        let parse: NativeFn = Rc::new(|_i, _t, args| {
            let s = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            Ok(JsValue::Num(parse_date(&s)))
        });
        let f = self.native(parse);
        ctor.borrow_mut().set_prop("parse", f, false);
        let utc: NativeFn = Rc::new(|interp, _t, args| {
            let mut nums = Vec::with_capacity(args.len());
            for v in args {
                nums.push(interp.to_number_value(v)?);
            }
            let n = |i: usize, d: f64| nums.get(i).copied().unwrap_or(d);
            let mut y = n(0, f64::NAN);
            if (0.0..=99.0).contains(&y) && y.fract() == 0.0 {
                y += 1900.0;
            }
            Ok(JsValue::Num(make_time(
                y,
                n(1, 0.0),
                n(2, 1.0),
                n(3, 0.0),
                n(4, 0.0),
                n(5, 0.0),
                n(6, 0.0),
            )))
        });
        let f = self.native(utc);
        ctor.borrow_mut().set_prop("UTC", f, false);
        self.set_global("Date", JsValue::Object(ctor));

        fn date_ms(this: &JsValue) -> f64 {
            match this {
                JsValue::Object(o) => match o.borrow().kind {
                    ObjKind::Date(ms) => ms,
                    _ => f64::NAN,
                },
                _ => f64::NAN,
            }
        }
        let get_time: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::Num(date_ms(&this))));
        let f = self.native(get_time);
        date_proto
            .borrow_mut()
            .set_prop("getTime", f.clone(), false);
        date_proto.borrow_mut().set_prop("valueOf", f, false);
        let to_iso: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::str("Invalid Date"));
            }
            let (y, mo, d, h, m, s, millis, _) = super::value::civil_from_ms(ms);
            Ok(JsValue::str(format!(
                "{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z"
            )))
        });
        let f = self.native(to_iso);
        date_proto.borrow_mut().set_prop("toISOString", f, false);

        use super::value::civil_from_ms as civil;
        // Component getters (UTC math on the virtual clock — the engine has
        // no timezone surface, so local == UTC by design).
        // (name, index into the civil tuple); every local getter has a UTC
        // twin that reads the same field (the realm's zone is UTC).
        let getters: [(&str, &str, usize); 8] = [
            ("getFullYear", "getUTCFullYear", 0),
            ("getMonth", "getUTCMonth", 1), // 0-based per JS
            ("getDate", "getUTCDate", 2),
            ("getHours", "getUTCHours", 3),
            ("getMinutes", "getUTCMinutes", 4),
            ("getSeconds", "getUTCSeconds", 5),
            ("getMilliseconds", "getUTCMilliseconds", 6),
            ("getDay", "getUTCDay", 7),
        ];
        for (name, utc_name, idx) in getters {
            let g: NativeFn = Rc::new(move |_i, this, _a| {
                let ms = date_ms(&this);
                if !ms.is_finite() {
                    return Ok(JsValue::Num(f64::NAN));
                }
                let c = civil(ms);
                let raw = match idx {
                    0 => c.0,
                    1 => c.1 - 1, // JS months are 0-based
                    2 => c.2,
                    3 => c.3,
                    4 => c.4,
                    5 => c.5,
                    6 => c.6,
                    _ => c.7,
                };
                Ok(JsValue::Num(raw as f64))
            });
            let f = self.native(g.clone());
            date_proto.borrow_mut().set_prop(name, f, false);
            let f = self.native(g);
            date_proto.borrow_mut().set_prop(utc_name, f, false);
        }
        let get_year: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            Ok(JsValue::Num(if ms.is_finite() { (civil(ms).0 - 1900) as f64 } else { f64::NAN }))
        });
        let f = self.native(get_year);
        date_proto.borrow_mut().set_prop("getYear", f, false);
        let tz: NativeFn = Rc::new(|_i, _t, _a| Ok(JsValue::Num(0.0)));
        let f = self.native(tz);
        date_proto.borrow_mut().set_prop("getTimezoneOffset", f, false);

        // Setters: rebuild the time value from the civil fields with the
        // given ones replaced (trailing optional arguments cascade the way
        // the spec's `setHours(h, m, s, ms)` does). Each returns the new
        // time value and writes it into the Date.
        fn store(this: &JsValue, ms: f64) -> JsValue {
            let ms = time_clip(ms);
            if let JsValue::Object(o) = this {
                o.borrow_mut().kind = ObjKind::Date(ms);
            }
            JsValue::Num(ms)
        }
        let set_time: NativeFn = Rc::new(|interp, this, args| {
            let v = interp.number_arg(args.first(), f64::NAN)?;
            Ok(store(&this, v))
        });
        let f = self.native(set_time);
        date_proto.borrow_mut().set_prop("setTime", f, false);
        // (name, first field index it sets, how many fields may follow)
        let setters: [(&str, &str, usize, usize); 7] = [
            ("setFullYear", "setUTCFullYear", 0, 3),
            ("setMonth", "setUTCMonth", 1, 2),
            ("setDate", "setUTCDate", 2, 1),
            ("setHours", "setUTCHours", 3, 4),
            ("setMinutes", "setUTCMinutes", 4, 3),
            ("setSeconds", "setUTCSeconds", 5, 2),
            ("setMilliseconds", "setUTCMilliseconds", 6, 1),
        ];
        for (name, utc_name, first, count) in setters {
            let s: NativeFn = Rc::new(move |interp, this, args| {
                let ms = date_ms(&this);
                // An invalid date stays invalid except for setFullYear,
                // which starts from +0 (spec).
                let base = if ms.is_finite() {
                    ms
                } else if first == 0 {
                    0.0
                } else {
                    return Ok(store(&this, f64::NAN));
                };
                let c = civil(base);
                let mut fields: [f64; 7] = [
                    c.0 as f64,
                    (c.1 - 1) as f64,
                    c.2 as f64,
                    c.3 as f64,
                    c.4 as f64,
                    c.5 as f64,
                    c.6 as f64,
                ];
                if args.is_empty() {
                    return Ok(store(&this, f64::NAN));
                }
                for (i, a) in args.iter().take(count).enumerate() {
                    if let Some(slot) = fields.get_mut(first + i) {
                        *slot = interp.to_number_value(a)?;
                    }
                }
                let v = make_time(
                    fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
                );
                Ok(store(&this, v))
            });
            let f = self.native(s.clone());
            date_proto.borrow_mut().set_prop(name, f, false);
            let f = self.native(s);
            date_proto.borrow_mut().set_prop(utc_name, f, false);
        }

        // Formatters. `toString` / `toUTCString` / `toDateString` /
        // `toTimeString` render the conventional forms; the locale forms
        // use en-US shapes (the realm's locale).
        let to_string: NativeFn = Rc::new(|_i, this, _a| Ok(JsValue::str(format_date_string(date_ms(&this)))));
        let f = self.native(to_string);
        date_proto.borrow_mut().set_prop("toString", f, false);
        let to_utc: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::str("Invalid Date"));
            }
            let (y, mo, d, h, mi, s, _, dow) = civil(ms);
            let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
            let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            let dn = days.get(dow as usize).copied().unwrap_or("Thu");
            let mn = months.get((mo - 1).clamp(0, 11) as usize).copied().unwrap_or("Jan");
            Ok(JsValue::str(format!("{dn}, {d:02} {mn} {y:04} {h:02}:{mi:02}:{s:02} GMT")))
        });
        let f = self.native(to_utc);
        date_proto.borrow_mut().set_prop("toUTCString", f.clone(), false);
        date_proto.borrow_mut().set_prop("toGMTString", f, false);
        let to_date: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::str("Invalid Date"));
            }
            let full = format_date_string(ms);
            // "Thu Jan 01 1970" is the first 15 chars of the full form.
            Ok(JsValue::str(full.chars().take(15).collect::<String>()))
        });
        let f = self.native(to_date);
        date_proto.borrow_mut().set_prop("toDateString", f, false);
        let to_time: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::str("Invalid Date"));
            }
            let full = format_date_string(ms);
            Ok(JsValue::str(full.chars().skip(16).collect::<String>()))
        });
        let f = self.native(to_time);
        date_proto.borrow_mut().set_prop("toTimeString", f, false);
        let to_locale_date: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::str("Invalid Date"));
            }
            let (y, mo, d, ..) = civil(ms);
            Ok(JsValue::str(format!("{mo}/{d}/{y}")))
        });
        let f = self.native(to_locale_date);
        date_proto.borrow_mut().set_prop("toLocaleDateString", f, false);
        let to_locale_time: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::str("Invalid Date"));
            }
            let (_, _, _, h, mi, s, ..) = civil(ms);
            let (h12, ampm) = match h {
                0 => (12, "AM"),
                1..=11 => (h, "AM"),
                12 => (12, "PM"),
                _ => (h - 12, "PM"),
            };
            Ok(JsValue::str(format!("{h12}:{mi:02}:{s:02} {ampm}")))
        });
        let f = self.native(to_locale_time);
        date_proto.borrow_mut().set_prop("toLocaleTimeString", f, false);
        let to_locale: NativeFn = Rc::new(|_i, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::str("Invalid Date"));
            }
            let (y, mo, d, h, mi, s, ..) = civil(ms);
            let (h12, ampm) = match h {
                0 => (12, "AM"),
                1..=11 => (h, "AM"),
                12 => (12, "PM"),
                _ => (h - 12, "PM"),
            };
            Ok(JsValue::str(format!("{mo}/{d}/{y}, {h12}:{mi:02}:{s:02} {ampm}")))
        });
        let f = self.native(to_locale);
        date_proto.borrow_mut().set_prop("toLocaleString", f, false);
        // toJSON: the ISO string, or null for an invalid date (spec).
        let to_json: NativeFn = Rc::new(|interp, this, _a| {
            let ms = date_ms(&this);
            if !ms.is_finite() {
                return Ok(JsValue::Null);
            }
            let f = interp.get_property(&this, "toISOString")?;
            interp.call(f, this.clone(), &[])
        });
        let f = self.native(to_json);
        date_proto.borrow_mut().set_prop("toJSON", f, false);
        // Symbol.toPrimitive: "number" hint → time value, else the string.
        let to_prim: NativeFn = Rc::new(|_i, this, args| {
            let hint = args.first().map(|v| v.to_js_string()).unwrap_or_default();
            let ms = date_ms(&this);
            Ok(if hint == "number" {
                JsValue::Num(ms)
            } else {
                JsValue::str(format_date_string(ms))
            })
        });
        let f = self.native(to_prim);
        date_proto
            .borrow_mut()
            .set_prop(&symbol_key(SYM_TO_PRIMITIVE), f, false);
    }

    /// Promise.race — settles with the FIRST input to settle, in ITERATION
    /// ORDER for already-settled inputs: every input (promise or plain
    /// value) is processed uniformly through reactions/microtasks, so an
    /// already-fulfilled promise at index 0 beats a plain value at index 1
    /// (a plain value is treated as an already-resolved promise, per spec
    /// PromiseResolve + then-job ordering).
    fn install_promise_race(&mut self) {
        let Some(ctor) = self.global_object.borrow().get_prop("Promise") else {
            return;
        };
        let JsValue::Object(ctor) = ctor else { return };
        let race: NativeFn = Rc::new(|interp, _t, args| {
            let src = args.first().cloned().unwrap_or(JsValue::Undefined);
            let items = interp.iterate(&src)?;
            let result = interp.new_promise();
            for item in &items {
                match item {
                    JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::Promise(_)) => {
                        // Pass-through reactions: settled inputs enqueue a
                        // microtask NOW (queue order = iteration order);
                        // pending inputs settle the result when they settle.
                        interp.add_reactions(o, None, None, result.clone());
                    }
                    other => {
                        // Spec: a non-promise is wrapped by PromiseResolve
                        // into an already-resolved promise whose then-job
                        // queues like any other — NOT a synchronous win.
                        let wrapped = interp.new_promise();
                        interp.resolve_promise(&wrapped, other.clone(), true);
                        interp.add_reactions(&wrapped, None, None, result.clone());
                    }
                }
            }
            Ok(JsValue::Object(result))
        });
        let f = self.native(race);
        ctor.borrow_mut().set_prop("race", f, false);
    }

    /// Object.prototype.hasOwnProperty — own string keys + array indices.
    fn install_has_own_property(&mut self) {
        let hop: NativeFn = Rc::new(|interp, this, args| {
            let key = args
                .first()
                .map(|k| interp.to_property_key(k))
                .transpose()?
                .unwrap_or_default();
            let JsValue::Object(o) = &this else {
                // Primitive receivers: strings own their indices and `length`.
                if let JsValue::Str(s) = &this {
                    let n = s.chars().count();
                    return Ok(JsValue::Bool(
                        key == "length" || key.parse::<usize>().map(|i| i < n).unwrap_or(false),
                    ));
                }
                return Ok(JsValue::Bool(false));
            };
            let o = o.clone();
            Ok(JsValue::Bool(interp.has_own_property(&o, &key)?))
        });
        let f = self.native(hop);
        self.object_proto
            .borrow_mut()
            .set_prop("hasOwnProperty", f, false);
    }

    /// String.prototype match / at, and replace with capture-group
    /// substitutions ($1..$9, $&, $$) for both string and regex patterns.
    fn install_string_extras(&mut self) {
        let match_fn: NativeFn = Rc::new(|interp, this, args| {
            let input = this.to_js_string();
            let (source, flags) = match args.first() {
                Some(JsValue::Object(o)) if matches!(o.borrow().kind, ObjKind::RegExp { .. }) => {
                    match &o.borrow().kind {
                        ObjKind::RegExp { source, flags } => (source.clone(), flags.clone()),
                        _ => (String::new(), String::new()),
                    }
                }
                // Any non-RegExp argument (object included) is ToString'd and
                // compiled as a literal pattern, per spec coercion (invokes
                // the object's own toString via ToPrimitive).
                Some(v) => {
                    (regex_escape(&interp.to_string_value(v)?), String::new())
                }
                None => return Ok(JsValue::Null),
            };
            let Some(re) = super::regex::compile(&source, &flags) else {
                return Ok(JsValue::Null);
            };
            if flags.contains('g') {
                // Global: array of every match (no capture groups).
                let mut out = Vec::new();
                let chars: Vec<char> = input.chars().collect();
                let mut from = 0usize;
                let mut guard = 0usize;
                while from <= chars.len() && guard < 100_000 {
                    guard += 1;
                    let hay: String = chars.get(from..).unwrap_or(&[]).iter().collect();
                    match re.find(&hay) {
                        Some((s, e)) => {
                            let m: String = hay.chars().skip(s).take(e.saturating_sub(s)).collect();
                            out.push(JsValue::str(m));
                            from += e.max(s + 1);
                        }
                        None => break,
                    }
                }
                if out.is_empty() {
                    return Ok(JsValue::Null);
                }
                return Ok(interp.new_array(out));
            }
            match re.find_captures(&input) {
                Some(caps) => {
                    let mut items: Vec<JsValue> = Vec::new();
                    for c in &caps.groups {
                        items.push(match c {
                            Some(s) => JsValue::str(s.clone()),
                            None => JsValue::Undefined,
                        });
                    }
                    let arr = interp.new_array(items);
                    if let JsValue::Object(a) = &arr {
                        a.borrow_mut()
                            .set_prop("index", JsValue::Num(caps.start as f64), true);
                    }
                    Ok(arr)
                }
                None => Ok(JsValue::Null),
            }
        });
        let f = self.native(match_fn);
        self.string_proto.borrow_mut().set_prop("match", f, false);

        let at: NativeFn = Rc::new(|interp, this, args| {
            let s: Vec<char> = this.to_js_string().chars().collect();
            let len = s.len() as i64;
            let mut idx = interp.number_arg(args.first(), 0.0)? as i64;
            if idx < 0 {
                idx += len;
            }
            if idx < 0 || idx >= len {
                return Ok(JsValue::Undefined);
            }
            Ok(s.get(idx as usize)
                .map(|c| JsValue::str(c.to_string()))
                .unwrap_or(JsValue::Undefined))
        });
        let f = self.native(at);
        self.string_proto.borrow_mut().set_prop("at", f, false);

        // replace/replaceAll with $n capture substitution (regex patterns)
        // and FUNCTION replacers (match, p1..pn, offset, string) — OVERRIDES
        // the plain-string versions installed earlier.
        fn apply_repl(interp: &mut Interp, repl: &JsValue, caps: &Captures, input: &str) -> String {
            // `caps.start` is absolute here (callers add the consumed
            // prefix), so `$\`` / `$'` can see the whole input.
            let named_groups = caps.names.iter().any(|n| n.is_some());
            if let JsValue::Object(o) = repl {
                if o.borrow().is_callable() {
                    // fn(match, p1..pn, offset, string)
                    let mut args: Vec<JsValue> = Vec::new();
                    for g in &caps.groups {
                        args.push(match g {
                            Some(s) => JsValue::str(s.clone()),
                            None => JsValue::Undefined,
                        });
                    }
                    args.push(JsValue::Num(caps.start as f64));
                    args.push(JsValue::str(input.to_string()));
                    if named_groups {
                        let groups = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                        for (i, n) in caps.names.iter().enumerate() {
                            if let Some(n) = n {
                                let v = match caps.groups.get(i) {
                                    Some(Some(s)) => JsValue::str(s.clone()),
                                    _ => JsValue::Undefined,
                                };
                                groups.borrow_mut().set_prop(n, v, true);
                            }
                        }
                        args.push(JsValue::Object(groups));
                    }
                    return match interp.call(repl.clone(), JsValue::Undefined, &args) {
                        Ok(v) => v.to_js_string(),
                        Err(_) => String::new(),
                    };
                }
            }
            expand_template(&repl.to_js_string(), caps, input)
        }
        let make_replace = |all_default: bool| -> NativeFn {
            Rc::new(move |interp, this: JsValue, args: &[JsValue]| {
                let input = this.to_js_string();
                let repl = args.get(1).cloned().unwrap_or(JsValue::Undefined);
                match args.first() {
                    Some(JsValue::Object(o))
                        if matches!(o.borrow().kind, ObjKind::RegExp { .. }) =>
                    {
                        let (source, flags) = match &o.borrow().kind {
                            ObjKind::RegExp { source, flags } => (source.clone(), flags.clone()),
                            _ => (String::new(), String::new()),
                        };
                        let Some(re) = super::regex::compile(&source, &flags) else {
                            return Ok(JsValue::str(input));
                        };
                        let global = all_default || flags.contains('g');
                        let mut out = String::new();
                        let mut rest = input.clone();
                        let mut consumed = 0usize; // chars consumed, for real offsets
                        let mut guard = 0usize;
                        loop {
                            guard += 1;
                            if guard > 100_000 {
                                break;
                            }
                            match re.find_captures(&rest) {
                                Some(mut caps) => {
                                    let before: String = rest.chars().take(caps.start).collect();
                                    out.push_str(&before);
                                    let local_start = caps.start;
                                    let local_end = caps.end;
                                    caps.start += consumed; // absolute offset for fn replacers
                                    caps.end += consumed;
                                    out.push_str(&apply_repl(interp, &repl, &caps, &input));
                                    let after: String = rest.chars().skip(local_end).collect();
                                    if !global {
                                        out.push_str(&after);
                                        return Ok(JsValue::str(out));
                                    }
                                    if local_end == local_start {
                                        // Empty match: emit one char and advance.
                                        if let Some(c) = after.chars().next() {
                                            out.push(c);
                                            rest = after.chars().skip(1).collect();
                                            consumed += local_start + 1;
                                        } else {
                                            return Ok(JsValue::str(out));
                                        }
                                    } else {
                                        consumed += local_end;
                                        rest = after;
                                    }
                                    if rest.is_empty() {
                                        return Ok(JsValue::str(out));
                                    }
                                }
                                None => {
                                    out.push_str(&rest);
                                    return Ok(JsValue::str(out));
                                }
                            }
                        }
                        Ok(JsValue::str(out))
                    }
                    Some(pat) => {
                        // Plain-string replace: first occurrence (replace) or
                        // every occurrence (replaceAll); $$ / $& and function
                        // replacers honored.
                        let pat = pat.to_js_string();
                        if pat.is_empty() {
                            return Ok(JsValue::str(input));
                        }
                        let mut out = String::new();
                        let mut search = 0usize; // byte offset
                        loop {
                            match input.get(search..).and_then(|t| t.find(&pat)) {
                                Some(rel) => {
                                    let pos = search + rel;
                                    out.push_str(input.get(search..pos).unwrap_or(""));
                                    let offset_chars =
                                        input.get(..pos).map(|p| p.chars().count()).unwrap_or(0);
                                    let caps = Captures {
                                        start: offset_chars,
                                        end: offset_chars + pat.chars().count(),
                                        groups: vec![Some(pat.clone())],
                                        names: vec![None],
                                    };
                                    out.push_str(&apply_repl(interp, &repl, &caps, &input));
                                    search = pos + pat.len();
                                    if !all_default {
                                        out.push_str(input.get(search..).unwrap_or(""));
                                        return Ok(JsValue::str(out));
                                    }
                                }
                                None => {
                                    out.push_str(input.get(search..).unwrap_or(""));
                                    return Ok(JsValue::str(out));
                                }
                            }
                        }
                    }
                    None => Ok(JsValue::str(input)),
                }
            })
        };
        let f = self.native(make_replace(false));
        self.string_proto.borrow_mut().set_prop("replace", f, false);
        let f = self.native(make_replace(true));
        self.string_proto
            .borrow_mut()
            .set_prop("replaceAll", f, false);
    }

    /// Global isFinite + Number.isFinite (strict, no coercion for the static).
    fn install_is_finite(&mut self) {
        let global_is_finite: NativeFn = Rc::new(|interp, _t, args| {
            let n = interp.number_arg(args.first(), f64::NAN)?;
            Ok(JsValue::Bool(n.is_finite()))
        });
        let f = self.native(global_is_finite);
        self.set_global("isFinite", f);

        if let Some(JsValue::Object(number)) = self.global_object.borrow().get_prop("Number") {
            let strict_is_finite: NativeFn = Rc::new(|_i, _t, args| {
                Ok(JsValue::Bool(matches!(
                    args.first(),
                    Some(JsValue::Num(n)) if n.is_finite()
                )))
            });
            let f = JsValue::Object(JsObject::new(
                ObjKind::Native(strict_is_finite),
                Some(self.function_proto.clone()),
            ));
            number.borrow_mut().set_prop("isFinite", f, false);
        }
    }
}

pub use super::regex::Captures;

/// ToNumber for Date constructor arguments (ToPrimitive-free: the spec
/// coerces each argument with ToNumber, which for objects calls valueOf).
fn interp_num(v: &JsValue) -> f64 {
    v.to_number()
}

/// TimeClip: NaN for non-finite or out-of-range time values, else the
/// integer value.
fn time_clip(t: f64) -> f64 {
    if !t.is_finite() || t.abs() > 8.64e15 {
        f64::NAN
    } else {
        t.trunc() + 0.0
    }
}

/// MakeDate(MakeDay(y, m, d), MakeTime(h, mi, s, ms)) with month overflow
/// (`new Date(2024, 12, 1)` is January 2025) and every other field
/// carried, then TimeClip.
fn make_time(y: f64, m: f64, d: f64, h: f64, mi: f64, s: f64, ms: f64) -> f64 {
    for v in [y, m, d, h, mi, s, ms] {
        if !v.is_finite() {
            return f64::NAN;
        }
    }
    let (y, m) = (y.trunc(), m.trunc());
    let ym = y + (m / 12.0).floor();
    let mn = m.rem_euclid(12.0);
    if ym.abs() > 400_000.0 {
        return f64::NAN;
    }
    let days = days_from_civil(ym as i64, mn as i64 + 1, 1) as f64 + d.trunc() - 1.0;
    let t = days * 86_400_000.0
        + h.trunc() * 3_600_000.0
        + mi.trunc() * 60_000.0
        + s.trunc() * 1000.0
        + ms.trunc();
    time_clip(t)
}

/// Date.parse for the forms pages actually produce: the ISO 8601 date-time
/// format (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM[:SS[.mmm]]` with `Z` or a
/// `±HH:MM` offset; a date-only string is UTC, a date-time without a zone
/// is local, which is UTC here), the RFC 2822 / `toString` forms
/// (`Thu, 01 Jan 1970 00:00:00 GMT`, `Thu Jan 01 1970 00:00:00 GMT+0000`,
/// `Jan 1, 1970`, `1 Jan 1970 00:00:00 +0100`), and `MM/DD/YYYY`. Anything
/// else is NaN (an Invalid Date), as in every engine.
fn parse_date(s: &str) -> f64 {
    let s = s.trim();
    if s.is_empty() {
        return f64::NAN;
    }
    if let Some(v) = parse_iso_date(s) {
        return v;
    }
    parse_loose_date(s).unwrap_or(f64::NAN)
}

fn parse_iso_date(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let digits = |from: usize, n: usize| -> Option<i64> {
        let part = s.get(from..from + n)?;
        if part.len() != n || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse::<i64>().ok()
    };
    // Year: YYYY, or ±YYYYYY.
    let (year, mut i) = match b.first() {
        Some(b'+') | Some(b'-') => {
            let y = digits(1, 6)?;
            (if b.first() == Some(&b'-') { -y } else { y }, 7)
        }
        _ => (digits(0, 4)?, 4),
    };
    let mut month = 1;
    let mut day = 1;
    let (mut h, mut mi, mut sec, mut ms) = (0i64, 0i64, 0i64, 0i64);
    let mut date_only = true;
    if b.get(i) == Some(&b'-') {
        month = digits(i + 1, 2)?;
        i += 3;
        if b.get(i) == Some(&b'-') {
            day = digits(i + 1, 2)?;
            i += 3;
        }
    }
    let mut offset_ms = 0i64;
    if matches!(b.get(i), Some(b'T') | Some(b't') | Some(b' ')) {
        date_only = false;
        h = digits(i + 1, 2)?;
        if b.get(i + 3) != Some(&b':') {
            return None;
        }
        mi = digits(i + 4, 2)?;
        i += 6;
        if b.get(i) == Some(&b':') {
            sec = digits(i + 1, 2)?;
            i += 3;
            if matches!(b.get(i), Some(b'.') | Some(b',')) {
                // Any number of fraction digits; the first three are ms.
                let start = i + 1;
                let mut end = start;
                while b.get(end).is_some_and(|c| c.is_ascii_digit()) {
                    end += 1;
                }
                if end == start {
                    return None;
                }
                let frac = s.get(start..end)?;
                let mut f3: String = frac.chars().take(3).collect();
                while f3.len() < 3 {
                    f3.push('0');
                }
                ms = f3.parse::<i64>().ok()?;
                i = end;
            }
        }
        match b.get(i) {
            Some(b'Z') | Some(b'z') => {
                i += 1;
            }
            Some(b'+') | Some(b'-') => {
                let sign = if b.get(i) == Some(&b'-') { -1 } else { 1 };
                let oh = digits(i + 1, 2)?;
                let om = if b.get(i + 3) == Some(&b':') {
                    i += 1;
                    digits(i + 3, 2)?
                } else {
                    digits(i + 3, 2)?
                };
                offset_ms = sign * (oh * 60 + om) * 60_000;
                i += 5;
            }
            None => {}
            _ => return None,
        }
    }
    if i != b.len() {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 24 || mi > 59 || sec > 59 {
        return None;
    }
    let _ = date_only;
    let days = days_from_civil(year, month, day);
    let t = days as f64 * 86_400_000.0
        + (h * 3_600_000 + mi * 60_000 + sec * 1000 + ms) as f64
        - offset_ms as f64;
    Some(time_clip(t))
}

/// The textual forms: tokens of month names, numbers, `HH:MM[:SS]`, an
/// optional `GMT`/`UTC`/`Z`/`±HHMM` zone, weekday names ignored.
fn parse_loose_date(s: &str) -> Option<f64> {
    let months = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let mut year: Option<i64> = None;
    let mut month: Option<i64> = None;
    let mut day: Option<i64> = None;
    let (mut h, mut mi, mut sec) = (0i64, 0i64, 0i64);
    let mut offset_ms = 0i64;
    let mut pm: Option<bool> = None;
    let cleaned: String = s
        .chars()
        .map(|c| if c == ',' || c == '(' || c == ')' { ' ' } else { c })
        .collect();
    for tok in cleaned.split_whitespace() {
        let lower = tok.to_ascii_lowercase();
        if let Some(m) = months.iter().position(|m| lower.starts_with(m)) {
            month = Some(m as i64 + 1);
            continue;
        }
        if lower == "am" || lower == "pm" {
            pm = Some(lower == "pm");
            continue;
        }
        if lower == "gmt" || lower == "utc" || lower == "z" || lower == "ut" {
            continue;
        }
        if lower.starts_with("gmt") || lower.starts_with("utc") || lower.starts_with('+') || (lower.starts_with('-') && lower.len() == 5) {
            let z = lower.trim_start_matches("gmt").trim_start_matches("utc");
            if z.is_empty() {
                continue;
            }
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits: String = z.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() == 4 {
                let oh = digits.get(..2)?.parse::<i64>().ok()?;
                let om = digits.get(2..)?.parse::<i64>().ok()?;
                offset_ms = sign * (oh * 60 + om) * 60_000;
                continue;
            }
            return None;
        }
        if tok.contains(':') {
            let mut parts = tok.split(':');
            h = parts.next()?.parse().ok()?;
            mi = parts.next()?.parse().ok()?;
            if let Some(sp) = parts.next() {
                sec = sp.split('.').next()?.parse().ok()?;
            }
            continue;
        }
        if tok.contains('/') {
            // MM/DD/YYYY (or M/D/YY).
            let mut parts = tok.split('/');
            month = Some(parts.next()?.parse().ok()?);
            day = Some(parts.next()?.parse().ok()?);
            let mut y: i64 = parts.next()?.parse().ok()?;
            if (0..=49).contains(&y) {
                y += 2000;
            } else if (50..=99).contains(&y) {
                y += 1900;
            }
            year = Some(y);
            continue;
        }
        if tok.bytes().all(|c| c.is_ascii_digit()) {
            let n: i64 = tok.parse().ok()?;
            if tok.len() >= 3 || n > 31 {
                year = Some(n);
            } else if day.is_none() {
                day = Some(n);
            } else if year.is_none() {
                year = Some(if n < 50 { n + 2000 } else { n + 1900 });
            }
            continue;
        }
        if lower.chars().all(|c| c.is_ascii_alphabetic()) {
            // A weekday name or other word: ignored, as engines do.
            continue;
        }
        return None;
    }
    let (year, month) = (year?, month?);
    let day = day.unwrap_or(1);
    if let Some(is_pm) = pm {
        if is_pm && h < 12 {
            h += 12;
        } else if !is_pm && h == 12 {
            h = 0;
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 24 || mi > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let t = days as f64 * 86_400_000.0 + (h * 3_600_000 + mi * 60_000 + sec * 1000) as f64 - offset_ms as f64;
    Some(time_clip(t))
}

/// Expand a replacement template: `$1`..`$99` capture refs, `$<name>`,
/// `$&` (the match), `` $` `` (the text before it), `$'` (the text after
/// it) and `$$`. `caps.start`/`caps.end` are absolute char offsets into
/// `input`.
fn expand_template(template: &str, caps: &Captures, input: &str) -> String {
    let mut out = String::new();
    let has_names = caps.names.iter().any(|n| n.is_some());
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars.get(i).copied().unwrap_or('\0');
        if c == '$' {
            match chars.get(i + 1).copied() {
                Some('$') => {
                    out.push('$');
                    i += 2;
                }
                Some('&') => {
                    if let Some(Some(whole)) = caps.groups.first() {
                        out.push_str(whole);
                    }
                    i += 2;
                }
                Some(d) if d.is_ascii_digit() && d != '0' => {
                    // `$1`..`$99`: two digits when that group exists.
                    let mut n = (d as u8 - b'0') as usize;
                    let mut used = 2;
                    if let Some(d2) = chars.get(i + 2).and_then(|c| c.to_digit(10)) {
                        let two = n * 10 + d2 as usize;
                        if two < caps.groups.len() {
                            n = two;
                            used = 3;
                        }
                    }
                    if let Some(Some(g)) = caps.groups.get(n) {
                        out.push_str(g);
                    }
                    i += used;
                }
                Some('<') if has_names => {
                    // `$<name>`: a named group (an unknown name expands to
                    // the empty string; without ANY named groups in the
                    // pattern the `$<` stays literal).
                    let close = chars.get(i + 2..).and_then(|r| r.iter().position(|c| *c == '>'));
                    match close {
                        Some(off) => {
                            let name: String = chars.get(i + 2..i + 2 + off).unwrap_or(&[]).iter().collect();
                            if let Some(idx) = caps.names.iter().position(|n| n.as_deref() == Some(name.as_str())) {
                                if let Some(Some(g)) = caps.groups.get(idx) {
                                    out.push_str(g);
                                }
                            }
                            i += 3 + off;
                        }
                        None => {
                            out.push('$');
                            i += 1;
                        }
                    }
                }
                Some('`') => {
                    // `` $` ``: the input before the match.
                    out.extend(input.chars().take(caps.start));
                    i += 2;
                }
                Some('\'') => {
                    // `$'`: the input after the match.
                    out.extend(input.chars().skip(caps.end));
                    i += 2;
                }
                _ => {
                    out.push('$');
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Escape regex metacharacters so a plain string can be compiled literally.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\^$.|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
