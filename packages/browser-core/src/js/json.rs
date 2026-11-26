//! json — JSON.stringify / JSON.parse over the engine's value model.
//!
//! Panic-free: a cyclic structure is a thrown TypeError (as the spec
//! requires) and a depth cap backs that up; malformed JSON parses to a
//! thrown SyntaxError value, never a panic.

use std::rc::Rc;

use super::interp::Interp;
use super::value::{JsObject, JsValue, ObjKind, ObjRef, format_number};

const MAX_DEPTH: usize = 64;

/// JSON.stringify (no replacer/indent in the fast path; indent handled by
/// the caller when provided). Returns `Ok(None)` for undefined/function/
/// symbol roots, like the spec, and `Err` for a thrown getter, `toJSON`,
/// Proxy trap or a cyclic value — the script sees the exception.
pub fn stringify(interp: &mut Interp, v: &JsValue) -> Result<Option<String>, JsValue> {
    let mut out = String::new();
    let mut stack: Vec<ObjRef> = Vec::new();
    match write_value(interp, v, &mut out, &mut stack)? {
        true => Ok(Some(out)),
        false => Ok(None),
    }
}

/// Write one value; `Ok(false)` means "omit this value" (undefined,
/// functions, symbols), `Err` a thrown value from a Proxy trap or getter.
/// `stack` is the chain of objects being serialised (SerializeJSONObject's
/// cycle check).
fn write_value(
    interp: &mut Interp,
    v: &JsValue,
    out: &mut String,
    stack: &mut Vec<ObjRef>,
) -> Result<bool, JsValue> {
    let depth = stack.len();
    if depth > MAX_DEPTH {
        return Err(Interp::throw("RangeError: JSON.stringify nesting too deep"));
    }
    Ok(match v {
        JsValue::Undefined | JsValue::Symbol(_) => false,
        JsValue::Null => {
            out.push_str("null");
            true
        }
        JsValue::Bool(b) => {
            out.push_str(if *b { "true" } else { "false" });
            true
        }
        JsValue::Num(n) => {
            if n.is_finite() {
                out.push_str(&format_number(*n));
            } else {
                out.push_str("null");
            }
            true
        }
        JsValue::Str(s) => {
            write_json_string(s, out);
            true
        }
        JsValue::Object(o) => {
            if o.borrow().is_callable() {
                return Ok(false);
            }
            // `toJSON` (Date, and objects that define one) decides what is
            // serialised.
            let to_json = interp.get_property(v, "toJSON")?;
            if let JsValue::Object(f) = &to_json {
                if f.borrow().is_callable() {
                    let replaced = interp.call(to_json.clone(), v.clone(), &[])?;
                    if !matches!(&replaced, JsValue::Object(r) if Rc::ptr_eq(r, o)) {
                        return write_value(interp, &replaced, out, stack);
                    }
                }
            }
            // Primitive wrappers serialise as their primitive.
            let prim = match &o.borrow().kind {
                ObjKind::Primitive(p) => Some(p.as_ref().clone()),
                _ => None,
            };
            if let Some(p) = prim {
                return write_value(interp, &p, out, stack);
            }
            // A cycle is a TypeError, never silently altered JSON.
            if stack.iter().any(|s| Rc::ptr_eq(s, o)) {
                return Err(Interp::throw(
                    "TypeError: Converting circular structure to JSON",
                ));
            }
            stack.push(o.clone());
            let result = write_object_body(interp, v, o, out, stack);
            stack.pop();
            result?
        }
    })
}

/// SerializeJSONArray / SerializeJSONObject for `o` (already on `stack`):
/// every element and property is read through [[Get]], so array getters,
/// Proxy traps (Vue's reactive state) and accessors all run.
fn write_object_body(
    interp: &mut Interp,
    v: &JsValue,
    o: &ObjRef,
    out: &mut String,
    stack: &mut Vec<ObjRef>,
) -> Result<bool, JsValue> {
    let is_array = {
        let b = o.borrow();
        match &b.kind {
            ObjKind::Array => true,
            ObjKind::Proxy { target, .. } => matches!(target.borrow().kind, ObjKind::Array),
            _ => false,
        }
    };
    if is_array {
        let len = interp.get_property(v, "length")?.to_number();
        let len = if len.is_finite() && len > 0.0 { len as usize } else { 0 };
        out.push('[');
        for i in 0..len {
            if i > 0 {
                out.push(',');
            }
            let e = interp.get_property(v, &i.to_string())?;
            if !write_value(interp, &e, out, stack)? {
                out.push_str("null");
            }
        }
        out.push(']');
        return Ok(true);
    }
    let keys = interp.enumerable_own_string_keys(o)?;
    out.push('{');
    let mut first = true;
    for k in keys {
        let val = interp.get_property(v, &k)?;
        let mut tmp = String::new();
        if write_value(interp, &val, &mut tmp, stack)? {
            if !first {
                out.push(',');
            }
            first = false;
            write_json_string(&k, out);
            out.push(':');
            out.push_str(&tmp);
        }
    }
    out.push('}');
    Ok(true)
}

pub(crate) fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// JSON.parse. Returns the parsed value or a thrown SyntaxError value.
pub fn parse(interp: &mut Interp, src: &str) -> Result<JsValue, JsValue> {
    let mut p = JsonParser {
        chars: src.chars().collect(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.value(interp, 0)?;
    p.skip_ws();
    if p.pos < p.chars.len() {
        return Err(Interp::throw("SyntaxError: unexpected trailing JSON"));
    }
    Ok(v)
}

struct JsonParser {
    chars: Vec<char>,
    pos: usize,
}

impl JsonParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn skip_ws(&mut self) {
        while matches!(
            self.peek(),
            Some(' ') | Some('\t') | Some('\n') | Some('\r')
        ) {
            self.pos += 1;
        }
    }
    fn eat(&mut self, s: &str) -> bool {
        let end = self.pos + s.chars().count();
        if end <= self.chars.len() && self.chars[self.pos..end].iter().collect::<String>() == s {
            self.pos = end;
            true
        } else {
            false
        }
    }

    fn value(&mut self, interp: &mut Interp, depth: usize) -> Result<JsValue, JsValue> {
        if depth > MAX_DEPTH {
            return Err(Interp::throw("SyntaxError: JSON nesting too deep"));
        }
        self.skip_ws();
        match self.peek() {
            Some('n') if self.eat("null") => Ok(JsValue::Null),
            Some('t') if self.eat("true") => Ok(JsValue::Bool(true)),
            Some('f') if self.eat("false") => Ok(JsValue::Bool(false)),
            Some('"') => self.string().map(JsValue::str),
            Some('[') => {
                self.bump();
                let mut elems = Vec::new();
                self.skip_ws();
                if self.peek() == Some(']') {
                    self.bump();
                } else {
                    loop {
                        elems.push(self.value(interp, depth + 1)?);
                        self.skip_ws();
                        match self.bump() {
                            Some(',') => continue,
                            Some(']') => break,
                            _ => return Err(Interp::throw("SyntaxError: bad JSON array")),
                        }
                    }
                }
                Ok(interp.new_array(elems))
            }
            Some('{') => {
                self.bump();
                let obj = JsObject::new(ObjKind::Plain, Some(interp.object_proto.clone()));
                self.skip_ws();
                if self.peek() == Some('}') {
                    self.bump();
                } else {
                    loop {
                        self.skip_ws();
                        let k = self.string()?;
                        self.skip_ws();
                        if self.bump() != Some(':') {
                            return Err(Interp::throw("SyntaxError: bad JSON object"));
                        }
                        let v = self.value(interp, depth + 1)?;
                        obj.borrow_mut().set_prop(&k, v, true);
                        self.skip_ws();
                        match self.bump() {
                            Some(',') => continue,
                            Some('}') => break,
                            _ => return Err(Interp::throw("SyntaxError: bad JSON object")),
                        }
                    }
                }
                Ok(JsValue::Object(obj))
            }
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            _ => Err(Interp::throw("SyntaxError: unexpected JSON token")),
        }
    }

    fn string(&mut self) -> Result<String, JsValue> {
        if self.bump() != Some('"') {
            return Err(Interp::throw("SyntaxError: expected JSON string"));
        }
        let mut s = String::new();
        loop {
            match self.bump() {
                None => return Err(Interp::throw("SyntaxError: unterminated JSON string")),
                Some('"') => return Ok(s),
                Some('\\') => match self.bump() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('/') => s.push('/'),
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('r') => s.push('\r'),
                    Some('b') => s.push('\u{8}'),
                    Some('f') => s.push('\u{c}'),
                    Some('u') => {
                        let mut v = 0u32;
                        for _ in 0..4 {
                            let d = self.bump().and_then(|c| c.to_digit(16));
                            match d {
                                Some(d) => v = v * 16 + d,
                                None => return Err(Interp::throw("SyntaxError: bad \\u escape")),
                            }
                        }
                        s.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                    }
                    _ => return Err(Interp::throw("SyntaxError: bad JSON escape")),
                },
                Some(c) => s.push(c),
            }
        }
    }

    fn number(&mut self) -> Result<JsValue, JsValue> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
        }
        if self.peek() == Some('.') {
            self.bump();
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.bump();
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.bump();
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
        }
        let text: String = self
            .chars
            .get(start..self.pos)
            .map(|s| s.iter().collect())
            .unwrap_or_default();
        text.parse::<f64>()
            .map(JsValue::Num)
            .map_err(|_| Interp::throw("SyntaxError: bad JSON number"))
    }
}
