//! A compact, non-self-describing binary serde codec (a small postcard-style
//! format) for precompiled wasm modules.
//!
//! The vendored tinywasm types derive `ferrite_app::serde::{Serialize,
//! Deserialize}`. Encoding a validated module as JSON is ~7.6 MB; this codec
//! brings the same graph to ~2 MB so the precompiled quickjs module embeds in
//! the app source without blowing the source budget. The format is
//! non-self-describing: encoder and decoder must agree on the type, which they
//! do because both sides are this crate.
//!
//! Integer encoding: unsigned LEB128 varints; signed values zig-zag first.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{self, Display};

use ferrite_app::serde::de::{
    self, DeserializeOwned, DeserializeSeed, IntoDeserializer, SeqAccess, Visitor,
};
use ferrite_app::serde::ser::{self, Serialize};

#[derive(Debug)]
pub struct CodecError(String);

impl Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CodecError {}
impl ser::Error for CodecError {
    fn custom<T: Display>(msg: T) -> Self {
        CodecError(msg.to_string())
    }
}
impl de::Error for CodecError {
    fn custom<T: Display>(msg: T) -> Self {
        CodecError(msg.to_string())
    }
}

type Result<T> = core::result::Result<T, CodecError>;

/// Most elements one `from_bytes` call may decode from sequences and maps
/// without consuming a byte of input (`()`, unit structs, skipped fields).
/// Elements that consume input are bounded by the input length; this bounds
/// the rest, whose count a hostile input can declare in a few bytes.
const MAX_ZERO_BYTE_ELEMENTS: usize = 65_536;

fn err<T>(m: &str) -> Result<T> {
    Err(CodecError(m.to_string()))
}

pub fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut ser = Encoder { out: Vec::new() };
    value.serialize(&mut ser)?;
    Ok(ser.out)
}

pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut de = Decoder {
        input: bytes,
        pos: 0,
        zero_byte_elements: 0,
    };
    T::deserialize(&mut de)
}

fn write_uvarint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    fn u(&mut self, v: u64) {
        write_uvarint(&mut self.out, v);
    }
    fn i(&mut self, v: i64) {
        write_uvarint(&mut self.out, zigzag(v));
    }
}

impl ser::Serializer for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.out.push(v as u8);
        Ok(())
    }
    fn serialize_i8(self, v: i8) -> Result<()> {
        // postcard stores i8 as a single raw byte (not zig-zag varint).
        self.out.push(v as u8);
        Ok(())
    }
    fn serialize_i16(self, v: i16) -> Result<()> {
        self.i(v as i64);
        Ok(())
    }
    fn serialize_i32(self, v: i32) -> Result<()> {
        self.i(v as i64);
        Ok(())
    }
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.i(v);
        Ok(())
    }
    fn serialize_u8(self, v: u8) -> Result<()> {
        self.out.push(v);
        Ok(())
    }
    fn serialize_u16(self, v: u16) -> Result<()> {
        self.u(v as u64);
        Ok(())
    }
    fn serialize_u32(self, v: u32) -> Result<()> {
        self.u(v as u64);
        Ok(())
    }
    fn serialize_u64(self, v: u64) -> Result<()> {
        self.u(v);
        Ok(())
    }
    fn serialize_f32(self, v: f32) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_f64(self, v: f64) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_char(self, v: char) -> Result<()> {
        self.u(v as u64);
        Ok(())
    }
    fn serialize_str(self, v: &str) -> Result<()> {
        self.u(v.len() as u64);
        self.out.extend_from_slice(v.as_bytes());
        Ok(())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.u(v.len() as u64);
        self.out.extend_from_slice(v);
        Ok(())
    }
    fn serialize_none(self) -> Result<()> {
        self.out.push(0);
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<()> {
        self.out.push(1);
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
    ) -> Result<()> {
        self.u(idx as u64);
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<()> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()> {
        self.u(idx as u64);
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        let len = len.ok_or_else(|| CodecError("seq needs a known length".to_string()))?;
        self.u(len as u64);
        Ok(self)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Ok(self)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.u(idx as u64);
        Ok(self)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        let len = len.ok_or_else(|| CodecError("map needs a known length".to_string()))?;
        self.u(len as u64);
        Ok(self)
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.u(idx as u64);
        Ok(self)
    }
}

// The four sequence-like serializer traits share one body; written out
// per trait (the code gate refuses app-defined macros).
impl ser::SerializeSeq for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeTuple for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeTupleStruct for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeTupleVariant for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeMap for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        key.serialize(&mut **self)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeStruct for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeStructVariant for &mut Encoder {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

struct Decoder<'de> {
    input: &'de [u8],
    pos: usize,
    zero_byte_elements: usize,
}

impl<'de> Decoder<'de> {
    fn take(&mut self, n: usize) -> Result<&'de [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.input.len())
            .ok_or_else(|| CodecError("unexpected end of input".to_string()))?;
        let s = &self.input[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn uvarint(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let b = self.byte()?;
            if shift == 63 && b > 1 {
                return err(if b & 0x80 != 0 {
                    "varint too long"
                } else {
                    "varint overflow"
                });
            }
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }
    // The count is not compared with the remaining input: elements such as
    // `()` encode to zero bytes, so a valid count can exceed the input.
    fn ulen(&mut self) -> Result<usize> {
        usize::try_from(self.uvarint()?).map_err(|_| CodecError("length overflow".to_string()))
    }
    fn ivarint(&mut self) -> Result<i64> {
        Ok(unzigzag(self.uvarint()?))
    }
}

impl<'de> de::Deserializer<'de> for &mut Decoder<'de> {
    type Error = CodecError;

    fn deserialize_any<V: Visitor<'de>>(self, _v: V) -> Result<V::Value> {
        err("non-self-describing format: deserialize_any is unsupported")
    }

    fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_bool(self.byte()? != 0)
    }
    fn deserialize_i8<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_i8(self.byte()? as i8)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_i16(self.ivarint()? as i16)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_i32(self.ivarint()? as i32)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_i64(self.ivarint()?)
    }
    fn deserialize_u8<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_u8(self.byte()?)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_u16(self.uvarint()? as u16)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_u32(self.uvarint()? as u32)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_u64(self.uvarint()?)
    }
    fn deserialize_f32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let b = self.take(4)?;
        v.visit_f32(f32::from_le_bytes(b.try_into().unwrap()))
    }
    fn deserialize_f64<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let b = self.take(8)?;
        v.visit_f64(f64::from_le_bytes(b.try_into().unwrap()))
    }
    fn deserialize_char<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let c = char::from_u32(self.uvarint()? as u32)
            .ok_or_else(|| CodecError("bad char".to_string()))?;
        v.visit_char(c)
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let len = self.ulen()?;
        let bytes = self.take(len)?;
        let s = core::str::from_utf8(bytes).map_err(|_| CodecError("bad utf8".to_string()))?;
        v.visit_borrowed_str(s)
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_str(v)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let len = self.ulen()?;
        let bytes = self.take(len)?;
        v.visit_borrowed_bytes(bytes)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_bytes(v)
    }
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        if self.byte()? == 0 {
            v.visit_none()
        } else {
            v.visit_some(self)
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        v: V,
    ) -> Result<V::Value> {
        v.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        v: V,
    ) -> Result<V::Value> {
        v.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let len = self.ulen()?;
        v.visit_seq(Elements::counted(self, len))
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value> {
        v.visit_seq(Elements::fixed(self, len))
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value> {
        v.visit_seq(Elements::fixed(self, len))
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let len = self.ulen()?;
        v.visit_map(Elements::counted(self, len))
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value> {
        v.visit_seq(Elements::fixed(self, fields.len()))
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value> {
        v.visit_enum(Enum { de: self })
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, _v: V) -> Result<V::Value> {
        err("identifier unsupported")
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _v: V) -> Result<V::Value> {
        err("ignored_any unsupported in non-self-describing format")
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

struct Elements<'a, 'de> {
    de: &'a mut Decoder<'de>,
    remaining: usize,
    // Whether `remaining` came off the wire (sequences, maps) and so counts
    // against `MAX_ZERO_BYTE_ELEMENTS`; tuples and structs have static length.
    counted: bool,
    entry_start: usize,
}

impl<'a, 'de> Elements<'a, 'de> {
    fn fixed(de: &'a mut Decoder<'de>, remaining: usize) -> Self {
        Elements {
            de,
            remaining,
            counted: false,
            entry_start: 0,
        }
    }

    fn counted(de: &'a mut Decoder<'de>, remaining: usize) -> Self {
        Elements {
            de,
            remaining,
            counted: true,
            entry_start: 0,
        }
    }

    fn charge_if_empty(&mut self, start: usize) -> Result<()> {
        if self.counted && self.de.pos == start {
            self.de.zero_byte_elements += 1;
            if self.de.zero_byte_elements > MAX_ZERO_BYTE_ELEMENTS {
                return err("too many zero-byte elements");
            }
        }
        Ok(())
    }

    fn capacity_hint(&self) -> usize {
        self.remaining
            .min(self.de.input.len().saturating_sub(self.de.pos))
    }
}

impl<'a, 'de> SeqAccess<'de> for Elements<'a, 'de> {
    type Error = CodecError;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        let start = self.de.pos;
        let value = seed.deserialize(&mut *self.de)?;
        self.charge_if_empty(start)?;
        Ok(Some(value))
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.capacity_hint())
    }
}

impl<'a, 'de> de::MapAccess<'de> for Elements<'a, 'de> {
    type Error = CodecError;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        self.entry_start = self.de.pos;
        seed.deserialize(&mut *self.de).map(Some)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        let value = seed.deserialize(&mut *self.de)?;
        self.charge_if_empty(self.entry_start)?;
        Ok(value)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.capacity_hint())
    }
}

struct Enum<'a, 'de> {
    de: &'a mut Decoder<'de>,
}

impl<'a, 'de> de::EnumAccess<'de> for Enum<'a, 'de> {
    type Error = CodecError;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self::Variant)> {
        let idx = self.de.uvarint()?;
        let val = seed.deserialize(idx.into_deserializer())?;
        Ok((val, self))
    }
}

impl<'a, 'de> de::VariantAccess<'de> for Enum<'a, 'de> {
    type Error = CodecError;
    fn unit_variant(self) -> Result<()> {
        Ok(())
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        seed.deserialize(&mut *self.de)
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value> {
        v.visit_seq(Elements::fixed(self.de, len))
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value> {
        v.visit_seq(Elements::fixed(self.de, fields.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(crate = "ferrite_app::serde")]
    enum Kind {
        Unit,
        Wrap(u32),
        Pair(i64, bool),
        Named { label: String, data: Vec<u8> },
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(crate = "ferrite_app::serde")]
    struct Graph {
        title: String,
        flag: bool,
        count: u64,
        delta: i64,
        ratio: f64,
        tag: char,
        bytes: Vec<u8>,
        maybe: Option<Vec<String>>,
        none: Option<u8>,
        kinds: Vec<Kind>,
        tuple: (u16, i32),
    }

    fn roundtrip<T: Serialize + de::DeserializeOwned + PartialEq + core::fmt::Debug>(v: &T) {
        let bytes = to_bytes(v).expect("encode");
        let back: T = from_bytes(&bytes).expect("decode");
        assert_eq!(&back, v);
    }

    // 1. representative graph roundtrip: fill every field, incl. all four
    //    Kind variants in `kinds`.
    #[test]
    fn representative_graph_roundtrips() {
        let g = Graph {
            title: "the graph".to_string(),
            flag: true,
            count: 4_294_967_400,
            delta: -987_654_321,
            ratio: -12.5,
            tag: 'λ',
            bytes: vec![0, 1, 2, 250, 255],
            maybe: Some(vec!["a".to_string(), "".to_string(), "cc".to_string()]),
            none: None,
            kinds: vec![
                Kind::Unit,
                Kind::Wrap(u32::MAX),
                Kind::Pair(i64::MIN, false),
                Kind::Named {
                    label: "n".to_string(),
                    data: vec![9, 8, 7],
                },
            ],
            tuple: (65535, -2_000_000_000),
        };
        roundtrip(&g);
    }

    // 2. integer boundaries roundtrip.
    #[test]
    fn integer_boundaries_roundtrip() {
        for v in [0u64, 127, 128, 16383, 16384, u64::MAX] {
            roundtrip(&v);
        }
        for v in [i64::MIN, -1, 0, 1, i64::MAX] {
            roundtrip(&v);
        }
    }

    // 3. varint wire shape.
    #[test]
    fn varint_wire_shape() {
        assert_eq!(to_bytes(&u64::MAX).expect("encode").len(), 10);
        assert_eq!(to_bytes(&0u64).expect("encode"), vec![0]);
        assert_eq!(to_bytes(&128u64).expect("encode"), vec![0x80, 0x01]);
    }

    // 4. zigzag unit checks.
    #[test]
    fn zigzag_units() {
        assert_eq!(zigzag(0), 0);
        assert_eq!(zigzag(-1), 1);
        assert_eq!(zigzag(1), 2);
        assert_eq!(unzigzag(zigzag(i64::MIN)), i64::MIN);
    }

    // 5. truncated input errors ("unexpected end of input"), never panics.
    #[test]
    fn truncated_input_errors() {
        let g = Graph {
            title: "trunc".to_string(),
            flag: false,
            count: 42,
            delta: -7,
            ratio: 1.0,
            tag: 'x',
            bytes: vec![1, 2, 3],
            maybe: None,
            none: Some(9),
            kinds: vec![Kind::Wrap(3)],
            tuple: (1, -1),
        };
        let bytes = to_bytes(&g).expect("encode");
        let err =
            from_bytes::<Graph>(&bytes[..bytes.len() - 1]).expect_err("truncation must error");
        assert!(
            err.to_string().contains("unexpected end of input"),
            "got: {err}"
        );
    }

    // 6. varint too long.
    #[test]
    fn varint_too_long_errors() {
        let err = from_bytes::<u64>(&[0x80; 11]).expect_err("overlong varint must error");
        assert!(err.to_string().contains("varint too long"), "got: {err}");
    }

    #[test]
    fn varint_tenth_byte_overflow_errors() {
        let mut bytes = vec![0xff; 9];
        bytes.push(0x02);
        let err = from_bytes::<u64>(&bytes).expect_err("overflowing varint must error");
        assert!(err.to_string().contains("varint overflow"), "got: {err}");
    }

    #[test]
    fn hostile_lengths_error() {
        let huge = [0xff, 0xff, 0xff, 0xff, 0x0f, b'a'];
        for result in [
            from_bytes::<String>(&huge).map(|_| ()),
            from_bytes::<Vec<u8>>(&huge).map(|_| ()),
            from_bytes::<Vec<u32>>(&huge).map(|_| ()),
            from_bytes::<std::collections::BTreeMap<u8, u8>>(&huge).map(|_| ()),
            from_bytes::<String>(&[5, b'a']).map(|_| ()),
        ] {
            let err = result.expect_err("hostile length must error");
            assert!(
                err.to_string().contains("unexpected end of input"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn length_beyond_usize_errors() {
        let mut bytes = vec![0xff; 9];
        bytes.push(0x01);
        let err = from_bytes::<String>(&bytes).expect_err("u64::MAX length must error");
        let msg = err.to_string();
        assert!(
            msg.contains("length overflow") || msg.contains("unexpected end of input"),
            "got: {msg}"
        );
    }

    #[test]
    fn zero_byte_elements_roundtrip() {
        let units = vec![(), (), ()];
        let bytes = to_bytes(&units).expect("encode");
        assert_eq!(bytes, vec![3]);
        assert_eq!(from_bytes::<Vec<()>>(&bytes).expect("decode"), units);

        let mut map = std::collections::BTreeMap::new();
        map.insert((), ());
        let bytes = to_bytes(&map).expect("encode");
        assert_eq!(bytes, vec![1]);
        assert_eq!(
            from_bytes::<std::collections::BTreeMap<(), ()>>(&bytes).expect("decode"),
            map
        );
    }

    #[test]
    fn hostile_zero_byte_counts_are_bounded() {
        let huge = to_bytes(&u64::from(u32::MAX)).expect("encode");
        for result in [
            from_bytes::<Vec<()>>(&huge).map(|_| ()),
            from_bytes::<Vec<Box<()>>>(&huge).map(|_| ()),
            from_bytes::<std::collections::BTreeMap<(), ()>>(&huge).map(|_| ()),
        ] {
            let err = result.expect_err("hostile zero-byte count must error");
            assert!(
                err.to_string().contains("too many zero-byte elements"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn zero_byte_element_limit_is_exact() {
        let at_limit = vec![(); MAX_ZERO_BYTE_ELEMENTS];
        let bytes = to_bytes(&at_limit).expect("encode");
        assert_eq!(from_bytes::<Vec<()>>(&bytes).expect("decode"), at_limit);

        let over = vec![(); MAX_ZERO_BYTE_ELEMENTS + 1];
        let bytes = to_bytes(&over).expect("encode");
        let err = from_bytes::<Vec<()>>(&bytes).expect_err("one past the limit");
        assert!(
            err.to_string().contains("too many zero-byte elements"),
            "got: {err}"
        );
    }

    #[test]
    fn elements_that_consume_input_are_not_charged() {
        let many: Vec<(u8, ())> = (0..=u8::MAX).cycle().take(200_000).map(|b| (b, ())).collect();
        roundtrip(&many);
    }

    // 7. Option encoding.
    #[test]
    fn option_encoding() {
        assert_eq!(to_bytes(&None::<u8>).expect("encode"), vec![0]);
        assert_eq!(to_bytes(&Some(7u8)).expect("encode"), vec![1, 7]);
    }

    // 8. empty containers roundtrip.
    #[test]
    fn empty_containers_roundtrip() {
        let v: (String, Vec<u8>, Vec<Kind>) = (String::new(), Vec::new(), Vec::new());
        roundtrip(&v);
    }
}
