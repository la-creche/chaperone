//! A JSON value whose shape no Rust type fixes, such as the arguments of a
//! tool call. Object keys sort by code point, so each value has exactly one
//! canonical text. The gate ID hashes that text (`docs/design.md` 5.3).

use std::collections::BTreeMap;

/// A finite `f64`. NaN and the infinities have no JSON text, so a value
/// that held one would share the canonical text `null` with
/// [`ArgValue::Null`], and two different calls would share one gate ID.
/// The type makes such a value impossible to build.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Finite(f64);

impl Finite {
    /// Zero.
    pub const ZERO: Self = Self(0.0);

    /// Wrap `value` when it is finite. `-0.0` becomes `0.0`, so equal
    /// numbers have one canonical text.
    #[must_use]
    pub fn new(value: f64) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        Some(if value == 0.0 {
            Self::ZERO
        } else {
            Self(value)
        })
    }

    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

/// One JSON value. The strict reader builds it from a text. Other code can
/// build one too, and every value it can build has a JSON text.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgValue {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(Finite),
    String(String),
    Array(Vec<ArgValue>),
    Object(BTreeMap<String, ArgValue>),
}

impl ArgValue {
    /// Convert a value that a protocol library parsed from bytes the strict
    /// reader already checked. Use [`crate::strict::read_value`] for raw
    /// bytes.
    #[must_use]
    pub fn from_json(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(flag) => Self::Bool(flag),
            serde_json::Value::Number(number) => Self::from_number(&number),
            serde_json::Value::String(text) => Self::String(text),
            serde_json::Value::Array(items) => {
                Self::Array(items.into_iter().map(Self::from_json).collect())
            }
            serde_json::Value::Object(members) => Self::Object(
                members
                    .into_iter()
                    .map(|(key, item)| (key, Self::from_json(item)))
                    .collect(),
            ),
        }
    }

    /// The value as a protocol library takes it. [`Self::from_json`] of the
    /// result gives back an equal value.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(flag) => serde_json::Value::Bool(*flag),
            Self::Int(int) => serde_json::Value::from(*int),
            Self::UInt(uint) => serde_json::Value::from(*uint),
            Self::Float(float) => serde_json::Number::from_f64(float.get())
                .map_or(serde_json::Value::Null, serde_json::Value::Number),
            Self::String(text) => serde_json::Value::String(text.clone()),
            Self::Array(items) => {
                serde_json::Value::Array(items.iter().map(Self::to_json).collect())
            }
            Self::Object(members) => serde_json::Value::Object(
                members
                    .iter()
                    .map(|(key, item)| (key.clone(), item.to_json()))
                    .collect(),
            ),
        }
    }

    fn from_number(number: &serde_json::Number) -> Self {
        if let Some(int) = number.as_i64() {
            return Self::Int(int);
        }
        if let Some(uint) = number.as_u64() {
            return Self::UInt(uint);
        }
        // Without the arbitrary_precision feature, every other number is a
        // finite f64. The fallback cannot happen; it keeps the value finite.
        Self::Float(
            number
                .as_f64()
                .and_then(Finite::new)
                .unwrap_or(Finite::ZERO),
        )
    }

    /// The canonical text: no white space, keys sorted by code point, each
    /// string and number written by `serde_json`. Equal values give equal
    /// texts.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    /// The canonical text of an object, from its members. The text equals
    /// that of `ArgValue::Object(members)`, with no copy of the members.
    #[must_use]
    pub fn canonical_object(members: &BTreeMap<String, ArgValue>) -> String {
        let mut out = String::new();
        write_object(members, &mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        use std::fmt::Write as _;

        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
            Self::Int(int) => {
                let _ = write!(out, "{int}");
            }
            Self::UInt(uint) => {
                let _ = write!(out, "{uint}");
            }
            Self::Float(float) => write_float(*float, out),
            Self::String(text) => write_string(text, out),
            Self::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Self::Object(members) => write_object(members, out),
        }
    }
}

fn write_object(members: &BTreeMap<String, ArgValue>, out: &mut String) {
    out.push('{');
    for (index, (key, item)) in members.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(key, out);
        out.push(':');
        item.write_canonical(out);
    }
    out.push('}');
}

fn write_string(text: &str, out: &mut String) {
    // A str always serializes. The fallback keeps the output well formed.
    match serde_json::to_string(text) {
        Ok(quoted) => out.push_str(&quoted),
        Err(_) => out.push_str("\"\""),
    }
}

fn write_float(float: Finite, out: &mut String) {
    // A finite float always serializes. The fallback keeps the text a number.
    match serde_json::to_string(&float.get()) {
        Ok(text) => out.push_str(&text),
        Err(_) => out.push('0'),
    }
}

#[cfg(test)]
mod tests {
    use super::{ArgValue, Finite};
    use crate::strict::{ByteCap, read_value};

    const CAP: ByteCap = ByteCap::new(4096);

    fn canon(text: &str) -> String {
        read_value(text.as_bytes(), CAP).unwrap().canonical()
    }

    #[test]
    fn key_order_and_white_space_do_not_change_the_canonical_text() {
        assert_eq!(
            canon(r#"{ "b": 1, "a": [true, null] }"#),
            canon(r#"{"a":[true,null],"b":1}"#)
        );
        assert_eq!(canon(r#"{"b":1,"a":2}"#), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn an_escape_and_its_character_give_one_text() {
        assert_eq!(canon(r#""\u0061""#), canon(r#""a""#));
    }

    #[test]
    fn the_object_text_equals_the_value_text() {
        let value = read_value(br#"{"b": [1, {"c": null}], "a": "x"}"#, CAP).unwrap();
        let ArgValue::Object(members) = &value else {
            panic!("not an object");
        };
        assert_eq!(ArgValue::canonical_object(members), value.canonical());
    }

    #[test]
    fn negative_zero_equals_zero() {
        assert_eq!(canon("-0.0"), canon("0.0"));
        assert_eq!(Finite::new(-0.0), Finite::new(0.0));
    }

    #[test]
    fn a_float_without_a_json_text_cannot_be_built() {
        assert_eq!(Finite::new(f64::NAN), None);
        assert_eq!(Finite::new(f64::INFINITY), None);
        assert_eq!(Finite::new(f64::NEG_INFINITY), None);
        assert_eq!(Finite::new(1.5).map(Finite::get), Some(1.5));
    }

    #[test]
    fn to_json_and_from_json_round_trip() {
        let text = br#"{"a":[1,-2,18446744073709551615,1.5,"x",null,true],"b":{"c":{}}}"#;
        let value = read_value(text, CAP).unwrap();
        let json = value.to_json();
        assert_eq!(ArgValue::from_json(json.clone()), value);
        assert_eq!(
            serde_json::to_string(&json).unwrap(),
            std::str::from_utf8(text).unwrap()
        );
    }

    #[test]
    fn integers_keep_their_full_range() {
        assert_eq!(canon("-9223372036854775808"), "-9223372036854775808");
        assert_eq!(canon("18446744073709551615"), "18446744073709551615");
    }
}
