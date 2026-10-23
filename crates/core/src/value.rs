//! A JSON value whose shape no Rust type fixes, such as the arguments of a
//! tool call. Object keys sort by code point, so each value has exactly one
//! canonical text. The gate ID hashes that text (`docs/design.md` 5.3).

use std::collections::BTreeMap;

/// One JSON value, built only by the strict reader.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgValue {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
    Array(Vec<ArgValue>),
    Object(BTreeMap<String, ArgValue>),
}

impl ArgValue {
    /// Convert a value that the strict reader already checked.
    pub(crate) fn from_json(value: serde_json::Value) -> Self {
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

    fn from_number(number: &serde_json::Number) -> Self {
        if let Some(int) = number.as_i64() {
            return Self::Int(int);
        }
        if let Some(uint) = number.as_u64() {
            return Self::UInt(uint);
        }
        // Without the arbitrary_precision feature, every other number is an f64.
        Self::Float(number.as_f64().unwrap_or(0.0))
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

fn write_float(float: f64, out: &mut String) {
    // The strict reader admits only finite floats. Treat -0.0 as 0.0.
    let float = if float == 0.0 { 0.0 } else { float };
    match serde_json::to_string(&float) {
        Ok(text) => out.push_str(&text),
        Err(_) => out.push_str("null"),
    }
}

#[cfg(test)]
mod tests {
    use super::ArgValue;
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
        assert_eq!(canon(r#""a""#), canon(r#""a""#));
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
    }

    #[test]
    fn integers_keep_their_full_range() {
        assert_eq!(canon("-9223372036854775808"), "-9223372036854775808");
        assert_eq!(canon("18446744073709551615"), "18446744073709551615");
    }
}
