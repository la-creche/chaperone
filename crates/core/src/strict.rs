//! The strict JSON reader. Every config file and every untrusted JSON body
//! passes through [`read`] or [`read_value`] before any other code sees it.
//!
//! A text is strict JSON when each of these rules holds:
//!
//! 1. Size. The text is not longer than the [`ByteCap`] of its caller.
//! 2. Encoding. The bytes are valid UTF-8. The first character is not
//!    U+FEFF, the byte order mark.
//! 3. Grammar. The bytes are one value of RFC 8259, with optional white
//!    space before and after it, and nothing else. `serde_json` checks this.
//! 4. Strings. No raw control character, no invalid escape, no lone
//!    surrogate. `serde_json` checks this when it decodes each string.
//! 5. Keys. Each key of an object appears one time only. [`Check`] does
//!    this, because `serde_json` keeps the last of two equal keys.
//! 6. Depth. Arrays and objects nest [`DEPTH_MAX`] levels or less.
//! 7. Numbers. A float is finite. `serde_json` refuses `1e999`. An integer
//!    outside the `i64` and `u64` ranges reads as a float. A typed field
//!    that takes an integer refuses it.
//!
//! The reader makes two passes. The first pass checks rules 3 to 6 and
//! builds nothing. The second pass fills the typed value.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::value::ArgValue;

/// The deepest nesting of arrays and objects that a text may have.
pub const DEPTH_MAX: usize = 64;

/// The largest text a caller accepts, in bytes. Each caller picks its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteCap(usize);

impl ByteCap {
    /// A cap of `bytes` bytes.
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        Self(bytes)
    }

    /// The cap in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}

/// Why a text is not strict JSON, or does not fit the type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StrictError {
    /// Rule 1.
    #[error("the text is longer than the cap of {cap} bytes")]
    TooLarge { cap: usize },
    /// Rule 2.
    #[error("the text is not valid UTF-8 at byte {offset}")]
    NotUtf8 { offset: usize },
    /// Rule 2.
    #[error("the text starts with a byte order mark")]
    ByteOrderMark,
    /// Rule 5.
    #[error("the key {key:?} appears twice in one object")]
    DuplicateKey { key: String },
    /// Rule 6.
    #[error("the text nests deeper than {DEPTH_MAX} levels")]
    TooDeep,
    /// Rules 3, 4 and 7.
    #[error("the text is not JSON at line {line}, column {column}: {message}")]
    Syntax {
        line: usize,
        column: usize,
        message: String,
    },
    /// The text is strict JSON, but it does not fit the type.
    #[error("the value does not fit at line {line}, column {column}: {message}")]
    Shape {
        line: usize,
        column: usize,
        message: String,
    },
}

/// Read `bytes` as strict JSON into a `T`.
///
/// # Errors
///
/// Returns a [`StrictError`] that names the first rule the text breaks.
pub fn read<T: DeserializeOwned>(bytes: &[u8], cap: ByteCap) -> Result<T, StrictError> {
    let text = check(bytes, cap)?;
    serde_json::from_str(text).map_err(|error| shape(&error))
}

/// Read `bytes` as strict JSON into an [`ArgValue`]. Use this for a body
/// whose shape no Rust type fixes, such as the arguments of a tool call.
///
/// # Errors
///
/// Returns a [`StrictError`] that names the first rule the text breaks.
pub fn read_value(bytes: &[u8], cap: ByteCap) -> Result<ArgValue, StrictError> {
    let value: serde_json::Value = read(bytes, cap)?;
    Ok(ArgValue::from_json(value))
}

/// Check rules 1 to 6 and return the text.
fn check(bytes: &[u8], cap: ByteCap) -> Result<&str, StrictError> {
    if bytes.len() > cap.bytes() {
        return Err(StrictError::TooLarge { cap: cap.bytes() });
    }

    let text = std::str::from_utf8(bytes).map_err(|error| StrictError::NotUtf8 {
        offset: error.valid_up_to(),
    })?;

    if text.starts_with('\u{FEFF}') {
        return Err(StrictError::ByteOrderMark);
    }

    let mut fault = None;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let checked = Check {
        depth: 0,
        fault: &mut fault,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());

    match (checked, fault) {
        (Ok(()), _) => Ok(text),
        (Err(_), Some(fault)) => Err(fault),
        (Err(error), None) => Err(syntax(&error)),
    }
}

fn syntax(error: &serde_json::Error) -> StrictError {
    StrictError::Syntax {
        line: error.line(),
        column: error.column(),
        message: error.to_string(),
    }
}

fn shape(error: &serde_json::Error) -> StrictError {
    StrictError::Shape {
        line: error.line(),
        column: error.column(),
        message: error.to_string(),
    }
}

/// The first pass. It visits every value, checks keys and depth, and keeps
/// nothing. A fault of rule 5 or 6 goes to `fault`, so that [`check`] can
/// tell it apart from a syntax error of `serde_json`.
struct Check<'a> {
    depth: usize,
    fault: &'a mut Option<StrictError>,
}

impl Check<'_> {
    fn child(&mut self) -> Check<'_> {
        Check {
            depth: self.depth.saturating_add(1),
            fault: &mut *self.fault,
        }
    }

    fn at_limit(&self) -> bool {
        self.depth >= DEPTH_MAX
    }

    fn fail<E: de::Error>(&mut self, fault: StrictError) -> E {
        let error = E::custom(&fault);
        *self.fault = Some(fault);
        error
    }
}

impl<'de> DeserializeSeed<'de> for Check<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Check<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        if self.at_limit() {
            return Err(self.fail(StrictError::TooDeep));
        }
        while seq.next_element_seed(self.child())?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<(), A::Error> {
        if self.at_limit() {
            return Err(self.fail(StrictError::TooDeep));
        }
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if keys.contains(&key) {
                return Err(self.fail(StrictError::DuplicateKey { key }));
            }
            keys.insert(key);
            map.next_value_seed(self.child())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const CAP: ByteCap = ByteCap::new(1024);

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Pair {
        a: u32,
        b: String,
    }

    fn err(text: &[u8]) -> StrictError {
        read::<serde_json::Value>(text, CAP).unwrap_err()
    }

    #[test]
    fn reads_a_typed_value() {
        let pair: Pair = read(br#"{"a": 1, "b": "x"}"#, CAP).unwrap();
        assert_eq!(
            pair,
            Pair {
                a: 1,
                b: "x".into()
            }
        );
    }

    #[test]
    fn refuses_a_text_over_the_cap() {
        let text = vec![b' '; 2048];
        assert_eq!(err(&text), StrictError::TooLarge { cap: 1024 });
    }

    #[test]
    fn refuses_invalid_utf8() {
        assert_eq!(err(b"\"a\xff\""), StrictError::NotUtf8 { offset: 2 });
    }

    #[test]
    fn refuses_a_byte_order_mark() {
        assert_eq!(err(b"\xef\xbb\xbf{}"), StrictError::ByteOrderMark);
    }

    #[test]
    fn refuses_a_duplicate_key() {
        assert_eq!(
            err(br#"{"a": 1, "a": 2}"#),
            StrictError::DuplicateKey { key: "a".into() }
        );
    }

    #[test]
    fn refuses_a_duplicate_key_written_with_an_escape() {
        assert_eq!(
            err(br#"{"a": 1, "a": 2}"#),
            StrictError::DuplicateKey { key: "a".into() }
        );
    }

    #[test]
    fn refuses_a_duplicate_key_in_a_nested_object() {
        assert_eq!(
            err(br#"[{"x": {"k": 1, "k": 1}}]"#),
            StrictError::DuplicateKey { key: "k".into() }
        );
    }

    #[test]
    fn accepts_the_depth_limit_and_refuses_one_more() {
        let at_limit = format!("{}{}", "[".repeat(DEPTH_MAX), "]".repeat(DEPTH_MAX));
        assert!(read::<serde_json::Value>(at_limit.as_bytes(), CAP).is_ok());

        let over = format!("{}{}", "[".repeat(DEPTH_MAX + 1), "]".repeat(DEPTH_MAX + 1));
        assert_eq!(err(over.as_bytes()), StrictError::TooDeep);
    }

    #[test]
    fn refuses_trailing_data() {
        assert!(matches!(err(b"{} {}"), StrictError::Syntax { .. }));
    }

    #[test]
    fn refuses_a_lone_surrogate() {
        assert!(matches!(err(br#""\ud800""#), StrictError::Syntax { .. }));
        assert!(matches!(err(br#""\udc00""#), StrictError::Syntax { .. }));
    }

    #[test]
    fn refuses_a_raw_control_character() {
        assert!(matches!(err(b"\"a\x01\""), StrictError::Syntax { .. }));
    }

    #[test]
    fn refuses_an_infinite_float() {
        assert!(matches!(err(b"1e999"), StrictError::Syntax { .. }));
    }

    #[test]
    fn refuses_nan_and_comments() {
        assert!(matches!(err(b"NaN"), StrictError::Syntax { .. }));
        assert!(matches!(err(b"{} // x"), StrictError::Syntax { .. }));
    }

    #[test]
    fn refuses_an_unknown_field_as_a_shape_error() {
        let error = read::<Pair>(br#"{"a": 1, "b": "x", "c": 0}"#, CAP).unwrap_err();
        assert!(matches!(error, StrictError::Shape { .. }));
    }

    #[test]
    fn refuses_an_integer_too_large_for_a_typed_field() {
        let error = read::<Pair>(br#"{"a": 99999999999999999999, "b": "x"}"#, CAP).unwrap_err();
        assert!(matches!(error, StrictError::Shape { .. }));
    }
}
