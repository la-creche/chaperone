//! The strict reader. Every config file and every untrusted body passes
//! through [`read`], [`read_value`] or [`read_toml`] before any other code
//! sees it. [`read`] and [`read_value`] take JSON. [`read_toml`] takes TOML.
//!
//! A text is strict when each of these rules holds:
//!
//! 1. Size. The text is not longer than the [`ByteCap`] of its caller.
//! 2. Encoding. The bytes are valid UTF-8. The first character is not
//!    U+FEFF, the byte order mark.
//! 3. Grammar. A JSON text is one value of RFC 8259, with optional white
//!    space before and after it, and nothing else. `serde_json` checks this.
//!    A TOML text is one document of TOML 1.1, and comments are allowed.
//!    The `toml` crate checks this.
//! 4. Strings. No raw control character, no invalid escape, no lone
//!    surrogate. The parser of each format checks this when it decodes each
//!    string.
//! 5. Keys. Each key of an object or a table appears one time only. In
//!    JSON, [`Check`] does this, because `serde_json` keeps the last of two
//!    equal keys. In TOML, the `toml` crate refuses a repeated key and a
//!    table defined twice.
//! 6. Depth. Arrays, objects and tables nest [`DEPTH_MAX`] levels or less.
//!    The root table of a TOML document is the first level.
//! 7. Numbers. A float is finite. `serde_json` refuses `1e999`. [`Check`]
//!    refuses the `inf` and `nan` of TOML. A JSON integer outside the `i64`
//!    and `u64` ranges reads as a float, and a typed field that takes an
//!    integer refuses it. A TOML integer is inside the `i64` range. [`Check`]
//!    refuses a larger one, because the `toml` crate reads it.
//!
//! The reader makes two passes. The first pass checks rules 3 to 7 and
//! builds nothing. The second pass fills the typed value.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::value::ArgValue;

/// The deepest nesting of arrays, objects and tables that a text may have.
pub const DEPTH_MAX: usize = 64;

/// The message of the `toml` parser for a key that appears twice (rule 5).
/// A `toml` version with another message gives a [`StrictError::Syntax`],
/// which still refuses the text.
const TOML_DUPLICATE_KEY: &str = "duplicate key";

/// The messages of the `toml` parser for nesting past its own limit of 80
/// levels (rule 6). The same fallback to [`StrictError::Syntax`] holds.
const TOML_TOO_DEEP: [&str; 2] = [
    "cannot recurse further; max recursion depth met",
    "recursion limit",
];

/// The largest text a caller accepts, in bytes. Each caller picks its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteCap(usize);

impl ByteCap {
    /// A cap of `bytes` bytes.
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}

/// Why a text is not strict JSON or strict TOML, or does not fit the type.
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
    /// Rule 5. The error holds the position, not the key: a key of an
    /// untrusted body can be a token (G9).
    #[error("a key appears twice at line {line}, column {column}")]
    DuplicateKey { line: usize, column: usize },
    /// Rule 6.
    #[error("the text nests deeper than {DEPTH_MAX} levels")]
    TooDeep,
    /// Rules 3, 4 and 7.
    #[error("the text is not valid at line {line}, column {column}: {message}")]
    Syntax {
        line: usize,
        column: usize,
        message: String,
    },
    /// The text is strict, but it does not fit the type. The error holds
    /// the position only: the message of `serde` can copy the rejected
    /// value (G9).
    #[error("the value does not fit at line {line}, column {column}")]
    Shape { line: usize, column: usize },
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

/// Read `bytes` as strict TOML into a `T`.
///
/// # Errors
///
/// Returns a [`StrictError`] that names the first rule the text breaks.
pub fn read_toml<T: DeserializeOwned>(bytes: &[u8], cap: ByteCap) -> Result<T, StrictError> {
    let text = decode(bytes, cap)?;
    let table = toml::de::DeTable::parse(text)
        .map_err(|error| toml_refusal(text, &error, toml_fault(&error)))?;

    let mut fault = None;
    Check {
        depth: 0,
        format: Format::Toml,
        fault: &mut fault,
    }
    .deserialize(toml::de::Deserializer::from(table.clone()))
    .map_err(|error| toml_refusal(text, &error, fault))?;

    T::deserialize(toml::de::Deserializer::from(table)).map_err(|error| {
        let (line, column) = toml_position(text, &error);
        StrictError::Shape { line, column }
    })
}

/// Check rules 1 and 2 and return the text.
fn decode(bytes: &[u8], cap: ByteCap) -> Result<&str, StrictError> {
    if bytes.len() > cap.bytes() {
        return Err(StrictError::TooLarge { cap: cap.bytes() });
    }

    let text = std::str::from_utf8(bytes).map_err(|error| StrictError::NotUtf8 {
        offset: error.valid_up_to(),
    })?;

    if text.starts_with('\u{FEFF}') {
        return Err(StrictError::ByteOrderMark);
    }
    Ok(text)
}

/// Check rules 1 to 7 for JSON and return the text.
fn check(bytes: &[u8], cap: ByteCap) -> Result<&str, StrictError> {
    let text = decode(bytes, cap)?;

    let mut fault = None;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let checked = Check {
        depth: 0,
        format: Format::Json,
        fault: &mut fault,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());

    match (checked, fault) {
        (Ok(()), _) => Ok(text),
        (Err(error), Some(Fault::DuplicateKey)) => Err(StrictError::DuplicateKey {
            line: error.line(),
            column: error.column(),
        }),
        (Err(_), Some(Fault::TooDeep)) => Err(StrictError::TooDeep),
        (Err(error), Some(Fault::NotFinite | Fault::OutOfRange) | None) => Err(syntax(&error)),
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
    }
}

/// The rule that a parse error of the `toml` crate names, when it is rule 5
/// or 6.
fn toml_fault(error: &toml::de::Error) -> Option<Fault> {
    let message = error.message();
    if message == TOML_DUPLICATE_KEY {
        return Some(Fault::DuplicateKey);
    }
    if TOML_TOO_DEEP.contains(&message) {
        return Some(Fault::TooDeep);
    }
    None
}

/// The refusal for an error of the `toml` crate in the parse or the first
/// pass. A syntax refusal copies the message of the error only. The
/// `Display` of a `toml` error quotes a line of the document (G9).
fn toml_refusal(text: &str, error: &toml::de::Error, fault: Option<Fault>) -> StrictError {
    let (line, column) = toml_position(text, error);
    match fault {
        Some(Fault::DuplicateKey) => StrictError::DuplicateKey { line, column },
        Some(Fault::TooDeep) => StrictError::TooDeep,
        Some(Fault::NotFinite | Fault::OutOfRange) | None => StrictError::Syntax {
            line,
            column,
            message: error.message().to_owned(),
        },
    }
}

/// The line and the column, both from 1, of the first byte of the span of
/// `error`. The column counts bytes, as the columns of `serde_json` do. An
/// error with no span points at the start of the text.
fn toml_position(text: &str, error: &toml::de::Error) -> (usize, usize) {
    let offset = error.span().map_or(0, |span| span.start);
    let before = text.as_bytes().get(..offset).unwrap_or_default();
    let line_start = before
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |at| at + 1);
    let line = before.iter().filter(|&&byte| byte == b'\n').count() + 1;
    (line, before.len() - line_start + 1)
}

/// The grammar that the first pass checks the numbers against.
#[derive(Debug, Clone, Copy)]
enum Format {
    Json,
    Toml,
}

/// A rule that the first pass found broken. The parser adds the position.
#[derive(Debug, Clone, Copy)]
enum Fault {
    DuplicateKey,
    TooDeep,
    NotFinite,
    OutOfRange,
}

/// The first pass. It visits every value, checks keys, depth and numbers,
/// and keeps nothing. A fault of rule 5, 6 or 7 goes to `fault`. The
/// caller uses it to tell the fault apart from a syntax error of the parser.
struct Check<'a> {
    depth: usize,
    format: Format,
    fault: &'a mut Option<Fault>,
}

impl Check<'_> {
    fn child(&mut self) -> Check<'_> {
        Check {
            depth: self.depth + 1,
            format: self.format,
            fault: &mut *self.fault,
        }
    }

    fn at_limit(&self) -> bool {
        self.depth >= DEPTH_MAX
    }

    fn fail<E: de::Error>(&mut self, fault: Fault) -> E {
        *self.fault = Some(fault);
        E::custom(match fault {
            Fault::DuplicateKey => "duplicate key",
            Fault::TooDeep => "too deep",
            Fault::NotFinite => "a float is not finite",
            Fault::OutOfRange => "an integer is out of range",
        })
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
        formatter.write_str("a JSON or TOML value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    /// `toml` gives a `u64` only above `i64::MAX`, and TOML 1.1 allows
    /// only the `i64` range. `serde_json` gives a `u64` for each integer
    /// from 0.
    fn visit_u64<E: de::Error>(mut self, _: u64) -> Result<(), E> {
        match self.format {
            Format::Json => Ok(()),
            Format::Toml => Err(self.fail(Fault::OutOfRange)),
        }
    }

    fn visit_i128<E: de::Error>(mut self, _: i128) -> Result<(), E> {
        Err(self.fail(Fault::OutOfRange))
    }

    fn visit_u128<E: de::Error>(mut self, _: u128) -> Result<(), E> {
        Err(self.fail(Fault::OutOfRange))
    }

    fn visit_f64<E: de::Error>(mut self, value: f64) -> Result<(), E> {
        if value.is_finite() {
            return Ok(());
        }
        Err(self.fail(Fault::NotFinite))
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        if self.at_limit() {
            return Err(self.fail(Fault::TooDeep));
        }
        while seq.next_element_seed(self.child())?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<(), A::Error> {
        if self.at_limit() {
            return Err(self.fail(Fault::TooDeep));
        }
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(self.fail(Fault::DuplicateKey));
            }
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
    fn refuses_a_duplicate_key_and_names_its_position() {
        assert_eq!(
            err(b"{\"a\": 1,\n \"a\": 2}"),
            StrictError::DuplicateKey { line: 2, column: 4 }
        );
    }

    #[test]
    fn refuses_a_duplicate_key_written_with_an_escape() {
        assert!(matches!(
            err(br#"{"a": 1, "a": 2}"#),
            StrictError::DuplicateKey { .. }
        ));
    }

    #[test]
    fn refuses_a_duplicate_key_in_a_nested_object() {
        assert!(matches!(
            err(br#"[{"x": {"k": 1, "k": 1}}]"#),
            StrictError::DuplicateKey { .. }
        ));
    }

    #[test]
    fn errors_do_not_copy_a_key_or_a_value_from_the_text() {
        let duplicate = err(br#"{"SECRET-key": 1, "SECRET-key": 2}"#);
        let shape = read::<Pair>(br#"{"a": "SECRET-value", "b": "x"}"#, CAP).unwrap_err();
        let unknown = read::<Pair>(br#"{"a": 1, "b": "x", "SECRET-field": 0}"#, CAP).unwrap_err();
        for error in [duplicate, shape, unknown] {
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains("SECRET"), "{shown}");
        }
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

    fn toml_err(text: &[u8]) -> StrictError {
        read_toml::<toml::Table>(text, CAP).unwrap_err()
    }

    /// The position of the syntax refusal of `text`, or `None` for another
    /// refusal.
    fn toml_syntax_at(text: &str) -> Option<(usize, usize)> {
        if let StrictError::Syntax { line, column, .. } = toml_err(text.as_bytes()) {
            return Some((line, column));
        }
        None
    }

    #[test]
    fn toml_reads_a_file_with_comments() {
        let text = b"# The pair.\na = 1 # One.\n\n# A string.\nb = \"x\"\n";
        let pair: Pair = read_toml(text, CAP).unwrap();
        assert_eq!(
            pair,
            Pair {
                a: 1,
                b: "x".into()
            }
        );
    }

    #[test]
    fn toml_refuses_an_unknown_field() {
        let error = read_toml::<Pair>(b"a = 1\nb = \"x\"\nc = 0\n", CAP).unwrap_err();
        assert_eq!(error, StrictError::Shape { line: 3, column: 1 });
    }

    #[test]
    fn toml_refuses_a_repeated_key() {
        assert_eq!(
            toml_err(b"a = 1\na = 2\n"),
            StrictError::DuplicateKey { line: 2, column: 1 }
        );
    }

    #[test]
    fn toml_refuses_a_table_defined_twice() {
        assert_eq!(
            toml_err(b"[t]\nx = 1\n[t]\ny = 2\n"),
            StrictError::DuplicateKey { line: 3, column: 2 }
        );
    }

    #[test]
    fn toml_refuses_a_dotted_key_that_redefines_a_table() {
        assert_eq!(
            toml_err(b"t.x = 1\n[t]\ny = 2\n"),
            StrictError::DuplicateKey { line: 2, column: 2 }
        );
    }

    #[test]
    fn toml_refuses_a_text_over_the_cap() {
        let text = vec![b'#'; 2048];
        assert_eq!(toml_err(&text), StrictError::TooLarge { cap: 1024 });
    }

    #[test]
    fn toml_refuses_a_byte_order_mark() {
        assert_eq!(toml_err(b"\xef\xbb\xbfa = 1\n"), StrictError::ByteOrderMark);
    }

    #[test]
    fn toml_refuses_invalid_utf8() {
        assert_eq!(
            toml_err(b"a = \"\xff\"\n"),
            StrictError::NotUtf8 { offset: 5 }
        );
    }

    #[test]
    fn toml_refuses_an_infinite_float() {
        for text in ["a = inf\n", "a = +inf\n", "a = -inf\n", "a = 1e999\n"] {
            assert_eq!(toml_syntax_at(text), Some((1, 5)), "{text}");
        }
    }

    #[test]
    fn toml_refuses_nan() {
        for text in ["a = nan\n", "a = +nan\n", "a = -nan\n"] {
            assert_eq!(toml_syntax_at(text), Some((1, 5)), "{text}");
        }
    }

    #[test]
    fn toml_refuses_a_non_finite_float_in_an_array() {
        assert_eq!(toml_syntax_at("a = [1.0, nan]\n"), Some((1, 11)));
    }

    /// The root table is the first level, so `a` holds `levels - 1` arrays.
    fn nested_arrays(levels: usize) -> String {
        format!("a = {}{}\n", "[".repeat(levels - 1), "]".repeat(levels - 1))
    }

    /// The root table is the first level, so `a` holds `levels - 1` tables.
    fn nested_tables(levels: usize) -> String {
        let depth = levels - 2;
        format!("a = {}{{}}{}\n", "{b = ".repeat(depth), "}".repeat(depth))
    }

    #[test]
    fn toml_accepts_the_depth_limit_and_refuses_one_more() {
        for nested in [nested_arrays, nested_tables] {
            let at_limit = nested(DEPTH_MAX);
            assert!(read_toml::<toml::Table>(at_limit.as_bytes(), CAP).is_ok());
            assert_eq!(
                toml_err(nested(DEPTH_MAX + 1).as_bytes()),
                StrictError::TooDeep
            );
        }
    }

    #[test]
    fn toml_refuses_nesting_past_the_parser_limit() {
        let arrays = nested_arrays(200);
        assert_eq!(toml_err(arrays.as_bytes()), StrictError::TooDeep);

        let dotted = format!("{} = 1\n", vec!["k"; 200].join("."));
        assert_eq!(toml_err(dotted.as_bytes()), StrictError::TooDeep);
    }

    #[test]
    fn toml_refuses_an_integer_outside_i64() {
        assert!(read_toml::<toml::Table>(b"a = 9223372036854775807\n", CAP).is_ok());
        assert!(read_toml::<toml::Table>(b"a = -9223372036854775808\n", CAP).is_ok());
        for text in [
            "a = 9223372036854775808\n",
            "a = -9223372036854775809\n",
            "a = 99999999999999999999999999999999999999999\n",
        ] {
            assert_eq!(toml_syntax_at(text), Some((1, 5)), "{text}");
        }
    }

    #[test]
    fn toml_refuses_an_integer_too_large_for_a_typed_field() {
        let error = read_toml::<Pair>(b"a = 99999999999\nb = \"x\"\n", CAP).unwrap_err();
        assert_eq!(error, StrictError::Shape { line: 1, column: 5 });
    }

    #[test]
    fn toml_refuses_a_syntax_error() {
        assert!(toml_syntax_at("a = \n").is_some());
    }

    #[test]
    fn toml_errors_do_not_copy_a_key_or_a_value_from_the_text() {
        let duplicate = toml_err(b"SECRET-key = 1\nSECRET-key = 2\n");
        let syntax = toml_err(b"a = \"SECRET-value\n");
        let shape = read_toml::<Pair>(b"a = \"SECRET-value\"\nb = \"x\"\n", CAP).unwrap_err();
        let unknown = read_toml::<Pair>(b"a = 1\nb = \"x\"\nSECRET-field = 0\n", CAP).unwrap_err();
        for error in [duplicate, syntax, shape, unknown] {
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains("SECRET"), "{shown}");
        }
    }
}
