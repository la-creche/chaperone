//! The form of a policy file, built from its JSON Schema (`docs/design.md`
//! 11). Nothing here knows the shape of the policy beyond two names: the
//! `plugins` map of an app instance, whose values take the schema of the
//! plugin named by the key, and `token_sha256`, which shows as a count.
//!
//! Every field name carries a kind and a JSON pointer, so a posted form
//! decodes back into the draft without the schema.

use std::fmt::Write as _;

use serde_json::{Map, Value};

/// The key under an app instance whose values take a plugin's own schema.
const PLUGINS_KEY: &str = "plugins";

/// The property that holds token digests. It shows as a count (G9).
const DIGESTS_KEY: &str = "token_sha256";

/// The schema a form is built from: the file schema and the section schema
/// of each plugin, both as the admin socket sent them.
#[derive(Debug, Clone)]
pub struct Schemas {
    pub file: Value,
    pub sections: Map<String, Value>,
}

/// Escape text for an HTML attribute or text node.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// One step of a JSON pointer, escaped (RFC 6901).
fn step(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// The steps of a JSON pointer, unescaped.
fn steps(pointer: &str) -> Vec<String> {
    pointer
        .split('/')
        .skip(1)
        .map(|part| part.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// The schema that `$ref` points at, or `schema` itself.
fn resolve<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return schema;
    };
    let Some(path) = reference.strip_prefix("#/") else {
        return schema;
    };
    let mut at = root;
    for part in path.split('/') {
        let part = part.replace("%20", " ");
        match at.get(&part) {
            Some(next) => at = next,
            None => return schema,
        }
    }
    at
}

/// The JSON types a schema names, without `null`.
fn types(schema: &Value) -> Vec<&str> {
    match schema.get("type") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many
            .iter()
            .filter_map(Value::as_str)
            .filter(|t| *t != "null")
            .collect(),
        Some(_) | None => Vec::new(),
    }
}

fn nullable(schema: &Value) -> bool {
    matches!(schema.get("type"), Some(Value::Array(many)) if many.iter().any(|t| t == "null"))
}

/// Whether a schema is a scalar: a string, a number, a boolean, or any of
/// those.
fn is_scalar(schema: &Value, root: &Value) -> bool {
    let schema = resolve(schema, root);
    if let Some(any) = schema.get("anyOf").and_then(Value::as_array) {
        return any.iter().all(|s| is_scalar(s, root));
    }
    let types = types(schema);
    !types.is_empty()
        && types
            .iter()
            .all(|t| matches!(*t, "string" | "integer" | "number" | "boolean"))
}

/// An empty value of a schema, for a new map entry: required properties
/// filled, everything else left out.
#[must_use]
pub fn template(schema: &Value, root: &Value) -> Value {
    let schema = resolve(schema, root);
    if let Some(variants) = schema.get("oneOf").and_then(Value::as_array)
        && let Some(first) = variants.first()
    {
        return template(first, root);
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && let Some(first) = values.first()
    {
        return first.clone();
    }
    let types = types(schema);
    match types.first().copied() {
        Some("object") => {
            let mut object = Map::new();
            let required: Vec<&str> = schema
                .get("required")
                .and_then(Value::as_array)
                .map(|list| list.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            for key in required {
                let property = schema
                    .get("properties")
                    .and_then(|p| p.get(key))
                    .unwrap_or(&Value::Bool(true));
                object.insert(key.to_owned(), template(property, root));
            }
            Value::Object(object)
        }
        Some("array") => Value::Array(Vec::new()),
        Some("string") => Value::String(String::new()),
        Some("integer" | "number") => Value::from(0),
        Some("boolean") => Value::Bool(false),
        Some(_) | None => Value::Object(Map::new()),
    }
}

/// Render the form fields of `value` under `schema` at `pointer`.
#[allow(
    clippy::too_many_lines,
    reason = "one match over every schema shape reads best in one place"
)]
fn render(
    out: &mut String,
    schemas: &Schemas,
    schema: &Value,
    value: Option<&Value>,
    pointer: &str,
    label: &str,
    required: bool,
) {
    let root = &schemas.file;
    let schema = resolve(schema, root);
    let id = escape(pointer);
    let shown = escape(label);
    let mark = if required { " *" } else { "" };
    let description = schema
        .get("description")
        .and_then(Value::as_str)
        .map(|text| format!("<p class=\"help\">{}</p>", escape(text)))
        .unwrap_or_default();

    if pointer.ends_with(&format!("/{DIGESTS_KEY}")) {
        let count = value.and_then(Value::as_array).map_or(0, Vec::len);
        let _ = write!(
            out,
            "<div class=\"field\"><span class=\"label\">{shown}</span> \
             <span>{count} token digest(s) present</span>{description}</div>"
        );
        return;
    }

    // A schema of `true`, or without a type: any JSON.
    if schema.as_bool() == Some(true) || (types(schema).is_empty() && !has_choice(schema)) {
        let text = value.map(|v| serde_json::to_string_pretty(v).unwrap_or_default());
        let _ = write!(
            out,
            "<div class=\"field\"><label for=\"{id}\">{shown}{mark} (JSON)</label>\
             <textarea id=\"{id}\" name=\"f:json:{id}\" rows=\"4\">{}</textarea>{description}</div>",
            escape(text.as_deref().unwrap_or("{}"))
        );
        return;
    }

    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let _ = write!(
            out,
            "<div class=\"field\"><label for=\"{id}\">{shown}{mark}</label><select id=\"{id}\" name=\"f:s:{id}\">"
        );
        for option in values.iter().filter_map(Value::as_str) {
            let selected = if value.and_then(Value::as_str) == Some(option) {
                " selected"
            } else {
                ""
            };
            let _ = write!(
                out,
                "<option value=\"{0}\"{selected}>{0}</option>",
                escape(option)
            );
        }
        let _ = write!(out, "</select>{description}</div>");
        return;
    }

    // An enum of single-key objects: a variant and a list of scalars.
    if let Some(variants) = schema.get("oneOf").and_then(Value::as_array) {
        let names: Vec<&str> = variants
            .iter()
            .filter_map(|v| v.get("properties").and_then(Value::as_object))
            .filter_map(|p| p.keys().next().map(String::as_str))
            .collect();
        let (current, payload) = value
            .and_then(Value::as_object)
            .and_then(|o| o.iter().next())
            .map_or((None, None), |(k, v)| (Some(k.as_str()), Some(v)));
        let _ = write!(
            out,
            "<div class=\"field\"><label for=\"{id}\">{shown}{mark}</label><select id=\"{id}\" name=\"f:variant:{id}\">"
        );
        for name in names {
            let selected = if current == Some(name) {
                " selected"
            } else {
                ""
            };
            let _ = write!(
                out,
                "<option value=\"{0}\"{selected}>{0}</option>",
                escape(name)
            );
        }
        let lines = payload
            .and_then(Value::as_array)
            .map(|items| items.iter().map(scalar_text).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        let _ = write!(
            out,
            "</select> <textarea name=\"f:payload:{id}\" rows=\"3\" placeholder=\"one value per line\">{}</textarea>{description}</div>",
            escape(&lines)
        );
        return;
    }

    // A scalar of several types, such as a bool, an int or a string.
    if schema.get("anyOf").is_some() && is_scalar(schema, root) {
        let text = value.map(scalar_text).unwrap_or_default();
        let _ = write!(
            out,
            "<div class=\"field\"><label for=\"{id}\">{shown}{mark}</label>\
             <input id=\"{id}\" name=\"f:x:{id}\" value=\"{}\">{description}</div>",
            escape(&text)
        );
        return;
    }

    match types(schema).first().copied() {
        Some("object") => {
            let _ = write!(out, "<fieldset><legend>{shown}{mark}</legend>{description}");
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                let required: Vec<&str> = schema
                    .get("required")
                    .and_then(Value::as_array)
                    .map(|list| list.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                for (key, property) in properties {
                    if key == "$schema" {
                        continue;
                    }
                    let child = format!("{pointer}/{}", step(key));
                    render(
                        out,
                        schemas,
                        property,
                        value.and_then(|v| v.get(key)),
                        &child,
                        key,
                        required.contains(&key.as_str()),
                    );
                }
            } else if let Some(each) = schema.get("additionalProperties") {
                let entries = value.and_then(Value::as_object);
                let is_plugins = pointer.ends_with(&format!("/{PLUGINS_KEY}"));
                if let Some(entries) = entries {
                    for (key, entry) in entries {
                        let child = format!("{pointer}/{}", step(key));
                        let entry_schema = if is_plugins {
                            schemas.sections.get(key).unwrap_or(each)
                        } else {
                            each
                        };
                        let _ = write!(
                            out,
                            "<div class=\"entry\"><button name=\"action\" value=\"remove:{}\" class=\"remove\">Remove {}</button>",
                            escape(&child),
                            escape(key)
                        );
                        render(out, schemas, entry_schema, Some(entry), &child, key, false);
                        out.push_str("</div>");
                    }
                }
                let empty = serde_json::to_string(&template(each, root)).unwrap_or_default();
                let _ = write!(
                    out,
                    "<div class=\"add\"><input name=\"key:{id}\" placeholder=\"new {shown} key\"> \
                     <input type=\"hidden\" name=\"tpl:{id}\" value=\"{}\"> \
                     <button name=\"action\" value=\"add:{id}\">Add to {shown}</button></div>",
                    escape(&empty)
                );
            }
            out.push_str("</fieldset>");
        }
        Some("array") => {
            let items = schema.get("items").unwrap_or(&Value::Bool(true));
            if is_scalar(items, root) {
                let lines = value
                    .and_then(Value::as_array)
                    .map(|items| items.iter().map(scalar_text).collect::<Vec<_>>().join("\n"))
                    .unwrap_or_default();
                let kind = if types(resolve(items, root)) == ["string"] {
                    "lines"
                } else {
                    "xlines"
                };
                let _ = write!(
                    out,
                    "<div class=\"field\"><label for=\"{id}\">{shown}{mark}</label>\
                     <textarea id=\"{id}\" name=\"f:{kind}:{id}\" rows=\"3\" placeholder=\"one value per line\">{}</textarea>{description}</div>",
                    escape(&lines)
                );
            } else {
                let text = value.map(|v| serde_json::to_string_pretty(v).unwrap_or_default());
                let _ = write!(
                    out,
                    "<div class=\"field\"><label for=\"{id}\">{shown}{mark} (JSON list)</label>\
                     <textarea id=\"{id}\" name=\"f:json:{id}\" rows=\"4\">{}</textarea>{description}</div>",
                    escape(text.as_deref().unwrap_or("[]"))
                );
            }
        }
        Some("string") => {
            let kind = if nullable(schema) || !required {
                "os"
            } else {
                "s"
            };
            let text = value.and_then(Value::as_str).unwrap_or_default();
            let _ = write!(
                out,
                "<div class=\"field\"><label for=\"{id}\">{shown}{mark}</label>\
                 <input id=\"{id}\" name=\"f:{kind}:{id}\" value=\"{}\">{description}</div>",
                escape(text)
            );
        }
        Some("integer" | "number") => {
            let text = value.map(Value::to_string).unwrap_or_default();
            let _ = write!(
                out,
                "<div class=\"field\"><label for=\"{id}\">{shown}{mark}</label>\
                 <input id=\"{id}\" type=\"number\" name=\"f:i:{id}\" value=\"{}\">{description}</div>",
                escape(&text)
            );
        }
        Some("boolean") => {
            let checked = if value.and_then(Value::as_bool) == Some(true) {
                " checked"
            } else {
                ""
            };
            let _ = write!(
                out,
                "<div class=\"field\"><input type=\"hidden\" name=\"h:{id}\" value=\"\">\
                 <label><input type=\"checkbox\" name=\"b:{id}\" value=\"true\"{checked}> {shown}{mark}</label>{description}</div>"
            );
        }
        Some(_) | None => {}
    }
}

fn has_choice(schema: &Value) -> bool {
    schema.get("enum").is_some() || schema.get("oneOf").is_some() || schema.get("anyOf").is_some()
}

/// A scalar as one line of text. A string is itself. Anything else is its
/// JSON.
fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other @ (Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::Array(_)
        | Value::Object(_)) => other.to_string(),
    }
}

/// One line of text as a scalar: a bool, an integer, or else a string.
fn scalar_of(line: &str) -> Value {
    match line {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        other => other
            .parse::<i64>()
            .map_or_else(|_| Value::String(other.to_owned()), Value::from),
    }
}

/// The whole form of `draft` under the file schema: the fields, the hidden
/// draft, and the buttons.
#[must_use]
pub fn render_policy(schemas: &Schemas, draft: &Value) -> String {
    let mut out = String::new();
    render(
        &mut out,
        schemas,
        &schemas.file,
        Some(draft),
        "",
        "policy.json",
        true,
    );
    out
}

/// Why a posted form does not apply to the draft.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormError {
    #[error("the draft is not JSON")]
    Draft,
    #[error("the field {0} is not JSON")]
    Json(String),
    #[error("the field {0} is not a whole number")]
    Number(String),
    #[error("the key for {0} is empty")]
    EmptyKey(String),
}

/// Set `value` at `pointer` in `draft`, creating objects on the way.
fn set(draft: &mut Value, pointer: &str, value: Value) {
    let parts = steps(pointer);
    let Some((last, parents)) = parts.split_last() else {
        *draft = value;
        return;
    };
    let mut at = draft;
    for part in parents {
        if !at.is_object() {
            *at = Value::Object(Map::new());
        }
        let Some(object) = at.as_object_mut() else {
            return;
        };
        at = object
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if !at.is_object() {
        *at = Value::Object(Map::new());
    }
    if let Some(object) = at.as_object_mut() {
        object.insert(last.clone(), value);
    }
}

/// Remove the entry at `pointer` from `draft`.
fn remove(draft: &mut Value, pointer: &str) {
    let parts = steps(pointer);
    let Some((last, parents)) = parts.split_last() else {
        return;
    };
    let mut at = draft;
    for part in parents {
        match at.get_mut(part) {
            Some(next) => at = next,
            None => return,
        }
    }
    if let Some(object) = at.as_object_mut() {
        object.remove(last);
    }
}

/// What the posted form asks for, after its fields are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Show the draft again.
    Edit,
    /// Send the draft to the check.
    Check,
    /// Check the draft, then write it.
    Save,
}

/// Apply the posted fields to the draft and read the action.
///
/// # Errors
///
/// Returns a [`FormError`] for a field that cannot become JSON.
pub fn apply(fields: &[(String, String)]) -> Result<(Value, Action), FormError> {
    let draft_text = fields
        .iter()
        .find(|(name, _)| name == "draft")
        .map(|(_, value)| value.as_str())
        .unwrap_or("{}");
    let mut draft: Value = serde_json::from_str(draft_text).map_err(|_| FormError::Draft)?;

    let mut variants: Vec<(String, String)> = Vec::new();
    let mut payloads: Vec<(String, String)> = Vec::new();
    let checked: Vec<&str> = fields
        .iter()
        .filter_map(|(name, _)| name.strip_prefix("b:"))
        .collect();
    for (name, value) in fields {
        if let Some(pointer) = name.strip_prefix("h:") {
            set(&mut draft, pointer, Value::Bool(checked.contains(&pointer)));
            continue;
        }
        let Some(rest) = name.strip_prefix("f:") else {
            continue;
        };
        let Some((kind, pointer)) = rest.split_once(':') else {
            continue;
        };
        match kind {
            "s" => set(&mut draft, pointer, Value::String(value.clone())),
            "os" => {
                if value.is_empty() {
                    remove(&mut draft, pointer);
                } else {
                    set(&mut draft, pointer, Value::String(value.clone()));
                }
            }
            "i" => {
                let number: i64 = value
                    .trim()
                    .parse()
                    .map_err(|_| FormError::Number(pointer.to_owned()))?;
                set(&mut draft, pointer, Value::from(number));
            }
            "x" => set(&mut draft, pointer, scalar_of(value.trim())),
            "lines" => {
                let items = value
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(|line| Value::String(line.to_owned()))
                    .collect();
                set(&mut draft, pointer, Value::Array(items));
            }
            "xlines" => {
                let items = value
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(scalar_of)
                    .collect();
                set(&mut draft, pointer, Value::Array(items));
            }
            "json" => {
                let parsed =
                    serde_json::from_str(value).map_err(|_| FormError::Json(pointer.to_owned()))?;
                set(&mut draft, pointer, parsed);
            }
            "variant" => variants.push((pointer.to_owned(), value.clone())),
            "payload" => payloads.push((pointer.to_owned(), value.clone())),
            _ => {}
        }
    }
    for (pointer, variant) in &variants {
        let payload = payloads
            .iter()
            .find(|(p, _)| p == pointer)
            .map(|(_, text)| text.as_str())
            .unwrap_or("");
        let items: Vec<Value> = payload
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(scalar_of)
            .collect();
        let mut object = Map::new();
        object.insert(variant.clone(), Value::Array(items));
        set(&mut draft, pointer, Value::Object(object));
    }

    let action = fields
        .iter()
        .find(|(name, _)| name == "action")
        .map(|(_, value)| value.as_str())
        .unwrap_or("edit");
    let action = match action {
        "check" => Action::Check,
        "save" => Action::Save,
        other => {
            if let Some(pointer) = other.strip_prefix("add:") {
                let key = fields
                    .iter()
                    .find(|(name, _)| name == &format!("key:{pointer}"))
                    .map(|(_, value)| value.trim())
                    .unwrap_or("");
                if key.is_empty() {
                    return Err(FormError::EmptyKey(pointer.to_owned()));
                }
                let template = fields
                    .iter()
                    .find(|(name, _)| name == &format!("tpl:{pointer}"))
                    .and_then(|(_, value)| serde_json::from_str(value).ok())
                    .unwrap_or(Value::Object(Map::new()));
                set(&mut draft, &format!("{pointer}/{}", step(key)), template);
            } else if let Some(pointer) = other.strip_prefix("remove:") {
                remove(&mut draft, pointer);
            }
            Action::Edit
        }
    };
    Ok((draft, action))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schemas() -> Schemas {
        Schemas {
            file: serde_json::json!({
                "type": "object",
                "properties": {
                    "version": {"type": "integer"},
                    "apps": {
                        "type": "object",
                        "additionalProperties": {"$ref": "#/$defs/App"}
                    }
                },
                "required": ["version"],
                "additionalProperties": false,
                "$defs": {
                    "App": {
                        "type": "object",
                        "properties": {
                            "note": {"type": ["string", "null"]},
                            "token_sha256": {"type": "array", "items": {"type": "string"}},
                            "on": {"type": "boolean"},
                            "mode": {"type": "string", "enum": ["none", "required"]},
                            "fence": {"oneOf": [
                                {"type": "object", "properties": {"allow": {"type": "array", "items": {"anyOf": [{"type": "boolean"}, {"type": "integer"}, {"type": "string"}]}}}, "required": ["allow"]},
                                {"type": "object", "properties": {"deny": {"type": "array", "items": {"type": "string"}}}, "required": ["deny"]}
                            ]},
                            "plugins": {"type": "object", "additionalProperties": true}
                        },
                        "required": ["token_sha256"],
                        "additionalProperties": false
                    }
                }
            }),
            sections: serde_json::json!({
                "ha-call": {"type": "object", "properties": {"entities": {"type": "array", "items": {"type": "string"}}}, "required": ["entities"]}
            })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        }
    }

    #[test]
    fn the_form_shows_digests_as_a_count_and_a_plugin_section_by_its_schema() {
        let draft = serde_json::json!({
            "version": 1,
            "apps": {"librechat": {
                "token_sha256": ["a", "b"],
                "plugins": {"ha-call": {"entities": ["light.kitchen"]}}
            }}
        });
        let html = render_policy(&schemas(), &draft);
        assert!(html.contains("2 token digest(s) present"), "{html}");
        assert!(!html.contains("\"a\""));
        assert!(html.contains("name=\"f:lines:/apps/librechat/plugins/ha-call/entities\""));
        assert!(html.contains("light.kitchen"));
        assert!(html.contains("name=\"f:i:/version\" value=\"1\""));
        assert!(html.contains("action\" value=\"remove:/apps/librechat\""));
        assert!(html.contains("name=\"key:/apps\""));
    }

    #[test]
    fn posted_fields_apply_to_the_draft_by_kind() {
        let fields = vec![
            (
                "draft".to_owned(),
                r#"{"version":1,"apps":{"a":{"token_sha256":[]}}}"#.to_owned(),
            ),
            ("f:i:/version".to_owned(), "2".to_owned()),
            ("f:os:/apps/a/note".to_owned(), "".to_owned()),
            ("h:/apps/a/on".to_owned(), String::new()),
            ("b:/apps/a/on".to_owned(), "true".to_owned()),
            ("f:s:/apps/a/mode".to_owned(), "required".to_owned()),
            ("f:variant:/apps/a/fence".to_owned(), "allow".to_owned()),
            (
                "f:payload:/apps/a/fence".to_owned(),
                "true\n7\nx".to_owned(),
            ),
            (
                "f:lines:/apps/a/plugins/ha-call/entities".to_owned(),
                "light.a\n\nlight.b".to_owned(),
            ),
            ("action".to_owned(), "check".to_owned()),
        ];
        let (draft, action) = apply(&fields).unwrap();
        assert_eq!(action, Action::Check);
        assert_eq!(draft["version"], 2);
        assert!(draft["apps"]["a"].get("note").is_none());
        assert_eq!(draft["apps"]["a"]["on"], true);
        assert_eq!(draft["apps"]["a"]["mode"], "required");
        assert_eq!(
            draft["apps"]["a"]["fence"],
            serde_json::json!({"allow": [true, 7, "x"]})
        );
        assert_eq!(
            draft["apps"]["a"]["plugins"]["ha-call"]["entities"],
            serde_json::json!(["light.a", "light.b"])
        );
    }

    #[test]
    fn add_and_remove_change_the_draft_and_show_it_again() {
        let fields = vec![
            ("draft".to_owned(), r#"{"version":1,"apps":{}}"#.to_owned()),
            ("key:/apps".to_owned(), "new-app".to_owned()),
            ("tpl:/apps".to_owned(), r#"{"token_sha256":[]}"#.to_owned()),
            ("action".to_owned(), "add:/apps".to_owned()),
        ];
        let (draft, action) = apply(&fields).unwrap();
        assert_eq!(action, Action::Edit);
        assert_eq!(
            draft["apps"]["new-app"]["token_sha256"],
            serde_json::json!([])
        );

        let fields = vec![
            ("draft".to_owned(), draft.to_string()),
            ("action".to_owned(), "remove:/apps/new-app".to_owned()),
        ];
        let (draft, _) = apply(&fields).unwrap();
        assert!(draft["apps"].as_object().unwrap().is_empty());

        let fields = vec![
            ("draft".to_owned(), r#"{"apps":{}}"#.to_owned()),
            ("key:/apps".to_owned(), "  ".to_owned()),
            ("action".to_owned(), "add:/apps".to_owned()),
        ];
        assert_eq!(
            apply(&fields).unwrap_err(),
            FormError::EmptyKey("/apps".into())
        );
    }

    #[test]
    fn a_template_fills_the_required_properties() {
        let schemas = schemas();
        let app = template(&serde_json::json!({"$ref": "#/$defs/App"}), &schemas.file);
        assert_eq!(app, serde_json::json!({"token_sha256": []}));
        let fence = template(
            &schemas.file["$defs"]["App"]["properties"]["fence"],
            &schemas.file,
        );
        assert_eq!(fence, serde_json::json!({"allow": []}));
    }

    #[test]
    fn text_is_escaped() {
        assert_eq!(
            escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
