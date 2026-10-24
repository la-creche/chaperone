//! The mechanical parts of the comment rules in `AGENTS.md`. A test in
//! `tests/comments.rs` runs these checks over every Rust source file of the
//! workspace, so `cargo test` and CI enforce them. Rule 1 and rule 4 need a
//! human reader. This crate does not check them.

use std::fmt;

/// The longest comment sentence, in words (`docs/writing-standard.md` 3).
pub const SENTENCE_MAX: usize = 25;

/// Words that tie a comment to outside context (`AGENTS.md`, comment rule 2).
const OUTSIDE_CONTEXT: &[&str] = &[
    "review",
    "reviewer",
    "finding",
    "pull request",
    "conversation",
    "the fix",
];

/// Words that describe what the code did before (`AGENTS.md`, comment rule 3).
const HISTORY: &[&str] = &["previously", "used to", "no longer", "anymore"];

/// Words that point at an unnamed later change (`AGENTS.md`, comment rule 3).
const UNNAMED_LATER: &[&str] = &[
    "todo",
    "fixme",
    "xxx",
    "for now",
    "eventually",
    "in the future",
];

/// One comment rule that a comment breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The comment names outside context.
    OutsideContext,
    /// The comment cites a change by number or holds a date.
    Reference,
    /// The comment describes what the code did before.
    History,
    /// The comment points at a later change with no build step.
    UnnamedLater,
    /// The comment holds a semicolon or an em dash.
    Punctuation,
    /// A sentence of the comment is longer than [`SENTENCE_MAX`] words.
    LongSentence,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutsideContext => "names outside context (comment rule 2)",
            Self::Reference => "cites a change by number or holds a date (comment rule 2)",
            Self::History => "describes what the code did before (comment rule 3)",
            Self::UnnamedLater => "points at a later change with no build step (comment rule 3)",
            Self::Punctuation => "holds a semicolon or an em dash (writing standard 3)",
            Self::LongSentence => "has a sentence over 25 words (writing standard 3)",
        })
    }
}

/// One fault at one line of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub line: usize,
    pub fault: Fault,
}

/// One comment block: consecutive comment lines, with the line number of
/// the first one.
struct Block {
    start: usize,
    lines: Vec<String>,
}

/// The text of a comment line, or `None` for a line that is no comment.
fn comment_text(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("//!")
        .or_else(|| trimmed.strip_prefix("///"))
        .or_else(|| trimmed.strip_prefix("//"))?;
    Some(rest.strip_prefix(' ').unwrap_or(rest))
}

/// Split `source` into comment blocks. Lines inside a fenced code block of a
/// doc comment are left out, because they hold code, not prose.
fn blocks(source: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut current: Option<Block> = None;
    let mut fenced = false;
    for (index, line) in source.lines().enumerate() {
        let Some(text) = comment_text(line) else {
            blocks.extend(current.take());
            fenced = false;
            continue;
        };
        if text.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        current
            .get_or_insert_with(|| Block {
                start: index + 1,
                lines: Vec::new(),
            })
            .lines
            .push(text.to_owned());
    }
    blocks.extend(current);
    blocks
}

/// The text with each code span in backticks replaced by one word, so code
/// does not count as prose.
fn without_code(text: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for part in text.split('`') {
        if in_code {
            out.push_str("CODE");
        } else {
            out.push_str(part);
        }
        in_code = !in_code;
    }
    out
}

/// Whether `text` holds `word` as a whole word or phrase, in any case.
fn has_word(text: &str, word: &str) -> bool {
    let lower = text.to_lowercase();
    let mut from = 0;
    while let Some(found) = lower.get(from..).and_then(|rest| rest.find(word)) {
        let start = from + found;
        let end = start + word.len();
        let before = lower[..start].chars().next_back();
        let after = lower[end..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric());
        if boundary(before) && boundary(after) {
            return true;
        }
        from = end;
    }
    false
}

/// Whether `text` cites a change by number, with a number sign or the
/// two-letter short form, or holds a date in the form YYYY-MM-DD.
fn has_reference(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digits = |from: usize, count: usize| {
        bytes
            .get(from..from + count)
            .is_some_and(|run| run.iter().all(u8::is_ascii_digit))
    };
    let date = (0..bytes.len()).any(|at| {
        digits(at, 4)
            && bytes.get(at + 4) == Some(&b'-')
            && digits(at + 5, 2)
            && bytes.get(at + 7) == Some(&b'-')
            && digits(at + 8, 2)
    });
    let number = (0..bytes.len()).any(|at| bytes[at] == b'#' && digits(at + 1, 1));
    date || number || has_word(text, "pr")
}

/// Check one comment block.
fn check_block(block: &Block) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut add = |offset: usize, fault: Fault| {
        let finding = Finding {
            line: block.start + offset,
            fault,
        };
        if !findings.contains(&finding) {
            findings.push(finding);
        }
    };
    for (offset, line) in block.lines.iter().enumerate() {
        let prose = without_code(line);
        if OUTSIDE_CONTEXT.iter().any(|word| has_word(&prose, word)) {
            add(offset, Fault::OutsideContext);
        }
        if has_reference(&prose) {
            add(offset, Fault::Reference);
        }
        if HISTORY.iter().any(|word| has_word(&prose, word)) {
            add(offset, Fault::History);
        }
        if UNNAMED_LATER.iter().any(|word| has_word(&prose, word)) {
            add(offset, Fault::UnnamedLater);
        }
        if prose.contains(';') || prose.contains('\u{2014}') {
            add(offset, Fault::Punctuation);
        }
    }
    for (offset, paragraph) in paragraphs(block) {
        let prose = without_code(&paragraph);
        for sentence in prose.split_inclusive(['.', '!', '?']) {
            if sentence.split_whitespace().count() > SENTENCE_MAX {
                add(offset, Fault::LongSentence);
            }
        }
    }
    findings
}

/// Whether a comment line starts a new paragraph: a heading or a list item.
fn starts_paragraph(line: &str) -> bool {
    let line = line.trim_start();
    let numbered = line.split_once(". ").is_some_and(|(number, _)| {
        !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
    });
    line.starts_with('#') || line.starts_with("- ") || line.starts_with("| ") || numbered
}

/// The paragraphs of a block, each with the offset of its first line. A
/// blank line ends a paragraph. A heading, a list item or a table row
/// starts a new one, so a line with no period does not join the next line.
fn paragraphs(block: &Block) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut open = false;
    for (offset, line) in block.lines.iter().enumerate() {
        if line.trim().is_empty() {
            open = false;
            continue;
        }
        if open && !starts_paragraph(line) {
            if let Some((_, text)) = out.last_mut() {
                text.push(' ');
                text.push_str(line);
            }
        } else {
            out.push((offset, line.clone()));
            open = true;
        }
    }
    out
}

/// Check every comment of one Rust source file.
#[must_use]
pub fn check(source: &str) -> Vec<Finding> {
    blocks(source).iter().flat_map(check_block).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn faults(source: &str) -> Vec<Fault> {
        check(source)
            .into_iter()
            .map(|finding| finding.fault)
            .collect()
    }

    #[test]
    fn a_clean_comment_passes() {
        assert!(faults("/// The time `duration` later.\nfn f() {}\n").is_empty());
        assert!(faults("//! A module doc.\n").is_empty());
    }

    #[test]
    fn each_rule_is_caught() {
        assert_eq!(faults("// See the review.\n"), [Fault::OutsideContext]);
        assert_eq!(faults("// Added in #12.\n"), [Fault::Reference]);
        assert_eq!(faults("// Changed on 2026-10-24.\n"), [Fault::Reference]);
        assert_eq!(faults("// This used to panic.\n"), [Fault::History]);
        assert_eq!(faults("// TODO: tidy.\n"), [Fault::UnnamedLater]);
        assert_eq!(faults("// One; two.\n"), [Fault::Punctuation]);
        let long = format!("// {}.\n", vec!["word"; 26].join(" "));
        assert_eq!(faults(&long), [Fault::LongSentence]);
    }

    #[test]
    fn code_is_not_prose() {
        assert!(faults("/// Call `a; b` here.\n").is_empty());
        assert!(faults("/// ```\n/// let a = 1; // review\n/// ```\n").is_empty());
    }

    #[test]
    fn a_word_inside_another_word_is_not_a_hit() {
        assert!(faults("// The preview shows a refinding.\n").is_empty());
        assert!(faults("// The process runs.\n").is_empty());
    }

    #[test]
    fn a_heading_does_not_join_the_next_sentence() {
        let words = vec!["word"; 20].join(" ");
        let source = format!("/// # Errors\n///\n/// Errors\n/// {words}.\nfn f() {{}}\n");
        assert!(check(&source).is_empty(), "{:?}", check(&source));
    }

    #[test]
    fn a_sentence_over_two_lines_counts_once() {
        let words = vec!["word"; 20].join(" ");
        let source = format!("// {words}\n// {words}.\n");
        assert_eq!(
            check(&source),
            [Finding {
                line: 1,
                fault: Fault::LongSentence
            }]
        );
    }
}
