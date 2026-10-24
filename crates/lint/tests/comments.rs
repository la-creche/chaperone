//! Every Rust source file of the workspace keeps the mechanical comment
//! rules of `AGENTS.md`.

use std::fs;
use std::path::{Path, PathBuf};

/// The directories that hold Rust sources, relative to the workspace root.
const ROOTS: &[&str] = &["crates", "plugins"];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `dir`, outside `target` directories, sorted.
fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "target") {
                sources(&path, found);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn every_comment_keeps_the_mechanical_rules() {
    let root = workspace();
    let mut files = Vec::new();
    for dir in ROOTS {
        sources(&root.join(dir), &mut files);
    }
    assert!(files.len() > 20, "found only {} source files", files.len());

    let mut report = Vec::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            report.push(format!("{}: cannot read", file.display()));
            continue;
        };
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        for finding in chaperone_lint::check(&text) {
            report.push(format!("{shown}:{} {}", finding.line, finding.fault));
        }
    }
    assert!(
        report.is_empty(),
        "comment rule breaks:\n{}",
        report.join("\n")
    );
}
