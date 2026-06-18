//! Discover the in-scope transcript files under the Claude/Codex homes and map
//! each to its destination path inside the export tree. Mirrors the whitelist and
//! cwd-extraction rules of the former export script exactly.

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::cli::Config;

/// One file to redact into the export, with its manifest metadata.
pub struct Entry {
    pub src: PathBuf,
    /// Destination path relative to the export root.
    pub dest_rel: PathBuf,
    pub source: &'static str,
    pub cwd: Option<String>,
    pub notes: &'static str,
}

/// Gather every in-scope entry, in a deterministic (sorted-by-source-path) order.
pub fn collect(cfg: &Config) -> Vec<Entry> {
    let mut entries = Vec::new();
    collect_claude_projects(cfg, &mut entries);
    collect_claude_sessions(cfg, &mut entries);
    collect_codex(cfg, &mut entries);
    entries
}

fn collect_claude_projects(cfg: &Config, out: &mut Vec<Entry>) {
    let projects = cfg.claude_home.join("projects");
    for src in sorted_files(&projects, "jsonl") {
        let cwd = first_jsonl_cwd(&src);
        if !cfg.in_scope(cwd.as_deref()) {
            continue;
        }
        let rel = src.strip_prefix(&projects).unwrap_or(&src);
        out.push(Entry {
            dest_rel: Path::new("sources/claude/projects").join(rel),
            src: src.clone(),
            source: "claude",
            cwd,
            notes: "Claude Code project transcript JSONL",
        });
    }
    if cfg.include_all {
        for src in sorted_named(&projects, "sessions-index.json") {
            let rel = src.strip_prefix(&projects).unwrap_or(&src);
            out.push(Entry {
                dest_rel: Path::new("sources/claude/projects").join(rel),
                src: src.clone(),
                source: "claude",
                cwd: None,
                notes: "Claude Code project sessions index",
            });
        }
    }
}

fn collect_claude_sessions(cfg: &Config, out: &mut Vec<Entry>) {
    let sessions = cfg.claude_home.join("sessions");
    for src in sorted_files_shallow(&sessions, "json") {
        let cwd = json_file_cwd(&src);
        if !cfg.in_scope(cwd.as_deref()) {
            continue;
        }
        let name = src.file_name().unwrap_or_default();
        out.push(Entry {
            dest_rel: Path::new("sources/claude/sessions").join(name),
            src: src.clone(),
            source: "claude",
            cwd,
            notes: "Claude Code session metadata",
        });
    }
}

fn collect_codex(cfg: &Config, out: &mut Vec<Entry>) {
    let sessions = cfg.codex_home.join("sessions");
    for src in sorted_files(&sessions, "jsonl") {
        let cwd = session_meta_cwd(&src);
        if !cfg.in_scope(cwd.as_deref()) {
            continue;
        }
        let rel = src.strip_prefix(&sessions).unwrap_or(&src);
        out.push(Entry {
            dest_rel: Path::new("sources/codex/sessions").join(rel),
            src: src.clone(),
            source: "codex",
            cwd,
            notes: "Codex CLI session JSONL",
        });
    }
    // The codex index can reveal unrelated session titles, so it ships only in
    // --all mode.
    let index = cfg.codex_home.join("session_index.jsonl");
    if cfg.include_all && index.is_file() {
        out.push(Entry {
            dest_rel: PathBuf::from("sources/codex/session_index.jsonl"),
            src: index,
            source: "codex",
            cwd: None,
            notes: "Codex CLI session index; included only in --all mode",
        });
    }
}

/// All files under `dir` (recursive) with the given extension, sorted.
fn sorted_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    sorted_walk(dir, |p| p.extension().and_then(|e| e.to_str()) == Some(ext))
}

/// All files under `dir` (recursive) whose file name equals `name`, sorted.
fn sorted_named(dir: &Path, name: &str) -> Vec<PathBuf> {
    sorted_walk(dir, |p| {
        p.file_name().and_then(|n| n.to_str()) == Some(name)
    })
}

fn sorted_walk(dir: &Path, keep: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut files: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| keep(p))
        .collect();
    files.sort();
    files
}

/// Files directly under `dir` (non-recursive) with the given extension, sorted.
fn sorted_files_shallow(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some(ext))
        .collect();
    files.sort();
    files
}

/// Read a file as text, replacing invalid UTF-8 (like Python's `errors=replace`).
/// Used for cwd extraction so a transcript with non-UTF-8 bytes is still scoped
/// IN — the redactor then fails on it (fail-closed), rather than being silently
/// dropped from the export because its cwd could not be read.
fn read_lossy(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// First non-empty `cwd` from the top-level / `payload` / `message` of any
/// parseable JSON line.
fn first_jsonl_cwd(path: &Path) -> Option<String> {
    let text = read_lossy(path)?;
    for line in text.lines() {
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        for key_path in [&["cwd"][..], &["payload", "cwd"], &["message", "cwd"]] {
            if let Some(cwd) = dig_str(&obj, key_path) {
                return Some(cwd);
            }
        }
    }
    None
}

/// `cwd` of a single-object JSON session-metadata file.
fn json_file_cwd(path: &Path) -> Option<String> {
    let text = read_lossy(path)?;
    let obj: serde_json::Value = serde_json::from_str(&text).ok()?;
    dig_str(&obj, &["cwd"])
}

/// `payload.cwd` of the first `session_meta` line in a Codex transcript.
fn session_meta_cwd(path: &Path) -> Option<String> {
    let text = read_lossy(path)?;
    for line in text.lines() {
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if obj.get("type").and_then(|t| t.as_str()) == Some("session_meta") {
            return dig_str(&obj, &["payload", "cwd"]);
        }
    }
    None
}

/// Follow `keys` into nested objects and return the leaf as a non-empty string.
fn dig_str(obj: &serde_json::Value, keys: &[&str]) -> Option<String> {
    let mut cur = obj;
    for k in keys {
        cur = cur.get(k)?;
    }
    cur.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}
