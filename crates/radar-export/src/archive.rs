//! Write the export's metadata (README, manifest, summary, project paths) and
//! pack the whole tree into a `.zip` in-process (no external `zip` binary).

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::cli::Config;
use crate::collect::Entry;

/// A manifest row, as written to MANIFEST.csv.
pub struct ManifestRow {
    pub source: &'static str,
    pub file_path: String,
    pub recorded_cwd: String,
    pub notes: &'static str,
}

/// Write README.md and metadata/project_paths.txt into `export_root`.
pub fn write_readme(cfg: &Config, export_root: &Path, generated_at: &str) -> io::Result<()> {
    let mode = if cfg.include_all {
        "all transcript files"
    } else {
        "project-scoped transcript files"
    };
    let readme = README_TEMPLATE
        .replace("{generated_at}", generated_at)
        .replace("{mode}", mode);
    fs::write(export_root.join("README.md"), readme)?;
    let meta = export_root.join("metadata");
    fs::create_dir_all(&meta)?;
    let mut paths = String::new();
    for root in &cfg.project_roots {
        paths.push_str(&root.to_string_lossy());
        paths.push('\n');
    }
    fs::write(meta.join("project_paths.txt"), paths)
}

/// Write MANIFEST.csv and metadata/summary.json.
pub fn write_manifest_and_summary(
    cfg: &Config,
    export_root: &Path,
    rows: &[ManifestRow],
    generated_at: &str,
) -> io::Result<()> {
    let mut csv = String::from("source,file_path,recorded_cwd,notes\n");
    for r in rows {
        csv.push_str(&csv_field(r.source));
        csv.push(',');
        csv.push_str(&csv_field(&r.file_path));
        csv.push(',');
        csv.push_str(&csv_field(&r.recorded_cwd));
        csv.push(',');
        csv.push_str(&csv_field(r.notes));
        csv.push('\n');
    }
    fs::write(export_root.join("MANIFEST.csv"), csv)?;

    let summary = serde_json::json!({
        "generated_at": generated_at,
        "mode": if cfg.include_all { "all" } else { "project" },
        "matched_files": rows.len(),
        "claude_home": cfg.claude_home.to_string_lossy(),
        "codex_home": cfg.codex_home.to_string_lossy(),
    });
    let body = serde_json::to_string_pretty(&summary).unwrap_or_default();
    fs::write(
        export_root.join("metadata").join("summary.json"),
        body + "\n",
    )
}

/// Build a manifest row from a collected entry (its dest path + recorded cwd).
pub fn manifest_row(entry: &Entry) -> ManifestRow {
    ManifestRow {
        source: entry.source,
        file_path: entry.dest_rel.to_string_lossy().into_owned(),
        recorded_cwd: entry.cwd.clone().unwrap_or_default(),
        notes: entry.notes,
    }
}

/// Pack `export_root` into `zip_path`, with archive paths prefixed by the export
/// folder name (so unzipping recreates `<name>/…`), Deflate-compressed.
pub fn zip_tree(export_root: &Path, zip_path: &Path) -> io::Result<()> {
    if zip_path.exists() {
        fs::remove_file(zip_path)?;
    }
    let root_name = export_root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut writer = ZipWriter::new(File::create(zip_path)?);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for entry in WalkDir::new(export_root).sort_by_file_name() {
        let entry = entry.map_err(io::Error::other)?;
        let rel = entry
            .path()
            .strip_prefix(export_root)
            .unwrap_or(entry.path());
        if rel.as_os_str().is_empty() {
            continue;
        }
        let name = format!("{root_name}/{}", rel.to_string_lossy());
        if entry.file_type().is_dir() {
            writer.add_directory(format!("{name}/"), opts)?;
        } else {
            writer.start_file(name, opts)?;
            writer.write_all(&fs::read(entry.path())?)?;
        }
    }
    writer.finish()?;
    Ok(())
}

/// CSV-quote a field (RFC-4180 style: wrap in quotes, double internal quotes).
fn csv_field(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

const README_TEMPLATE: &str = r#"# Radar agent session export

Generated: {generated_at}

Mode: {mode}

This archive contains Claude Code and Codex CLI session transcript files for Radar
historical import / analysis.

## Redaction (read this)

Every file in this archive was passed line-by-line through `radar-redact` (the
same secret/PII redactor the Radar daemon and control plane use) before it was
written. Detected secret/token shapes and high-entropy values are replaced with
`<redacted>`.

This redacts SECRETS, not context, and it is BEST-EFFORT, not a guarantee.

Filesystem paths are INTENTIONALLY KEPT — absolute `cwd`/file paths in the
transcripts, the MANIFEST `recorded_cwd` column, and `metadata/project_paths.txt`
all remain. They are analysis signal (which repo, monorepo vs standalone,
worktree layout, where in the tree the agent worked) for mining workflow
patterns, so the redactor deliberately does not strip them.

Redaction also does not remove arbitrary prose, names, or business-sensitive
text. So the archive still contains your directory structure and raw session
context: review the contents before sharing, and rotate any credential that may
have appeared in these sessions.

Included (each redacted):
- Claude Code project JSONL transcripts from `~/.claude/projects`
- Claude Code active/recent session metadata from `~/.claude/sessions` when `cwd` matches
- Codex CLI JSONL transcripts from `~/.codex/sessions`
- `~/.codex/session_index.jsonl` only in `--all` mode

Excluded as FILES (note: their content can still appear inside transcript bodies,
which is why redaction runs):
- credentials and auth files
- settings/config files
- SQLite logs/databases
- caches
- shell snapshots
- full source repositories
"#;
