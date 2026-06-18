//! `radar-export` — a single self-contained executable that exports redacted
//! Claude Code / Codex CLI session transcripts as a folder + zip.
//!
//! It subsumes what previously required bash, python3, cargo, the `zip` binary,
//! and two compiled helpers: scoping by recorded cwd, JSON-aware redaction (via
//! the in-process `radar-redact` crate), the optional verbose redaction report,
//! the manifest/summary/README, and zip creation — all in one binary with no
//! runtime dependency. Honors `CLAUDE_HOME`/`CODEX_HOME` overrides.
//!
//! Fail-closed: if anything fails mid-build, the half-written export tree and zip
//! are removed so a partial, possibly-unscanned archive is never left behind.

mod archive;
mod cli;
mod collect;
mod redact;

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use chrono::Utc;
use clap::Parser;

use cli::{Cli, Config};
use collect::Entry;

fn main() -> ExitCode {
    let cfg = match Config::from_cli(Cli::parse()) {
        Ok(cfg) => cfg,
        Err(outcome) => return outcome.finish(),
    };
    match run(&cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("radar-export: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cfg: &Config) -> io::Result<()> {
    let entries = collect::collect(cfg);
    let export_root = cfg.output_dir.join(&cfg.export_name);
    let zip_path = cfg.output_dir.join(format!("{}.zip", cfg.export_name));
    let generated_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    if cfg.dry_run {
        return dry_run(cfg, &entries, &export_root, &zip_path);
    }

    // Fail-closed: any error after we start writing removes the partial export.
    let result = build_export(cfg, &entries, &export_root, &zip_path, &generated_at);
    if result.is_err() {
        let _ = fs::remove_dir_all(&export_root);
        let _ = fs::remove_file(&zip_path);
    }
    result
}

fn dry_run(cfg: &Config, entries: &[Entry], export_root: &Path, zip_path: &Path) -> io::Result<()> {
    let mut err = io::stderr().lock();
    for entry in entries {
        if cfg.verbose {
            redact::report_redactions(&entry.src, &entry.dest_rel, &mut err)?;
        }
        println!(
            "would copy (redacted) {} -> {}",
            entry.src.display(),
            export_root.join(&entry.dest_rel).display()
        );
    }
    println!("would create {}", zip_path.display());
    println!("matched files: {}", entries.len());
    Ok(())
}

fn build_export(
    cfg: &Config,
    entries: &[Entry],
    export_root: &Path,
    zip_path: &Path,
    generated_at: &str,
) -> io::Result<()> {
    if export_root.exists() {
        fs::remove_dir_all(export_root)?;
    }
    fs::create_dir_all(export_root)?;
    archive::write_readme(cfg, export_root, generated_at)?;

    let mut err = io::stderr().lock();
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        if cfg.verbose {
            redact::report_redactions(&entry.src, &entry.dest_rel, &mut err)?;
        }
        redact::redacting_copy(&entry.src, &export_root.join(&entry.dest_rel))?;
        rows.push(archive::manifest_row(entry));
    }
    drop(err);

    archive::write_manifest_and_summary(cfg, export_root, &rows, generated_at)?;
    archive::zip_tree(export_root, zip_path)?;

    let mut out = io::stdout().lock();
    writeln!(out, "Created: {}", zip_path.display())?;
    writeln!(
        out,
        "Manifest: {}",
        export_root.join("MANIFEST.csv").display()
    )?;
    writeln!(out, "Matched files: {}", rows.len())?;
    Ok(())
}
