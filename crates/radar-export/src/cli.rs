//! Command-line surface and resolved [`Config`] for `radar-export`.
//!
//! Mirrors the behavior of the former `scripts/export-agent-sessions.sh`: same
//! flags, same `CLAUDE_HOME`/`CODEX_HOME` env overrides, same scoping. Running
//! with neither `--all` nor `--project` prints the full help (so the operator
//! sees where the zip will land) and exits 0.

use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use chrono::Utc;
use clap::Parser;

/// Default basename stem for the export folder/zip; a `-YYYY-MM-DD` date is
/// appended at runtime.
const NAME_STEM: &str = "radar-agent-session-export";

#[derive(Parser, Debug)]
#[command(
    name = "radar-export",
    about = "Export redacted Claude Code / Codex CLI session transcripts as a zip.",
    long_about = "Export redacted Claude Code / Codex CLI session transcripts as a folder + zip.\n\n\
        Every transcript is scrubbed line-by-line through the radar-redact secret/PII \
        redactor before it is written; known secret/token shapes, env-assignment values, \
        and opaque high-entropy values become <redacted>. Filesystem paths, code, and \
        identifiers are intentionally KEPT as analysis signal.\n\n\
        OUTPUT: a folder <output-dir>/<name>/ and a <output-dir>/<name>.zip. By default \
        <output-dir> is the current directory and <name> is \
        radar-agent-session-export-<today>. So with no --output-dir, the zip lands in the \
        directory you run this from.\n\n\
        Provide --all or at least one --project to run. With neither, this help is shown.",
    after_help = "EXAMPLES:\n  \
        radar-export --project ~/work/myrepo            # sessions whose cwd is in myrepo\n  \
        radar-export --all --output-dir /tmp            # every session, zip in /tmp\n  \
        radar-export --all --verbose                    # stream every redaction to stderr\n  \
        radar-export --project . --dry-run --verbose    # preview, write nothing"
)]
pub struct Cli {
    /// Include sessions whose recorded cwd is PATH or below it. May be repeated.
    #[arg(long, value_name = "PATH")]
    pub project: Vec<PathBuf>,

    /// Include all Claude/Codex transcripts found, regardless of cwd.
    #[arg(long)]
    pub all: bool,

    /// Directory where the export folder/zip are written (default: current dir).
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub output_dir: PathBuf,

    /// Export folder/zip basename (default: radar-agent-session-export-YYYY-MM-DD).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Print what would be exported, but write nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Stream every redacted item to stderr as `<rel>\t<REASON>\t<item>`.
    #[arg(long)]
    pub verbose: bool,
}

/// Fully-resolved, validated run configuration.
pub struct Config {
    pub claude_home: PathBuf,
    pub codex_home: PathBuf,
    pub output_dir: PathBuf,
    pub export_name: String,
    pub project_roots: Vec<PathBuf>,
    pub include_all: bool,
    pub dry_run: bool,
    pub verbose: bool,
}

impl Config {
    /// Resolve a [`Cli`] into a [`Config`], or return an error message (validation)
    /// or [`ExitCode`] (clean help-and-exit when no scope was requested).
    pub fn from_cli(cli: Cli) -> Result<Config, CliOutcome> {
        if !cli.all && cli.project.is_empty() {
            // No scope requested: show full help so the operator learns where the
            // zip lands, and exit cleanly (not an error).
            return Err(CliOutcome::Help);
        }
        if cli.all && !cli.project.is_empty() {
            return Err(CliOutcome::Error(
                "use either --all or --project, not both".into(),
            ));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let claude_home = env_home("CLAUDE_HOME", home.as_deref(), ".claude")?;
        let codex_home = env_home("CODEX_HOME", home.as_deref(), ".codex")?;
        let export_name = cli
            .name
            .unwrap_or_else(|| format!("{NAME_STEM}-{}", Utc::now().format("%Y-%m-%d")));
        let project_roots = cli.project.iter().map(|p| normalize(p)).collect();
        Ok(Config {
            claude_home,
            codex_home,
            output_dir: normalize(&cli.output_dir),
            export_name,
            project_roots,
            include_all: cli.all,
            dry_run: cli.dry_run,
            verbose: cli.verbose,
        })
    }

    /// True if a session with `cwd` is in scope: every session in `--all` mode, or
    /// one whose normalized cwd is at or below a `--project` root.
    pub fn in_scope(&self, cwd: Option<&str>) -> bool {
        if self.include_all {
            return true;
        }
        let Some(cwd) = cwd.filter(|c| !c.is_empty()) else {
            return false;
        };
        let p = normalize(Path::new(cwd));
        self.project_roots.iter().any(|root| p.starts_with(root))
    }
}

/// What `Config::from_cli` decided when it did not produce a `Config`.
pub enum CliOutcome {
    /// Print full help and exit 0.
    Help,
    /// A validation error message; print to stderr and exit 2.
    Error(String),
}

impl CliOutcome {
    /// Render the outcome and produce the process exit code.
    pub fn finish(self) -> ExitCode {
        use clap::CommandFactory;
        match self {
            CliOutcome::Help => {
                let _ = Cli::command().print_long_help();
                println!();
                ExitCode::SUCCESS
            }
            CliOutcome::Error(msg) => {
                eprintln!("radar-export: {msg}");
                ExitCode::from(2)
            }
        }
    }
}

fn env_home(var: &str, home: Option<&Path>, default_sub: &str) -> Result<PathBuf, CliOutcome> {
    if let Some(v) = std::env::var_os(var) {
        return Ok(normalize(Path::new(&v)));
    }
    match home {
        Some(h) => Ok(h.join(default_sub)),
        None => Err(CliOutcome::Error(format!(
            "neither ${var} nor $HOME is set; cannot locate {default_sub}"
        ))),
    }
}

/// Lexically normalize a path to absolute form: make it absolute (against the
/// current dir if relative) and resolve `.`/`..` WITHOUT touching the filesystem.
/// Recorded session cwds may no longer exist, so canonicalization is unusable.
pub fn normalize(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => out.push(comp.as_os_str()),
            Component::Normal(s) => out.push(s),
        }
    }
    out
}
