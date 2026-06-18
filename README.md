# radar-export

A small, self-contained command-line tool that exports your **Claude Code** and
**Codex CLI** session transcripts as a **redacted** zip archive — for sharing
historical agent sessions for analysis without leaking secrets.

This repository contains the **complete source** for the tool so you can review
exactly what it does before you run it. There is nothing else: two Rust crates,
their tests, and the build scripts.

## What it does

For each transcript it finds, the tool:

1. **Scopes** by the session's recorded working directory (`--project PATH`) or
   takes everything (`--all`).
2. **Redacts** every line through `radar-redact` (the crate in this repo):
   known secret/token shapes (GitHub, AWS, Slack, GitLab, `sk-…` API keys, JWTs),
   secret-ish `KEY=VALUE` assignment values, and opaque high-entropy values become
   `<redacted>`. It does this JSON-aware, so JSONL framing is never corrupted.
3. **Keeps** the analysis signal on purpose: filesystem paths, code, function and
   identifier names, branch names, and URLs are NOT redacted.
4. Writes a folder + `.zip` with a `MANIFEST.csv`, a `README.md`, and a
   `metadata/summary.json`.

What it does **not** do: it is best-effort secret redaction, **not** PII removal.
The archive still contains your prose, directory structure, and raw session
context. Review the contents before sharing, and rotate any credential that may
have appeared in a session.

## Build

Requires a Rust toolchain (1.75+). No other runtime dependency — the compiled
binary is a single self-contained executable (no python, bash, cargo, or `zip`
needed to run it).

```bash
cargo build --release -p radar-export
# binary at: target/release/radar-export
```

## Run

```bash
# Show help (also shown when run with no arguments), including where the zip lands:
./target/release/radar-export --help

# Export sessions whose recorded cwd is in a given repo:
./target/release/radar-export --project ~/work/myrepo

# Export everything, and watch exactly what gets redacted as it streams:
./target/release/radar-export --all --verbose --output-dir /tmp

# Preview without writing anything:
./target/release/radar-export --project . --dry-run --verbose
```

By default the export folder and `.zip` are written to the current directory,
named `radar-agent-session-export-<date>`. Override with `--output-dir` / `--name`.

`--verbose` streams every redacted item to stderr as `<file>\t<REASON>\t<item>`
(REASON ∈ `API_KEY`, `GH_TOKEN`, `AWS_KEY`, `SLACK_TOKEN`, `GITLAB_TOKEN`, `JWT`,
`ENV_VALUE`, `ENTROPY_BLOB`, `ENTROPY_IDENT`) so you can audit the decisions.
Note: `--verbose` reveals cleartext secrets on your terminal.

## Verify the redactor

The redaction logic lives in `crates/radar-redact`. Its test suite encodes the
secret-detection and false-positive controls (including a shared conformance
corpus in `fixtures/`):

```bash
cargo test                                   # all crates
cargo test -p radar-redact                   # just the redactor
bash scripts/tests/export-agent-sessions.test.sh   # end-to-end export integration tests
```

## Layout

```
crates/radar-export/   the CLI binary (scoping, report, manifest, zip)
crates/radar-redact/   the secret/PII redactor (the security-critical part)
fixtures/              shared secret-detection conformance corpus (used by tests)
scripts/               convenience wrapper + a standalone redaction reporter + the
                       integration test harness
```

## Other tools in here

- `scripts/redaction-report.sh` — list every item the redactor would remove from
  any JSONL/text input, with a reason code (audit aid; reveals cleartext).
- `scripts/export-agent-sessions.sh` — a thin wrapper that builds (if needed) and
  runs the `radar-export` binary; identical behavior to running the binary directly.

## License

See [LICENSE](./LICENSE).
