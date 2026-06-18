#!/usr/bin/env bash
#
# export-agent-sessions.sh — convenience wrapper around the `radar-export` binary.
#
# All export logic lives in ONE self-contained executable (crates/radar-export):
# scoping by recorded cwd, JSON-aware redaction, the --verbose redaction report,
# the manifest/README, and zip creation. This script just locates (or builds) that
# binary and execs it, so the documented path keeps working and there is a single
# source of truth.
#
# For delivery to someone without the Rust toolchain, hand them the compiled
# `radar-export` binary instead — it has no python/bash/cargo/zip dependency.
#
# Usage (run with --help for the full list; no args prints help):
#   scripts/export-agent-sessions.sh --project "$PWD"
#   scripts/export-agent-sessions.sh --all --verbose --output-dir /tmp
#
# Env: CLAUDE_HOME (default ~/.claude), CODEX_HOME (default ~/.codex),
#      RADAR_EXPORT_BIN (use a prebuilt binary instead of locating/building one).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BIN="${RADAR_EXPORT_BIN:-}"
if [[ -z "$BIN" ]]; then
  for cand in "$REPO_ROOT/target/release/radar-export" "$REPO_ROOT/target/debug/radar-export"; do
    [[ -x "$cand" ]] && { BIN="$cand"; break; }
  done
fi
if [[ -z "$BIN" && -f "$REPO_ROOT/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
  echo "export-agent-sessions: building radar-export (one-time)…" >&2
  ( cd "$REPO_ROOT" && cargo build --release -p radar-export >&2 )
  BIN="$REPO_ROOT/target/release/radar-export"
fi
if [[ ! -x "$BIN" ]]; then
  echo "export-agent-sessions: radar-export binary not found and could not be built." >&2
  echo "  Build it:  cargo build --release -p radar-export" >&2
  echo "  or set RADAR_EXPORT_BIN=/path/to/radar-export." >&2
  exit 1
fi

exec "$BIN" "$@"
