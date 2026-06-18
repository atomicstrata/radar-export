#!/usr/bin/env bash
# Integration test harness for scripts/export-agent-sessions.sh.
#
# Runs the REAL export script end-to-end against synthetic ~/.claude and ~/.codex
# homes (via the CLAUDE_HOME/CODEX_HOME overrides the script supports), with the
# REAL radar-redact filter, and asserts on the produced export. Each test gets a
# fresh sandbox tempdir; nothing touches the developer's actual agent homes.
#
# Usage:  scripts/tests/export-agent-sessions.test.sh
# Exit:   0 if every assertion passed, 1 otherwise.
#
# Deliberately uses `set -u` but NOT `set -e`: a failing assertion must not abort
# the run — we want the full pass/fail tally.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXPORT_SCRIPT="$REPO_ROOT/scripts/export-agent-sessions.sh"

# Known sentinels reused across cases. The SECRETs must never survive into an
# export; the KEEP marker must always survive (redaction must not over-scrub
# ordinary text).
SECRET_SK="sk-ABCDEF1234567890abcdef1234567890"
SECRET_AWS="AKIAIOSFODNN7EXAMPLE"
KEEP="ORDINARY_TEXT_KEEP_ME"

PASS=0
FAIL=0
CURRENT=""

pass() { PASS=$((PASS + 1)); }
fail() {
  FAIL=$((FAIL + 1))
  echo "  ✗ [$CURRENT] $1" >&2
}

# --- assertions -------------------------------------------------------------

assert_status() { # expected actual msg
  if [[ "$1" == "$2" ]]; then pass; else fail "${3:-status}: expected exit $1, got $2"; fi
}
assert_file() { # path msg
  if [[ -f "$1" ]]; then pass; else fail "${2:-expected file}: $1 missing"; fi
}
assert_no_file() { # path msg
  if [[ ! -e "$1" ]]; then pass; else fail "${2:-unexpected file}: $1 exists"; fi
}
assert_grep() { # pattern path msg
  if grep -rq -- "$1" "$2" 2>/dev/null; then pass; else fail "${3:-expected match}: '$1' not in $2"; fi
}
assert_no_grep() { # pattern path msg
  if grep -rq -- "$1" "$2" 2>/dev/null; then fail "${3:-unexpected match}: '$1' found in $2"; else pass; fi
}

# Load-bearing security assertion: NO known secret anywhere under the export dir.
assert_export_clean() { # export_dir
  if grep -rqF -e "$SECRET_SK" -e "$SECRET_AWS" "$1" 2>/dev/null; then
    fail "SECURITY: a raw secret survived into $1"
  else
    pass
  fi
}

# --- sandbox + fixture builders --------------------------------------------

new_sandbox() { # -> sets SBX, CH, CO, OUT
  SBX="$(mktemp -d "${TMPDIR:-/tmp}/radar-export-test.XXXXXX")"
  CH="$SBX/claude"
  CO="$SBX/codex"
  OUT="$SBX/out"
  mkdir -p "$CH/projects" "$CH/sessions" "$CO/sessions" "$OUT"
}

# Claude encodes the project cwd into the project dir name: / -> - with a leading -.
claude_enc() { printf -- '-%s' "${1//\//-}"; }

add_claude_project_session() { # cwd session_name jsonl_body...
  local cwd="$1" name="$2"
  shift 2
  local dir="$CH/projects/$(claude_enc "$cwd")"
  mkdir -p "$dir"
  printf '%s\n' "$@" > "$dir/$name.jsonl"
}

add_claude_session_meta() { # cwd session_name (single json object with cwd)
  local cwd="$1" name="$2"
  printf '{"cwd":"%s","id":"%s","%s":"x"}\n' "$cwd" "$name" "$KEEP" > "$CH/sessions/$name.json"
}

add_codex_session() { # cwd session_name extra_line
  local cwd="$1" name="$2" extra="${3:-}"
  local dir="$CO/sessions/2026/06/15"
  mkdir -p "$dir"
  {
    printf '{"type":"session_meta","payload":{"cwd":"%s"}}\n' "$cwd"
    [[ -n "$extra" ]] && printf '%s\n' "$extra"
  } > "$dir/$name.jsonl"
}

run_export() { # args... ; runs against the sandbox homes, captures EXIT + LOG
  LOG="$SBX/run.log"
  CLAUDE_HOME="$CH" CODEX_HOME="$CO" RADAR_EXPORT_BIN="$EXPORT_BIN" \
    bash "$EXPORT_SCRIPT" "$@" > "$LOG" 2>&1
  EXIT=$?
}

cleanup_sandbox() { [[ -n "${SBX:-}" && -d "$SBX" ]] && rm -rf "$SBX"; }

# --- build the export binary once ------------------------------------------
# The wrapper reuses this prebuilt binary (via RADAR_EXPORT_BIN), so per-test
# runs do not rebuild. radar-export carries the redactor in-process.

echo "Building radar-export…" >&2
if ! cargo build --release -p radar-export >/dev/null 2>&1; then
  echo "FATAL: could not build radar-export" >&2
  exit 1
fi
EXPORT_BIN="$REPO_ROOT/target/release/radar-export"
REDACT_BIN="$EXPORT_BIN"  # the json_with_escapes test builds the filter itself
[[ -x "$EXPORT_BIN" ]] || { echo "FATAL: $EXPORT_BIN missing after build" >&2; exit 1; }

# ============================================================================
# Test cases
# ============================================================================

test_redacts_secrets_keeps_text() {
  CURRENT="redacts_secrets_keeps_text"
  new_sandbox
  add_claude_project_session "$SBX/proj" sess \
    "{\"cwd\":\"$SBX/proj\",\"text\":\"start\"}" \
    "{\"text\":\"key $SECRET_SK and $SECRET_AWS and $KEEP\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_export_clean "$OUT/e"
  assert_grep "<redacted>" "$OUT/e/sources/claude" "secret replaced with marker"
  assert_grep "$KEEP" "$OUT/e/sources/claude" "ordinary text preserved"
  # Every redacted JSONL line must still be valid JSON.
  if python3 -c "import json,sys; [json.loads(l) for l in open(sys.argv[1])]" \
        "$OUT/e/sources/claude/projects/$(claude_enc "$SBX/proj")/sess.jsonl" 2>/dev/null; then
    pass; else fail "redacted JSONL is not valid JSON"; fi
  cleanup_sandbox
}

test_json_with_escapes_stays_valid() {
  CURRENT="json_with_escapes_stays_valid"
  new_sandbox
  local gh="ghp_abcdefghijklmnopqrstuvwx123456"
  # A string VALUE embedding escaped quotes and a backslash right next to a
  # secret — the exact shape that corrupted real transcripts under raw-text
  # redaction (35 valid lines -> invalid). Single quotes keep the \" and \\
  # literal in the file. The JSON-aware filter must scrub the token AND keep the
  # line valid JSON.
  local line='{"cwd":"'"$SBX/proj"'","text":"he said \"deploy '"$gh"'\\path\" now"}'
  add_claude_project_session "$SBX/proj" sess "$line"
  # Guard: the SOURCE is valid JSON, so we are exercising the JSON path (not the
  # non-JSON text fallback).
  python3 -c "import json,sys; json.loads(open(sys.argv[1]).readline())" \
    "$CH/projects/$(claude_enc "$SBX/proj")/sess.jsonl" 2>/dev/null \
    || { fail "test fixture is not valid JSON"; cleanup_sandbox; return; }
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  local f="$OUT/e/sources/claude/projects/$(claude_enc "$SBX/proj")/sess.jsonl"
  assert_no_grep "$gh" "$f" "secret scrubbed despite adjacent escapes"
  if python3 -c "import json,sys; [json.loads(l) for l in open(sys.argv[1])]" \
        "$f" 2>/dev/null; then
    pass; else fail "redacted JSONL with escapes is not valid JSON"; fi
  cleanup_sandbox
}

test_scope_includes_and_excludes() {
  CURRENT="scope_includes_and_excludes"
  new_sandbox
  add_claude_project_session "$SBX/in" inside "{\"cwd\":\"$SBX/in\",\"text\":\"$KEEP-IN\"}"
  add_claude_project_session "$SBX/out" outside "{\"cwd\":\"$SBX/out\",\"text\":\"$KEEP-OUT\"}"
  run_export --project "$SBX/in" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_grep "$KEEP-IN" "$OUT/e" "in-scope session included"
  assert_no_grep "$KEEP-OUT" "$OUT/e" "out-of-scope session excluded"
  cleanup_sandbox
}

test_scope_nested_cwd_included() {
  CURRENT="scope_nested_cwd_included"
  new_sandbox
  add_claude_project_session "$SBX/proj/sub/dir" nested "{\"cwd\":\"$SBX/proj/sub/dir\",\"text\":\"$KEEP-NESTED\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_grep "$KEEP-NESTED" "$OUT/e" "session in a subdir of the project root is in scope"
  cleanup_sandbox
}

test_session_without_cwd_excluded_when_scoped() {
  CURRENT="session_without_cwd_excluded_when_scoped"
  new_sandbox
  add_claude_project_session "$SBX/proj" nocwd "{\"text\":\"$KEEP-NOCWD\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_no_grep "$KEEP-NOCWD" "$OUT/e" "session with no recorded cwd is excluded in scoped mode"
  cleanup_sandbox
}

test_all_mode_includes_everything() {
  CURRENT="all_mode_includes_everything"
  new_sandbox
  add_claude_project_session "$SBX/a" sa "{\"cwd\":\"$SBX/a\",\"text\":\"$KEEP-A\"}"
  add_claude_project_session "$SBX/b" sb "{\"text\":\"$KEEP-B-NOCWD\"}"  # no cwd, still included in --all
  run_export --all --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_grep "$KEEP-A" "$OUT/e" "--all includes scoped session"
  assert_grep "$KEEP-B-NOCWD" "$OUT/e" "--all includes cwd-less session"
  cleanup_sandbox
}

test_codex_session_redacted_and_scoped() {
  CURRENT="codex_session_redacted_and_scoped"
  new_sandbox
  add_codex_session "$SBX/proj" cx "{\"text\":\"codex $SECRET_SK $KEEP-CODEX\"}"
  add_codex_session "$SBX/other" cxout "{\"text\":\"$KEEP-CODEX-OUT\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_grep "$KEEP-CODEX" "$OUT/e/sources/codex" "in-scope codex session included"
  assert_no_grep "$KEEP-CODEX-OUT" "$OUT/e" "out-of-scope codex session excluded"
  assert_export_clean "$OUT/e"
  cleanup_sandbox
}

test_codex_index_only_in_all() {
  CURRENT="codex_index_only_in_all"
  new_sandbox
  printf '{"id":"x","title":"%s"}\n' "$KEEP-IDX" > "$CO/session_index.jsonl"
  add_codex_session "$SBX/proj" cx "{\"text\":\"$KEEP\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name scoped
  assert_no_grep "$KEEP-IDX" "$OUT/scoped" "session_index excluded in scoped mode"
  run_export --all --output-dir "$OUT" --name allmode
  assert_grep "$KEEP-IDX" "$OUT/allmode/sources/codex/session_index.jsonl" "session_index included in --all"
  cleanup_sandbox
}

test_claude_session_meta_json_scoped() {
  CURRENT="claude_session_meta_json_scoped"
  new_sandbox
  add_claude_session_meta "$SBX/proj" smeta
  add_claude_session_meta "$SBX/elsewhere" smeta_out
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_file "$OUT/e/sources/claude/sessions/smeta.json" "in-scope session metadata included"
  assert_no_file "$OUT/e/sources/claude/sessions/smeta_out.json" "out-of-scope session metadata excluded"
  cleanup_sandbox
}

test_dry_run_writes_nothing() {
  CURRENT="dry_run_writes_nothing"
  new_sandbox
  add_claude_project_session "$SBX/proj" sess "{\"cwd\":\"$SBX/proj\",\"text\":\"$KEEP\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e --dry-run
  assert_status 0 "$EXIT" "dry-run exit"
  assert_no_file "$OUT/e" "dry-run created no export dir"
  assert_no_file "$OUT/e.zip" "dry-run created no zip"
  assert_grep "matched files: 1" "$LOG" "dry-run reports the match count"
  assert_grep "would copy (redacted)" "$LOG" "dry-run notes redaction"
  cleanup_sandbox
}

test_outputs_present_and_manifest() {
  CURRENT="outputs_present_and_manifest"
  new_sandbox
  add_claude_project_session "$SBX/proj" sess "{\"cwd\":\"$SBX/proj\",\"text\":\"$KEEP\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "run"
  assert_file "$OUT/e.zip" "zip created"
  assert_file "$OUT/e/README.md" "README present"
  assert_file "$OUT/e/MANIFEST.csv" "manifest present"
  assert_file "$OUT/e/metadata/summary.json" "summary present"
  assert_grep "sources/claude/projects" "$OUT/e/MANIFEST.csv" "manifest lists the transcript"
  assert_grep "Redaction" "$OUT/e/README.md" "README documents redaction"
  cleanup_sandbox
}

test_relative_output_dir_creates_zip() {
  CURRENT="relative_output_dir_creates_zip"
  new_sandbox
  add_claude_project_session "$SBX/proj" sess "{\"cwd\":\"$SBX/proj\",\"text\":\"$KEEP\"}"
  # Regression: the zip step runs with cwd=output_dir, so a RELATIVE --output-dir
  # must still resolve. Run from inside the sandbox with a relative output path.
  ( cd "$SBX" && CLAUDE_HOME="$CH" CODEX_HOME="$CO" RADAR_EXPORT_BIN="$EXPORT_BIN" \
      bash "$EXPORT_SCRIPT" --project "$SBX/proj" --output-dir relout --name e >/dev/null 2>&1 )
  assert_status 0 "$?" "relative --output-dir export succeeds"
  assert_file "$SBX/relout/e.zip" "zip created with relative --output-dir"
  assert_file "$SBX/relout/e/MANIFEST.csv" "export tree created with relative --output-dir"
  cleanup_sandbox
}

test_non_utf8_fails_loud_no_partial() {
  CURRENT="non_utf8_fails_loud_no_partial"
  new_sandbox
  local dir="$CH/projects/$(claude_enc "$SBX/proj")"
  mkdir -p "$dir"
  # First line is valid (carries cwd so it is in scope); second line is invalid UTF-8.
  printf '{"cwd":"%s","text":"start"}\n' "$SBX/proj" > "$dir/bad.jsonl"
  printf '\xff\xfe not utf8\n' >> "$dir/bad.jsonl"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  # The filter must error on non-UTF-8 -> script fails AND leaves nothing behind:
  # no half-redacted transcript (atomic temp+rename), and no half-built export
  # tree or zip (fail-closed cleanup). A partial/unscanned artifact must never be
  # available to share. (codex review: fail-closed at the artifact, not just exit.)
  if [[ "$EXIT" -ne 0 ]]; then pass; else fail "expected non-zero exit on non-UTF-8 input"; fi
  assert_no_file "$OUT/e/sources/claude/projects/$(claude_enc "$SBX/proj")/bad.jsonl" \
    "partial redacted transcript not left behind"
  assert_no_file "$OUT/e/sources/claude/projects/$(claude_enc "$SBX/proj")/bad.jsonl.partial" \
    "temp .partial file cleaned up"
  assert_no_file "$OUT/e" "half-built export tree removed on failure"
  assert_no_file "$OUT/e.zip" "no zip left behind on failure"
  cleanup_sandbox
}

test_empty_homes_ok() {
  CURRENT="empty_homes_ok"
  new_sandbox
  run_export --all --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "empty homes still succeed"
  assert_grep "Matched files: 0" "$LOG" "reports zero matches"
  cleanup_sandbox
}

test_rerun_overwrites() {
  CURRENT="rerun_overwrites"
  new_sandbox
  add_claude_project_session "$SBX/proj" sess "{\"cwd\":\"$SBX/proj\",\"text\":\"$KEEP\"}"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  # Drop a stray file into the export dir; a re-run must rmtree and recreate it.
  touch "$OUT/e/STALE_FILE"
  run_export --project "$SBX/proj" --output-dir "$OUT" --name e
  assert_status 0 "$EXIT" "re-run"
  assert_no_file "$OUT/e/STALE_FILE" "re-run replaces the export dir cleanly"
  cleanup_sandbox
}

test_arg_errors() {
  CURRENT="arg_errors"
  new_sandbox
  run_export ; assert_status 0 "$EXIT" "no args -> prints help, exits 0"
  assert_grep "Usage" "$LOG" "no args prints usage"
  assert_grep "zip lands" "$LOG" "no-args help says where the zip lands"
  run_export --all --project "$SBX/x" ; assert_status 2 "$EXIT" "--all + --project rejected"
  run_export --bogus ; assert_status 2 "$EXIT" "unknown arg rejected"
  run_export --help ; assert_status 0 "$EXIT" "--help succeeds"
  assert_grep "Usage" "$LOG" "--help prints usage"
  cleanup_sandbox
}

# ============================================================================

for t in \
  test_redacts_secrets_keeps_text \
  test_json_with_escapes_stays_valid \
  test_scope_includes_and_excludes \
  test_scope_nested_cwd_included \
  test_session_without_cwd_excluded_when_scoped \
  test_all_mode_includes_everything \
  test_codex_session_redacted_and_scoped \
  test_codex_index_only_in_all \
  test_claude_session_meta_json_scoped \
  test_dry_run_writes_nothing \
  test_outputs_present_and_manifest \
  test_relative_output_dir_creates_zip \
  test_non_utf8_fails_loud_no_partial \
  test_empty_homes_ok \
  test_rerun_overwrites \
  test_arg_errors \
; do
  "$t"
done

echo
echo "export-agent-sessions tests: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
