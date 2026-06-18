#!/usr/bin/env bash
#
# redaction-report.sh — list every item radar-redact would redact, one per line,
# each prefixed with a short REASON code (see crates/radar-redact/examples/
# redaction_report.rs for the code list).
#
# Usage:
#   scripts/redaction-report.sh                      # read JSONL/text on stdin
#   scripts/redaction-report.sh FILE...              # scan specific files
#   scripts/redaction-report.sh DIR...               # scan every *.jsonl under DIR
#   scripts/redaction-report.sh --file DIR           # also prefix each line with the source path
#   scripts/redaction-report.sh --count DIR          # aggregate: "<count> <REASON>" sorted desc
#
# Output (default):  <REASON>\t<item>
# Output (--file):   <path>\t<REASON>\t<item>
# Output (--count):  <count> <REASON>
#
# WARNING: this prints CLEARTEXT secrets. Treat its output as sensitive as the
# input. To produce a REDACTED artifact instead, use scripts/export-agent-sessions.sh
# or the radar-redact-filter binary directly.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

mode="plain"
case "${1:-}" in
  --file) mode="file"; shift ;;
  --count) mode="count"; shift ;;
esac

echo "redaction-report: building reporter (one-time)…" >&2
if ! ( cd "$REPO_ROOT" && cargo build --release -p radar-redact --example redaction_report >&2 ); then
  echo "redaction-report: failed to build redaction_report" >&2
  exit 1
fi
BIN="$REPO_ROOT/target/release/examples/redaction_report"
[[ -x "$BIN" ]] || { echo "redaction-report: $BIN missing after build" >&2; exit 1; }

# Collect the list of input files (empty => stdin).
declare -a files=()
for path in "$@"; do
  if [[ -d "$path" ]]; then
    while IFS= read -r f; do files+=("$f"); done < <(find "$path" -name '*.jsonl' | sort)
  else
    files+=("$path")
  fi
done

emit() {
  if [[ "${#files[@]}" -eq 0 ]]; then
    "$BIN"
  else
    for f in "${files[@]}"; do
      if [[ "$mode" == "file" ]]; then
        "$BIN" < "$f" | sed "s#^#${f}\t#"
      else
        "$BIN" < "$f"
      fi
    done
  fi
}

if [[ "$mode" == "count" ]]; then
  emit | cut -f1 | sort | uniq -c | sort -rn
else
  emit
fi
