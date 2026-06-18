//! `radar-redact-filter` — stdin→stdout secret redactor for JSONL transcripts.
//!
//! Reads text on stdin one LINE at a time and writes the redacted line to
//! stdout, so a JSONL transcript keeps one JSON object per line. Each line is
//! handled JSON-first:
//!
//!   * If the line parses as JSON, [`radar_redact::redact_json_value`] scrubs
//!     every string VALUE in place and the document is re-serialized. This is
//!     the only correct way to redact JSON — editing the raw text can rewrite a
//!     secret span across an escape sequence (`\"`, `\\`) and break the line's
//!     framing, turning valid JSON into invalid JSON (observed on real
//!     transcripts). Value-level redaction is structure-preserving by
//!     construction. Re-serialized objects come out with serde_json's default
//!     sorted keys (values untouched) — key order is irrelevant to the JSON
//!     consumers that read the export.
//!   * If the line is NOT JSON (e.g. a plain-text log line), it falls back to
//!     raw-text [`radar_redact::redact`].
//!
//! Detection is per-line and automatic — there is no `--json` flag — because a
//! transcript can interleave JSON and non-JSON lines, and the right behavior is
//! always "redact JSON correctly when it is JSON, redact text otherwise."
//!
//! Used by `scripts/export-agent-sessions.sh` to scrub agent transcripts before
//! they leave the machine. This is the SAME redactor the daemon and control
//! plane use, so the export and the product agree on what counts as a secret.
//!
//! Best-effort by design: it catches known secret/token shapes and high-entropy
//! values, NOT arbitrary prose, names, or filesystem paths. A redacted export
//! still warrants a human review before sharing.

use std::io::{self, BufRead, BufWriter, Write};

/// Redact a single transcript line. JSON lines are scrubbed at the value level
/// (framing preserved); non-JSON lines fall back to raw-text redaction.
fn redact_line(line: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(mut value) => {
            radar_redact::redact_json_value(&mut value);
            // Re-serialization of an already-parsed value cannot fail for any
            // value serde_json itself produced from `from_str`.
            serde_json::to_string(&value).expect("re-serializing parsed JSON cannot fail")
        }
        Err(_) => radar_redact::redact(line),
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        // A non-UTF-8 line is a hard error rather than a silent pass-through: we
        // must not emit bytes we did not scan.
        let line = line?;
        writeln!(out, "{}", redact_line(&line))?;
    }
    out.flush()
}
