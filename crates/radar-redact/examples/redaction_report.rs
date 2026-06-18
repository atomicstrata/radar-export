//! Emit one line per redacted item: `<REASON>\t<item>`.
//!
//! Reads JSONL (or plain text) on stdin and, for every secret `radar_redact`
//! would redact, prints a short REASON code and the matched item. JSON string
//! VALUES and KEYS are scanned (mirroring `redact_json_value`); non-JSON lines
//! are scanned as raw text. This is an audit aid — to see exactly WHAT the
//! redactor decided to remove and to judge true vs false positives.
//!
//! REASON codes:
//!   API_KEY / GH_TOKEN / AWS_KEY / SLACK_TOKEN / GITLAB_TOKEN / JWT  — known prefix
//!   ENV_VALUE        — secret-ish `KEY=VALUE` / `KEY: VALUE` assignment value
//!   ENTROPY_BLOB     — opaque high-entropy token (random/base64-shaped)
//!   ENTROPY_IDENT    — high-entropy token that looks identifier-shaped (likely a
//!                      false positive: a long function/test/tool name)
//!
//! WARNING: this prints CLEARTEXT secrets to stdout for human audit. Its output
//! is as sensitive as the input — do not share it. Use `radar-redact-filter` to
//! produce a redacted artifact; this tool is the opposite (it reveals).

use std::io::{self, BufRead, BufWriter, Write};

use radar_redact::{scan, SecretKind};

/// Hint for HighEntropy items: does the item contain a real word run (a
/// lowercase run of >= 4 letters with a vowel)? A residual function/test name
/// does; a random/base64 blob does not. Used only to split ENTROPY_IDENT (likely
/// a false positive worth eyeballing) from ENTROPY_BLOB.
fn identifier_like(token: &str) -> bool {
    let mut run = 0usize;
    let mut run_has_vowel = false;
    for c in token.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_lowercase() {
            run += 1;
            run_has_vowel |= matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y');
        } else {
            if run >= 4 && run_has_vowel {
                return true;
            }
            run = 0;
            run_has_vowel = false;
        }
    }
    false
}

/// Higher = more specific/confident; wins when several findings overlap one span.
fn priority(kind: SecretKind) -> u8 {
    match kind {
        SecretKind::ApiKey
        | SecretKind::GithubToken
        | SecretKind::AwsKey
        | SecretKind::SlackToken
        | SecretKind::GitlabToken
        | SecretKind::Jwt => 3,
        SecretKind::EnvAssignment => 2,
        SecretKind::HighEntropy => 1,
    }
}

fn reason(kind: SecretKind, item: &str) -> &'static str {
    match kind {
        SecretKind::GithubToken => "GH_TOKEN",
        SecretKind::AwsKey => "AWS_KEY",
        SecretKind::SlackToken => "SLACK_TOKEN",
        SecretKind::GitlabToken => "GITLAB_TOKEN",
        SecretKind::ApiKey => "API_KEY",
        SecretKind::Jwt => "JWT",
        SecretKind::EnvAssignment => "ENV_VALUE",
        SecretKind::HighEntropy if identifier_like(item) => "ENTROPY_IDENT",
        SecretKind::HighEntropy => "ENTROPY_BLOB",
    }
}

/// Report ONE line per actually-redacted span. Mirrors `redact()`'s merge: scan
/// findings are sorted by start; overlapping findings collapse into a single
/// span (the union), and the highest-[`priority`] kind among them names it — so
/// `OPENAI_API_KEY=sk-…` reports once as API_KEY, not three times.
fn report_str(s: &str, out: &mut impl Write) -> io::Result<()> {
    let findings = scan(s);
    let mut idx = 0;
    while idx < findings.len() {
        let start = findings[idx].start;
        let mut end = findings[idx].end;
        let mut best = findings[idx].kind;
        let mut k = idx + 1;
        while k < findings.len() && findings[k].start < end {
            end = end.max(findings[k].end);
            if priority(findings[k].kind) > priority(best) {
                best = findings[k].kind;
            }
            k += 1;
        }
        // Items never legitimately contain newlines; guard so one span stays one
        // output line.
        let item = s[start..end].replace(['\n', '\r', '\t'], " ");
        writeln!(out, "{}\t{}", reason(best, &item), item)?;
        idx = k;
    }
    Ok(())
}

fn report_value(v: &serde_json::Value, out: &mut impl Write) -> io::Result<()> {
    match v {
        serde_json::Value::String(s) => report_str(s, out),
        serde_json::Value::Array(a) => a.iter().try_for_each(|x| report_value(x, out)),
        serde_json::Value::Object(o) => o.iter().try_for_each(|(k, x)| {
            report_str(k, out)?;
            report_value(x, out)
        }),
        _ => Ok(()),
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(v) => report_value(&v, &mut out)?,
            Err(_) => report_str(&line, &mut out)?,
        }
    }
    out.flush()
}
