//! Per-file redaction: stream a transcript through `radar_redact` (JSON-aware,
//! line by line) writing to a temp then atomically renaming, and — when verbose —
//! report every redacted span as `<rel>\t<REASON>\t<item>`.
//!
//! Redaction runs in-process via `radar_redact::redact_json_value`; there is no
//! subprocess, so this binary needs no external redactor.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use radar_redact::{redact, redact_json_value, scan, SecretKind};

/// Redact `src` into `dest` atomically (temp + rename). A non-UTF-8 line is a
/// hard error; the temp is removed and `dest` never appears, so a half-redacted
/// file is never committed.
pub fn redacting_copy(src: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("partial");
    let result = (|| {
        let reader = BufReader::new(File::open(src)?);
        let mut writer = BufWriter::new(File::create(&tmp)?);
        for line in reader.lines() {
            writeln!(writer, "{}", redact_line(&line?))?;
        }
        writer.flush()
    })();
    match result {
        Ok(()) => fs::rename(&tmp, dest),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Redact one transcript line: JSON-aware when it parses, raw-text otherwise.
fn redact_line(line: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(mut value) => {
            redact_json_value(&mut value);
            serde_json::to_string(&value).expect("re-serializing parsed JSON cannot fail")
        }
        Err(_) => redact(line),
    }
}

/// Write a `<rel>\t<REASON>\t<item>` line to `out` for every redacted span in
/// `src`. Mirrors `redact_line`: JSON keys + values are scanned, non-JSON lines
/// whole. This REVEALS cleartext for audit — callers send it to stderr only.
pub fn report_redactions(src: &Path, rel: &Path, out: &mut impl Write) -> io::Result<()> {
    let rel = rel.to_string_lossy();
    let reader = BufReader::new(File::open(src)?);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(v) => report_value(&v, &rel, out)?,
            Err(_) => report_str(&line, &rel, out)?,
        }
    }
    Ok(())
}

fn report_value(v: &serde_json::Value, rel: &str, out: &mut impl Write) -> io::Result<()> {
    match v {
        serde_json::Value::String(s) => report_str(s, rel, out),
        serde_json::Value::Array(a) => a.iter().try_for_each(|x| report_value(x, rel, out)),
        serde_json::Value::Object(o) => o.iter().try_for_each(|(k, x)| {
            report_str(k, rel, out)?;
            report_value(x, rel, out)
        }),
        _ => Ok(()),
    }
}

/// Emit one line per actually-redacted span, mirroring `redact()`'s merge:
/// overlapping findings collapse to one span named by the most specific kind.
fn report_str(s: &str, rel: &str, out: &mut impl Write) -> io::Result<()> {
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
        let item = s[start..end].replace(['\n', '\r', '\t'], " ");
        writeln!(out, "{rel}\t{}\t{item}", reason(best, &item))?;
        idx = k;
    }
    Ok(())
}

/// Higher = more specific/confident; wins when several findings overlap a span.
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
        SecretKind::HighEntropy if word_like(item) => "ENTROPY_IDENT",
        SecretKind::HighEntropy => "ENTROPY_BLOB",
    }
}

/// Hint: does the item contain a real word run (>=4 lowercase letters with a
/// vowel)? Splits ENTROPY_IDENT (likely a residual false positive) from
/// ENTROPY_BLOB; purely a label, the redaction already happened.
fn word_like(token: &str) -> bool {
    let mut run = 0usize;
    let mut vowel = false;
    for c in token.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_lowercase() {
            run += 1;
            vowel |= matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y');
        } else {
            if run >= 4 && vowel {
                return true;
            }
            run = 0;
            vowel = false;
        }
    }
    false
}
