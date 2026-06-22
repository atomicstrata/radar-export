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

/// Drop un-analyzable opaque-blob fields that are pure noise for downstream
/// analysis (and a large fraction of export size): the Codex reasoning
/// `encrypted_content` (OpenAI-encrypted reasoning ciphertext) and the Claude
/// thinking-block `signature` (Anthropic integrity token). Both are removed ONLY
/// inside their owning block (`type":"reasoning"` / `type":"thinking"`), so a
/// `signature`/`encrypted_content` field meaning something else (e.g. a commit
/// signature) is never touched. The plaintext `summary` / `thinking` content
/// beside them is preserved — that is the part atomicradar can actually use.
fn strip_noise_fields(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        match map.get("type").and_then(|t| t.as_str()) {
            Some("reasoning") => {
                map.remove("encrypted_content");
            }
            Some("thinking") => {
                map.remove("signature");
            }
            _ => {}
        }
        for child in map.values_mut() {
            strip_noise_fields(child);
        }
    } else if let serde_json::Value::Array(items) = value {
        for child in items.iter_mut() {
            strip_noise_fields(child);
        }
    }
}

/// Minimum length for a no-whitespace base64/binary string value to be filtered
/// as an opaque blob. Useful transcript content (prose, code, diffs, tool output,
/// file contents) carries whitespace and ordinary punctuation; a value this long
/// with neither is binary data atomicradar cannot use (images, encoded
/// attachments). Short tokens/hashes stay in the secret redactor's scope.
const FILTER_BLOB_MIN_LEN: usize = 1024;

/// Fraction of a value's chars that must lie in the base64url alphabet for it to
/// count as an opaque blob — high enough that minified code (braces, parens,
/// operators) and prose (spaces) never qualify, only true base64/binary runs.
const FILTER_BLOB_BASE64_RATIO: f64 = 0.95;

/// True if `s` is a large opaque base64/binary blob: long, whitespace-free, and
/// almost entirely base64url charset. Catches images, data-URI payloads, and
/// other encoded attachments — none analyzable by atomicradar — while sparing
/// text, code, and diffs (which carry whitespace and non-base64 punctuation).
fn is_large_opaque_blob(s: &str) -> bool {
    if s.len() < FILTER_BLOB_MIN_LEN || s.bytes().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    let b64 = s
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
        .count();
    (b64 as f64 / s.len() as f64) >= FILTER_BLOB_BASE64_RATIO
}

/// Short placeholder for a filtered opaque blob, with a content-type hint from
/// the magic prefix (so atomicradar still sees *that* an image/attachment was
/// present) and the original byte length.
fn blob_placeholder(s: &str) -> String {
    let kind = if s.starts_with("data:") {
        "data-uri"
    } else if s.starts_with("/9j/") {
        "image/jpeg"
    } else if s.starts_with("iVBORw0KGgo") {
        "image/png"
    } else if s.starts_with("R0lGOD") {
        "image/gif"
    } else if s.starts_with("UklGR") {
        "image/webp"
    } else {
        "opaque"
    };
    format!("<filtered {kind} blob, {} bytes>", s.len())
}

/// Replace every large opaque-blob string value (anywhere in the JSON) with a
/// short placeholder. Runs BEFORE secret redaction so a blob is filtered as
/// un-useful content rather than mislabeled as a secret.
fn filter_large_blobs(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) if is_large_opaque_blob(s) => {
            *s = blob_placeholder(s);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(filter_large_blobs),
        serde_json::Value::Object(map) => map.values_mut().for_each(filter_large_blobs),
        _ => {}
    }
}

/// Redact one transcript line: drop noise fields, filter large opaque blobs, then
/// redact secrets. JSON-aware when it parses, raw-text otherwise.
fn redact_line(line: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(mut value) => {
            strip_noise_fields(&mut value);
            filter_large_blobs(&mut value);
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
            Ok(mut v) => {
                // Mirror redact_line: report only what survives noise-stripping
                // and blob-filtering, so dropped fields and filtered blobs are
                // not counted as redactions.
                strip_noise_fields(&mut v);
                filter_large_blobs(&mut v);
                report_value(&v, &rel, out)?
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_codex_reasoning_encrypted_content_keeps_summary() {
        let line = r#"{"type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"plan the work"}],"encrypted_content":"gAAAAABo5EUOg8AEoosfNTbXsecretciphertext"}}"#;
        let v: serde_json::Value = serde_json::from_str(&redact_line(line)).unwrap();
        assert!(
            v["payload"].get("encrypted_content").is_none(),
            "encrypted_content not dropped"
        );
        assert_eq!(v["payload"]["summary"][0]["text"], "plan the work");
    }

    #[test]
    fn drops_claude_thinking_signature_keeps_thinking() {
        let line = r#"{"message":{"content":[{"type":"thinking","thinking":"reason about it","signature":"Es4CCmMIDhgCsignaturedata"}]}}"#;
        let v: serde_json::Value = serde_json::from_str(&redact_line(line)).unwrap();
        assert!(
            v["message"]["content"][0].get("signature").is_none(),
            "signature not dropped"
        );
        assert_eq!(v["message"]["content"][0]["thinking"], "reason about it");
    }

    #[test]
    fn keeps_signature_outside_a_thinking_block() {
        // A `signature` on a non-thinking object (e.g. a commit signature) is a
        // real field, not the opaque thinking integrity token — preserve it.
        let line = r#"{"type":"commit","signature":"-----BEGIN PGP SIGNATURE-----"}"#;
        let v: serde_json::Value = serde_json::from_str(&redact_line(line)).unwrap();
        assert!(
            v.get("signature").is_some(),
            "non-thinking signature dropped"
        );
    }

    #[test]
    fn filters_large_base64_image_blob() {
        let img = format!("/9j/{}", "ABCDabcd1234".repeat(120)); // ~1.4KB, no ws, base64
        let line = format!(r#"{{"type":"image","source":{{"data":"{img}"}}}}"#);
        let v: serde_json::Value = serde_json::from_str(&redact_line(&line)).unwrap();
        let out = v["source"]["data"].as_str().unwrap();
        assert!(out.starts_with("<filtered"), "blob not filtered: {out}");
        assert!(out.contains("image/jpeg"), "type hint missing: {out}");
    }

    #[test]
    fn keeps_large_text_content() {
        // Large but real text (whitespace + prose) is preserved — useful signal.
        let text = "the daemon restarts cleanly and the test passes. ".repeat(40);
        let text = text.trim();
        let line = format!(r#"{{"type":"text","text":"{text}"}}"#);
        let v: serde_json::Value = serde_json::from_str(&redact_line(&line)).unwrap();
        assert_eq!(
            v["text"].as_str().unwrap().len(),
            text.len(),
            "real text wrongly filtered"
        );
    }

    #[test]
    fn keeps_minified_code_not_filtered() {
        // Minified code is large + low-whitespace but full of non-base64
        // punctuation; it is code (useful), not an opaque blob.
        let code = format!("function f(){{return {}0;}}", "a.b(c)*d[e]||f;".repeat(80));
        let line = format!(r#"{{"text":"{code}"}}"#);
        let v: serde_json::Value = serde_json::from_str(&redact_line(&line)).unwrap();
        assert!(
            !v["text"].as_str().unwrap().starts_with("<filtered"),
            "code wrongly filtered"
        );
    }
}
