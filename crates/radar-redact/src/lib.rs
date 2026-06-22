//! Shared secret / PII redactor (FR-003, trust-boundary boundary re-scan).
//!
//! This crate is consumed on **both sides** of the local→hosted boundary so the
//! same detector vocabulary backs every re-scan:
//!
//!   * In the **local daemon** it is the *second* line of defense (defense in
//!     depth): the hook (`hooks/shared/sanitize.js`) redacts known-secret token
//!     shapes before raw session bytes ever cross the loopback, and the daemon
//!     re-scans already-distilled content before it can be ingested or shared.
//!   * In the **hosted control plane** it is the *enforcement* boundary: the
//!     daemon is untrusted code shipped to user devices, so the control plane
//!     re-scans every shared atom itself (decision D28) and fails closed —
//!     never trusting the daemon's daemon-side gate.
//!
//! "Raw never crosses" is the primary rule; this scanner is the secret-byte
//! backstop behind it on both sides.
//!
//! Parity with the hook: the same prefix-anchored token classes (GitHub, AWS,
//! Slack, GitLab, JWT). Prefix-anchoring is load-bearing — it is precisely why
//! commit SHAs and UUIDs do not match the token detectors.
//!
//! Beyond the hook (FR-003), this module adds two detectors the JS version
//! lacks:
//!   1. **Env-file assignments** — `KEY=VALUE` / `KEY: VALUE` where the key name
//!      looks secret-ish and the value is non-trivial. The value is redacted;
//!      the key stays visible.
//!   2. **High-entropy values** — a conservative secondary detector for opaque
//!      high-entropy tokens that match no known prefix. It is deliberately tuned
//!      to NOT flag legitimate dev artifacts (git SHAs, UUIDs, filesystem
//!      paths), because false alarms are a first-class concern.
//!
//! Determinism: every public function produces identical output for identical
//! input. No RNG, no wall-clock, no map-iteration-order dependence. Findings
//! carry only byte offsets — never a copy of the secret text — so they can be
//! logged safely.

#![deny(missing_docs)]

use std::sync::OnceLock;

use regex::Regex;

/// Minimum length of a standalone token before the high-entropy detector will
/// even consider it. Short tokens carry too little signal to classify safely.
const MIN_ENTROPY_TOKEN_LEN: usize = 32;

/// Shannon entropy threshold (bits per character) that a sufficiently long
/// standalone token must **strictly exceed** to be treated as a likely secret.
/// 4.0 bits/char sits well above ordinary prose while catching base64-ish keys.
///
/// The comparison is strict-greater (`> 4.0`), not `>=`, and that choice is
/// load-bearing for the hex false-positive controls: a hex alphabet has 16
/// symbols, so its maximum possible per-char entropy is exactly `log2(16) = 4.0`
/// bits — reached only by a perfectly uniform hex string. With strict-greater,
/// no pure-hex string of any length can ever clear the gate, which gives the
/// entropy detector zero false-positives on hex ids regardless of the length
/// exemptions below.
const ENTROPY_BITS_THRESHOLD: f64 = 4.0;

/// Length of a hex-encoded MD5 digest (also the shape of a dash-stripped UUID or
/// any 128-bit hex id). Exempt from the high-entropy detector. Belt-and-braces
/// alongside the strict-greater entropy gate, which already spares hex.
const HEX_MD5_LEN: usize = 32;

/// Length of a hex-encoded SHA-1 digest (git object id). Exempt from the
/// high-entropy detector so commit SHAs are never flagged.
const HEX_SHA1_LEN: usize = 40;

/// Length of a hex-encoded SHA-256 digest. Also exempt from the high-entropy
/// detector.
const HEX_SHA256_LEN: usize = 64;

/// Minimum value length for an env-file assignment to be treated as a secret.
/// Trivially short values (e.g. `DEBUG=1`) are not redacted.
const MIN_ENV_VALUE_LEN: usize = 6;

/// Separator characters that delimit identifier segments. Beyond snake_case /
/// kebab-case (`_`/`-`), this includes path/branch/URL separators (`/`/`.`) and
/// `key=value` (`=`). Treating these as separators is what lets the word-coverage
/// test recognize branch names (`feat/gh-237-add-harness`), migration paths
/// (`api/alembic/versions/..._merge_heads`), and URLs as structured identifiers
/// rather than opaque blobs — while base64 (mixed-case, non-word segments) still
/// fails the test. `+` and TRAILING `=` remain base64 signals and are NOT
/// separators (see [`looks_like_identifier`]).
const IDENTIFIER_SEPARATORS: [char; 5] = ['_', '-', '/', '.', '='];

/// Maximum fraction of digits a token may contain and still be treated as an
/// identifier rather than an opaque token. Real secrets are digit-dense
/// (base64/base62 average ~16% digits, often higher); identifiers are
/// letter-dominated. 0.4 leaves headroom for date-stamped names
/// (`...-2026-05-23`) without admitting digit-heavy blobs.
const MAX_IDENTIFIER_DIGIT_RATIO: f64 = 0.4;

/// Minimum segment length to count as a "word". Real identifier words
/// (`status`, `client`, `tool`, `case`) reach this; the short chaotic fragments
/// a random/base64 token splits into (`Xk`, `ZQp`, `Rt`) do not.
const IDENTIFIER_WORD_MIN_LEN: usize = 4;

/// A token must contain at least this many word segments to be an identifier.
/// Single opaque runs (`singleopaquelowercaserun`) have one "word" and stay
/// redacted.
const MIN_IDENTIFIER_WORDS: usize = 2;

/// Minimum fraction of a token's letters that must belong to word segments. Real
/// identifiers are almost entirely words (≈1.0); random tokens fragment into
/// mostly non-word pieces and fall well under this.
const MIN_IDENTIFIER_WORD_COVERAGE: f64 = 0.6;

/// A URL/path must have at least this many tame structural segments (words,
/// uuids, hashes, digits, short path words) to be exempted as a URL/path. A
/// slash-bearing base64 blob fragments into opaque mixed-case chunks that are
/// NOT tame, so it never reaches two and stays redacted; a real URL/path
/// (`com/services/…`, `org/en-US/docs/…`, `9650/ext/bc/<id>/rpc`) easily clears
/// it. Deliberately no cap on opaque segments: an ordinary URL may carry several
/// ids, and a known secret-bearing URL (Slack webhook) is redacted precisely by
/// [`scan_tokens`] regardless — so exempting the surrounding URL keeps the
/// redaction surgical (only the secret segment goes, host/ids survive).
const MIN_URL_PATH_TAME_SEGMENTS: usize = 2;

/// Segments at or below this length are tame structural path words (`ext`, `bc`,
/// `rpc`, `api`, `v1`, `com`). Kept at 3 so a 4-char base64 chunk (`Zm9v`) is
/// NOT tame and a slash-split base64 blob stays redacted.
const SHORT_PATH_SEGMENT_LEN: usize = 3;

/// Length floor for an env-assignment value to be considered secret-shaped by
/// entropy. Lower than [`MIN_ENTROPY_TOKEN_LEN`] (the standalone floor) because
/// the secret-ish key corroborates — the env detector's unique role is catching
/// medium-length opaque values a bare standalone scan would skip.
const MIN_ENV_SECRET_VALUE_LEN: usize = 16;

/// Replacement text substituted for every redacted secret span.
const REDACTION_PLACEHOLDER: &str = "<redacted>";

/// The class of secret a [`SecretFinding`] identifies.
///
/// `EnvAssignment` and `HighEntropy` are the FR-003 additions beyond the hook's
/// token classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// GitHub token (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`).
    GithubToken,
    /// AWS access key id (`AKIA`/`ASIA`).
    AwsKey,
    /// Slack token (`xox[abp]-…`).
    SlackToken,
    /// GitLab personal access token (`glpat-…`).
    GitlabToken,
    /// Anthropic / OpenAI-style API secret key (`sk-…`).
    ApiKey,
    /// JSON Web Token (`eyJ….….…`).
    Jwt,
    /// Secret-ish env-file assignment value (`API_KEY=…`).
    EnvAssignment,
    /// Opaque high-entropy token matching no known prefix.
    HighEntropy,
}

/// A detected secret occurrence, identified purely by its byte span.
///
/// The struct intentionally has **no string field**: it never carries a copy of
/// the secret text, so findings can be logged or persisted without leaking the
/// value they describe. `start`/`end` are byte offsets into the scanned input
/// (`end` exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretFinding {
    /// The class of secret detected.
    pub kind: SecretKind,
    /// Inclusive byte offset where the secret span begins.
    pub start: usize,
    /// Exclusive byte offset where the secret span ends.
    pub end: usize,
}

/// One prefix-anchored token detector: a compiled regex plus the kind it emits.
struct TokenPattern {
    regex: Regex,
    kind: SecretKind,
}

/// Compile the prefix-anchored token detectors once, lazily.
///
/// These mirror `hooks/shared/sanitize.js` exactly. Compilation cannot fail at
/// runtime for these literal patterns; the `expect` lives only in the one-time
/// initializer path, never on a per-call public path.
fn token_patterns() -> &'static [TokenPattern] {
    static PATTERNS: OnceLock<Vec<TokenPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // Each spec is the *body* of a known-secret token (no anchors). The body
        // is wrapped below in `(?:^|[^A-Za-z0-9])(body)` so the prefix is accepted
        // at the start of the value OR after any non-alphanumeric delimiter —
        // crucially including `_`. A `\b`-anchored prefix does NOT fire after `_`
        // (an underscore is a regex word char), so `config_sk-…`, `setting_AKIA…`,
        // `prefix_glpat-…` etc. would otherwise bypass redaction entirely. The
        // alphanumeric guard still rejects mid-word substrings (`task-…` never
        // matches `sk-`). Capture group 1 is the secret; the delimiter is not
        // consumed into the redacted span.
        let specs: &[(&str, SecretKind)] = &[
            (r"ghp_[A-Za-z0-9]{20,}", SecretKind::GithubToken),
            (r"gho_[A-Za-z0-9]{20,}", SecretKind::GithubToken),
            (r"ghu_[A-Za-z0-9]{20,}", SecretKind::GithubToken),
            (r"ghs_[A-Za-z0-9]{20,}", SecretKind::GithubToken),
            (r"ghr_[A-Za-z0-9]{20,}", SecretKind::GithubToken),
            (r"AKIA[A-Z0-9]{16}", SecretKind::AwsKey),
            (r"ASIA[A-Z0-9]{16}", SecretKind::AwsKey),
            (r"xox[abp]-[A-Za-z0-9-]+", SecretKind::SlackToken),
            (r"glpat-[A-Za-z0-9_-]{20,}", SecretKind::GitlabToken),
            // Anthropic / OpenAI secret keys — added to hooks/shared/sanitize.js in
            // the dogfood-producer slice; mirrored here to keep the sets aligned.
            (r"sk-[A-Za-z0-9_-]{10,}", SecretKind::ApiKey),
            (
                r"eyJ[A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+",
                SecretKind::Jwt,
            ),
        ];
        specs
            .iter()
            .map(|(body, kind)| TokenPattern {
                regex: Regex::new(&format!(r"(?:^|[^A-Za-z0-9])({body})"))
                    .expect("static secret pattern must compile"),
                kind: *kind,
            })
            .collect()
    })
}

/// Compile the env-file assignment detector once, lazily.
///
/// Matches `KEY=VALUE` or `KEY: VALUE` where the key contains a secret-ish
/// word. Capture group 1 is the value span (the part actually redacted); the
/// key is preserved. The value stops at whitespace, quotes, or end of line so
/// surrounding text is not swallowed.
fn env_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        let key = "(?i)[A-Za-z0-9_]*\
            (?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|\
            CREDENTIAL|CREDS|AUTH|SESSION_KEY)[A-Za-z0-9_]*";
        let pattern = format!(r#"\b{key}\s*[:=]\s*["']?([^\s"']+)["']?"#);
        Regex::new(&pattern).expect("static env-assignment pattern must compile")
    })
}

/// Compile the standalone-token splitter once, lazily.
///
/// A "standalone token" is a maximal run of characters that can appear in an
/// opaque secret (alphanumerics plus a small punctuation set). The high-entropy
/// detector evaluates each such run independently. Path handling splits two
/// ways: `\` (backslash) is NOT in the class, so a Windows path is broken into
/// short segments that individually fall below [`MIN_ENTROPY_TOKEN_LEN`]; `/`
/// (forward slash) IS in the class, so a Unix path matches as one long token and
/// relies on the [`looks_like_path`] exemption to avoid being flagged.
fn standalone_token_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9+/=_\-]{16,}").expect("static token pattern must compile")
    })
}

/// Compile the Slack incoming-webhook detector once, lazily.
///
/// `hooks.slack.com/services/T<id>/B<id>/<secret>` — the trailing segment is the
/// webhook secret (anyone holding the full URL can post to the channel). Capture
/// group 1 is the secret segment ONLY, so redaction leaves the host + team/bot
/// ids (workflow context) intact and removes just the credential. This runs in
/// [`scan_tokens`], so it fires even though the high-entropy URL exemption skips
/// the same span — the precise detector is the authority for this known-secret
/// URL shape.
fn slack_webhook_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/([A-Za-z0-9]{16,})")
            .expect("static slack webhook pattern must compile")
    })
}

/// Shannon entropy of `s` in bits per character over its byte distribution.
///
/// Deterministic: iterates a fixed-size frequency table, never a hash map, so
/// there is no iteration-order nondeterminism in the floating-point sum.
fn shannon_entropy_bits(s: &str) -> f64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in counts.iter() {
        if count == 0 {
            continue;
        }
        let p = f64::from(count) / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// True if `s` is a hex string of exactly MD5 (128-bit), SHA-1, or SHA-256
/// length. Length 32 also covers a dash-stripped UUID / any 128-bit hex id.
fn is_hex_digest(s: &str) -> bool {
    (s.len() == HEX_MD5_LEN || s.len() == HEX_SHA1_LEN || s.len() == HEX_SHA256_LEN)
        && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True if `s` is a canonical `8-4-4-4-12` hex UUID.
fn is_uuid(s: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let mut parts = s.split('-');
    for &expected in groups.iter() {
        match parts.next() {
            Some(part) if part.len() == expected && part.bytes().all(|b| b.is_ascii_hexdigit()) => {
            }
            _ => return false,
        }
    }
    parts.next().is_none()
}

/// True if `s` is an ANCHORED filesystem path (absolute, home, explicit
/// relative, or a Windows drive).
///
/// **Load-bearing — do not remove as apparently-dead code.** Because `/` is part
/// of the standalone-token character class (see [`standalone_token_pattern`]), a
/// long Unix path matches as a single token and would otherwise clear the
/// high-entropy gate.
///
/// Only ANCHORED paths are exempted here. UN-anchored relative paths and branch
/// names (`crates/foo/mod.rs`, `feat/gh-237-…`) are recognized by
/// [`looks_like_identifier`]'s word-coverage test instead — which, unlike a
/// per-segment entropy check, is not fooled by a base64 blob split into short
/// low-entropy chunks by incidental slashes (the old un-anchored branch was).
/// `+`/trailing-`=` are base64 signals, so a base64 token that happens to start
/// with `/` is still not treated as a path.
fn looks_like_path(s: &str) -> bool {
    if s.contains('+') || s.ends_with('=') {
        return false;
    }
    s.starts_with('/')
        || s.starts_with('~')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('\\')
        || s.contains(":\\")
}

/// True if `seg` is a hex-and-dash id (a uuid fragment / worktree id), e.g.
/// `46c9-8d66-74551c200319`: only hex digits and dashes, at least one hex digit.
/// A base64 chunk has non-hex letters / mixed case, so it never qualifies.
fn is_hex_dash_id(seg: &str) -> bool {
    !seg.is_empty()
        && seg.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        && seg.bytes().any(|b| b.is_ascii_hexdigit())
}

/// True if a `/`-separated segment is "tame" — a structural URL/path segment
/// rather than an opaque secret chunk: a very short path word (`ext`/`bc`/`rpc`),
/// all-digits, a hex digest, a uuid, a hex-dash id, or a cleanly-structured
/// word/identifier. Used by [`looks_like_url_path`]. The short-word floor stays
/// at 3 so a 4-char base64 chunk is NOT tame (keeps base64 blobs redacted).
fn is_tame_path_segment(seg: &str) -> bool {
    !seg.is_empty()
        && (seg.len() <= SHORT_PATH_SEGMENT_LEN
            || seg.bytes().all(|b| b.is_ascii_digit())
            || is_hex_digest(seg)
            || is_uuid(seg)
            || is_hex_dash_id(seg)
            || is_word_segment(seg)
            || looks_like_identifier(seg))
}

/// True if `token` is `key=<id-or-hash>` where the value is a uuid, a hex digest,
/// or an (optionally `0x`-prefixed) hex run — a non-secret id/hash in a query
/// param or key=value (`thread_id=<uuid>`, `ref=<sha>`, `datasetId=0x<hex>`).
///
/// Safe by construction: pure hex/uuid values are never high-entropy secrets the
/// detector would otherwise catch (hex maxes at exactly 4.0 bits/char, the
/// strict-greater gate already spares it), so this only fixes the LABEL on a
/// mixed letters+hex token — it never exempts an opaque base64 secret after `=`
/// (those are not all-hex, so the value check fails).
fn looks_like_keyed_id(token: &str) -> bool {
    let Some(eq) = token.rfind('=') else {
        return false;
    };
    let (key, val) = (&token[..eq], &token[eq + 1..]);
    if key.is_empty() || val.is_empty() {
        return false;
    }
    let key_ok = key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    let hex_val = val
        .strip_prefix("0x")
        .or_else(|| val.strip_prefix("0X"))
        .unwrap_or(val);
    let is_long_hex =
        hex_val.len() >= HEX_MD5_LEN && hex_val.bytes().all(|b| b.is_ascii_hexdigit());
    key_ok && (is_uuid(val) || is_hex_digest(hex_val) || is_long_hex)
}

/// True if `token` is a `+`-joined list of words (`typecheck+build+test`,
/// `standalone+grouped`) rather than a `+`-bearing base64 blob. Reuses
/// [`looks_like_identifier`] by treating `+` as a separator (mapping it to `-`);
/// a base64 blob's chunks are not clean words, so it still fails. A trailing `=`
/// (base64 padding) is rejected by `looks_like_identifier` itself.
fn looks_like_word_list(token: &str) -> bool {
    token.contains('+') && looks_like_identifier(&token.replace('+', "-"))
}

/// True if `token` is a URL or multi-segment path rather than an opaque blob.
///
/// Exempts ordinary URLs/paths whose segments are structural (words/ids/hashes/
/// short path words) with at most [`MAX_URL_PATH_OPAQUE_SEGMENTS`] opaque
/// segment, while keeping slash-bearing base64 blobs redacted: any base64 signal
/// (`+` / trailing `=`) disqualifies outright, and a blob's several opaque chunks
/// exceed the opaque budget / fall short of [`MIN_URL_PATH_TAME_SEGMENTS`]. A
/// known secret-bearing URL (Slack webhook) is still redacted precisely by
/// [`scan_tokens`], independent of this exemption.
fn looks_like_url_path(token: &str) -> bool {
    if token.contains('+') || token.ends_with('=') || !token.contains('/') {
        return false;
    }
    let tame = token
        .split('/')
        .filter(|s| !s.is_empty() && is_tame_path_segment(s))
        .count();
    tame >= MIN_URL_PATH_TAME_SEGMENTS
}

/// Split a token into segments on `_`/`-` separators and camelCase boundaries
/// (a lowercase/digit immediately followed by an uppercase letter). The returned
/// slices borrow from `token`. Pure ASCII handling — secrets and identifiers are
/// ASCII, and non-ASCII bytes simply stay inside a segment.
fn split_identifier_segments(token: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    for part in token.split(|c| IDENTIFIER_SEPARATORS.contains(&c)) {
        let bytes = part.as_bytes();
        let mut start = 0usize;
        for i in 1..bytes.len() {
            let (prev, cur) = (bytes[i - 1], bytes[i]);
            if cur.is_ascii_uppercase() && (prev.is_ascii_lowercase() || prev.is_ascii_digit()) {
                segments.push(&part[start..i]);
                start = i;
            }
        }
        if start < part.len() {
            segments.push(&part[start..]);
        }
    }
    segments
}

/// True if a segment contains a vowel (`y` included). A word-length segment with
/// no vowel is a consonant cluster — the signature of a random/base64 fragment,
/// not a real word.
fn has_vowel(seg: &str) -> bool {
    seg.bytes().any(|b| {
        matches!(
            b.to_ascii_lowercase(),
            b'a' | b'e' | b'i' | b'o' | b'u' | b'y'
        )
    })
}

/// True if `seg` is a real word segment of an identifier: long enough
/// ([`IDENTIFIER_WORD_MIN_LEN`]), contains a vowel, and its *letters* are cleanly
/// cased — all-lowercase, all-uppercase, or a single leading uppercase then
/// lowercase. Digits are permitted anywhere (so `context7` and `sha1` count).
///
/// The clean-case requirement is the load-bearing guard against a secret
/// concatenated into an identifier: a base64 chunk like `AbCdEf1234567890`
/// interleaves case and so is NOT a word, which keeps `config_sk-<key>` (a
/// secret the `\bsk-` token detector misses after `_`) from being exempted.
fn is_word_segment(seg: &str) -> bool {
    if seg.len() < IDENTIFIER_WORD_MIN_LEN || !has_vowel(seg) {
        return false;
    }
    let letters: Vec<u8> = seg.bytes().filter(|b| b.is_ascii_alphabetic()).collect();
    let Some((first, rest)) = letters.split_first() else {
        return false;
    };
    let all_lower = letters.iter().all(u8::is_ascii_lowercase);
    let all_upper = letters.iter().all(u8::is_ascii_uppercase);
    let capitalized = first.is_ascii_uppercase() && rest.iter().all(u8::is_ascii_lowercase);
    all_lower || all_upper || capitalized
}

/// True if `token` is shaped like a source-code identifier (camelCase,
/// snake_case, kebab-case, SCREAMING_SNAKE) rather than an opaque random/base64
/// secret. The high-entropy detector cannot tell a letter-diverse identifier
/// from a random token by entropy alone, so this structural exemption is the
/// false-positive control for that class.
///
/// Conservative by construction so it never exempts a real secret. A token
/// qualifies ONLY if it carries no base64 signal (no `+`, and no TRAILING `=`
/// padding — a mid-string `=` from `key=value` is fine), is letter-dominated
/// (digit ratio at/under [`MAX_IDENTIFIER_DIGIT_RATIO`]), and — after splitting
/// on [`IDENTIFIER_SEPARATORS`] + camelCase — is dominated by *word* segments
/// ([`is_word_segment`]): at least [`MIN_IDENTIFIER_WORDS`] of them covering at
/// least [`MIN_IDENTIFIER_WORD_COVERAGE`] of its letters. A random/base64 token
/// fragments into short, vowel-poor, chaotically-cased pieces and fails both
/// bars. This never overrides the prefixed-secret or env detectors — those run
/// independently, so a known-prefix secret trips regardless of identifier shape.
fn looks_like_identifier(token: &str) -> bool {
    // `+` and trailing `=` are base64 signals; `/` and mid-string `=` are not
    // (they are path / `key=value` separators), so they are handled by splitting.
    if token.contains('+') || token.ends_with('=') {
        return false;
    }
    let digits = token.bytes().filter(|b| b.is_ascii_digit()).count();
    let total_letters = token.bytes().filter(|b| b.is_ascii_alphabetic()).count();
    if total_letters == 0 || (digits as f64 / token.len() as f64) > MAX_IDENTIFIER_DIGIT_RATIO {
        return false;
    }
    let mut word_count = 0usize;
    let mut word_letters = 0usize;
    for seg in split_identifier_segments(token) {
        if is_word_segment(seg) {
            word_count += 1;
            word_letters += seg.bytes().filter(|b| b.is_ascii_alphabetic()).count();
        }
    }
    word_count >= MIN_IDENTIFIER_WORDS
        && (word_letters as f64 / total_letters as f64) >= MIN_IDENTIFIER_WORD_COVERAGE
}

/// Compile the shaped-public-crypto-id detector once, lazily.
///
/// Matches ONLY clearly-public, prefix-shaped ids: Avalanche `NodeID-…` and IPFS
/// CIDs (`baf…` CIDv1 base32, `Qm…` CIDv0 base58). These are public network
/// addresses, not secrets. A bare base58/base32 blob with NO such prefix is not
/// matched and stays subject to the high-entropy detector — it could be a
/// private key. Anchored (`^…$`) full-token match so a prefix appearing inside a
/// larger opaque secret cannot exempt it.
fn public_crypto_id_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"^(?:NodeID-[1-9A-HJ-NP-Za-km-z]+|baf[a-z][a-z2-7]{20,}|Qm[1-9A-HJ-NP-Za-km-z]{44})$",
        )
        .expect("static public crypto id pattern must compile")
    })
}

/// True if `token` is a shaped public crypto id (Avalanche NodeID / IPFS CID).
fn is_public_crypto_id(token: &str) -> bool {
    public_crypto_id_pattern().is_match(token)
}

/// True if `token` is a Subresource-Integrity hash (`sha256-`/`sha384-`/
/// `sha512-` followed by base64) from an npm/pnpm lockfile. These are public
/// content hashes, not secrets. Prefix-anchored so only the SRI shape qualifies.
fn is_sri_hash(token: &str) -> bool {
    let rest = token
        .strip_prefix("sha512-")
        .or_else(|| token.strip_prefix("sha384-"))
        .or_else(|| token.strip_prefix("sha256-"));
    match rest {
        Some(body) => {
            !body.is_empty()
                && body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        }
        None => false,
    }
}

/// True if a standalone token should be exempted from high-entropy redaction.
///
/// Exemptions are the false-positive controls: git SHAs, UUIDs, path-like
/// strings, and cleanly-structured source identifiers are legitimate dev
/// artifacts and must never be flagged.
fn is_entropy_exempt(token: &str) -> bool {
    is_hex_digest(token)
        || is_uuid(token)
        || looks_like_path(token)
        || looks_like_url_path(token)
        || looks_like_keyed_id(token)
        || looks_like_word_list(token)
        || is_public_crypto_id(token)
        || is_sri_hash(token)
        || looks_like_identifier(token)
}

/// Collect prefix-anchored token findings. The pattern consumes an optional
/// leading delimiter, so the redacted span is capture group 1 (the secret
/// itself) — never the delimiter character before it.
fn scan_tokens(input: &str, out: &mut Vec<SecretFinding>) {
    for pattern in token_patterns() {
        for caps in pattern.regex.captures_iter(input) {
            let Some(secret) = caps.get(1) else { continue };
            out.push(SecretFinding {
                kind: pattern.kind,
                start: secret.start(),
                end: secret.end(),
            });
        }
    }
    // Slack incoming-webhook URL: redact only the trailing secret segment
    // (capture group 1), leaving the host + team/bot ids as workflow context.
    for caps in slack_webhook_pattern().captures_iter(input) {
        let Some(secret) = caps.get(1) else { continue };
        out.push(SecretFinding {
            kind: SecretKind::SlackToken,
            start: secret.start(),
            end: secret.end(),
        });
    }
}

/// True if an env-assignment value is itself secret-shaped: a known-prefix
/// token, or an opaque high-entropy run. Key context corroborates, so the
/// length floor is lower than the standalone detector's, but all the FP
/// exemptions still apply. This is the 2026-06-22 retune: a secret-ish KEY name
/// alone no longer redacts the value — the value must look like a secret — which
/// removes the dominant code/type/identifier false positives (`token_budget:
/// number`, `Authorization: Bearer`, `inputTokens: usage.inputTokens`).
fn env_value_is_secret(value: &str) -> bool {
    if token_patterns().iter().any(|p| p.regex.is_match(value)) {
        return true;
    }
    // The opaque-value branch requires a SINGLE base64url-charset token. Code
    // expressions assigned to a secret-ish key (`fixture_key(Profile::X)`,
    // `process.env.X`, `PrivateKey::from_seed(64_000)`) carry high Shannon
    // entropy too, so without this charset gate they would be misread as
    // secrets — the dominant residual env false positive on real transcripts.
    let is_opaque_token = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    is_opaque_token
        && value.len() >= MIN_ENV_SECRET_VALUE_LEN
        && !is_entropy_exempt(value)
        && shannon_entropy_bits(value) > ENTROPY_BITS_THRESHOLD
}

/// Collect env-file assignment findings (the value span only), but ONLY when the
/// value is itself secret-shaped (see [`env_value_is_secret`]).
fn scan_env(input: &str, out: &mut Vec<SecretFinding>) {
    for caps in env_pattern().captures_iter(input) {
        let Some(value) = caps.get(1) else { continue };
        if value.as_str().len() < MIN_ENV_VALUE_LEN || !env_value_is_secret(value.as_str()) {
            continue;
        }
        out.push(SecretFinding {
            kind: SecretKind::EnvAssignment,
            start: value.start(),
            end: value.end(),
        });
    }
}

/// Collect high-entropy standalone-token findings, applying FP exemptions.
fn scan_high_entropy(input: &str, out: &mut Vec<SecretFinding>) {
    for m in standalone_token_pattern().find_iter(input) {
        let token = m.as_str();
        if token.len() < MIN_ENTROPY_TOKEN_LEN || is_entropy_exempt(token) {
            continue;
        }
        // Strict-greater: a pure-hex token maxes out at exactly 4.0 bits/char,
        // so `>` (not `>=`) guarantees no uniform hex id is ever flagged. See
        // ENTROPY_BITS_THRESHOLD.
        if shannon_entropy_bits(token) > ENTROPY_BITS_THRESHOLD {
            out.push(SecretFinding {
                kind: SecretKind::HighEntropy,
                start: m.start(),
                end: m.end(),
            });
        }
    }
}

/// Scan `input` and return every detected secret span.
///
/// Findings are ordered by `start` (ties broken by `end`) and carry only byte
/// offsets — never the secret text. Deterministic for identical input.
pub fn scan(input: &str) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    scan_tokens(input, &mut findings);
    scan_env(input, &mut findings);
    scan_high_entropy(input, &mut findings);
    findings.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
    findings
}

/// True iff no secrets are detected in `input`.
pub fn is_clean(input: &str) -> bool {
    scan(input).is_empty()
}

/// Redact every detected secret span in `input`, replacing each with
/// `<redacted>`.
///
/// Overlapping or adjacent findings (e.g. a high-entropy token that is also the
/// value of a secret-ish env assignment) are merged deterministically: spans
/// are processed in `start` order and any finding contained in or overlapping an
/// already-emitted span is skipped, so the placeholder is never doubled or the
/// output corrupted.
pub fn redact(input: &str) -> String {
    let findings = scan(input);
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    for finding in findings {
        // A finding that begins before where we have already copied to overlaps a
        // prior placeholder. It must still ABSORB its tail: when two findings share
        // a start but this one ends later (e.g. an env-value span vs. a shorter
        // token span at the same offset), failing to advance the cursor would emit
        // the longer finding's tail verbatim — leaking part of a secret.
        if finding.start < cursor {
            cursor = cursor.max(finding.end);
            continue;
        }
        out.push_str(&input[cursor..finding.start]);
        out.push_str(REDACTION_PLACEHOLDER);
        cursor = finding.end;
    }
    out.push_str(&input[cursor..]);
    out
}

/// Redact secrets inside a parsed JSON document **in place**, scrubbing every
/// string *value* while leaving the JSON structure (objects, arrays, keys,
/// numbers, booleans) untouched.
///
/// This is the correct way to redact JSON: running [`redact`] over the raw text
/// of a serialized JSON line can corrupt its framing, because a secret span that
/// abuts an escape sequence (`\"`, `\\`) inside a string value may be rewritten
/// across the escaping and break the surrounding quotes. By walking the parsed
/// value and redacting only the *contents* of each [`serde_json::Value::String`],
/// the output is guaranteed to re-serialize as valid JSON.
///
/// Object **keys are intentionally left intact** — they are field names, not
/// secret material, and redacting them would destroy the structure's meaning.
/// Only string values (at any nesting depth) are scrubbed. Non-string scalars
/// (numbers, booleans, null) are never touched.
///
/// Note: this mutates a parsed [`serde_json::Value`] in place and does not
/// itself re-serialize. A caller that re-serializes the value gets serde_json's
/// default key ordering (sorted) — this crate intentionally does not enable the
/// `preserve_order` feature; see `Cargo.toml` for why (audit-chain determinism).
///
/// Deterministic: the traversal order is fixed and [`redact`] is itself
/// deterministic, so identical input yields identical output.
pub fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            let redacted = redact(s);
            if redacted != *s {
                *s = redacted;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_json_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            // Redact VALUES and KEYS. A secret used as an object key (e.g. a map
            // keyed by token/id) would otherwise survive, since serde only lets us
            // mutate values in place. Rebuild the map so a secret-shaped key is
            // replaced too; a redacted-key collision keeps the last entry, which is
            // acceptable for a sanitized export.
            let rebuilt = std::mem::take(map)
                .into_iter()
                .map(|(key, mut entry)| {
                    redact_json_value(&mut entry);
                    (redact(&key), entry)
                })
                .collect();
            *map = rebuilt;
        }
        // Numbers, booleans, and null carry no redactable string content.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_github_token() {
        let input = "use ghp_abcdefghijklmnopqrstuvwx123456 now";
        assert_eq!(redact(input), "use <redacted> now");
        assert_eq!(scan(input)[0].kind, SecretKind::GithubToken);
    }

    #[test]
    fn redacts_aws_key() {
        let input = "key AKIAIOSFODNN7EXAMPLE here";
        assert_eq!(redact(input), "key <redacted> here");
        assert_eq!(scan(input)[0].kind, SecretKind::AwsKey);
    }

    #[test]
    fn redacts_slack_token() {
        let input = "tok xoxb-123456789012-abcdefABCDEF end";
        assert_eq!(redact(input), "tok <redacted> end");
        assert_eq!(scan(input)[0].kind, SecretKind::SlackToken);
    }

    #[test]
    fn redacts_slack_webhook_secret_segment() {
        // Security property: the webhook secret is gone and a SlackToken finding
        // names it precisely. (Surgical context-preservation — keeping the host +
        // T/B ids — additionally requires the URL exemption; see
        // `slack_webhook_context_preserved_with_url_exemption`.)
        let input =
            "post to https://hooks.slack.com/services/T00000000000/B00000000000/EXAMPLEdummyWebhookSecret now";
        assert!(
            !redact(input).contains("EXAMPLEdummyWebhookSecret"),
            "webhook secret survived: {}",
            redact(input)
        );
        assert!(scan(input).iter().any(|f| f.kind == SecretKind::SlackToken));
    }

    #[test]
    fn redacts_gitlab_token() {
        let input = "pat glpat-abcdefghijklmnopqrstuvwx end";
        assert_eq!(redact(input), "pat <redacted> end");
        assert_eq!(scan(input)[0].kind, SecretKind::GitlabToken);
    }

    #[test]
    fn redacts_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fw";
        let input = format!("auth {jwt} done");
        assert_eq!(redact(&input), "auth <redacted> done");
        assert_eq!(scan(&input)[0].kind, SecretKind::Jwt);
    }

    #[test]
    fn redacts_env_assignment_value_keeps_key() {
        // New contract (2026-06-22): the value must be secret-SHAPED. A
        // high-entropy opaque value (19 chars: above the env floor of 16, below
        // the standalone floor of 32 so only the key-corroborated env scanner
        // catches it) is redacted; the key survives.
        let input = "API_KEY=Xk7Qz9Lm2Wp5Rt8Nv3J";
        assert_eq!(redact(input), "API_KEY=<redacted>");
        assert_eq!(scan(input)[0].kind, SecretKind::EnvAssignment);
    }

    #[test]
    fn env_low_entropy_value_is_not_redacted() {
        // Decision 2026-06-22: env no longer redacts a low-entropy value on key
        // context alone — that fired on code (`token_budget: number`,
        // `Authorization: Bearer`). These stay clean.
        for s in [
            "DB_PASSWORD=hunter2",
            "token_budget: number",
            "Authorization: Bearer",
            "api_key: local-dev-key",
            "inputTokens: usage.inputTokens",
        ] {
            assert!(
                is_clean(s),
                "low-entropy env value wrongly redacted: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn env_colon_form_high_entropy_value_redacted() {
        assert_eq!(
            redact("password: aG9yc2ViYXR0ZXJ5c3RhcGxl12"),
            "password: <redacted>"
        );
    }

    #[test]
    fn env_code_expression_value_is_not_redacted() {
        // Code assigned to a secret-ish key has high Shannon entropy but is NOT a
        // secret. The value-shape gate requires a single base64url token, so code
        // punctuation (`(`, `::`, `.`, `;`) disqualifies these.
        for s in [
            "let secret = fixture_authority_key(DeploymentProfile::PublicDevnet);",
            "key = ed25519::PrivateKey::from_seed(64_000);",
            "const token = process.env.OPENAI_API_KEY",
        ] {
            assert!(
                is_clean(s),
                "code expression wrongly redacted: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn quoted_env_value_redacted_quotes_preserved() {
        // The value-capture group excludes the surrounding quotes, so only the
        // inner value is redacted and the quote characters remain.
        let input = "API_KEY=\"sk-livesecret123\"";
        assert_eq!(redact(input), "API_KEY=\"<redacted>\"");
    }

    #[test]
    fn env_known_prefix_value_still_redacted() {
        // A known-prefix secret as an env value trips regardless of entropy —
        // via the token detector, which the env value-shape gate also honors.
        assert_eq!(
            redact("API_KEY=\"sk-livesecret1234567890\""),
            "API_KEY=\"<redacted>\""
        );
    }

    #[test]
    fn non_secret_env_key_is_not_redacted() {
        let input = "PATH=/usr/bin";
        assert!(is_clean(input));
        assert_eq!(redact(input), input);
    }

    #[test]
    fn trivial_secret_value_below_min_len_is_not_redacted() {
        // The key IS secret-ish (TOKEN), so the key filter does not suppress
        // this; it is the value-length floor (MIN_ENV_VALUE_LEN) that does.
        let input = "TOKEN=ab12";
        assert!(is_clean(input));
        assert_eq!(scan(input).len(), 0);
    }

    #[test]
    fn redacts_high_entropy_token() {
        let input = "blob aG9yc2ViYXR0ZXJ5c3RhcGxlMTIzNDU2Nzg5MA== end";
        assert_eq!(scan(input)[0].kind, SecretKind::HighEntropy);
        assert_eq!(redact(input), "blob <redacted> end");
    }

    #[test]
    fn fp_control_git_sha_not_redacted() {
        let input = "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 landed";
        assert!(is_clean(input));
        assert_eq!(redact(input), input);
    }

    #[test]
    fn fp_control_sha256_not_redacted() {
        // Uniform 64-hex: each of the 16 symbols appears exactly 4 times, so its
        // entropy is exactly 4.0 bits/char (the hex maximum). Only the
        // is_hex_digest exemption — not a sub-threshold entropy score — saves it,
        // so this fixture actually exercises the length-64 hex guard.
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(sha.len(), HEX_SHA256_LEN);
        let input = format!("digest {sha} ok");
        assert!(is_clean(&input));
    }

    #[test]
    fn fp_control_uuid_not_redacted() {
        let input = "id 550e8400-e29b-41d4-a716-446655440000 used";
        assert!(is_clean(input));
        assert_eq!(redact(input), input);
    }

    #[test]
    fn fp_control_file_path_not_redacted() {
        let input = "/Users/dev/projects/atomicradar/crates/radar-daemon/src/redact/mod.rs";
        assert!(is_clean(input));
        assert_eq!(redact(input), input);
    }

    #[test]
    fn fp_control_prose_not_redacted() {
        let input = "The quick brown fox jumps over the lazy dog repeatedly today.";
        assert!(is_clean(input));
    }

    #[test]
    fn fp_control_short_word_not_redacted() {
        let input = "hello";
        assert!(is_clean(input));
    }

    #[test]
    fn sk_api_key_is_scanned_as_token() {
        // sk- was added to hooks/shared/sanitize.js in the dogfood-producer slice;
        // this crate claims to mirror that set — drift caught in the PR #26 audit.
        let findings = scan("bare token sk-AbC123xyz789LMN in prose");
        assert!(
            findings.iter().any(|f| f.kind == SecretKind::ApiKey),
            "sk- token must be found: {findings:?}"
        );
    }

    /// Cross-sanitizer conformance corpus (fixtures/sanitizer-conformance.json):
    /// every secret_must_trip string must be found by scan(); every must_pass
    /// string must be clean. Shared with the JS hooks suite and the surface
    /// sanitizer so the three sets cannot drift.
    #[test]
    fn conformance_corpus_holds() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/sanitizer-conformance.json"
        );
        let raw = std::fs::read_to_string(path).expect("conformance corpus must exist");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("corpus must parse");
        for s in v["secret_must_trip"].as_array().expect("secret_must_trip") {
            let s = s.as_str().unwrap();
            assert!(!is_clean(s), "secret NOT found by scan: {s:?}");
        }
        for s in v["must_pass"].as_array().expect("must_pass") {
            let s = s.as_str().unwrap();
            assert!(is_clean(s), "false positive on: {s:?}");
        }
    }

    #[test]
    fn scan_is_deterministic() {
        let input = "API_KEY=sk-livesecret123 and ghp_abcdefghijklmnopqrstuvwx123456";
        assert_eq!(scan(input), scan(input));
        assert_eq!(redact(input), redact(input));
    }

    #[test]
    fn findings_ordered_by_start_offset() {
        let input = "ghp_abcdefghijklmnopqrstuvwx123456 then API_KEY=sk-livesecret123";
        let findings = scan(input);
        for pair in findings.windows(2) {
            assert!(pair[0].start <= pair[1].start);
        }
    }

    #[test]
    fn overlapping_env_and_token_match_no_double_redaction() {
        // The JWT is also the value of a secret-ish env assignment, so the
        // token detector and env detector both fire on overlapping spans.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fw";
        let input = format!("AUTH_TOKEN={jwt}");
        let redacted = redact(&input);
        assert_eq!(redacted, "AUTH_TOKEN=<redacted>");
        assert_eq!(redacted.matches(REDACTION_PLACEHOLDER).count(), 1);
    }

    #[test]
    fn finding_struct_has_no_secret_text_field() {
        // Structural proof that a finding carries only offsets: constructing one
        // requires exactly kind/start/end and nothing that could hold the
        // secret bytes. Cloning/copying the finding cannot move secret text.
        let input = "ghp_abcdefghijklmnopqrstuvwx123456";
        let finding = scan(input)[0];
        let echoed = SecretFinding {
            kind: finding.kind,
            start: finding.start,
            end: finding.end,
        };
        assert_eq!(finding, echoed);
    }

    #[test]
    fn entropy_of_uniform_text_is_low() {
        assert!(shannon_entropy_bits("aaaaaaaaaaaaaaaa") < 1.0);
    }

    // --- identifier exemption (FP control for the high-entropy detector) -------
    //
    // Long source identifiers (function/test/tool names, kebab filenames) are a
    // dominant false-positive class for the entropy detector: a letter-diverse
    // 32+ char identifier clears the 4.0-bit gate exactly like a random token.
    // These must NOT be redacted, or every downstream surface that consumes
    // sanitized text loses identifier-level signal. The exemption is conservative
    // — it spares cleanly-cased word/number segment tokens only, never opaque
    // random/base64 blobs, and never overrides the prefixed-secret detectors.

    /// Workflow identifiers that must survive sanitization untouched.
    const MUST_PASS_IDENTIFIERS: &[&str] = &[
        "testIslandLevelIsStatusBarAboveModalDialogs",
        "clean_qualifier_does_not_veto_a_real_finding",
        "over_limit_backlog_pages_oldest_first_without_skips",
        "dogfood-next-action-mcp-tool",
        "handleWebSocketReconnectionWithExponentialBackoff",
        "RADAR_ISLAND_START_EXPANDED_SCENARIO",
        "atomic-radar-island-presentation-2026-05-23",
        // Real survivors from the 13-transcript diagnostic: acronym (URLs) and
        // digit-bearing (context7) segments that the first (case-structure) rule
        // wrongly redacted.
        "testLoopApiClientBuildsURLsWithQueryPaths",
        "mcp__plugin_context7_context7__query-docs",
        "mcp__plugin_context7_context7__resolve-library-id",
        // A cargo build-artifact name (lib + build hash): real words + a hex
        // suffix. Stays exempt — it is workflow signal, not a secret.
        "libfutures_task-a06f1b2c3d4e5f2cc624",
    ];

    /// Opaque tokens that superficially resemble identifiers (have `_`/`-` or case
    /// changes) but are random/base64-ish and MUST still trip.
    const MUST_TRIP_PSEUDO_IDENTIFIERS: &[&str] = &[
        "XkLmZQpRtyBwNcVhJsDgKaZqWeRtUiOp", // mixed-case random, no digits
        "qZ3xRt9pLmW2kBvN8cHj7sDgF4aYeUiKp", // mixed-case + digits
        "dGhpc19pc19hX3Rva2Vu-Zm9vYmFyMTIz", // base64url-ish, dashes + digits
        "aG9yc2ViYXR0ZXJ5c3RhcGxlMTIzNDU2Nzg5MA", // base64-ish blob
        // A real secret concatenated into an identifier after `_`: the `\bsk-`
        // token detector misses it (no word boundary after `_`), so the
        // high-entropy fallback MUST NOT exempt it. The base64 key chunk is not a
        // clean word, so the whole token stays redacted.
        "config_sk-AbCdEf1234567890GhIjKl",
        "prefixword_AbCdEfGhIjKlMnOpQrStUv", // mixed-case key chunk beside a word
    ];

    #[test]
    fn must_pass_identifiers_are_not_redacted() {
        for id in MUST_PASS_IDENTIFIERS {
            assert!(
                is_clean(id),
                "identifier wrongly flagged as secret: {id:?} -> {:?}",
                scan(id)
            );
            // And in a realistic sentence context.
            let ctx = format!("calling {id} now");
            assert_eq!(redact(&ctx), ctx, "identifier redacted in context: {id:?}");
        }
    }

    #[test]
    fn must_trip_pseudo_identifiers_are_redacted() {
        for tok in MUST_TRIP_PSEUDO_IDENTIFIERS {
            assert!(
                !is_clean(tok),
                "random token wrongly exempted as identifier: {tok:?}"
            );
        }
    }

    #[test]
    fn prefixed_secret_trips_even_if_identifier_shaped() {
        // The exemption only touches the high-entropy path; a known-prefix secret
        // is still caught by the token detector regardless of identifier shape.
        let input = "key sk-island_level_status_bar_above_dialogs_value";
        assert!(!is_clean(input));
        assert_eq!(scan(input)[0].kind, SecretKind::ApiKey);
    }

    #[test]
    fn prefixed_secret_trips_after_any_delimiter_including_underscore() {
        // A `\b`-anchored prefix does NOT fire after `_` (underscore is a regex
        // word char), so a secret concatenated after `_` (or `.`/`/`/`:`) would
        // bypass redaction. Every prefix family must trip after every delimiter.
        // Lowercase key material matters: it also looks identifier-shaped, so the
        // high-entropy fallback would skip it too — the token detector must catch
        // it. (Caught in the codex review of the identifier-exemption work.)
        let secrets = [
            "sk-abcdefghijklmnopqrstuvwxyzabcd",
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "glpat-abcdefghijklmnopqrstuvwx",
            "xoxb-abcdefghijklmnopqrstuvwx",
            "AKIAIOSFODNN7EXAMPLE",
        ];
        for delim in ["_", "-", ".", "/", ":", " "] {
            for secret in secrets {
                let input = format!("config{delim}{secret}");
                // Security property (all delimiters): the secret trips and is gone.
                assert!(!is_clean(&input), "leaked: {input:?}");
                let redacted = redact(&input);
                assert!(!redacted.contains(secret), "secret survived: {redacted:?}");
                // Context property: for every delimiter EXCEPT '/', redaction is
                // surgical and the prefix+delimiter survive. '/' keeps the prefix
                // and secret as one path-shaped token, which the high-entropy
                // detector may redact wholesale — safe over-redaction, not a leak.
                if delim != "/" {
                    assert!(
                        redacted.starts_with(&format!("config{delim}")),
                        "delimiter swallowed: {input:?} -> {redacted:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn prefix_mid_word_substring_is_not_a_false_positive() {
        // The leading guard must still reject a prefix that is a mid-word
        // substring (preceded by an alphanumeric), e.g. the `sk-` inside a cargo
        // artifact name `libfutures_task-<hash>` — that is workflow signal, not a
        // secret. (This is what the codex-review survivor turned out to be.)
        assert!(is_clean("disk-aabbccddeeff00112233"));
        assert!(is_clean("a_task-aabbccddeeff00112233"));
    }

    #[test]
    fn looks_like_identifier_classifies_shapes() {
        assert!(looks_like_identifier("testIslandLevelIsStatusBar"));
        assert!(looks_like_identifier("snake_case_function_name"));
        assert!(looks_like_identifier("kebab-case-tool-name"));
        assert!(looks_like_identifier("SCREAMING_SNAKE_CONSTANT"));
        // Rejections: base64 symbols, digit-heavy, single opaque run, chaotic case.
        assert!(!looks_like_identifier("aGVsbG8+d29ybGQ/Zm9v=padding"));
        assert!(!looks_like_identifier("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"));
        assert!(!looks_like_identifier(
            "singleopaquelowercaserunwithoutbreaks"
        ));
        assert!(!looks_like_identifier("XkLmZQpRtyBwNcVhJsDgKaZqWeRtUiOp"));
    }

    #[test]
    fn json_redacts_secret_in_string_value() {
        let mut v: serde_json::Value = serde_json::from_str(
            r#"{"role":"user","text":"deploy ghp_abcdefghijklmnopqrstuvwx123456 now"}"#,
        )
        .unwrap();
        redact_json_value(&mut v);
        assert_eq!(v["text"], serde_json::json!("deploy <redacted> now"));
        // Key and sibling value are untouched.
        assert_eq!(v["role"], serde_json::json!("user"));
    }

    #[test]
    fn json_value_with_secret_beside_escapes_stays_valid_json() {
        // The real-data corruption case: a secret abutting an escaped quote and
        // backslash inside a JSON string. Raw-text redaction broke the framing;
        // value-level redaction must keep the line re-serializable as valid JSON.
        let line = r#"{"q":"he said \"use ghp_abcdefghijklmnopqrstuvwx123456\\path\" ok"}"#;
        let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
        redact_json_value(&mut v);
        let out = serde_json::to_string(&v).unwrap();
        // Re-parses cleanly (no broken escaping) and the secret is gone.
        let reparsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(!out.contains("ghp_abcdefghijklmnopqrstuvwx123456"));
        assert!(reparsed["q"].as_str().unwrap().contains("<redacted>"));
    }

    #[test]
    fn json_redacts_nested_arrays_and_objects() {
        let mut v: serde_json::Value = serde_json::from_str(
            r#"{"msgs":[{"body":"key AKIAIOSFODNN7EXAMPLE"},{"body":"clean"}]}"#,
        )
        .unwrap();
        redact_json_value(&mut v);
        assert_eq!(v["msgs"][0]["body"], serde_json::json!("key <redacted>"));
        assert_eq!(v["msgs"][1]["body"], serde_json::json!("clean"));
    }

    #[test]
    fn json_leaves_keys_and_non_string_scalars_untouched() {
        // A secret-shaped string used as an OBJECT KEY is preserved (keys are
        // field names, not secret material); numbers/bools/null are never touched.
        let mut v: serde_json::Value =
            serde_json::from_str(r#"{"count":42,"ok":true,"nil":null}"#).unwrap();
        let before = v.clone();
        redact_json_value(&mut v);
        assert_eq!(v, before);
    }

    #[test]
    fn json_reserializes_with_sorted_keys_values_redacted() {
        // Without `preserve_order` (deliberately off — see Cargo.toml), serde_json
        // emits object keys sorted. The contract is: same key SET, secret values
        // redacted, clean values intact, output is valid JSON. Key order is NOT a
        // guarantee and is irrelevant to downstream JSON consumers.
        let line = r#"{"z":"clean","a":"ghp_abcdefghijklmnopqrstuvwx123456","m":"clean"}"#;
        let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
        redact_json_value(&mut v);
        let out = serde_json::to_string(&v).unwrap();
        assert_eq!(
            out, r#"{"a":"<redacted>","m":"clean","z":"clean"}"#,
            "serde_json default ordering is sorted; values redacted, keys intact"
        );
    }

    // --- audit regressions (F1/F3/F4) -----------------------------------------

    #[test]
    fn f1_base64_secret_with_slash_is_not_treated_as_path() {
        // A high-entropy base64 blob containing '/' (and '='/'+') must NOT be
        // exempted as a path — that was a real bypass.
        for s in [
            "aGVsbG8/d29ybGQrc2VjcmV0L2Jheg==",
            "abQ/cdEFghIJklMNopQRstUVwxYZ0123456789zzz",
        ] {
            assert!(!is_clean(s), "base64-with-slash leaked: {s:?}");
        }
    }

    #[test]
    fn url_path_tokens_are_exempt() {
        // Real ENTROPY_IDENT false positives from the 2026-06-22 export review:
        // URLs and multi-segment paths whose segments are structural (words,
        // uuids, hashes, digits, short path words) with at most one opaque id.
        for s in [
            "com/karpathy/442a6bf555914893e9891c11519de94f",
            "com/gists/442a6bf555914893e9891c11519de94f/comments",
            "4321/sessions/01a5d8cd-94eb-4d43-b509-58b0ef17992a/events",
            "9650/ext/bc/2K6Jd2ZX1mAndukLmFC27akGg8AkpVCXYD5F6vmfSA9JjbKimE/rpc",
            "org/en-US/docs/Web/HTTP/Status/403",
            "7080/v1/datasets/c58b6937e8d789f3da678eed48aa12a231d8090cacbfad66bbb99073cfda0e1e",
        ] {
            assert!(
                is_clean(s),
                "url/path wrongly flagged: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn base64_with_slash_still_trips_after_url_exemption() {
        // F1 must hold: slash-bearing base64 blobs are NOT url-paths (base64
        // signal, or several opaque chunks / too few tame segments).
        for s in [
            "aGVsbG8/d29ybGQrc2VjcmV0L2Jheg==",
            "abQ/cdEFghIJklMNopQRstUVwxYZ0123456789zzz",
            "Zm9v/YmFy/c2VjcmV0a2V5/MTIzNDU2Nzg5MDEy",
        ] {
            assert!(!is_clean(s), "base64-with-slash leaked: {s:?}");
        }
    }

    #[test]
    fn slack_webhook_context_preserved_with_url_exemption() {
        // With the URL exemption, the high-entropy detector no longer eats the
        // whole webhook token; only the precise Slack detector fires, so the
        // host + T/B ids survive and just the secret segment is redacted.
        let input =
            "see hooks.slack.com/services/T00000000000/B00000000000/EXAMPLEdummyWebhookSecret ok";
        let out = redact(input);
        assert!(
            !out.contains("EXAMPLEdummyWebhookSecret"),
            "secret survived: {out}"
        );
        assert!(
            out.contains("hooks.slack.com/services/T00000000000/B00000000000/"),
            "context lost: {out}"
        );
    }

    #[test]
    fn keyed_id_or_hash_after_equals_is_exempt() {
        // Residual FP tail (2026-06-22): an id/hash in a `key=value` or query
        // param — uuid, git sha, 0x-hex — is workflow signal, not a secret.
        for s in [
            "thread_id=019e8026-1372-7991-ac37-025d98f62def",
            "ref=5a807d8e8c4a6f98354d7d7181223accf7412b6d",
            "datasetId=0xaf943f4f6ba8ea30cbe82e7c4441d8c68f3f6c9fe375fea9",
        ] {
            assert!(
                is_clean(s),
                "keyed id wrongly flagged: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn keyed_opaque_secret_after_equals_still_trips() {
        // The exemption is only for uuid/hex values — an opaque base64 secret
        // after `=` must still trip (no leak).
        assert!(!is_clean("session=aG9yc2ViYXR0ZXJ5c3RhcGxlMTIzNDU2Nzg5MA"));
    }

    #[test]
    fn sri_integrity_hash_is_exempt() {
        // Subresource-integrity hashes from npm/pnpm lockfiles are public.
        for s in [
            "sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIih",
            "sha384-JlCMOehdEIKqlFxk6IfVoAUVmgz7cU7zDh9XZ0qzeosSHmUJVOzSQvvY",
        ] {
            assert!(
                is_clean(s),
                "SRI hash wrongly flagged: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn worktree_hex_dash_id_with_slug_is_exempt() {
        // `<hex-dash-id>/<word-slug>` worktree dir names are workflow signal.
        assert!(is_clean("46c9-8d66-74551c200319/buttered-xylocarp"));
    }

    #[test]
    fn plus_joined_word_list_is_exempt() {
        for s in [
            "typecheck+build+test+fallow+boundary-grep",
            "standalone+grouped",
        ] {
            assert!(
                is_clean(s),
                "word list wrongly flagged: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn plus_bearing_base64_blob_still_trips() {
        // Allowing `+`-joined WORD lists must not exempt a `+`-bearing base64 blob.
        assert!(!is_clean("aGVsbG8+d29ybGQrc2VjcmV0a2V5MTIzNDU2Nzg5"));
    }

    #[test]
    fn shaped_public_crypto_ids_are_exempt() {
        // Decision 2026-06-22: exempt clearly-public, prefix-shaped ids only.
        for s in [
            "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
            "bafkzcibcd4bdomn3tgwgrh3g532zopskstnbrd2n3sxfqbze7rxt7vqn7veigmy",
            "QmYwAPJzv5CZsnaZ3pHsT6tV5urR8aP6kRfd2pY9NPCWHy",
        ] {
            assert!(
                is_clean(s),
                "public id wrongly flagged: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn bare_base58_blob_without_public_prefix_still_trips() {
        // A bare high-entropy base58 blob could be a private key — NOT exempt.
        assert!(!is_clean(
            "5KJvsngHeMpm884wtkpnx5tRunosvjjHu2pX7T46GwL8MeC8oVT"
        ));
    }

    #[test]
    fn f1_real_paths_still_exempt() {
        // The fix must not reintroduce path false positives.
        for p in [
            "/Users/dev/projects/atomicradar/crates/radar-daemon/src/redact/mod.rs",
            "crates/radar-daemon/src/redact/mod.rs",
            "../sibling/pkg/lib.rs",
            "~/.config/radar/settings.toml",
        ] {
            assert!(is_clean(p), "path wrongly flagged: {p:?} -> {:?}", scan(p));
        }
    }

    #[test]
    fn over_redaction_control_branches_paths_urls_exempt() {
        // Real items the --verbose report flagged as ENTROPY_IDENT over-redaction
        // on partner data: branch names, migration paths, URL paths, config keys.
        // These are analysis signal, not secrets, and must survive. Fixed by
        // treating `/`, `.`, `=` as identifier separators so the word-coverage
        // test recognizes them as structured, not opaque.
        for s in [
            "feat/gh-237-add-agent-harness-on-top-of-worktrees-for-full-plan-ship",
            "fix/gh-227-wt-clone-make-non-bare-the-default-move-bare-repo-layout",
            "api/alembic/versions/2026_06_02_1544-dccf210db471_merge_aie551_and_aie573_heads",
            "path=/api/v1/assistant/conversations/presence-channel-status",
            "asyncio_default_fixture_loop_scope=function",
        ] {
            assert!(
                is_clean(s),
                "over-redacted non-secret: {s:?} -> {:?}",
                scan(s)
            );
        }
    }

    #[test]
    fn base64_with_slash_still_trips_after_separator_change() {
        // Allowing `/` as an identifier separator must NOT reopen F1: a base64
        // blob with a slash has no word segments and stays redacted.
        for s in [
            "aGVsbG8/d29ybGQrc2VjcmV0L2Jheg==",
            "abQ/cdEFghIJklMNopQRstUVwxYZ0123456789zzz",
            "Zm9v/YmFy/c2VjcmV0a2V5/MTIzNDU2Nzg5MDEy",
        ] {
            assert!(!is_clean(s), "base64-with-slash leaked: {s:?}");
        }
    }

    #[test]
    fn f3_overlapping_findings_do_not_leak_a_tail() {
        // The env-value finding spans the whole value; the sk- token finding stops
        // at '+'. They share a start; the shorter sorts first. The merge must
        // absorb the longer finding's tail instead of emitting it.
        let input = "password: sk-abcdefghij+morestuffafterplusandmore==";
        let out = redact(input);
        assert!(out.contains("<redacted>"));
        assert!(!out.contains("morestuffafterplus"), "leaked tail: {out:?}");
        assert!(!out.contains("sk-abcdefghij"), "leaked head: {out:?}");
    }

    #[test]
    fn f4_json_redacts_secret_object_keys() {
        let mut v: serde_json::Value = serde_json::from_str(
            r#"{"sk-abcdefghijklmnopqrstuv":"x","AKIAIOSFODNN7EXAMPLE":1,"role":"user"}"#,
        )
        .unwrap();
        redact_json_value(&mut v);
        let out = serde_json::to_string(&v).unwrap();
        assert!(
            !out.contains("sk-abcdefghijklmnopqrstuv"),
            "secret key survived: {out}"
        );
        assert!(
            !out.contains("AKIAIOSFODNN7EXAMPLE"),
            "aws key survived: {out}"
        );
        assert!(out.contains("<redacted>"));
        // Benign key/value preserved.
        assert!(out.contains(r#""role":"user""#), "benign field lost: {out}");
    }
}
