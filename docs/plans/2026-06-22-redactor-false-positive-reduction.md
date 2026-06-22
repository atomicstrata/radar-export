# Redactor False-Positive Reduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Cut the radar-export redactor's ~97% false-positive rate on agent transcripts (264K of 272K redactions are the two fuzzy heuristics firing on code/URLs/paths/ids) without weakening real-secret detection.

**Architecture:** Keep the precise prefix detectors untouched. Add one precise detector (Slack incoming-webhook URL). Retune the env-assignment detector to require a secret-shaped value. Expand the high-entropy detector's exemptions to cover URLs, multi-segment paths, and shaped public crypto ids. The conformance corpus (`fixtures/sanitizer-conformance.json`) plus the real-log oracle (`tmp/measure/*.txt`) are the test oracles.

**Tech Stack:** Rust, `regex`, `serde_json`; tests via `cargo test -p radar-redact`; measurement via the `redaction_report` example.

**User decisions (locked):** Slack webhook = real secret, keep redacting via precise detector. Heuristics = conservative + new precise detectors. Crypto ids = exempt only shaped/located public ids (NodeID-, IPFS CID, base58-in-RPC-URL); a BARE base58 blob still redacts. Env = require secret-shaped value (drops low-entropy env secrets, which become a human-review concern).

**Divergence note:** This intentionally makes the radar-export redactor more conservative than the monorepo's shared sanitizer (the "three sanitizers parity" in lib.rs). That is the point of a less-noisy *export*; a future port-back to the monorepo is out of scope here.

---

## File structure

- `crates/radar-redact/src/lib.rs` — all detector + exemption logic and unit tests (single-file crate, established pattern).
- `fixtures/sanitizer-conformance.json` — add real-log FP strings to `must_pass`; add Slack webhook to `secret_must_trip`.
- `tmp/measure/{ENTROPY_IDENT,ENV_VALUE,ENTROPY_BLOB}.txt` — measurement corpus (already extracted; not committed).

## Measurement oracle (run after each task)

```bash
cargo build -p radar-redact --example redaction_report --release
for r in ENTROPY_IDENT ENV_VALUE ENTROPY_BLOB; do
  n=$(./target/release/examples/redaction_report < tmp/measure/$r.txt 2>/dev/null | wc -l)
  printf "%-15s %8d still trip (of %d)\n" "$r" "$n" "$(wc -l < tmp/measure/$r.txt)"
done
```
Baseline: ENTROPY_IDENT 120811/120811, ENV_VALUE 332/5782 (bare values), ENTROPY_BLOB 1792/1792.

---

### Task 1: Slack incoming-webhook URL detector (precise; runs before exemptions)

**Files:** Modify `crates/radar-redact/src/lib.rs`.

The Slack secret must trip regardless of any URL exemption added later, so it is a precise token-style detector, not part of the entropy path. It redacts the trailing secret segment only.

- [ ] **Step 1: Write failing tests** (add to `mod tests`)

```rust
#[test]
fn redacts_slack_webhook_secret_segment() {
    let input = "post to https://hooks.slack.com/services/T00000000000/B00000000000/EXAMPLEdummyWebhookSecret now";
    let out = redact(input);
    assert!(!out.contains("EXAMPLEdummyWebhookSecret"), "webhook secret survived: {out}");
    // Workflow context (host + T/B ids) is preserved; only the secret segment goes.
    assert!(out.contains("hooks.slack.com/services/T00000000000/B00000000000/"), "context lost: {out}");
    assert!(scan(input).iter().any(|f| f.kind == SecretKind::SlackToken));
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p radar-redact --lib redacts_slack_webhook_secret_segment`
Expected: FAIL — secret still present (no detector).

- [ ] **Step 3: Implement** — add a webhook pattern. In `token_patterns()`, the prefix-anchored wrap captures group 1; for the webhook we want to redact only the secret tail, so add a SEPARATE scanner rather than reuse the delimiter-wrap. Add after `standalone_token_pattern()`:

```rust
/// Compile the Slack incoming-webhook detector once, lazily.
///
/// `hooks.slack.com/services/T<id>/B<id>/<secret>` — the trailing segment is the
/// webhook secret (anyone holding the full URL can post). Capture group 1 is the
/// secret segment ONLY, so redaction leaves the host + team/bot ids (workflow
/// context) intact and removes just the credential. This runs in `scan_tokens`,
/// so it fires even though the high-entropy URL exemption (Task 3) would skip the
/// same span — the precise detector is the authority for this known secret URL.
fn slack_webhook_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/([A-Za-z0-9]{16,})")
            .expect("static slack webhook pattern must compile")
    })
}
```

Add a `SlackWebhook` is unnecessary — reuse `SecretKind::SlackToken`. Extend `scan_tokens` to also run the webhook scanner:

```rust
fn scan_tokens(input: &str, out: &mut Vec<SecretFinding>) {
    for pattern in token_patterns() {
        for caps in pattern.regex.captures_iter(input) {
            let Some(secret) = caps.get(1) else { continue };
            out.push(SecretFinding { kind: pattern.kind, start: secret.start(), end: secret.end() });
        }
    }
    for caps in slack_webhook_pattern().captures_iter(input) {
        let Some(secret) = caps.get(1) else { continue };
        out.push(SecretFinding { kind: SecretKind::SlackToken, start: secret.start(), end: secret.end() });
    }
}
```

- [ ] **Step 4: Run to verify pass + full suite**

Run: `cargo test -p radar-redact --lib`
Expected: PASS (42+).

- [ ] **Step 5: Commit**

```bash
git add crates/radar-redact/src/lib.rs
git commit -F commit-message.txt   # "feat(redact): precise Slack incoming-webhook detector"
```

---

### Task 2: High-entropy URL / multi-segment-path exemption

**Files:** Modify `crates/radar-redact/src/lib.rs`.

A URL/path token is exempt iff it has no base64 signal and is dominated by tame structural segments (words / uuids / hex / digits / ≤3-char path words) with AT MOST ONE opaque segment. This exempts `com/karpathy/<sha>`, `4321/sessions/<uuid>/events`, `9650/ext/bc/<base58>/rpc` while keeping base64-with-slash blobs (F1) redacted, and (harmlessly) the Slack span — which Task 1 redacts precisely anyway.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn url_path_tokens_are_exempt() {
    for s in [
        "com/karpathy/442a6bf555914893e9891c11519de94f",
        "com/gists/442a6bf555914893e9891c11519de94f/comments",
        "4321/sessions/01a5d8cd-94eb-4d43-b509-58b0ef17992a/events",
        "9650/ext/bc/2K6Jd2ZX1mAndukLmFC27akGg8AkpVCXYD5F6vmfSA9JjbKimE/rpc",
        "org/en-US/docs/Web/HTTP/Status/403",
        "7080/v1/datasets/c58b6937e8d789f3da678eed48aa12a231d8090cacbfad66bbb99073cfda0e1e",
    ] {
        assert!(is_clean(s), "url/path wrongly flagged: {s:?} -> {:?}", scan(s));
    }
}

#[test]
fn base64_with_slash_still_trips_after_url_exemption() {
    // F1 must hold: slash-bearing base64 blobs are NOT url-paths.
    for s in [
        "aGVsbG8/d29ybGQrc2VjcmV0L2Jheg==",
        "abQ/cdEFghIJklMNopQRstUVwxYZ0123456789zzz",
        "Zm9v/YmFy/c2VjcmV0a2V5/MTIzNDU2Nzg5MDEy",
    ] {
        assert!(!is_clean(s), "base64-with-slash leaked: {s:?}");
    }
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p radar-redact --lib url_path_tokens_are_exempt`
Expected: FAIL — url/path tokens currently flagged.

- [ ] **Step 3: Implement** — add constants near the other identifier constants:

```rust
/// A `/`-separated path token may carry at most this many opaque (non-tame)
/// segments and still be exempted as a URL/path. One allows a single id/hash in
/// an otherwise-structural path (`/ext/bc/<chain-id>/rpc`); a base64 blob split
/// by incidental slashes has several opaque chunks and stays redacted.
const MAX_URL_PATH_OPAQUE_SEGMENTS: usize = 1;

/// A URL/path must have at least this many tame structural segments to be
/// exempt — so `abQ/<blob>` (one tiny segment + one blob) is NOT exempt.
const MIN_URL_PATH_TAME_SEGMENTS: usize = 2;

/// Segments at or below this length are tame structural path words (`ext`, `bc`,
/// `rpc`, `api`, `v1`, `com`). Kept at 3 so a 4-char base64 chunk (`Zm9v`) is
/// NOT tame and a slash-split base64 blob stays redacted.
const SHORT_PATH_SEGMENT_LEN: usize = 3;
```

Add the helper (after `looks_like_path`):

```rust
/// True if a `/`-separated segment is "tame" — a structural URL/path segment
/// rather than an opaque secret chunk: a word, a uuid, a hex digest, all-digits,
/// or a very short path word (`ext`/`bc`/`rpc`). Used by [`looks_like_url_path`].
fn is_tame_path_segment(seg: &str) -> bool {
    !seg.is_empty()
        && (seg.len() <= SHORT_PATH_SEGMENT_LEN
            || seg.bytes().all(|b| b.is_ascii_digit())
            || is_hex_digest(seg)
            || is_uuid(seg)
            || is_word_segment(seg)
            || looks_like_identifier(seg))
}

/// True if `token` is a URL or multi-segment path rather than an opaque blob.
///
/// Exempts ordinary URLs/paths whose segments are structural (words/ids/hashes)
/// with at most [`MAX_URL_PATH_OPAQUE_SEGMENTS`] opaque segment, while keeping
/// slash-bearing base64 blobs redacted (they have several opaque chunks and any
/// base64 signal — `+` / trailing `=` — disqualifies outright). A known
/// secret-bearing URL (Slack webhook) is redacted precisely by `scan_tokens`
/// regardless of this exemption.
fn looks_like_url_path(token: &str) -> bool {
    if token.contains('+') || token.ends_with('=') || !token.contains('/') {
        return false;
    }
    let mut tame = 0usize;
    let mut opaque = 0usize;
    for seg in token.split('/').filter(|s| !s.is_empty()) {
        if is_tame_path_segment(seg) {
            tame += 1;
        } else {
            opaque += 1;
        }
    }
    tame >= MIN_URL_PATH_TAME_SEGMENTS && opaque <= MAX_URL_PATH_OPAQUE_SEGMENTS
}
```

Wire into `is_entropy_exempt`:

```rust
fn is_entropy_exempt(token: &str) -> bool {
    is_hex_digest(token)
        || is_uuid(token)
        || looks_like_path(token)
        || looks_like_url_path(token)
        || looks_like_identifier(token)
}
```

- [ ] **Step 4: Run tests + measure**

Run: `cargo test -p radar-redact --lib` (expect PASS, F1 tests still green).
Run the measurement oracle. Expect ENTROPY_IDENT to drop substantially.

- [ ] **Step 5: Commit**

```bash
git add crates/radar-redact/src/lib.rs
git commit -F commit-message.txt   # "feat(redact): exempt URL/multi-segment-path tokens from high-entropy"
```

---

### Task 3: Shaped public crypto-id exemption (NodeID-, IPFS CID)

**Files:** Modify `crates/radar-redact/src/lib.rs`.

Bare (no-slash) public ids the URL rule can't reach: Avalanche `NodeID-…` and IPFS CIDs. Narrow prefix shapes only — a bare base58 blob with no such prefix still redacts (could be a private key).

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn shaped_public_crypto_ids_are_exempt() {
    for s in [
        "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
        "bafkzcibcd4bdomn3tgwgrh3g532zopskstnbrd2n3sxfqbze7rxt7vqn7veigmy",
        "QmYwAPJzv5CZsnaZ3pHsT6tV5urR8aP6kRfd2pY9NPCWHy",
    ] {
        assert!(is_clean(s), "public id wrongly flagged: {s:?} -> {:?}", scan(s));
    }
}

#[test]
fn bare_base58_blob_without_public_prefix_still_trips() {
    // A bare high-entropy base58 blob could be a private key — NOT exempt.
    assert!(!is_clean("5KJvsngHeMpm884wtkpnx5tRunosvjjHu2pX7T46GwL8MeC8oVT"));
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p radar-redact --lib shaped_public_crypto_ids_are_exempt`
Expected: FAIL.

- [ ] **Step 3: Implement** — add detector + wire:

```rust
/// Compile the shaped-public-crypto-id detector once, lazily.
///
/// Matches ONLY clearly-public, prefix-shaped ids: Avalanche `NodeID-…` and IPFS
/// CIDs (`baf…` CIDv1 base32, `Qm…` CIDv0 base58). These are public network
/// addresses, not secrets. A bare base58/base32 blob with no such prefix is NOT
/// matched and stays subject to the high-entropy detector (it could be a private
/// key). Anchored full-token match (`^…$`) so a prefix substring of a larger
/// secret cannot exempt it.
fn public_crypto_id_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"^(?:NodeID-[1-9A-HJ-NP-Za-km-z]+|baf[a-z][a-z2-7]{20,}|Qm[1-9A-HJ-NP-Za-km-z]{44})$",
        )
        .expect("static public crypto id pattern must compile")
    })
}

/// True if `token` is a shaped public crypto id (NodeID-/IPFS CID).
fn is_public_crypto_id(token: &str) -> bool {
    public_crypto_id_pattern().is_match(token)
}
```

Wire into `is_entropy_exempt` (append `|| is_public_crypto_id(token)`).

- [ ] **Step 4: Run + measure**

Run: `cargo test -p radar-redact --lib`. Run the oracle (expect ENTROPY_BLOB to drop).

- [ ] **Step 5: Commit**

```bash
git add crates/radar-redact/src/lib.rs
git commit -F commit-message.txt   # "feat(redact): exempt shaped public crypto ids (NodeID-, IPFS CID)"
```

---

### Task 4: Env-assignment requires a secret-shaped value

**Files:** Modify `crates/radar-redact/src/lib.rs`.

Per the user decision, the env detector redacts a value ONLY when the value itself is secret-shaped — a known prefix, OR opaque high-entropy (length floor lowered to 16 because the secret-ish key corroborates), with all the FP exemptions applied. This drops `number`/`string`/`Bearer`/`usage.inputTokens`/`local-dev-key` while keeping `API_KEY=<high-entropy>`.

- [ ] **Step 1: Update existing tests to the new contract + add new ones**

Change `redacts_env_assignment_value_keeps_key` and `env_assignment_colon_form_redacts_value` to use a high-entropy value, and ADD the new negative contract:

```rust
#[test]
fn redacts_env_assignment_value_keeps_key() {
    // New contract: the value must be secret-SHAPED. A high-entropy opaque value
    // assigned to a secret-ish key is redacted; the key stays.
    let input = "API_KEY=aG9yc2ViYXR0ZXJ5c3RhcGxl12";
    assert_eq!(redact(input), "API_KEY=<redacted>");
}

#[test]
fn env_low_entropy_value_is_not_redacted() {
    // Decision 2026-06-22: env no longer redacts low-entropy values via key
    // context alone — that fired on code (`token_budget: number`). These stay.
    for s in [
        "DB_PASSWORD=hunter2",
        "token_budget: number",
        "Authorization: Bearer",
        "api_key: local-dev-key",
        "inputTokens: usage.inputTokens",
    ] {
        assert!(is_clean(s), "low-entropy env value wrongly redacted: {s:?} -> {:?}", scan(s));
    }
}

#[test]
fn env_known_prefix_value_still_redacted() {
    // A known-prefix secret as the value trips regardless of entropy.
    assert_eq!(redact("API_KEY=\"sk-livesecret1234567890\""), "API_KEY=\"<redacted>\"");
}
```

Delete `env_assignment_colon_form_redacts_value` (its `password: hunter2supersecret` is now intentionally clean — covered by `env_low_entropy_value_is_not_redacted` conceptually; re-add a high-entropy colon-form case):

```rust
#[test]
fn env_colon_form_high_entropy_value_redacted() {
    assert_eq!(redact("password: aG9yc2ViYXR0ZXJ5c3RhcGxl12"), "password: <redacted>");
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p radar-redact --lib env_low_entropy_value_is_not_redacted`
Expected: FAIL — current env redacts these.

- [ ] **Step 3: Implement** — add a constant and a value-shape gate, then guard `scan_env`:

```rust
/// Length floor for an env value to be considered secret-shaped by entropy. Lower
/// than [`MIN_ENTROPY_TOKEN_LEN`] (the standalone floor) because the secret-ish
/// key corroborates — the env detector's unique role is catching medium-length
/// opaque values a bare scan would skip.
const MIN_ENV_SECRET_VALUE_LEN: usize = 16;

/// True if an env-assignment value is itself secret-shaped: a known-prefix token,
/// or an opaque high-entropy run (key-corroborated, so the length floor is lower
/// than the standalone detector's) that is not an FP-exempt shape. This is the
/// 2026-06-22 retune: the key name alone no longer redacts a value — the value
/// must look like a secret — which removes the dominant code/type/identifier FPs.
fn env_value_is_secret(value: &str) -> bool {
    if token_patterns().iter().any(|p| p.regex.is_match(value)) {
        return true;
    }
    value.len() >= MIN_ENV_SECRET_VALUE_LEN
        && !is_entropy_exempt(value)
        && shannon_entropy_bits(value) > ENTROPY_BITS_THRESHOLD
}
```

Guard the push in `scan_env`:

```rust
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
```

- [ ] **Step 4: Run + measure**

Run: `cargo test -p radar-redact --lib`. Then run the export on a sample and confirm ENV_VALUE FPs collapse (full re-run in Task 6).

- [ ] **Step 5: Commit**

```bash
git add crates/radar-redact/src/lib.rs
git commit -F commit-message.txt   # "feat(redact): env-assignment requires a secret-shaped value"
```

---

### Task 5: Conformance corpus — add real-log FP must_pass + Slack must_trip

**Files:** Modify `fixtures/sanitizer-conformance.json`.

Lock the wins into the shared corpus so they can't regress. Add representative real-log FP strings to `must_pass` and the Slack webhook to `secret_must_trip`. The existing `conformance_corpus_holds` test enforces both directions.

- [ ] **Step 1: Add entries** — to `secret_must_trip` add:

```json
"slack hook https://hooks.slack.com/services/T00000000000/B00000000000/EXAMPLEdummyWebhookSecret"
```

to `must_pass` add (representative of each FP class):

```json
"see com/karpathy/442a6bf555914893e9891c11519de94f gist",
"GET 4321/sessions/01a5d8cd-94eb-4d43-b509-58b0ef17992a/events",
"rpc 9650/ext/bc/2K6Jd2ZX1mAndukLmFC27akGg8AkpVCXYD5F6vmfSA9JjbKimE/rpc",
"node NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg joined",
"cid bafkzcibcd4bdomn3tgwgrh3g532zopskstnbrd2n3sxfqbze7rxt7vqn7veigmy stored",
"interface { token_budget: number; inputTokens: number }",
"send Authorization: Bearer to the API",
"export OPENAI_API_KEY=local-dev-key for tests"
```

- [ ] **Step 2: Run the corpus test**

Run: `cargo test -p radar-redact --lib conformance_corpus_holds`
Expected: PASS (secret trips, all must_pass clean). If a must_pass fails, the prior tasks have a gap — fix there, not by deleting the case.

- [ ] **Step 3: Commit**

```bash
git add fixtures/sanitizer-conformance.json
git commit -F commit-message.txt   # "test(redact): corpus locks real-log FP controls + Slack webhook"
```

---

### Task 6: Full re-measure + residual review

**Files:** none (measurement + report to user).

- [ ] **Step 1: Re-run the full export report on the actual transcripts**

```bash
# Re-run the export with --verbose to regenerate the report, OR re-scan the
# extracted measure corpus for a fast proxy:
cargo build -p radar-redact --example redaction_report --release
for r in ENTROPY_IDENT ENV_VALUE ENTROPY_BLOB; do
  before=$(wc -l < tmp/measure/$r.txt)
  after=$(./target/release/examples/redaction_report < tmp/measure/$r.txt 2>/dev/null | wc -l)
  printf "%-15s %8d -> %8d unique still trip\n" "$r" "$before" "$after"
done
```

- [ ] **Step 2: Sample residual trips** — for each class, show the top remaining items so the user can confirm they are genuine secrets or flag a new FP pattern:

```bash
./target/release/examples/redaction_report < tmp/measure/ENTROPY_IDENT.txt 2>/dev/null \
  | awk -F'\t' '{print $1}' | sort | uniq -c | sort -rn | head -30
```

- [ ] **Step 3: Report numbers + residual patterns to the user; iterate on any new FP class with a new must_pass case + exemption (loop Tasks 2-5 as needed).**

---

## Final verification

- [ ] `cargo test -p radar-redact` — all green (existing + new).
- [ ] `cargo build --release` — workspace builds.
- [ ] Measurement oracle shows ENTROPY_IDENT and ENTROPY_BLOB collapsed; ENV_VALUE FPs gone on a real re-run.
- [ ] `secret_must_trip` (incl. Slack webhook) all still trip; no real secret regressed.
