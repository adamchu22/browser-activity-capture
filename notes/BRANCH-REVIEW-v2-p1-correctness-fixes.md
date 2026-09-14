# P1 correctness fixes — test branch for Adam (2026-09-13)

**Branch:** `v2-p1-correctness-fixes` (off `v2-video-and-redaction-fixes` @ 9c5e9ac)
**Status: TESTING — not merged.** Pull this branch locally, run the suites, review the
diff, and decide whether to merge. This note is written so a local coding agent can
review it with full context.

```bash
git fetch && git checkout v2-p1-correctness-fixes
node --test tests/*.mjs          # expect 133 pass
python -m unittest discover -s tests -p 'test_*.py'   # expect 285 OK (1 skipped)
git diff v2-video-and-redaction-fixes..v2-p1-correctness-fixes
```

## What this branch is

The five independent repo reviews (see `notes/SYNTHESIS.md`) produced a consensus
bug list. v2 (the Astra build, merged as 2ba7919 + follow-ups) fixed many of them.
Before touching anything I verified every candidate against the live tree —
several "open" items turned out to be already fixed in v2 (details below). This
branch builds the ones that were still genuinely broken, each with a regression
test that was **mutation-probed**: reverting the fix fails the test (proof at the
bottom of this file).

## What was fixed (6 fixes, 4 files + 2 new test files)

1. **HAR pause-time inflation** (SYNTHESIS bug #2 — found by 4 of 5 reviewers).
   `entry.time` was computed as raw CDP wall-clock delta
   (`responseTs - _start`), so a request spanning a pause reported minutes of
   "latency" the one-clock invariant says never happened.
   Fix: freeze the recording-clock reading (`_t0Clock: now()`) at
   `requestWillBeSent`; measure `entry.time` on the same clock at
   `responseReceived`. `_t0Clock` is stripped on export alongside `_start`.
   Files: `extension/src/background.js`, `extension/src/bundle-streams.js`.
   *Note:* `startedDateTime`/`_t`/`_start` are intentionally unchanged — the HAR
   spec wants wall-clock there, and `_t` (one-clock request-start offset) is
   already correct.

2. **scrubNode raw fallback** (SYNTHESIS #9 — blind_c + astra, HIGH).
   If JSON (de)serialization of an rrweb node failed, the raw, unredacted node
   was persisted to events.jsonl. A secret embedded in that node bypassed the
   entire redaction pipeline.
   Fix: on scrub failure the node is **dropped** and replaced with a marker
   (`{rrweb: "‹node dropped: scrub failed›"}`). A lost DOM-diff node is a
   recoverable rendering gap; a leaked token is not.
   File: `extension/src/background.js`.

3. **PEM marker-only redaction** (SYNTHESIS #12 — blind_b + astra, HIGH).
   The token-shape regex matched only `-----BEGIN…PRIVATE KEY-----`, leaving the
   base64 key material in the clear after the marker was replaced.
   Fix: match the FULL block (`BEGIN…END`) plus an unterminated variant that
   redacts to end-of-string. Applied to `redact.js` AND the verbatim mirror in
   `content.js` (the existing drift test `test_input_token_sync.mjs` enforces
   they stay identical).
   Files: `extension/src/redact.js`, `extension/src/content.js`.
   *Deliberately unchanged:* `analyze/validate_bundle.py` TOKEN_RE — it flags
   *unredacted* leaks, and a redacted block contains neither marker nor material.

4. **errors.json redaction** (SYNTHESIS #11 — astra + glm, MEDIUM).
   `logError()` persisted raw error messages and stacks (which can embed
   captured URLs with `?token=…`, header dumps, DOM selectors with secret
   values) straight into the exported bundle.
   Fix: message and stack pass through `scrubTokens(redactUrl(s))` before
   persisting. File: `extension/src/background.js`.

5. **Frame coverage from disk truth** (SYNTHESIS #3 — 4 of 5 reviewers).
   The coverage gap check (validator + `check_coverage.py` CLI) read
   `manifest.frames`, which can under-index; a real frame hole was invisible.
   Fix: `Bundle.disk_frames()` (validator) and `_load()` (CLI) rebuild the frame
   list from the `frames/*.png` entries on disk/zip (filename = ms offset),
   falling back to the manifest only for a stripped bundle. Files:
   `analyze/validate_bundle.py`, `analyze/check_coverage.py`.

6. **scroll/focus are content-script kinds** (blind_c's KNOWN_KINDS observation,
   applied to the coverage check).
   A tab whose only post-navigation events were scrolls looked "never captured"
   to the gap detector. `CONTENT_KINDS` now includes `scroll` and `focus`.
   File: `analyze/check_coverage.py`.

## What I verified was ALREADY FIXED in v2 (do not re-fix)

Checked at the exact file:line the reviews cited — all confirmed handled in the
merged v2 tree:

- `applyReshare` duplication (#1) — gone; 0 occurrences.
- VTT `00:` hardcoded hour (#15) — `buildTranscript` computes hours.
- `'speech'` missing from validator KNOWN_KINDS — present.
- IDB connections per-call (glm) — `db.js` holds one cached connection with
  `onversionchange`/`onclose` reset.
- Windows test failures (#17) — 279 OK locally pre-branch.
- Path traversal in `run_claude.py` (astra) — kebab-case allowlist + device-name
  block + `resolve()` containment check already in place.
- Download-before-confirmed (#14) — `download.js` completion-gated path landed
  in v2.
- HAR keys per debugger target — composite `requestKey` (tab+session+requestId)
  everywhere; `test_har_key_contract.mjs` enforces it.
- pack.py stub false positive (blind_c) — `_transcript_is_stub` requires real
  cue structure.
- phantom frame metadata on IDB write failure (blind_b) — `state.frames.push`
  only runs after the awaited `db.append` succeeds.
- Token regex drift (#8) — content.js synced to redact.js with
  `test_input_token_sync.mjs` as the drift gate.

## Deliberately NOT fixed here (owner decisions, unchanged)

- **Visual stream redaction (#13)** — pixels/screenshots are unredacted by the
  owner's explicit v2 constraint ("only keys ON SCREEN masked"). Design gap,
  not a bug to patch silently.
- **rrweb URL/attribute redaction** (astra) — same constraint family; the
  token-shape scrub (`scrubNode`) covers value-shape secrets, which is the v2
  agreed scope.
- **Background-tab events as tab switches (pack.py)** — analysis-quality
  question, belongs with the AI-consumption backlog, not correctness.

## Where the suggestions came from (for your local reviewer)

`notes/SYNTHESIS.md` consolidates five blind reviews (hermes, blind_b, blind_c,
astra, glm). The P0 security/data-loss items were built in v2; this branch is
the remaining P1 correctness set plus the two small redaction gaps (#11, #12)
that were cheap to do correctly alongside. Full review texts:
`notes/review-2026-09-1{1,2}-*.md`.

## Mutation-proof each fix (already run — repeat if you like)

Every regression test was proven able to fail:
- M1 revert scrubNode→raw fallback → `scrubNode drops the node` test fails ✓
- M2 revert PEM to marker-only → PEM test fails ✓
- M3 remove `_t0Clock` from export strip-list → strip test fails ✓
- M4 revert logError scrub → logError test fails ✓
- M5 revert CONTENT_KINDS → `scroll_focus_are_content_kinds` fails ✓
- M6 revert `_load` disk-frames → `test_load_prefers_disk_frames_over_manifest`
  fails ✓

New tests: `tests/test_p1_fixes.py` (6), `tests/test_p1_extension_fixes.mjs` (4).

## Suggested review questions for the local agent

1. Is dropping the node on scrub failure the right trade vs. a per-field
   fallback? (I'd argue a partial redaction is worse than a clear drop marker.)
2. `entry.time` now uses the recording clock — should the HAR also carry the
   wall-clock duration somewhere for DevTools parity, or is `_start` +
   `startedDateTime` enough?
3. Does `CONTENT_KINDS += {scroll, focus}` make any existing capture-gap WARNING
   noisier on real bundles? (Scroll events are frequent, so the *absence*
   detection gets stronger; false CAPTURE GAPs should not increase since the
   set only grows.)
4. errors.json now scrubs URLs in messages — any downside for debugging?