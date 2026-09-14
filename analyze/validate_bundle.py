#!/usr/bin/env python3
"""Validate a Capture Bundle (zip or directory) before analysis.

Run this right after the extension exports a `capture-*.zip` and before
`pack.py`. It answers three questions:

  1. Is this the right shape? (required files, parseable JSON, known event kinds)
  2. Is it internally consistent? (frames referenced actually exist, timeline
     sorted on one clock, manifest counts roughly match)
  3. Did redaction hold? (no auth headers / secret-looking values in the clear)

Stdlib only. Exit code 0 = pass, 1 = problems found.

Usage:
    python validate_bundle.py ./capture-2026-06-16.zip
    python validate_bundle.py ./capture-dir/
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import zipfile
from pathlib import Path

# Sibling module — works whether run as `python3 analyze/validate_bundle.py` or
# imported in tests (its own dir is on the path either way once we add it).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_coverage import analyze_coverage  # noqa: E402

KNOWN_KINDS = {"nav", "speech", "click", "hover", "input", "key", "network",
               "annotation:select", "annotation:draw", "scroll", "focus", "tab-activated"}
REQUIRED = ["manifest.json", "timeline.json"]
EXPECTED = ["events.jsonl", "network.har", "transcript.vtt"]

# Things that must NEVER appear in a written bundle. If they do, redaction failed.
# Two header shapes: object-key (`"authorization": "x"`) and HAR name/value
# (`{"name":"Authorization","value":"x"}`). Either with a non-redacted value leaks.
SECRET_NAMES = r"authorization|cookie|set-cookie|x-api-key|proxy-authorization"
SECRET_HEADER_RES = [
    re.compile(rf'"(?:{SECRET_NAMES})"\s*:\s*"(?!‹redacted)', re.I),
    re.compile(rf'"name"\s*:\s*"(?:{SECRET_NAMES})"\s*,\s*"value"\s*:\s*"(?!‹redacted)', re.I),
]
# A token sitting in the clear — JWT/bearer plus high-confidence provider key shapes.
# In lockstep with redact.js TOKEN_VALUE_RE so the gate flags exactly what the
# extension is supposed to have scrubbed (if you add a shape there, add it here).
# Case-insensitive and tolerant of a URL-encoded space.
TOKEN_RE = re.compile(
    "|".join([
        r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]+)?",  # JWT
        r"Bearer(?:\s|%20|\+)+[A-Za-z0-9._-]{12,}",         # bearer token
        r"(?:AKIA|ASIA)[A-Z0-9]{16}",                       # AWS access key id
        r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",            # Stripe secret/restricted key
        r"gh[posu]_[A-Za-z0-9]{36,}",                       # GitHub token
        r"github_pat_[A-Za-z0-9_]{40,}",                    # GitHub fine-grained PAT
        r"AIza[A-Za-z0-9_-]{35}",                           # Google API key
        r"ya29\.[A-Za-z0-9_-]{20,}",                        # Google OAuth access token
        r"xox[baprs]-[A-Za-z0-9-]{10,}",                    # Slack token
        r"sk-ant-[A-Za-z0-9_-]{20,}",                       # Anthropic API key
        r"sk-[A-Za-z0-9]{32,}",                             # OpenAI API key
        r"-----BEGIN(?:[A-Z ]+)?PRIVATE KEY-----",          # PEM private key block
    ]),
    re.IGNORECASE,
)


class Bundle:
    """Read files from either a directory or a zip, uniformly."""

    def __init__(self, path: Path):
        self.path = path
        self.zip = zipfile.ZipFile(path) if path.is_file() else None
        if self.zip:
            self.names = set(self.zip.namelist())
        else:
            self.names = {p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file()}

    def has(self, name: str) -> bool:
        return name in self.names

    def text(self, name: str) -> str:
        # errors="replace": a non-UTF-8 byte in an untrusted bundle must not crash
        # the validator (load_json catches the resulting JSON error; the redaction
        # scan still runs over the decoded text).
        raw = self.zip.read(name) if self.zip else (self.path / name).read_bytes()
        return raw.decode("utf-8", errors="replace")

    def frame_files(self) -> set[str]:
        return {n for n in self.names if n.startswith("frames/") and n.endswith(".png")}

    def disk_frames(self) -> list[dict]:
        """Frames as [{t, file}] parsed from the DISK/zip filenames — the complete
        list even when manifest.frames under-indexes (SYNTHESIS #3)."""
        out = []
        for n in self.frame_files():
            stem = n[len("frames/"): -len(".png")]
            if re.fullmatch(r"\d+", stem):
                out.append({"t": int(stem), "file": n})
        out.sort(key=lambda f: f["t"])
        return out


class Report:
    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.info: list[str] = []

    def err(self, m): self.errors.append(m)
    def warn(self, m): self.warnings.append(m)
    def ok(self, m): self.info.append(m)

    def render(self) -> int:
        for m in self.info:
            print(f"  ✓ {m}")
        for m in self.warnings:
            print(f"  ! {m}")
        for m in self.errors:
            print(f"  ✗ {m}")
        print()
        if self.errors:
            print(f"FAIL — {len(self.errors)} problem(s), {len(self.warnings)} warning(s).")
            return 1
        print(f"PASS — {len(self.warnings)} warning(s). Ready for pack.py.")
        return 0


def load_json(b: Bundle, name: str, r: Report):
    try:
        return json.loads(b.text(name))
    except Exception as e:  # noqa: BLE001
        r.err(f"{name} is not valid JSON: {e}")
        return None


def valid_time(value):
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and value >= 0)


def check_manifest(m: dict, b: Bundle, r: Report):
    if not valid_time(m.get("duration_ms")):
        r.err("manifest duration_ms must be finite and non-negative")
    for segment in m.get("video_segments", []) if isinstance(m.get("video_segments", []), list) else []:
        if not isinstance(segment, dict) or not valid_time(segment.get("offset_ms")):
            r.err("video segment offset_ms must be finite and non-negative")
    for key in ("t0_wall", "duration_ms", "sync_mode"):
        if key not in m:
            r.err(f"manifest.json missing `{key}`")
    if m.get("sync_mode") not in (None, "self_record", "loom_offset"):
        r.warn(f"manifest sync_mode `{m.get('sync_mode')}` is unexpected")
    red = m.get("redaction")
    if not isinstance(red, dict):
        red = {}
    if not red.get("password_fields_masked"):
        r.warn("manifest does not assert password_fields_masked — confirm redaction ran")
    else:
        r.ok("manifest declares redaction policy")
    frames = m.get("frames")
    return frames if isinstance(frames, list) else []


def check_timeline(events, r: Report):
    if not isinstance(events, list) or not events:
        r.err("timeline.json is empty or not a list")
        return [], []
    last_t = -1
    bad_kinds, unsorted = set(), False
    referenced_frames = []
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            r.err(f"timeline event #{i} is not an object")
            continue
        if "t" not in e or "kind" not in e:
            r.err(f"timeline event #{i} missing `t` or `kind`")
            continue
        t = e["t"]
        if not valid_time(t):
            r.err(f"timeline event #{i} has an invalid `t` (expected finite non-negative milliseconds)")
            continue
        kind = e["kind"]
        if not isinstance(kind, str):
            r.err(f"timeline event #{i} has a non-string kind")
        if isinstance(kind, str) and kind not in KNOWN_KINDS:
            bad_kinds.add(kind)
        if t < last_t:
            unsorted = True
        last_t = t
        if isinstance(e.get("frame"), str) and e["frame"]:
            referenced_frames.append(e["frame"])
    if bad_kinds:
        r.warn(f"timeline has unknown event kinds: {sorted(bad_kinds)}")
    if unsorted:
        r.err("timeline is not sorted by `t` — the one-clock invariant is broken")
    else:
        r.ok(f"timeline OK: {len(events)} events on one clock")
    return events, referenced_frames


def check_frames(manifest_frames, referenced, b: Bundle, r: Report):
    on_disk = b.frame_files()
    wanted = set()
    for f in manifest_frames:
        if isinstance(f, dict) and not valid_time(f.get("t")):
            r.err("manifest frame timestamp must be finite and non-negative")
        name = f.get("file") if isinstance(f, dict) else f
        if isinstance(name, str):
            wanted.add(name)
    wanted |= set(referenced)
    missing = {w for w in wanted if w and w not in on_disk}
    if missing:
        r.err(f"{len(missing)} referenced frame(s) not in bundle: {sorted(missing)[:3]}…")
    elif on_disk:
        r.ok(f"frames OK: {len(on_disk)} present, all references resolve")


def check_coverage_gap(timeline, manifest, b: Bundle, r: Report):
    """Catch the capture-on-navigation bug: a tab whose content-script capture
    (clicks/rrweb/frames) stopped while network kept recording. The bundle is
    still well-formed and usable — so this is a loud WARNING, not a hard failure —
    but it means part of the session was captured network-only. See
    analyze/check_coverage.py.

    Frames come from DISK (b.disk_frames()), not manifest.frames — the manifest
    can under-index (SYNTHESIS #3), which made the gap check look at an
    incomplete frame list and miss real coverage gaps."""
    disk_frames = b.disk_frames()
    frames_for_check = disk_frames if disk_frames else manifest.get("frames", [])
    res = analyze_coverage(timeline, frames_for_check, manifest.get("duration_ms"))
    for f in res["failures"]:
        r.warn(f"CAPTURE GAP — {f}")
    if res["failures"]:
        r.warn("→ DOM/visual capture stopped while network continued; the recording is "
               "usable but incomplete (run analyze/check_coverage.py for detail).")
    else:
        for w in res["warnings"]:
            r.warn(f"frame coverage: {w}")
        if not res["warnings"]:
            r.ok("capture coverage OK — content-script capture tracked network on every active tab")


def check_redaction(b: Bundle, r: Report):
    """Validate existing redaction scope; never rewrite captured content."""
    secret_names = set(SECRET_NAMES.split("|"))
    leaks = 0

    def inspect(value, headers, depth=0):
        token, header = False, False
        if depth > 100:
            return False, False
        if isinstance(value, str):
            token = bool(TOKEN_RE.search(value))
            # Decode JSON-in-JSON bodies and escaped strings, without depending on
            # object key order or the spelling of Unicode escapes.
            if value.lstrip().startswith(("{", "[")):
                try:
                    a, h = inspect(json.loads(value), headers, depth + 1)
                    token |= a
                    header |= h
                except (ValueError, RecursionError):
                    pass
        elif isinstance(value, list):
            for child in value:
                a, h = inspect(child, headers, depth + 1)
                token |= a
                header |= h
        elif isinstance(value, dict):
            if headers:
                for key, val in value.items():
                    if key.lower() in secret_names and isinstance(val, str):
                        header |= not val.startswith("‹redacted")
                if str(value.get("name", "")).lower() in secret_names and "value" in value:
                    header |= not str(value["value"]).startswith("‹redacted")
            for key, child in value.items():
                token |= bool(TOKEN_RE.search(key))
                a, h = inspect(child, headers, depth + 1)
                token |= a
                header |= h
        return token, header

    for name in ("timeline.json", "network.har", "events.jsonl",
                 "manifest.json", "errors.json", "transcript.vtt"):
        if not b.has(name):
            continue
        headers = name in ("timeline.json", "network.har", "events.jsonl")
        bodies = b.text(name).splitlines() if name.endswith(".jsonl") else [b.text(name)]
        token = header = False
        for body in bodies:
            try:
                parsed = json.loads(body)
            except (ValueError, RecursionError):
                parsed = body
            a, h = inspect(parsed, headers)
            token |= a
            header |= h
        if header:
            r.err(f"{name} contains an auth/cookie header that is NOT redacted")
            leaks += 1
        if token:
            r.err(f"{name} contains a token/bearer value in the clear")
            leaks += 1
    if not leaks:
        r.ok("redaction check passed — no auth headers or tokens in the clear")


def validate(path: Path) -> int:
    print(f"Validating {path} …\n")
    r = Report()
    b = Bundle(path)

    for name in REQUIRED:
        if not b.has(name):
            r.err(f"missing required file `{name}`")
    if r.errors:  # can't continue without the basics
        return r.render()

    for name in EXPECTED:
        if not b.has(name):
            r.warn(f"no `{name}` (optional, but the extension normally emits it)")

    manifest = load_json(b, "manifest.json", r)
    if manifest is not None and not isinstance(manifest, dict):
        r.err("manifest.json is not a JSON object")
        manifest = None
    timeline = load_json(b, "timeline.json", r)
    manifest_frames = check_manifest(manifest, b, r) if isinstance(manifest, dict) else []
    _, referenced = check_timeline(timeline, r)
    check_frames(manifest_frames, referenced, b, r)
    if isinstance(manifest, dict) and isinstance(timeline, list) and not r.errors:
        check_coverage_gap(timeline, manifest, b, r)
    if b.has("network.har"):
        har = load_json(b, "network.har", r)
        log = har.get("log") if isinstance(har, dict) else None
        entries = log.get("entries") if isinstance(log, dict) else None
        if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
            r.err("network.har must contain log.entries as an array of objects")
        else:
            for e in entries:
                if "_t" in e and not valid_time(e["_t"]):
                    r.err("HAR _t must be finite and non-negative")
            r.ok("network.har structure OK")
    check_redaction(b, r)

    if b.zip:
        b.zip.close()
    return r.render()


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate a Capture Bundle before analysis.")
    ap.add_argument("bundle", type=Path, help="path to a capture .zip or bundle directory")
    args = ap.parse_args()
    if not args.bundle.exists():
        sys.exit(f"error: {args.bundle} does not exist")
    sys.exit(validate(args.bundle))


if __name__ == "__main__":
    main()
