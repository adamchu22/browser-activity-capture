#!/usr/bin/env python3
"""Capture-coverage checker.

Detects the failure mode where the content script silently dies mid-session —
e.g. on a full-page navigation in a server-rendered app — so that only network
(the CDP debugger, which survives navigations) keeps recording while
clicks / hovers / DOM (rrweb) / frames stop. That bug lost ~4.5 min of a 6 min
session before anyone noticed, because the bundle still "validated" (it had a
video, no errors, hundreds of events) — the events were just all network.

Signature: on a tab that was clearly being captured (>= a few content-script
events), network activity continues well AFTER the last content-script event.

Usage:
    python3 analyze/check_coverage.py <bundle-dir-or-zip>

Exit code 0 = PASS, 1 = coverage gap found. Stdlib only.
"""

import json
import re
import sys
import zipfile
from pathlib import Path

# Events produced by the content script (page side). If these stop but network
# keeps going, the content script died.
CONTENT_KINDS = {"click", "hover", "nav", "input", "key", "annotation:select", "annotation:draw",
                 "scroll", "focus"}
NETWORK_KIND = "network"

# A tab needs at least this many content events to count as "was being captured"
# (so we don't flag a tab the user merely had open and never touched).
MIN_CONTENT_EVENTS = 3
# Network continuing more than this long past the last content event = the bug.
DEFAULT_GAP_MS = 45_000
# Frames should now be on a ~3s timer; warn if any gap is much larger.
DEFAULT_FRAME_GAP_MS = 60_000

# Frame filenames are the ms offset, zero-padded (frames/000123.png).
_FRAME_STEM_RE = re.compile(r"^(\d+)$")
_ZIP_FRAME_RE = re.compile(r"^frames/(\d+)\.png$")


def _fmt(ms):
    s = max(0, int(_num(ms) // 1000))
    return f"{s // 60}:{s % 60:02d}"


def _num(v, default=0.0):
    """Coerce to float, falling back to `default` — so a non-numeric timestamp in an
    untrusted bundle can't crash arithmetic/sorting here."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def analyze_coverage(timeline, frames=None, duration_ms=None,
                     gap_threshold_ms=DEFAULT_GAP_MS, frame_gap_ms=DEFAULT_FRAME_GAP_MS):
    """Pure analysis over parsed data. Returns a dict:
        { ok, failures: [...], warnings: [...], tabs: {tab: {...}} }
    `ok` is False only for hard coverage failures (content capture died);
    frame gaps are warnings.
    """
    by_tab = {}
    for e in timeline:
        if not isinstance(e, dict):
            continue  # untrusted bundle: skip non-object timeline entries
        tab = e.get("tab")
        if not isinstance(tab, (str, int, type(None))):  # keep the dict key hashable
            tab = None
        kind = e.get("kind")
        t = _num(e.get("t", 0))
        slot = by_tab.setdefault(tab, {"content": [], "network": []})
        if kind in CONTENT_KINDS:
            slot["content"].append(t)
        elif kind == NETWORK_KIND:
            slot["network"].append(t)

    failures, warnings, tabs = [], [], {}
    for tab, slot in by_tab.items():
        content, network = sorted(slot["content"]), sorted(slot["network"])
        info = {
            "content_events": len(content),
            "network_events": len(network),
            "content_last": content[-1] if content else None,
            "network_last": network[-1] if network else None,
        }
        tabs[tab] = info
        if len(content) >= MIN_CONTENT_EVENTS and network:
            gap = network[-1] - content[-1]
            info["gap_ms"] = gap
            if gap > gap_threshold_ms:
                failures.append(
                    f"tab {tab}: content-script capture stopped at {_fmt(content[-1])} "
                    f"but network kept recording until {_fmt(network[-1])} "
                    f"({_fmt(gap)} of network-only capture — the content script likely "
                    f"died on a navigation and never re-attached)."
                )

    # Frame coverage: with the periodic timer, frames should be regular. A big
    # gap means visual coverage lapsed (often the same root cause).
    if frames:
        fts = sorted(_num(f.get("t", 0)) for f in frames if isinstance(f, dict))
        prev = 0
        biggest = 0
        for t in fts:
            biggest = max(biggest, t - prev)
            prev = t
        if duration_ms is not None:
            biggest = max(biggest, _num(duration_ms) - prev)
        if biggest > frame_gap_ms:
            warnings.append(
                f"largest gap between frames is {_fmt(biggest)} "
                f"(expected a frame every few seconds)."
            )

    return {"ok": not failures, "failures": failures, "warnings": warnings, "tabs": tabs}


def _parse(raw):
    """Best-effort JSON parse — bytes or str, never raises (untrusted bundle)."""
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def _load(bundle):
    """Load timeline + frames from a bundle dir or zip. Tolerates a
    malformed/missing file: the loaders fall back to safe shapes so the CLI can't
    crash on an untrusted bundle. FRAMES come from DISK when a frames/ dir or
    zip entries exist — the manifest can under-index them (SYNTHESIS #3) — with
    the manifest list only as a fallback for a stripped bundle."""
    p = Path(bundle)
    timeline = manifest = None
    disk_frames = []
    if p.is_dir():
        timeline = _parse((p / "timeline.json").read_bytes()) if (p / "timeline.json").exists() else None
        manifest = _parse((p / "manifest.json").read_bytes()) if (p / "manifest.json").exists() else None
        fdir = p / "frames"
        if fdir.is_dir():
            disk_frames = [
                {"t": int(m.group(1)), "file": f"frames/{q.name}"}
                for q in sorted(fdir.iterdir())
                if q.suffix.lower() == ".png" and (m := _FRAME_STEM_RE.match(q.stem))
            ]
    elif zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            names = set(z.namelist())
            timeline = _parse(z.read("timeline.json")) if "timeline.json" in names else None
            manifest = _parse(z.read("manifest.json")) if "manifest.json" in names else None
            disk_frames = []
            for name in sorted(names):
                m = _ZIP_FRAME_RE.match(name)
                if m:
                    disk_frames.append({"t": int(m.group(1)), "file": name})
            disk_frames.sort(key=lambda f: f["t"])
    else:
        sys.exit(f"not a bundle dir or zip: {bundle}")
    if not isinstance(timeline, list):
        timeline = []
    if not isinstance(manifest, dict):
        manifest = {}
    frames = manifest.get("frames")
    frames = frames if isinstance(frames, list) else []
    return timeline, (disk_frames if disk_frames else frames), manifest.get("duration_ms")


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: python3 analyze/check_coverage.py <bundle-dir-or-zip>")
    timeline, frames, duration = _load(argv[1])
    r = analyze_coverage(timeline, frames, duration)

    print(f"tabs analyzed: {len(r['tabs'])}")
    for tab, info in r["tabs"].items():
        last_c = _fmt(info["content_last"]) if info["content_last"] is not None else "—"
        last_n = _fmt(info["network_last"]) if info["network_last"] is not None else "—"
        print(f"  tab {tab}: {info['content_events']} content (last {last_c}), "
              f"{info['network_events']} network (last {last_n})")
    for w in r["warnings"]:
        print(f"WARN: {w}")
    if r["ok"]:
        print("PASS — content-script capture tracked network for every active tab.")
        return 0
    print("FAIL — capture coverage gap detected:")
    for f in r["failures"]:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
