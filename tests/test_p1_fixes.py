"""Regression tests for the v2-p1 correctness branch (2026-09-13).

Each test defends one fix from notes/SYNTHESIS.md that was documented but not
built at v2 merge time. Mutation-probe each: reverting the fix must fail the test.
"""

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyze"))

import check_coverage  # noqa: E402
import validate_bundle  # noqa: E402


class TestCoverageKinds(unittest.TestCase):
    """scroll + focus are content-script events: a capture that keeps 'network'
    alive but has only scroll/focus after the clicks stop must count as a
    content-script death, not as 'was never captured'."""

    def test_scroll_focus_are_content_kinds(self):
        timeline = [
            {"t": 0, "kind": "nav", "tab": 1},
            {"t": 1000, "kind": "click", "tab": 1},
            {"t": 2000, "kind": "click", "tab": 1},
            {"t": 3000, "kind": "scroll", "tab": 1},
            {"t": 3200, "kind": "focus", "tab": 1},
        ] + [{"t": t, "kind": "network", "tab": 1} for t in range(4000, 300000, 1000)]
        res = check_coverage.analyze_coverage(timeline)
        # Without scroll/focus in CONTENT_KINDS the tab has only 3 content
        # events… which is exactly MIN_CONTENT_EVENTS — the gap fires either
        # way. The kind-set claim is checked directly:
        self.assertIn("scroll", check_coverage.CONTENT_KINDS)
        self.assertIn("focus", check_coverage.CONTENT_KINDS)
        # And a scroll-only tab (below MIN_CONTENT_EVENTS in clicks) still
        # counts as captured when network outlives it:
        tl2 = [
            {"t": 0, "kind": "nav", "tab": 1},
            {"t": 100, "kind": "scroll", "tab": 1},
            {"t": 200, "kind": "focus", "tab": 1},
            {"t": 300, "kind": "scroll", "tab": 1},
        ] + [{"t": t, "kind": "network", "tab": 1} for t in range(1000, 200000, 1000)]
        res2 = check_coverage.analyze_coverage(tl2)
        self.assertFalse(res2["ok"], "scroll/focus-only capture death must be a failure")


class TestDiskFrameTruth(unittest.TestCase):
    """The coverage check must use DISK frames, not manifest.frames — the
    manifest can under-index (SYNTHESIS #3)."""

    def _bundle_dir(self, disk_frame_ts, manifest_frame_ts):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        fdir = root / "frames"
        fdir.mkdir()
        for ts in disk_frame_ts:
            (fdir / f"{ts:010d}.png").write_bytes(b"\x89PNG")
        manifest = {
            "t0_wall": "2026-06-17T00:00:00.000Z",
            "duration_ms": 600000,
            "sync_mode": "self_record",
            "frames": [{"t": t, "file": f"frames/{t:010d}.png"} for t in manifest_frame_ts],
        }
        (root / "manifest.json").write_text(json.dumps(manifest))
        return root

    def test_load_prefers_disk_frames_over_manifest(self):
        # Disk has regular frames every 3s; the manifest claims only one.
        root = self._bundle_dir(disk_frame_ts=list(range(0, 60000, 3000)),
                                manifest_frame_ts=[0])
        # also a timeline so _load has one
        (root / "timeline.json").write_text(json.dumps([{"t": 0, "kind": "nav", "tab": 1}]))
        _, frames, _ = check_coverage._load(root)
        self.assertEqual(len(frames), 20, "disk truth (20 frames) must beat the manifest's 1")

    def test_gap_detected_from_disk_frames(self):
        # Disk shows a 120s frame hole; the manifest (under-indexed) hides it.
        disk = [0, 3000, 6000, 126000, 129000, 132000]
        root = self._bundle_dir(disk_frame_ts=disk, manifest_frame_ts=[0, 3000, 6000])
        (root / "timeline.json").write_text(json.dumps([{"t": 0, "kind": "nav", "tab": 1}]))
        _, frames, _ = check_coverage._load(root)
        res = check_coverage.analyze_coverage(
            [{"t": 0, "kind": "nav", "tab": 1}], frames, duration_ms=135000)
        self.assertTrue(any("gap between frames" in w for w in res["warnings"]),
                        "the 120s disk frame hole must surface as a warning")

    def test_validator_uses_disk_frames(self):
        # Disk frames every 3s but the manifest lists ONLY one → pre-fix, the
        # frame-gap warning fired from the under-indexed manifest list; post-fix
        # it reads disk truth and stays quiet on frame coverage.
        root = self._bundle_dir(disk_frame_ts=list(range(0, 60000, 3000)),
                                manifest_frame_ts=[0])
        (root / "timeline.json").write_text(json.dumps([
            {"t": 0, "kind": "nav", "tab": 1},
            {"t": 1000, "kind": "click", "tab": 1},
            {"t": 2000, "kind": "click", "tab": 1},
            {"t": 3000, "kind": "click", "tab": 1},
            {"t": 4000, "kind": "click", "tab": 1},
        ] + [{"t": t, "kind": "network", "tab": 1} for t in range(5000, 60000, 3000)]))
        b = validate_bundle.Bundle(root)
        self.assertEqual(len(b.disk_frames()), 20)
        r = validate_bundle.Report()
        validate_bundle.check_coverage_gap(
            json.loads((root / "timeline.json").read_text()),
            json.loads((root / "manifest.json").read_text()), b, r)
        frame_gap_warnings = [w for w in r.warnings if "gap between frames" in w]
        self.assertFalse(frame_gap_warnings,
                        "disk frames every 3s → no frame-gap warning despite the manifest listing only 1")

    def test_validator_flags_frame_gap_from_disk_truth(self):
        # The inverse: the manifest claims dense frames, but disk shows a 120s
        # hole. Pre-fix (manifest as source) the hole was invisible.
        disk = [0, 3000, 6000, 126000, 129000, 132000]
        root = self._bundle_dir(disk_frame_ts=disk,
                                manifest_frame_ts=list(range(0, 135000, 3000)))
        (root / "timeline.json").write_text(json.dumps([
            {"t": 0, "kind": "nav", "tab": 1},
            {"t": 1000, "kind": "click", "tab": 1},
            {"t": 2000, "kind": "click", "tab": 1},
            {"t": 3000, "kind": "click", "tab": 1},
            {"t": 126000, "kind": "click", "tab": 1},
        ]))
        b = validate_bundle.Bundle(root)
        r = validate_bundle.Report()
        validate_bundle.check_coverage_gap(
            json.loads((root / "timeline.json").read_text()),
            json.loads((root / "manifest.json").read_text()), b, r)
        frame_gap_warnings = [w for w in r.warnings if "gap between frames" in w]
        self.assertTrue(frame_gap_warnings,
                        "a 120s frame hole on disk must warn even when the manifest hides it")

    def test_zip_bundle_disk_frames(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        zpath = Path(tmp.name) / "b.zip"
        with zipfile.ZipFile(zpath, "w") as z:
            for ts in range(0, 30000, 3000):
                z.writestr(f"frames/{ts:010d}.png", b"\x89PNG")
            z.writestr("manifest.json", json.dumps({
                "t0_wall": "2026-06-17T00:00:00.000Z", "duration_ms": 30000,
                "sync_mode": "self_record", "frames": []}))
            z.writestr("timeline.json", json.dumps([{"t": 0, "kind": "nav", "tab": 1}]))
        _, frames, _ = check_coverage._load(zpath)
        self.assertEqual(len(frames), 10, "zip frames must be read from entry names")


if __name__ == "__main__":
    unittest.main()