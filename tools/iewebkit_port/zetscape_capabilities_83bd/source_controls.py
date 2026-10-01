"""Exact-preimage/private-output controls; no engine, guest or build starts.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
"""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
import prepare_probe
import syntax_check


class SourceControls(unittest.TestCase):
    def test_current_preimage_stages_without_capability_claims(self):
        source, difference, record = prepare_probe.prepare()
        self.assertEqual(hashlib.sha256(source).hexdigest(), record["staged_source"]["sha256"])
        self.assertEqual(hashlib.sha256(difference).hexdigest(), record["patch"]["sha256"])
        self.assertEqual(record["required_cases"], 8)
        for key in ("canonical_source_modified", "engine_built", "guest_executed", "browser_pass", "gpu_pass"):
            self.assertFalse(record[key])

    def test_changed_preimage_is_rejected_before_staging(self):
        with patch.object(prepare_probe, "PREIMAGE_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "preimage changed"):
                prepare_probe.prepare()

    def test_ambiguous_patch_anchor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            prepare_probe.once("repeat repeat", "repeat", "modified")

    def test_existing_staged_evidence_is_preserved(self):
        existing = prepare_probe.HERE / "private/probe-r2/probe-source-pin.json"
        before = existing.read_bytes()
        with self.assertRaisesRegex(ValueError, "existing evidence"):
            prepare_probe.stage(existing.parent)
        self.assertEqual(before, existing.read_bytes())

    def test_source_output_cannot_escape_lane(self):
        with self.assertRaisesRegex(ValueError, "under this lane"):
            prepare_probe.stage(Path("/root/Win98-Modern-boot/build/disallowed-zetscape-output"))

    def test_check_output_cannot_escape_lane(self):
        with self.assertRaisesRegex(ValueError, "under this lane"):
            syntax_check.bounded_output(Path("/root/Win98-Modern-boot/build/disallowed-zetscape-output"))


if __name__ == "__main__":
    unittest.main()
