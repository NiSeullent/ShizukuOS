#!/usr/bin/env python3
"""Read-only rejection controls against an actual private JSC graph.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Malformed graph/profile reads are injected in memory. No source, build graph,
receipt or guest is written, and no compiler or process is launched.
"""
import argparse
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
from core_build import runtime_link_input
from core_jsc_profile_gate import validate_build_profile, _stanza


class ProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = cls.work.resolve(strict=True)
        core = json.loads((cls.work / "core-build.json").read_text())
        cls.runtime = Path(core["runtime_link_input"]["object"])
        cls.source = cls.work / "webkitgtk-2.54.0"
        cls.build = cls.work / "build-jsc-win9x"
        cls.profile = validate_build_profile(cls.work, cls.source, cls.repo, cls.runtime)

    def validate(self, **kwargs):
        return validate_build_profile(self.work, self.source, self.repo, self.runtime, **kwargs)

    def reject_read(self, path, text, fragment):
        original = Path.read_text

        def read(current, *args, **kwargs):
            return text if current == path else original(current, *args, **kwargs)

        with patch.object(Path, "read_text", read):
            with self.assertRaisesRegex(ValueError, fragment):
                self.validate()

    def test_unchanged_actual_profile(self):
        self.assertTrue(self.profile["profile_gate_passed"])
        self.assertGreaterEqual(len(self.profile["inputs"]), 40)
        self.assertEqual(self.validate(expected=self.profile), self.profile)

    def test_dependency_without_link_flag_is_rejected(self):
        path = self.build / "build.ninja"
        text = path.read_text()
        header, fields = _stanza(text, "build bin/jsc.exe: ")
        self.assertIn(str(self.runtime), header)
        line = "  LINK_FLAGS = " + fields["LINK_FLAGS"]
        offset = text.index(line, text.index(header))
        changed = line.replace(str(self.runtime) + " ", "", 1)
        self.assertNotIn(str(self.runtime), changed)
        self.reject_read(path, text[:offset] + changed + text[offset + len(line):], "linker flags")

    def test_order_only_runtime_is_rejected(self):
        path = self.build / "build.ninja"
        text = path.read_text()
        header, _ = _stanza(text, "build bin/jsc.exe: ")
        self.assertIn(" || ", header)
        changed = header.replace(str(self.runtime), "", 1).replace(
            " || ", " || " + str(self.runtime) + " ", 1)
        self.reject_read(path, text.replace(header, changed, 1), "before order-only")

    def test_allocator_macro_override_is_rejected(self):
        path = self.build / "compile_commands.json"
        entries = json.loads(path.read_text())
        selected = next(row for row in entries if row["file"].endswith("/mimalloc/src/static.c"))
        if "arguments" in selected:
            selected["arguments"].append("-UIEWEBKIT_WIN9X")
        else:
            selected["command"] += " -UIEWEBKIT_WIN9X"
        self.reject_read(path, json.dumps(entries), "overrides the Win9x")

    def test_generic_loop_layout_is_rejected(self):
        path = self.build / "cmakeconfig.h"
        self.reject_read(path, path.read_text() + "\n#define USE_GENERIC_EVENT_LOOP 1\n", "incompatible RunLoop")

    def test_completed_profile_drift_is_rejected(self):
        changed = copy.deepcopy(self.profile)
        changed["runtime_object"] = str(self.work / "unbound-runtime.o")
        with self.assertRaisesRegex(ValueError, "profile changed"):
            self.validate(expected=changed)

    def test_obsolete_genuine_runtime_is_rejected(self):
        # Actual source/object validation remains separate from graph validity.
        with self.assertRaisesRegex(ValueError, "binding failed"):
            runtime_link_input(self.obsolete_runtime)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--iewebkit-repo", type=Path, required=True)
    parser.add_argument("--obsolete-runtime", type=Path, required=True,
                        help="Preserved genuine runtime compiled before the current source pin")
    args = parser.parse_args()
    ProfileControls.work = args.work
    ProfileControls.repo = args.iewebkit_repo
    ProfileControls.obsolete_runtime = args.obsolete_runtime
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProfileControls))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
