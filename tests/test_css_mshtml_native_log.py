#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic protocol controls only; no native/style/paint evidence is created."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import css_mshtml_native_log as protocol


def fixture():
    values = dict(protocol.FIXED)
    values.update({k: "PASS" for k in protocol.CHECKS})
    values.update({k: "00000000" for k in protocol.HRESULTS})
    values.update({"SETUP.MSHTML_MODULE": "C:\\WINDOWS\\SYSTEM\\MSHTML.DLL",
        "INITIAL_SEQUENCE.INITIAL_TICK": "1000", "MODIFIED_SEQUENCE.MODIFIED_TICK": "11200",
        "MODIFIED_SEQUENCE.INITIAL_HOLD_MS": "10000", "COMPLETE_SEQUENCE.MODIFIED_HOLD_MS": "12000"})
    return values


def raw(values):
    return ("\r\n".join(k + "=" + v for k, v in values.items()) + "\r\n").encode()


class Protocol(unittest.TestCase):
    def test_synthetic_protocol_only(self):
        self.assertFalse(protocol.component(raw(fixture()))["native_paint_verified"])

    def test_each_missing_or_failed_row(self):
        for key in fixture():
            with self.subTest(missing=key), self.assertRaises(ValueError):
                values = fixture(); del values[key]; protocol.component(raw(values))
        for key in protocol.CHECKS | protocol.HRESULTS:
            with self.subTest(failed=key), self.assertRaises(ValueError):
                values = fixture(); values[key] = "FAIL" if key in protocol.CHECKS else "80004005"
                protocol.component(raw(values))

    def test_duplicate_partial_unknown(self):
        data = raw(fixture())
        for bad in (data + b"EXIT.STATUS=PASS_COMPONENT_ONLY\r\n", data[:-2],
                    data + b"extra=PASS\r\n", data.replace(b"\r\n", b"\n")):
            with self.subTest(bad=bad[-80:]), self.assertRaises(ValueError):
                protocol.component(bad)

    def test_clock_bounds_and_wrap(self):
        for key, value in (("MODIFIED_SEQUENCE.INITIAL_HOLD_MS", "9999"),
                           ("COMPLETE_SEQUENCE.MODIFIED_HOLD_MS", "11999"),
                           ("COMPLETE_SEQUENCE.MODIFIED_HOLD_MS", "35000"),
                           ("MODIFIED_SEQUENCE.MODIFIED_TICK", "9000"),
                           ("INITIAL_SEQUENCE.INITIAL_TICK", "4294967296")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                values = fixture(); values[key] = value; protocol.component(raw(values))
        values = fixture(); values["INITIAL_SEQUENCE.INITIAL_TICK"] = str(0xfffff000)
        values["MODIFIED_SEQUENCE.MODIFIED_TICK"] = str((0xfffff000 + 10200) & 0xffffffff)
        self.assertEqual(protocol.component(raw(values))["initial_hold_ms"], 10000)


if __name__ == "__main__":
    unittest.main()
