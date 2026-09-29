#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for shizukudos/ntdrv/store.py: package copy is byte-identical, the index describes the package (models,
rules, services, missing files), verify detects changes, match ranks across packages. Uses the synthetic INFs under
tests/inf (with placeholder payload files) and, when built, the ReactOS corpus packages from
build/shizukudos/ntdrv/packages (shizukudos/ntdrv/corpus/build.py --packages).

Run: python3 shizukudos/ntdrv/tests/test_store.py
"""
import contextlib
import io
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import store as S  # noqa: E402

FIX = HERE / "inf"
CORPUS_PKGS = HERE.parents[2] / "build" / "shizukudos" / "ntdrv" / "packages"


def make_synth_nic(base):
    """synth_nic.inf as a vendor would ship it: INF at the top, payload under the SourceDisksNames.amd64 path 'x64'."""
    pkg = base / "SynthNic"
    (pkg / "x64" / "sub").mkdir(parents=True)
    shutil.copyfile(FIX / "synth_nic.inf", pkg / "synth_nic.inf")
    (pkg / "x64" / "synthnic.sys").write_bytes(b"placeholder payload 1\r\n\x00\xff")     # not a driver: test bytes
    (pkg / "x64" / "sub" / "synthnic2.sys").write_bytes(b"placeholder payload 2")
    return pkg


def quiet(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **kw)
    return r, buf.getvalue()


def test_add_copies_bytes_and_indexes():
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        pkg = make_synth_nic(t / "src")
        root = t / "media"
        rec, out = quiet(S.cmd_add, root, pkg, None, S.I.Target())
        dest = root / "DRIVERS" / "SynthNic"
        for p in pkg.rglob("*"):
            if p.is_file():
                assert (dest / p.relative_to(pkg)).read_bytes() == p.read_bytes()
        assert len(rec["files"]) == 3 and rec["infs"][0]["class"] == "Net"
        # Windows x64 rules pick the NTamd64.10.0...16299 models (5 lines); nothing needs the undecorated fallback
        assert [m["rules"] for m in rec["models"]] == ["W"] * 5
        sn1 = rec["models"][0]
        assert sn1["service"] == "synthnic" and sn1["binary"] == "%12%\\synthnic.sys" and sn1["sig"] == 0x80 and sn1["feature"] == 0xFF
        assert rec["models"][3]["feature"] == 0x30
        assert rec["missing"] == [], rec["missing"]                       # both payload files resolved via SourceDisks*
        idx = (root / "DRIVERS" / "INDEX.TXT").read_bytes().decode("utf-8").split("\r\n")          # CRLF lines
        assert idx[0].startswith("SHZDRV-INDEX\t1\tNTamd64.10.0...")
        models = [l.split("\t") for l in idx if l.startswith("MODEL\t")]
        assert len(models) == 5 and models[0][11] == "PCI\\VEN_1AF4&DEV_7001&SUBSYS_00011AF4&REV_01"
        assert models[3][12] == "PCI\\VEN_1AF4&DEV_7002&CC_020000;PCI\\CC_0200" and models[3][7] == "30"
        files = [l.split("\t") for l in idx if l.startswith("FILE\t")]
        assert sorted(f[2] for f in files) == ["synth_nic.inf", "x64\\sub\\synthnic2.sys", "x64\\synthnic.sys"]
        assert quiet(S.cmd_verify, root)[0] == 0
        (dest / "x64" / "synthnic.sys").write_bytes(b"changed")
        assert quiet(S.cmd_verify, root)[0] == 1


def test_missing_payload_reported():
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        pkg = make_synth_nic(t / "src")
        (pkg / "x64" / "sub" / "synthnic2.sys").unlink()
        rec, out = quiet(S.cmd_add, t / "media", pkg, None, S.I.Target())
        assert rec["missing"] == [{"inf": "synth_nic.inf", "file": "synthnic2.sys"}]
        assert "missing from the package: synthnic2.sys" in out
        assert "MISS\tSynthNic\tsynth_nic.inf\tsynthnic2.sys" in (t / "media" / "DRIVERS" / "INDEX.TXT").read_text()


def test_names_and_rejections():
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        pkg = make_synth_nic(t / "src")
        for bad in ("../x", "a b", "-x", "x" * 65):
            try:
                quiet(S.cmd_add, t / "media", pkg, bad, S.I.Target())
                raise AssertionError(f"accepted {bad!r}")
            except SystemExit:
                pass
        quiet(S.cmd_add, t / "media", pkg, "Nic1", S.I.Target())
        try:
            quiet(S.cmd_add, t / "media", pkg, "NIC1", S.I.Target())          # the medium is case-insensitive
            raise AssertionError("case-insensitive duplicate accepted")
        except SystemExit:
            pass
        empty = t / "empty"
        empty.mkdir()
        (empty / "readme.txt").write_text("no inf")
        try:
            quiet(S.cmd_add, t / "media", empty, None, S.I.Target())
            raise AssertionError("package without INF accepted")
        except SystemExit:
            pass


def test_match_across_packages():
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        root = t / "media"
        quiet(S.cmd_add, root, make_synth_nic(t / "a"), None, S.I.Target())
        for name in ("synth_rank_old.inf", "synth_rank_new.inf"):
            d = t / "b" / name[:-4]
            d.mkdir(parents=True)
            shutil.copyfile(FIX / name, d / name)
            quiet(S.cmd_add, root, d, None, S.I.Target())
        res, out = quiet(S.cmd_match, root, ["1AF4:7001:00011AF4:01:020000", "1AF4:7005:00051AF4:02:020000", "10DE:1234"],
                         S.I.Target(), True)
        (d1, h1, r1), (d2, h2, r2), (d3, h3, r3) = res
        # FeatureScore 0x30 (SN2, compatible/compatible) outranks every FeatureScore-0xFF hardware match
        assert h1[0]["model"]["install"] == "SN2.ndi" and h1[1]["identifier_score"] == 0
        # device 7005: SN2's FeatureScore 0x30 again first (compatible PCI\CC_0200, 0x3106), then SUBSYS hardware ID of
        # new.inf (device hw position 1), the VEN&DEV&CC hardware ID of old.inf (position 4), old.inf's PCI\CC_0200 (0x3006)
        assert [h["install"]["services"][0]["name"] for h in h2] == ["synthnic2", "newC", "oldC", "oldB"]
        assert [h["rank"] for h in h2] == [0x80303106, 0x80FF0001, 0x80FF0004, 0x80FF3006]
        assert h3 == [] and "no driver in the store" in out


def test_boot_log_devices(tmp=None):
    with tempfile.TemporaryDirectory() as t:
        log = Path(t) / "boot.log"
        log.write_text("K64: boot\nK64 pci: 0:3.0 8086:100e class 020000 irq 11\nnoise\n1af4:1000\n")
        devs = S.expand_devices([f"@{log}"])
        assert [d.hwids[0] for d in devs] == ["PCI\\VEN_8086&DEV_100E", "PCI\\VEN_1AF4&DEV_1000"]


def check_corpus_packages():
    """ReactOS corpus packages: their INFs use undecorated Models sections, which Windows x64 ignores; the store indexes
    them as rules=L and match falls back to them only when no Windows-rule model matches."""
    if not CORPUS_PKGS.is_dir():
        print("corpus packages: not built (corpus/build.py --packages); skipped")
        return 0
    with tempfile.TemporaryDirectory() as t:
        root = Path(t) / "media"
        n = 0
        for pkg in sorted(CORPUS_PKGS.iterdir()):
            rec, _ = quiet(S.cmd_add, root, pkg, None, S.I.Target())
            w = sum(1 for m in rec["models"] if m["rules"] == "W")
            print(f"corpus package {pkg.name}: {len(rec['files'])} files, {len(rec['models'])} models ({w} W), "
                  f"missing {[x['file'] for x in rec['missing']]}")
            n += 1
        fails = 0
        if (CORPUS_PKGS / "e1000").is_dir():
            res, out = quiet(S.cmd_match, root, ["K64 pci: 0:3.0 8086:100e class 020000 irq 11"], S.I.Target())
            dev, hits, rules = res[0]
            ok = hits and hits[0]["install"]["services"][0]["name"] == "e1000" and rules == "L"
            print(f"corpus match 8086:100E -> {hits[0]['inf'] if hits else None} ({rules}): {'ok' if ok else 'FAIL'}")
            fails += 0 if ok else 1
        fails += quiet(S.cmd_verify, root)[0]
        print(f"corpus packages: {n} added, verify {'ok' if not fails else 'FAILED'}")
        return fails


def main():
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS: {name}")
        except Exception as e:                                                # noqa: BLE001
            import traceback
            failed += 1
            print(f"FAIL: {name}: {e}")
            traceback.print_exc()
    print(f"test_store: {len(tests)} tests, {failed} failed")
    failed += check_corpus_packages()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
