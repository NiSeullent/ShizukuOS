#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check actual linked NE relocations and archived native import closure; no VM."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from build import REPO, validate_ne


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exported_ordinals(path):
    data = path.read_bytes()
    ne = struct.unpack_from("<I", data, 60)[0]
    if data[ne:ne + 2] != b"NE":
        raise AssertionError("Frozen installed dependency is not NE")
    start, size = struct.unpack_from("<HH", data, ne + 4)
    pos, end, ordinal, exported = ne + start, ne + start + size, 1, set()
    if end > len(data):
        raise AssertionError("Frozen dependency export table is incomplete")
    while pos < end:
        count = data[pos]
        pos += 1
        if not count:
            break
        kind = data[pos]
        pos += 1
        if kind:
            stride = 6 if kind == 255 else 3
            if pos + count * stride > end:
                raise AssertionError("Frozen dependency export bundle is incomplete")
            exported.update(range(ordinal, ordinal + count))
            pos += count * stride
        ordinal += count
    return exported


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--native-diagnostics", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve(strict=True)
    if not out.is_relative_to(REPO / "build" / "shizukudos"):
        raise SystemExit("Test output must stay under the private build tree")
    good_path = out / "package" / "SHZGOP.DRV"
    old_path = REPO / "build/shizukudos/shizuku-gop-anchor/package/SHZGOP.DRV"
    data = good_path.read_bytes()
    good = validate_ne(data)
    checks = [{"name": "actual corrected linked NE", "status": "PASS"}]

    def rejected(name, altered):
        try:
            validate_ne(altered)
        except RuntimeError as error:
            checks.append({"name": name, "status": "PASS", "rejection": str(error)})
        else:
            raise AssertionError("Validator accepted " + name)

    rejected("actual archived stripped-selector defect", old_path.read_bytes())
    ne = struct.unpack_from("<I", data, 60)[0]
    segment_table = ne + struct.unpack_from("<H", data, ne + 34)[0]
    shift = struct.unpack_from("<H", data, ne + 50)[0]
    page, size, flags, _ = struct.unpack_from("<4H", data, segment_table)
    at = page << shift
    record_table = at + size + 2
    records = struct.unpack_from("<H", data, at + size)[0]
    internal = imported = None
    for i in range(records):
        rec = record_table + i * 8
        kind = data[rec + 1] & 3
        target = struct.unpack_from("<H", data, rec + 4)[0]
        if kind == 0:
            internal = rec
        if kind == 1:
            imported = rec
    if internal is None or imported is None:
        raise AssertionError("Actual linked driver lacks expected testable relocations")

    def mutate_word(name, offset, value):
        altered = bytearray(data)
        struct.pack_into("<H", altered, offset, value)
        rejected(name, altered)

    mutate_word("missing internal segment", internal + 4, 3)
    mutate_word("missing import module", imported + 4, 3)
    mutate_word("zero import ordinal", imported + 6, 0)
    mutate_word("entry CS absent", ne + 22, 3)
    mutate_word("entry IP beyond backing", ne + 20, size)
    mutate_word("data selector absent", ne + 14, 3)
    mutate_word("truncated segment table", ne + 34, 65535)
    mutate_word("truncated import table", ne + 40, 65535)
    mutate_word("relocation source outside backing", internal + 2, size)
    altered = bytearray(data)
    altered[internal + 1] = 0
    struct.pack_into("<H", altered, internal + 4, 255)
    struct.pack_into("<H", altered, internal + 6, 65535)
    rejected("missing internal entry ordinal", altered)
    altered = bytearray(data)
    source = struct.unpack_from("<H", data, internal + 2)[0]
    struct.pack_into("<H", altered, at + source, source)
    rejected("cyclic relocation source chain", altered)
    rejected("truncated relocation backing", data[:record_table + records * 8 - 1])
    altered = bytearray(data)
    altered[internal] = 9
    rejected("unsupported source type", altered)

    entry = at + struct.unpack_from("<H", data, ne + 20)[0]
    if b"\x8c\xc8\x50" not in data[entry:entry + 64]:
        raise AssertionError("Actual DriverInit code does not push the current CS selector")
    copied = (out / "work/init.c").read_text()
    if "(__segment)pText" in copied or 'extern char __based( __segname( "_TEXT" ) ) *pText;' in copied:
        raise AssertionError("Compiled source still contains the stripped selector declaration")
    checks.append({"name": "actual compiled current-CS selector", "status": "PASS"})
    diagnostics = args.native_diagnostics.resolve(strict=True)
    dependencies = {"KERNEL": diagnostics / "KRNL386.EXE", "DIBENG": diagnostics / "DIBENG.DLL"}
    expected = {"KERNEL": "25a5fe42b1132b3fa54d7fd065e91101bbe8bb97f7055fb122f382f4b10a905e",
                "DIBENG": "b7c0b676cd8c9960da4c53deae8de846d1251e9534ef4e4b2f05c988306dd2bd"}
    for module, path in dependencies.items():
        if sha(path) != expected[module]:
            raise AssertionError("Installed dependency differs from frozen native extraction")
        exports = exported_ordinals(path)
        required = [item["symbol"] for item in good["imports"] if item["module"] == module]
        if any(symbol not in exports for symbol in required):
            raise AssertionError("Actual installed import ordinal closure is incomplete")
        checks.append({"name": module + " frozen installed ordinal closure", "status": "PASS", "imports": len(required)})
    receipt = {"schema": 1, "status": "HOST-CHECK-PASS", "checks": checks,
               "check_count": len(checks), "corrected_drv_sha256": sha(good_path),
               "archived_drv_sha256": sha(old_path), "linked_ne": good,
               "installed_dependencies": {name: {"path": str(path), "sha256": sha(path)} for name, path in dependencies.items()},
               "diagnostic_manifest_sha256": sha(diagnostics / "manifest.json"),
               "test_source_sha256": sha(Path(__file__)),
               "native_frontend_initialization": "pending new cold-clone trial"}
    (out / "host-ne-validation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "checks": len(checks)}))


if __name__ == "__main__":
    main()
