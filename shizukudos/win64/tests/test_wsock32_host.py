#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run real decoder and sanitizers; build a PE DLL and verify fixed legacy exports."""
import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path


def pe_exports(path):
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    sections, optional_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x20b
    directory, size = struct.unpack_from("<II", data, optional + 112)

    def offset(rva):
        for i in range(sections):
            section = optional + optional_size + 40 * i
            virtual_size, virtual, raw_size, raw = struct.unpack_from("<IIII", data, section + 8)
            if virtual <= rva < virtual + max(virtual_size, raw_size):
                return raw + rva - virtual
        raise AssertionError(f"RVA {rva:x} outside sections")

    def string(rva):
        start = offset(rva)
        return data[start:data.index(0, start)].decode("ascii")

    header = offset(directory)
    base, functions, count, addresses, names, ordinals = struct.unpack_from("<IIIIII", data, header + 16)
    exports = {}
    for i in range(count):
        name = string(struct.unpack_from("<I", data, offset(names) + 4 * i)[0])
        index = struct.unpack_from("<H", data, offset(ordinals) + 2 * i)[0]
        assert index < functions
        address = struct.unpack_from("<I", data, offset(addresses) + 4 * index)[0]
        exports[name] = {"ordinal": base + index,
                         "forwarder": string(address) if directory <= address < directory + size else None}
    return exports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    out = args.build_dir or Path(tempfile.mkdtemp(prefix="shz-wsock32-"))
    out.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_suffix(".c")
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
    for cc, flags, name in (("gcc", ["-O2"], "contract"),
                           ("clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"], "sanitized")):
        exe = out / name
        subprocess.run([cc, *common, *flags, str(source), "-o", str(exe)], check=True, timeout=60)
        result = subprocess.run([str(exe)], text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise SystemExit(result.stdout + result.stderr)
        print(name + ": " + result.stdout.strip())
    module = source.parent.parent / "dlls" / "wsock32"
    cfg = json.loads((module / "module.json").read_text())
    definition = out / "wsock32.def"
    definition.write_text("LIBRARY wsock32.dll\nEXPORTS\n  GetAcceptExSockaddrs @1142\n" +
                          "\n".join("  " + f for f in cfg["forwarders"]) + "\n")
    dll = out / "wsock32.dll"
    subprocess.run(["x86_64-w64-mingw32-gcc", *common, "-O2", "-ffreestanding", "-fno-builtin",
                    "-fno-stack-protector", "-mno-red-zone", "-shared", "-nostdlib", "-Wl,--entry,0",
                    str(module / "wsock32.c"), str(definition), "-lws2_32", "-o", str(dll)], check=True, timeout=60)
    exports = pe_exports(dll)
    assert exports["GetAcceptExSockaddrs"] == {"ordinal": 1142, "forwarder": None}
    for forwarder in cfg["forwarders"]:
        name, _, target, ordinal = forwarder.split()
        assert exports[name] == {"ordinal": int(ordinal[1:]), "forwarder": target}
    assert len(exports) == len(cfg["forwarders"]) + 1
    assert "AcceptEx" not in exports and "TransmitFile" not in exports
    (out / "exports.json").write_text(json.dumps(exports, indent=2) + "\n")
    print(f"PE exports: {len(exports)} verified, actual decoder ordinal 1142; AcceptEx absent")
    print("Isolated outputs:", out)


if __name__ == "__main__":
    main()
