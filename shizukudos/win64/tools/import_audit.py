# SPDX-License-Identifier: GPL-2.0-only
"""PE32+ import audit: every import of an executable must resolve against the exports of the DLLs that
will actually be packed beside it. Fails (non-zero / ValueError) on unresolved imports or missing DLLs.
Resolution is by name or ordinal against the real export tables; forwarders count as exported."""
import struct
import sys
from pathlib import Path


def _sections(b):
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    nsec, = struct.unpack_from("<H", b, pe + 6)
    opt_size, = struct.unpack_from("<H", b, pe + 20)
    opt = pe + 24
    if struct.unpack_from("<H", b, opt)[0] != 0x20B:
        raise ValueError("not PE32+")
    dirs = [struct.unpack_from("<II", b, opt + 112 + 8 * i) for i in range(16)]
    secs = []
    for i in range(nsec):
        n = opt + opt_size + 40 * i
        vs, va, rs, ro = struct.unpack_from("<IIII", b, n + 8)
        secs.append((va, max(vs, rs), ro, rs))
    return secs, dirs


def _off(secs, rva):
    for va, vs, ro, rs in secs:
        if va <= rva < va + vs:
            return ro + rva - va
    raise ValueError(f"RVA {rva:#x} outside sections")


def _cstr(b, off):
    return b[off:b.index(b"\0", off)].decode("ascii", "replace")


def exports(b):
    secs, dirs = _sections(b)
    rva, size = dirs[0]
    if not rva:
        return set(), set()
    o = _off(secs, rva)
    base, nfun, nnames, af, an, ao = struct.unpack_from("<IIIIII", b, o + 16)[0:6]
    names, ords = set(), set()
    for i in range(nfun):
        frva, = struct.unpack_from("<I", b, _off(secs, af) + 4 * i)
        if frva:
            ords.add(base + i)
    for i in range(nnames):
        nrva, = struct.unpack_from("<I", b, _off(secs, an) + 4 * i)
        names.add(_cstr(b, _off(secs, nrva)).lower())
    return names, ords


def imports(b):
    secs, dirs = _sections(b)
    rva, _ = dirs[1]
    out = {}
    if not rva:
        return out
    o = _off(secs, rva)
    while True:
        oft, _, _, name, ft = struct.unpack_from("<IIIII", b, o)
        if not name and not ft:
            break
        dll = _cstr(b, _off(secs, name)).lower()
        t = _off(secs, oft or ft)
        lst = out.setdefault(dll, [])
        while True:
            v, = struct.unpack_from("<Q", b, t)
            if not v:
                break
            if v >> 63:
                lst.append(("ord", v & 0xFFFF))
            else:
                lst.append(("name", _cstr(b, _off(secs, v & 0x7FFFFFFF) + 2).lower()))
            t += 8
        o += 20
    return out


def audit(exe_bytes, dlls):
    """dlls: {lowercase dll file name: bytes}. Returns list of problems (empty = all resolved)."""
    problems, cache = [], {}
    for dll, items in imports(exe_bytes).items():
        if dll not in dlls:
            problems.append(f"{dll}: not packed ({len(items)} imports)")
            continue
        if dll not in cache:
            cache[dll] = exports(dlls[dll])
        names, ords = cache[dll]
        for kind, v in items:
            if (kind == "name" and v not in names) or (kind == "ord" and v not in ords):
                problems.append(f"{dll}!{v}")
    return problems


def main(argv):
    if len(argv) < 3:
        raise SystemExit("usage: import_audit.py app.exe dll [dll ...]")
    dlls = {Path(p).name.lower(): Path(p).read_bytes() for p in argv[2:]}
    bad = audit(Path(argv[1]).read_bytes(), dlls)
    for p in bad:
        print("UNRESOLVED", p)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
