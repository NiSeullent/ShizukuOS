# SPDX-License-Identifier: GPL-2.0-only
"""Select the built production runtime, including the shell and font data.

The installer consumes the actual archive, rather than reconstructing a subset
from DLL names and silently dropping Wine libraries or system programs.
"""
import hashlib
import struct


def desktop_runtime(archive, expected_sha256):
    if hashlib.sha256(archive).hexdigest() != expected_sha256:
        raise ValueError("WIN64.IMG does not match its build receipt")
    if len(archive) < 16 or archive[:8] != b"SHZARC01":
        raise ValueError("invalid runtime archive header")
    count, reserved = struct.unpack_from("<II", archive, 8)
    table_end = 16 + count * 136
    if reserved or table_end > len(archive):
        raise ValueError("invalid runtime archive table")
    files, seen = [], set()
    for i in range(count):
        at = 16 + i * 136
        raw = archive[at:at + 120]
        if b"\0" not in raw:
            raise ValueError("unterminated runtime archive path")
        path = raw.split(b"\0", 1)[0].decode("ascii")
        key = path.upper()
        offset, size = struct.unpack_from("<QQ", archive, at + 120)
        if not path.startswith("\\") or ".." in path.split("\\") or key in seen:
            raise ValueError("invalid or duplicate runtime archive path")
        if offset < table_end or offset > len(archive) or size > len(archive) - offset:
            raise ValueError("runtime archive member outside image")
        seen.add(key)
        # The shell's bundled launcher must work after installation as well as
        # from the full initrd. Retain this one demo executable, not the QA suite.
        if key.startswith(("\\SHZ\\SYS64\\", "\\SHZ\\FONTS\\")) or key == "\\SHZ\\TESTS\\T_HELLO.EXE":
            files.append((path, archive[offset:offset + size]))
    required = {"\\SHZ\\SYS64\\NTDLL.DLL", "\\SHZ\\SYS64\\KERNEL32.DLL",
                "\\SHZ\\SYS64\\USER32.DLL", "\\SHZ\\SYS64\\GDI32.DLL", "\\SHZ\\SYS64\\SHZDESK.EXE",
                "\\SHZ\\TESTS\\T_HELLO.EXE"}
    missing = sorted(required - {p.upper() for p, _ in files})
    if missing:
        raise ValueError("desktop runtime missing: " + ", ".join(missing))
    return files
