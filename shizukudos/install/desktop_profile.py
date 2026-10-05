# SPDX-License-Identifier: GPL-2.0-only
"""Select the built production runtime, including the shell, fonts and public trust inputs.

The installer consumes the actual archive, rather than reconstructing a subset
from DLL names and silently dropping Wine libraries or system programs.
"""
import hashlib
import re
import struct

SOUND_PATHS = {'\\SHZ\\MEDIA\\' + name for name in (
    'SHIZUKUCONNECT.WAV', 'SHIZUKUDISCONNECT.WAV', 'SHIZUKUERROR.WAV', 'SHIZUKULOGIN.WAV', 'SHIZUKULOGOUT.WAV', 'SHIZUKUNAVIGATION.WAV', 'SHIZUKUNOTIFICATION.WAV', 'SHIZUKUSHUTDOWN.WAV', 'SHIZUKUSTARTUP.WAV', 'SHIZUKUWARNING.WAV')}
SOUND_PATHS.add('\\SHZ\\SHZSOUND.INI')
THEME_LICENSE_PATHS = {'\\SHZ\\SYSTEM\\THEMES\\' + name for name in ('THEME-NOTICE.TXT', 'THEME-GPL3.TXT')}


def desktop_runtime(archive, expected_sha256, theme_paths=(), sound_paths=(), theme_license_hashes=None):
    allowed_themes = {'\\SHZ\\SYSTEM\\THEMES\\' + name + '\\THEME.INI' for name in ('SLADE', 'FLUTE', 'JADE')}
    theme_paths = set(theme_paths)
    if theme_paths and theme_paths != allowed_themes:
        raise ValueError('expected exactly the three native shell theme paths')
    sound_paths = set(sound_paths)
    if sound_paths and sound_paths != SOUND_PATHS:
        raise ValueError('expected the complete pinned desktop sound scheme and assets')
    theme_license_hashes = {} if theme_license_hashes is None else theme_license_hashes
    if not isinstance(theme_license_hashes, dict) or (theme_license_hashes and
            (set(theme_license_hashes) != THEME_LICENSE_PATHS or theme_paths != allowed_themes or
             any(not isinstance(h, str) or re.fullmatch('[0-9a-f]{64}', h) is None for h in theme_license_hashes.values()))):
        raise ValueError('expected the complete pinned theme notice and GPL3 license')
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
        if key.startswith(("\\SHZ\\SYS64\\", "\\SHZ\\FONTS\\", "\\SHZ\\CERTS\\")) or key == "\\SHZ\\TESTS\\T_HELLO.EXE" or key in theme_paths or key in sound_paths or key in theme_license_hashes:
            files.append((path, archive[offset:offset + size]))
    required = {"\\SHZ\\SYS64\\NTDLL.DLL", "\\SHZ\\SYS64\\KERNEL32.DLL",
                "\\SHZ\\SYS64\\USER32.DLL", "\\SHZ\\SYS64\\GDI32.DLL", "\\SHZ\\SYS64\\SHZDESK.EXE",
                "\\SHZ\\TESTS\\T_HELLO.EXE"}
    required.update(sound_paths)
    required.update(theme_license_hashes)
    missing = sorted(required - {p.upper() for p, _ in files})
    if missing:
        raise ValueError("desktop runtime missing: " + ", ".join(missing))
    actual = {p.upper(): hashlib.sha256(data).hexdigest() for p, data in files}
    if any(actual[p] != h for p, h in theme_license_hashes.items()):
        raise ValueError('native theme notice or GPL3 license differs from stage receipt')
    return files
