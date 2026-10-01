"""Apply the exact LibreOffice 26.8 SAL wall-clock port in a private source tree.

The original source and the replacement are hash pinned. No build, application,
network access or VM is started. This is one prerequisite, not an Office port.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


HERE = Path(__file__).resolve().parent
SOURCE = Path("sal/osl/w32/time.cxx")
PIN = HERE / "office_steam_sal_clock_pin.json"
ORIGINAL = HERE / "office_steam_upstream_time.cxx"
BEFORE = b"""    // use ~1 microsecond resolution
    GetSystemTimePreciseAsFileTime(reinterpret_cast<LPFILETIME>(&CurTime));
"""
AFTER = b"""#if defined(LIBO_WIN98) && LIBO_WIN98
    // Keep UTC FILETIME semantics with the native Win98 clock's resolution.
    GetSystemTimeAsFileTime(reinterpret_cast<LPFILETIME>(&CurTime));
#else
    // use ~1 microsecond resolution
    GetSystemTimePreciseAsFileTime(reinterpret_cast<LPFILETIME>(&CurTime));
#endif
"""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_path(root: Path, relative: Path) -> Path:
    """Refuse symlinks at every component, including a supplied source root."""
    root = Path(os.path.abspath(root))
    path = root.anchor
    for part in root.parts[1:] + relative.parts:
        path = Path(path) / part
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"symlink in source path: {path}")
    result = root / relative
    metadata = result.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("source must be a private regular file with one link")
    if metadata.st_size > 65536:
        raise ValueError("source exceeds the pinned bounded-file profile")
    return result


def pinned_source() -> tuple[dict, bytes, bytes]:
    pin = json.loads(PIN.read_text(encoding="utf-8"))
    original = ORIGINAL.read_bytes()
    if pin["source_path"] != SOURCE.as_posix():
        raise ValueError("unexpected source path in pin")
    if pin["original"]["sha256"] != digest(original):
        raise ValueError("preserved upstream source hash mismatch")
    if pin["patch"]["sha256"] != digest((HERE / "office_steam_sal_clock.patch").read_bytes()):
        raise ValueError("published source diff hash mismatch")
    if original.count(BEFORE) != 1:
        raise ValueError("original wall-clock call is not unique")
    modified = original.replace(BEFORE, AFTER, 1)
    if pin["modified"]["sha256"] != digest(modified):
        raise ValueError("replacement does not match the reviewed source pin")
    return pin, original, modified


def apply(source_root: Path, *, check_only: bool = False) -> dict:
    pin, original, modified = pinned_source()
    path = checked_path(source_root, SOURCE)
    before_metadata = path.stat()
    current = path.read_bytes()
    if current not in (original, modified):
        raise ValueError("source is neither the exact upstream file nor this exact port")
    already_applied = current == modified
    if not check_only and not already_applied:
        # Stage on the same filesystem. Check the named source again before
        # replacing it; keep its permissions and never mutate another hardlink.
        temporary = None
        try:
            fd, name = tempfile.mkstemp(prefix=".office-steam-sal-", dir=path.parent)
            temporary = Path(name)
            with os.fdopen(fd, "wb") as output:
                output.write(modified)
                output.flush()
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), stat.S_IMODE(before_metadata.st_mode))
            latest = checked_path(source_root, SOURCE).stat()
            if (latest.st_dev, latest.st_ino, latest.st_size, latest.st_mtime_ns) != (
                before_metadata.st_dev, before_metadata.st_ino,
                before_metadata.st_size, before_metadata.st_mtime_ns,
            ) or path.read_bytes() != original:
                raise ValueError("source changed while preparing the port")
            temporary.replace(path)
            temporary = None
            if path.read_bytes() != modified:
                raise ValueError("applied bytes do not match the reviewed port")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return {
        "schema": "win98modern.libreoffice-sal-clock.v1",
        "upstream_commit": pin["upstream_commit"],
        "source_path": str(path),
        "input_sha256": digest(current),
        "expected_modified_sha256": digest(modified),
        "result_sha256": digest(path.read_bytes()),
        "check_only": check_only,
        "already_applied": already_applied,
        "source_port_applied": not check_only or already_applied,
        "activation": "LIBO_WIN98=1 on the actual SAL translation unit",
        "native_application_executed": False,
        "native_application_compatibility": "unverified",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root", type=Path,
                        help="private LibreOffice source tree containing sal/osl/w32/time.cxx")
    parser.add_argument("--check", action="store_true", help="validate without changing the source")
    args = parser.parse_args(argv)
    try:
        report = apply(args.source_root, check_only=args.check)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"office_steam_sal_clock: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
