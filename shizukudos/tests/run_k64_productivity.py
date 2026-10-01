#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Probe publisher Legcord and LibreOffice packages in an isolated Kernel64 guest.

Uses run_k64_electron's existing standalone QEMU, AHCI FAT32 and autorun
implementation. It never changes that runner or a Windows 98 VM. The package
tree stays read-only; the generated disk belongs to this probe and is attached
with snapshot=on. This profile has no network device.

Legcord starts its real packaged application, with no fabricated success marker.
LibreOffice runs its console launcher with --version: matching version output
and a normal exit proves that command only. Neither probe is a Discord login,
document editing, or complete product functionality pass.

Examples:
  python3 shizukudos/tests/run_k64_productivity.py --app legcord --tree /path/to/legcord --timeout 90 --guest-timeout 60
  python3 shizukudos/tests/run_k64_productivity.py --app libreoffice --tree /path/to/LibreOffice --timeout 90 --guest-timeout 60
Run controls are passed to run_k64_electron.py. Product command, environment and
expected output are fixed so a caller-selected marker cannot prove compatibility.
"""
import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import sys

sys.dont_write_bytecode = True
import run_k64_electron as runner

PRODUCTS = {
    "legcord": {
        "version": "1.3.0", "candidates": ("Legcord.exe",), "dir": "legcord",
        "args": runner.COMMON + " --disable-direct-composition --no-first-run --user-data-dir=D:\\legprofile",
        "expect": None, "scenario": "packaged-application-startup",
        "publisher": "https://github.com/Legcord/Legcord/releases/tag/v1.3.0",
    },
    "libreoffice": {
        "version": "26.8.0", "candidates": ("program/soffice.com", "soffice.com"), "dir": "libreoffice",
        "args": "--headless --nologo --nodefault --nofirststartwizard --version",
        "expect": "LibreOffice 26.8.0", "scenario": "console-version-command",
        "publisher": "https://www.libreoffice.org/download/",
    },
}


def find_product_exe(tree, candidates):
    """Resolve actual package spelling; reject traversal and ambiguity."""
    root = Path(tree).resolve(strict=True)
    for candidate in candidates:
        parts = PureWindowsPath(candidate).parts
        if PureWindowsPath(candidate).is_absolute() or ".." in parts:
            raise ValueError("executable must be relative to the application tree")
        current = root
        chosen = []
        for part in parts:
            matches = [p for p in current.iterdir() if p.name.casefold() == part.casefold()]
            if len(matches) > 1:
                raise ValueError("ambiguous case-insensitive executable path")
            if not matches:
                break
            current = matches[0]
            chosen.append(current.name)
            if not current.resolve().is_relative_to(root):
                raise ValueError("executable path escapes the application tree")
        else:
            if current.is_file():
                return "\\".join(chosen), current
    return None, None


def pe_machine(path):
    """Small PE identity check; the guest remains the loader authority."""
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            return None
        offset = int.from_bytes(header[60:64], "little")
        stream.seek(offset)
        coff = stream.read(6)
    return int.from_bytes(coff[4:6], "little") if coff[:4] == b"PE\0\0" and len(coff) == 6 else None


def tree_fingerprint(tree):
    """Hash package names and content, including same-size binary changes."""
    root = Path(tree).resolve(strict=True)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("application tree contains a symlink")
        if path.is_file():
            relative = path.relative_to(root).as_posix().encode()
            digest.update(len(relative).to_bytes(4, "little"))
            digest.update(relative)
            digest.update(path.stat().st_size.to_bytes(8, "little"))
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def build_product_image(image, tree, volume_dir, original_builder, overlay=None):
    """Upgrade the reused runner's names/sizes cache with a content key."""
    if overlay:
        raise ValueError("product probes require the publisher package without a probe overlay")
    content_key = tree_fingerprint(tree)
    stamp = Path(str(image) + ".json")
    previous = {}
    if stamp.exists():
        try:
            previous = json.loads(stamp.read_text())
        except (ValueError, OSError):
            pass
    if previous.get("productivity_content_sha256") != content_key:
        stamp.unlink(missing_ok=True)
    listing = original_builder(image, tree, volume_dir, overlay)
    if tree_fingerprint(tree) != content_key:
        stamp.unlink(missing_ok=True)
        raise ValueError("application tree changed during disk preparation; guest was not started")
    receipt = json.loads(stamp.read_text())
    receipt["productivity_content_sha256"] = content_key
    stamp.write_text(json.dumps(receipt) + "\n")
    return listing


def classify_product(serial, expect, base_classifier):
    """Fail closed on guest faults and command failure despite version output."""
    result = base_classifier(serial, expect)
    lines = serial.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("K64 autorun: starting")), len(lines))
    app_text = "\n".join(lines[start:])
    # A surviving browser does not imply its required GPU child survived.
    # First-chance exceptions remain diagnostics: applications may handle them.
    result["first_chance_exceptions"] = [line for line in lines[start:]
                                         if line.startswith("K64 exc:") and " first-chance " in line][:20]
    child_failures = []
    seen = set()
    for line in lines[start:]:
        match = re.search(r"GPU process exited unexpectedly: exit_code=(-?\d+)", line)
        if match and int(match.group(1)) != 0:
            # Console and debug streams duplicate Chromium diagnostics.
            detail = line[line.index("GPU process exited unexpectedly:"):]
            if detail not in seen:
                seen.add(detail)
                child_failures.append(line)
    result["child_process_failures"] = child_failures[:20]
    if expect and expect not in app_text:
        # The underlying runner also checks the complete log for a marker.
        # Clear its exit gate when the matching text belonged to a boot test.
        result["exit_code"] = None
        result["furthest"] = "required product output absent after autorun start; " + result["furthest"]
    if result["loader_failures"] or result["node_fatal"] or result["chromium_fatal"] or child_failures:
        result["faulted"] = True
    if child_failures:
        result["furthest"] = "required GPU child failed: " + child_failures[0] + "; " + result["furthest"]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument("--app", choices=sorted(PRODUCTS), required=True)
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--qemu")
    parser.add_argument("--accel", choices=("auto", "kvm", "tcg"))
    parser.add_argument("--memory")
    parser.add_argument("--display", choices=("vga", "none"))
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--guest-timeout", type=int)
    parser.add_argument("--no-trace", action="store_true")
    args = parser.parse_args(argv)
    rest = []
    for option in ("qemu", "accel", "memory", "display", "timeout", "guest_timeout"):
        value = getattr(args, option)
        if value is not None:
            rest += ["--" + option.replace("_", "-"), str(value)]
    if args.no_trace:
        rest.append("--no-trace")
    product = PRODUCTS[args.app]
    try:
        exe, executable = find_product_exe(args.tree, product["candidates"])
        if not executable:
            raise ValueError("package executable not found: " + ", ".join(product["candidates"]))
        machine = pe_machine(executable)
        if machine != 0x8664:
            raise ValueError(f"standalone Kernel64 needs AMD64 PE (0x8664); package machine is {machine!r}")
    except (OSError, ValueError) as error:
        print(f"BLOCKED: {error}")
        return 2
    out = (args.out or (runner.K64S / f"run_productivity_{args.app}")).resolve()
    image = (args.image or (runner.BUILD / "productivity-images" / f"{args.app}.img")).resolve()
    spec = {key: product[key] for key in ("dir", "args", "expect")}
    spec["exe"] = exe
    runner.APPS[args.app] = spec
    original_find = runner.find_exe
    original_classify = runner.classify
    original_build = runner.build_image
    original_argv = sys.argv
    runner.find_exe = lambda tree, name: exe if Path(tree).resolve() == args.tree.resolve() and name == exe else original_find(tree, name)
    runner.classify = lambda serial, expect: classify_product(serial, expect, original_classify)
    runner.build_image = lambda image, tree, volume_dir, overlay=None: build_product_image(image, tree, volume_dir, original_build, overlay)
    sys.argv = [str(Path(runner.__file__)), "--app", args.app, "--tree", str(args.tree.resolve()),
                "--out", str(out), "--image", str(image), *rest]
    try:
        code = runner.main()
    finally:
        sys.argv = original_argv
        runner.find_exe = original_find
        runner.classify = original_classify
        runner.build_image = original_build
        runner.APPS.pop(args.app, None)
    result_path = out / "result.json"
    if result_path.exists() and code in (0, 1):
        result = json.loads(result_path.read_text())
        result.update({
            "product": args.app, "product_version": product["version"], "publisher": product["publisher"],
            "scenario": product["scenario"], "product_exe_sha256": runner.shzlib.sha256_file(executable),
            "package_tree_sha256": tree_fingerprint(args.tree), "forwarded_run_options": rest,
            "evidence_level": "standalone-kernel64-product-command", "guest_os": "ShizukuDOS Kernel64 standalone",
            "windows98_execution_verified": False, "app_functionality_verified": False,
            "discord_login_verified": False, "document_editing_verified": False,
            "network_attached": False,
        })
        runner.shzlib.write_json(result_path, result)
    return code


if __name__ == "__main__":
    sys.exit(main())
