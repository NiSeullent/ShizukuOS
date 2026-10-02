#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Public, nonbootable Windows 98 integration add-on ISO builder."""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tempfile
from types import MappingProxyType

DEFAULT_EPOCH = 1790899200
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_BYTES = 24 * 1024 * 1024
MAX_ISO_BYTES = 30 * 1024 * 1024
SOURCE_ROOTS = ("drivers", "shizukudos", "ntwddm", "platform/freestanding")
EXCLUDED_DIRS = frozenset({".git", "__pycache__", "build", "third_party", "data", "validation", "evidence", "node_modules"})
SOURCE_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".hpp", ".s", ".asm", ".py", ".ps1", ".sh", ".md", ".txt", ".def", ".inc", ".rc", ".js", ".ld", ".idl", ".mak", ".cmake", ".bat", ".patch", ".inf", ".html", ".spec", ".mc", ".ntth"})
SOURCE_BASENAMES = frozenset({"Makefile", "CMakeLists.txt", "LICENSE", "COPYING", "COPYING.LIB", "Wine-COPYING.LIB", "COPYING3", "COPYING.RUNTIME", "NOTICE", "AUTHORS", "vkd3d-AUTHORS", "vkd3d-COPYING"})
FORBIDDEN_EXTENSIONS = frozenset({".iso", ".img", ".ima", ".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2", ".cab", ".exe", ".dll", ".sys", ".vxd", ".o", ".obj", ".a", ".lib", ".bin", ".zip", ".7z", ".key", ".pfx", ".p12", ".pem", ".ini"})
PUBLIC_METADATA = frozenset({
    "shizukudos/win64/ntdll/ordinals.json",
    "shizukudos/win64/wineport/modules.json",
    "shizukudos/win64/wineport/mpr-module.json",
    "shizukudos/win64/wineport/oleacc-local-module.json",
    "shizukudos/win64/wineport/oleacc-module.json",
    "shizukudos/tests/e1_minapp/package.json",
    "shizukudos/win64/webkit/deps/tests/tests.json",
    "shizukudos/upstream/manifest.json",
    "shizukudos/csm/ios_gop/source-lineage.json",
    "shizukudos/win64/tests/fixtures/public-trust/manifest.json",
})
MODULE_NAMES = frozenset({"oleacc", "ole32", "netapi32", "ncrypt", "msvcp140", "advapi32", "dxgi", "dbghelp", "comctl32", "combase", "imm32", "wtsapi32", "wsock32", "ws2_32", "winhttp", "wer", "vcruntime140_1", "vcruntime140", "uxtheme", "userenv", "iphlpapi", "secur32", "psapi", "pdh", "pathcch", "oleaut32", "setupapi", "shcore", "shlwapi", "ucrtbase", "user32", "shell32"})
PUBLIC_CONFIGS = frozenset({"shizukudos/dos16/user/CONFIG.SYS", "shizukudos/install/shzsetup.ini", "shizukudos/install/tests/install-test.ini"})
PUBLIC_CERTIFICATES = frozenset("shizukudos/win64/tests/fixtures/public-trust/" + name for name in ("ca-bundle.pem", "server-0.pem", "server-1.pem", "server-2.pem"))
# This compiled message-resource test fixture is neither source nor a shipped executable.
OMITTED_FIXTURES = frozenset({"shizukudos/win64/tests/res/shzmsg.bin"})
FIXED_FILES = (
    "LICENSE", "README.md", "AGENTS.md", "ntwin32/prepare.py",
    "benchmarks/win98se-ko-oem-native-exports-v1.json",
    "licenses/Wine-LGPL-2.1.txt", "ntwin32/exception/COPYING.ReactOS",
    "tools/iewebkit_port/runtime/COPYING3", "tools/iewebkit_port/runtime/COPYING.RUNTIME",
    "tools/build_laptop_security_iso.py", "tools/tests/test_laptop_security_iso.py",
    "docs/releases/LAPTOP_SECURITY_ADDON_ISO.md",
    "docs/SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md", "docs/SHIZUKUOS_ARCHITECTURE_SUPPLEMENT.md",
    "docs/superpowers/specs/2026-10-02-laptop-security-iso.md",
    "docs/superpowers/plans/2026-10-02-laptop-security-iso.md",
    "docs/agents/plans/core-k64-persistent-ap.md",
    "docs/SHIZUKUOS_LAPTOP_SECURITY_STATUS.md",
    "docs/agents/status/FD5C2_AUTH_REVIEW.md",
    "docs/agents/status/FD5C2_GUI_AUTH.md",
    "docs/agents/status/FD5C2_LAPTOP.md",
    "docs/agents/status/FD5C2_PERSONALIZATION.md",
    "docs/agents/status/FD5C2_TOKEN.md",
    "docs/agents/status/FD5C2_TOKEN_IDENTITY.md",
)
HEX = re.compile(r"^[0-9a-f]{64}$")
LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
PRIVATE_KEY = re.compile(br"(?m)^\s*(?:#\s*)?-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
SECRET_KEYS = frozenset({"password", "client_secret", "private_key", "access_token", "refresh_token", "credential", "nas_credentials", "microsoft_media", "guest_disk", "media_path"})


class PackageError(ValueError):
    pass


@dataclass(frozen=True)
class ReceiptSpec:
    label: str
    path: Path


@dataclass(frozen=True)
class BinarySpec:
    name: str
    path: Path
    receipt: str


@dataclass(frozen=True)
class InputFile:
    relative: str
    sha256: str
    size: int


@dataclass(frozen=True)
class Selection:
    root: Path
    epoch: int
    inputs: tuple
    _payloads: tuple
    _manifest_bytes: bytes

    @property
    def payloads(self):
        return MappingProxyType(dict(self._payloads))

    @property
    def manifest(self):
        return json.loads(self._manifest_bytes)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def _absolute(path):
    path = Path(path)
    if ".." in path.parts:
        raise PackageError("Parent traversal is forbidden: " + str(path))
    return path.absolute()


def _no_symlinks(path):
    path = _absolute(path)
    for part in (path, *path.parents):
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise PackageError("Symlink is forbidden: " + str(part))
    return path


def _relative(root, path):
    path = Path(path)
    if ".." in path.parts:
        raise PackageError("Input parent traversal: " + str(path))
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError as error:
            raise PackageError("Input is outside the project: " + str(path)) from error
    relative = path.as_posix()
    if not relative or relative == "." or "\\" in relative or any(ord(c) < 32 for c in relative):
        raise PackageError("Invalid input path: " + relative)
    _no_symlinks(root / path)
    return relative


def _read(root, relative):
    path = _no_symlinks(root / relative)
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise PackageError("Not a bounded regular input: " + relative)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise PackageError("Input changed during open: " + relative)
            data = handle.read(MAX_FILE_BYTES + 1)
            after_fd = os.fstat(handle.fileno())
        after_path = path.stat()
    except OSError as error:
        raise PackageError("Cannot safely read input: " + relative) from error
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if len(data) > MAX_FILE_BYTES or stamp(before) != stamp(after_fd) or stamp(before) != stamp(after_path):
        raise PackageError("Input changed during read: " + relative)
    return data


def _public_json(data, relative):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PackageError("Duplicate JSON key in " + relative + ": " + key)
            result[key] = value
        return result
    def invalid_constant(value):
        raise PackageError("Nonfinite JSON number in " + relative + ": " + value)
    try:
        value = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PackageError("Invalid public JSON: " + relative) from error
    def visit(node):
        if isinstance(node, dict):
            for key, child in node.items():
                if key.lower() in SECRET_KEYS and isinstance(child, str) and child:
                    raise PackageError("Credential/private-media field in " + relative + ": " + key)
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)
    try:
        visit(value)
    except RecursionError as error:
        raise PackageError("Public JSON nesting is excessive: " + relative) from error
    return value


def _public_text(data, relative):
    if b"\0" in data or data.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"MSCF")) or PRIVATE_KEY.search(data):
        raise PackageError("Binary or private-key material in source: " + relative)
    if any(c < 32 and c not in (9, 10, 12, 13) for c in data):
        raise PackageError("Non-text source: " + relative)
    if relative.endswith(".json"):
        _public_json(data, relative)
    if relative in PUBLIC_CONFIGS:
        for match in re.finditer(br"(?im)^\s*([a-z_][a-z0-9_]*)\s*=\s*([^;\r\n]*)", data):
            key = match[1].decode("ascii").lower()
            if key in SECRET_KEYS | {"token", "api_key", "apikey", "secret"} and match[2].strip():
                raise PackageError("Credential value in public configuration template: " + relative)
    if relative in PUBLIC_CERTIFICATES:
        # Certificate-only fixtures are public source data; keys are never allowed.
        remainder = re.sub(br"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----", b"", data)
        remainder = re.sub(br"(?m)^#[^\r\n]*", b"", remainder)
        if b"-----BEGIN CERTIFICATE-----" not in data or remainder.strip():
            raise PackageError("Non-certificate PEM fixture: " + relative)


def _source_kind(relative):
    p = PurePosixPath(relative)
    name = p.name
    if name in {".gitignore", ".gitattributes"} or name == "VALIDATION.json" or relative in OMITTED_FIXTURES:
        return False
    parts = p.parts
    module = (len(parts) == 5 and parts[:3] == ("shizukudos", "win64", "dlls") and parts[3] in MODULE_NAMES and name == "module.json")
    if name in SOURCE_BASENAMES or p.suffix.lower() in SOURCE_EXTENSIONS or relative in PUBLIC_METADATA | PUBLIC_CONFIGS | PUBLIC_CERTIFICATES or module:
        return True
    if name.startswith(".env") or name.lower() in {"credentials.json", "secrets.json", "config.json", "token.json", "credentials", "id_rsa", "id_ed25519"} or p.suffix.lower() in FORBIDDEN_EXTENSIONS:
        raise PackageError("Unexpected media, binary or configuration in source: " + relative)
    return False


def _source_paths(root):
    found = set()
    for prefix in SOURCE_ROOTS:
        start = _no_symlinks(root / prefix)
        if not start.exists():
            continue
        if not start.is_dir():
            raise PackageError("Source root is not a directory: " + prefix)
        for base, directories, files in os.walk(start, followlinks=False):
            directories.sort()
            files.sort()
            for name in (*directories, *files):
                _no_symlinks(Path(base) / name)
            directories[:] = [name for name in directories if name not in EXCLUDED_DIRS]
            for name in files:
                relative = (Path(base) / name).relative_to(root).as_posix()
                if _source_kind(relative):
                    found.add(relative)
    for relative in FIXED_FILES:
        path = _no_symlinks(root / relative)
        if path.exists():
            found.add(relative)
    return tuple(sorted(found))


def _result_success(row):
    """Known original test/compile/reference row schemas; bool False is not exit 0."""
    if not isinstance(row, dict):
        return False
    for key in ("passed",):
        if key in row and row[key] is not True:
            return False
    if "status" in row and row["status"] != "PASS":
        return False
    if row.get("error"):
        return False
    for key in ("timeout", "timed_out", "compile_timeout", "run_timeout"):
        if key in row and row[key] is not False:
            return False
    for key in ("compile_exit", "run_exit", "exit", "returncode"):
        if key in row and (type(row[key]) is not int or row[key] != 0):
            return False
    if any(key in row for key in ("run_exit", "exit", "returncode")):
        return True
    if row.get("object_only") is True and type(row.get("compile_exit")) is int and row["compile_exit"] == 0:
        return HEX.fullmatch(str(row.get("object_sha256", ""))) is not None
    if row.get("status") == "PASS" and type(row.get("vectors")) is int and row["vectors"] == 57:
        return HEX.fullmatch(str(row.get("binary_sha256", ""))) is not None
    return False


def _receipt_sources(root, label, value, sources):
    if not isinstance(value, dict) or not isinstance(value.get("scope"), (str, dict)):
        raise PackageError("Receipt must declare its validation scope: " + label)
    passed = value.get("passed") is True
    compiled = value.get("source_stable") is True and value.get("missing_import_providers") == [] and HEX.fullmatch(str(value.get("exe_sha256", "")))
    rows = value.get("results")
    rows_valid = isinstance(rows, list) and bool(rows) and all(_result_success(row) for row in rows)
    if "results" in value and not rows_valid:
        raise PackageError("Receipt result array has a failed or unrecognized verdict: " + label)
    ap = value.get("status") == "PASS" and value.get("inputs_stable") is True and rows_valid
    stable_rows = value.get("source_stable") is True and rows_valid
    if "passed" in value and value["passed"] is not True:
        raise PackageError("Receipt explicitly failed validation: " + label)
    if "missing_import_providers" in value and value["missing_import_providers"] != []:
        raise PackageError("Receipt has missing import providers: " + label)
    if "status" in value and value["status"] != "PASS":
        raise PackageError("Receipt declares a failing top-level status: " + label)
    if not (passed or compiled or ap or stable_rows):
        raise PackageError("Receipt has no successful validation verdict: " + label)
    for flag in ("source_stable", "source_before_after_match", "inputs_stable"):
        if flag in value and value[flag] is not True:
            raise PackageError("Unstable source receipt: " + label)
    if "sources_before" in value or "sources_after" in value:
        if not ap or value.get("sources_before") != value.get("sources_after"):
            raise PackageError("AP before/after source binding changed or validation failed: " + label)
    tables = [value[key] for key in ("sources_sha256", "source_sha256", "sources_before", "sources_after") if key in value]
    if not tables or any(not isinstance(table, dict) or not table for table in tables):
        raise PackageError("Receipt has no source hash binding: " + label)
    pinned = set()
    for table in tables:
        for path, expected in table.items():
            if not isinstance(path, str) or not isinstance(expected, str) or not HEX.fullmatch(expected):
                raise PackageError("Invalid source hash in receipt: " + label)
            relative = _relative(root, path)
            if relative not in sources or _sha(sources[relative]) != expected:
                raise PackageError("Receipt source missing or changed: " + label + ": " + relative)
            pinned.add(relative)
    return frozenset(pinned)


def _validate_pe(name, data):
    expected = {"SHZPERS.EXE": (0x14c, 0x10b, 2), "ELEVATE.EXE": (0x8664, 0x20b, 3)}[name]
    if len(data) < 64 or data[:2] != b"MZ":
        raise PackageError("Executable has no DOS/PE header: " + name)
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    if offset < 64 or offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        raise PackageError("Invalid PE offset/signature: " + name)
    machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, offset + 4)
    if optional_size < 96 or offset + 24 + optional_size > len(data) or not sections or not characteristics & 2 or characteristics & 0x2000:
        raise PackageError("Invalid executable PE headers: " + name)
    magic = struct.unpack_from("<H", data, offset + 24)[0]
    subsystem = struct.unpack_from("<H", data, offset + 24 + 68)[0]
    if (machine, magic, subsystem) != expected or magic == 0x20b and optional_size < 112:
        raise PackageError("Executable architecture/subsystem mismatch: " + name)


def select_inputs(root, binaries=(), receipts=(), *, epoch=DEFAULT_EPOCH):
    """Freeze explicitly requested inputs. Does not build, discover binaries or run recipes."""
    root = _no_symlinks(root)
    if not root.is_dir():
        raise PackageError("Project root must be a real directory")
    if type(epoch) is not int or not 946684800 <= epoch <= 4102444799:
        raise PackageError("Timestamp must be an integer UTC epoch between 2000 and 2099")
    sources = {}
    inputs = {}
    payloads = {}
    for relative in _source_paths(root):
        data = _read(root, relative)
        _public_text(data, relative)
        sources[relative] = data
        inputs[relative] = InputFile(relative, _sha(data), len(data))
        payloads["SOURCE/" + relative] = data
    license_data = sources.get("LICENSE", b"")
    if b"GNU GENERAL PUBLIC LICENSE" not in license_data or b"Version 2" not in license_data:
        raise PackageError("Actual project GPLv2 LICENSE is required")
    receipt_values, receipt_manifest, receipt_pins = {}, {}, {}
    for receipt in receipts:
        if not LABEL.fullmatch(receipt.label) or receipt.label in receipt_values:
            raise PackageError("Invalid or duplicate validation label: " + receipt.label)
        relative = _relative(root, receipt.path)
        if not relative.endswith(".json"):
            raise PackageError("Validation receipt must be explicit JSON")
        data = _read(root, relative)
        _public_text(data, relative)
        value = _public_json(data, relative)
        receipt_pins[receipt.label] = _receipt_sources(root, receipt.label, value, sources)
        receipt_values[receipt.label] = value
        inputs[relative] = InputFile(relative, _sha(data), len(data))
        destination = "VALIDATION/" + receipt.label + ".json"
        payloads[destination] = data
        receipt_manifest[receipt.label] = {"file": destination, "sha256": _sha(data), "source": relative, "scope": value["scope"]}
    binary_manifest = {}
    required_sources = {
        "SHZPERS.EXE": ("ntwddm/win98/personalization/native.c", "ntwddm/win98/personalization/verify.py", "platform/freestanding/memory.c"),
        "ELEVATE.EXE": ("shizukudos/win64/apps/elevate/main.c", "shizukudos/win64/apps/elevate/build.py", "shizukudos/win64/crt/shzcrt.c", "shizukudos/abi/shz_auth.h"),
    }
    for binary in binaries:
        if binary.name not in required_sources or binary.name in binary_manifest:
            raise PackageError("Only one explicit SHZPERS.EXE and ELEVATE.EXE are permitted")
        relative = _relative(root, binary.path)
        if PurePosixPath(relative).parts[0] != "build" or PurePosixPath(relative).name != binary.name:
            raise PackageError("Binary must be its exact owned filename below project build/: " + relative)
        if binary.receipt not in receipt_values:
            raise PackageError("Binary has no explicit validation receipt: " + binary.name)
        if any(path not in sources for path in required_sources[binary.name]):
            raise PackageError("Missing executable recipe/static runtime source: " + binary.name)
        data = _read(root, relative)
        _validate_pe(binary.name, data)
        value = receipt_values[binary.receipt]
        # Build recipes must be shipped; actual production/runtime dependencies
        # must additionally be pinned by this executable's receipt.
        must_pin = {path for path in required_sources[binary.name] if not path.endswith(".py")}
        if not must_pin <= receipt_pins[binary.receipt]:
            raise PackageError("Binary receipt does not pin its production/static runtime sources: " + binary.name)
        executable = value.get("executable")
        if isinstance(executable, dict):
            expected = executable.get("sha256")
            if "file" in executable and _relative(root, executable["file"]) != relative:
                raise PackageError("Receipt executable path does not match selection")
            if "bytes" in executable and executable["bytes"] != len(data):
                raise PackageError("Receipt executable length does not match selection")
        else:
            expected = value.get("exe_sha256")
        if expected != _sha(data):
            raise PackageError("Receipt binary hash does not match selection: " + binary.name)
        inputs[relative] = InputFile(relative, _sha(data), len(data))
        destination = "BIN/" + binary.name
        payloads[destination] = data
        binary_manifest[binary.name] = {"file": destination, "source": relative, "sha256": _sha(data), "bytes": len(data), "receipt": binary.receipt, "architecture": "i486 PE32 Win98 GUI" if binary.name == "SHZPERS.EXE" else "x86_64 PE32+ auxiliary console", "external_toolchain_closure_complete": value.get("external_toolchain_closure_complete", False)}
    readme = (
        "ShizukuDOS / ShizukuOS Windows 98 integration add-on\n\n"
        "NONBOOTABLE source and component add-on; this is not the full installer.\n"
        "The project target is actual Windows 98 on ShizukuDOS, preserving VMM,\n"
        "USER/GDI and Explorer. No Microsoft media or installed guest is included.\n\n"
        "SHZPERS.EXE is the owned i486 PE32 personalization component. ELEVATE.EXE\n"
        "is an auxiliary PE64 component and requires the project native DLL/token\n"
        "services; it cannot run directly as a Windows 98 executable.\n"
        "Native DLL/auth/driver bindings, physical laptop tests, system suspend and\n"
        "the complete Windows 98 installer remain release gates. Host/compiler\n"
        "receipts do not establish native Windows 98 or hardware validation.\n\n"
        "SOURCE contains public project source, own static CRT/runtime and build\n"
        "recipes with GPL LICENSE and component notices. VALIDATION preserves\n"
        "source-bound receipts and their limited scopes. Toolchain closure flags\n"
        "are retained; external compiler/runtime closure is not proven by this ISO.\n"
        "MANIFEST.json lists every payload hash except its own self-reference.\n"
        "There is no autorun or disk installation action on this image.\n"
    ).encode()
    payloads["README.txt"] = readme
    manifest = {
        "schema": 1, "product": "ShizukuDOS Windows 98 laptop/security integration add-on",
        "epoch": epoch, "scope": {"bootable": False, "full_installer": False, "native_windows98_validated": False, "physical_hardware_validated": False, "microsoft_media_included": False},
        "source_roots": list(SOURCE_ROOTS), "omitted_compiled_test_fixtures": sorted(OMITTED_FIXTURES),
        "sources": {p: {"sha256": _sha(data), "bytes": len(data)} for p, data in sorted(sources.items())},
        "binaries": binary_manifest, "receipts": receipt_manifest,
        "files": {p: {"sha256": _sha(data), "bytes": len(data)} for p, data in sorted(payloads.items())},
    }
    manifest_bytes = _json_bytes(manifest)
    payloads["MANIFEST.json"] = manifest_bytes
    if sum(len(data) for data in payloads.values()) > MAX_PAYLOAD_BYTES:
        raise PackageError("Public payload exceeds the 24 MiB resource budget")
    selection = Selection(root, epoch, tuple(inputs[p] for p in sorted(inputs)), tuple(sorted(payloads.items())), manifest_bytes)
    _revalidate(selection)
    return selection


def _revalidate(selection):
    _no_symlinks(selection.root)
    expected_sources = {p[len("SOURCE/"):] for p, _ in selection._payloads if p.startswith("SOURCE/")}
    if set(_source_paths(selection.root)) != expected_sources:
        raise PackageError("Source selection changed after freezing inputs")
    for entry in selection.inputs:
        data = _read(selection.root, entry.relative)
        if len(data) != entry.size or _sha(data) != entry.sha256:
            raise PackageError("Frozen input changed: " + entry.relative)


def _run(argv, *, epoch):
    env = os.environ.copy()
    env.update({"SOURCE_DATE_EPOCH": str(epoch), "TZ": "UTC", "LC_ALL": "C"})
    try:
        proc = subprocess.run(argv, env=env, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PackageError("xorriso command failed or exceeded 60 seconds") from error
    if proc.returncode:
        raise PackageError("xorriso failed: " + proc.stderr.decode(errors="replace")[-4000:])
    return proc


def _stage(selection, directory):
    directory.mkdir()
    for relative, data in selection._payloads:
        destination = directory / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o644)
        os.utime(destination, (selection.epoch, selection.epoch))
    for folder in sorted([directory, *(p for p in directory.rglob("*") if p.is_dir())], reverse=True):
        folder.chmod(0o755)
        os.utime(folder, (selection.epoch, selection.epoch))


def _check_iso(path):
    if path.stat().st_size > MAX_ISO_BYTES:
        raise PackageError("ISO exceeds 30 MiB resource budget")
    with path.open("rb") as handle:
        handle.seek(16 * 2048)
        for _ in range(64):
            descriptor = handle.read(2048)
            if len(descriptor) != 2048 or descriptor[1:6] != b"CD001":
                raise PackageError("Invalid ISO9660 volume descriptors")
            if descriptor[0] == 0:
                raise PackageError("Unexpected boot record in add-on ISO")
            if descriptor[0] == 255:
                return
    raise PackageError("No ISO9660 volume descriptor terminator")


def _verify_extract(selection, image, destination, xorriso):
    _run([xorriso, "-no_rc", "-osirrox", "on", "-indev", "stdio:" + str(image), "-extract", "/", str(destination)], epoch=selection.epoch)
    observed = {}
    for p in destination.rglob("*"):
        if p.is_symlink():
            raise PackageError("Extracted payload contains an unexpected symlink")
        if p.is_file():
            observed[p.relative_to(destination).as_posix()] = p.read_bytes()
        elif not p.is_dir():
            raise PackageError("Extracted payload contains an unexpected special file")
    if observed != dict(selection._payloads):
        raise PackageError("Extracted payload differs from frozen manifest/source")


def build_iso(selection, output, work_dir):
    """Revalidate, build twice, extract/compare, then publish a new local ISO atomically."""
    _revalidate(selection)
    output = _no_symlinks(output)
    work_dir = _no_symlinks(work_dir)
    for path in (output, work_dir):
        if not path.is_relative_to(Path("/dev/shm")):
            raise PackageError("Staging and output must use /dev/shm; root/native VM reserves are protected")
    if output.exists() or output.suffix.lower() != ".iso":
        raise PackageError("Output must be a new .iso file")
    if work_dir.exists() and not work_dir.is_dir():
        raise PackageError("Workspace must be a real directory")
    if output.is_relative_to(selection.root) or work_dir.is_relative_to(selection.root):
        raise PackageError("ISO staging/output must stay outside the frozen source tree")
    xorriso = shutil.which("xorriso")
    if not xorriso:
        raise PackageError("Installed xorriso is required; the builder never downloads tools")
    work_dir.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(work_dir).free < MAX_ISO_BYTES * 6:
        raise PackageError("Insufficient bounded tmpfs workspace (180 MiB required)")
    date = datetime.fromtimestamp(selection.epoch, timezone.utc).strftime("%Y%m%d%H%M%S") + "00"
    with tempfile.TemporaryDirectory(prefix="shz-addon-", dir=work_dir) as owned:
        owned = Path(owned)
        images = []
        for number in (1, 2):
            stage = owned / ("stage-" + str(number))
            image = owned / ("build-" + str(number) + ".iso")
            _stage(selection, stage)
            _run([xorriso, "-no_rc", "-as", "mkisofs", "-r", "-J", "-joliet-long", "-iso-level", "3", "-uid", "0", "-gid", "0", "-V", "SHZ_LAPTOP_ADDON", "--modification-date=" + date, "--set_all_file_dates", date, "-o", str(image), str(stage)], epoch=selection.epoch)
            _check_iso(image)
            images.append(image)
        hashes = [_sha(image.read_bytes()) for image in images]
        if hashes[0] != hashes[1]:
            raise PackageError("Two independent ISO builds are not reproducible")
        _verify_extract(selection, images[0], owned / "extracted", xorriso)
        _revalidate(selection)
        _no_symlinks(output.parent)
        try:
            # Same-filesystem link is atomic and refuses an existing output.
            os.link(images[0], output, follow_symlinks=False)
        except OSError as error:
            raise PackageError("Could not publish a new ISO without overwriting") from error
        output.chmod(0o644)
        os.utime(output, (selection.epoch, selection.epoch))
        result = {"schema": 1, "iso": str(output), "iso_sha256": hashes[0], "bytes": output.stat().st_size, "manifest_sha256": _sha(selection._manifest_bytes), "reproducible": True, "extracted_manifest_verified": True, "bootable": False, "native_windows98_validated": False, "source_stable": True, "source_files": len(selection.manifest["sources"]), "validation_receipts": sorted(selection.manifest["receipts"]), "binaries": sorted(selection.manifest["binaries"])}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--epoch", type=int, default=DEFAULT_EPOCH)
    parser.add_argument("--personalization-binary", type=Path)
    parser.add_argument("--personalization-receipt", type=Path)
    parser.add_argument("--elevate-binary", type=Path)
    parser.add_argument("--elevate-receipt", type=Path)
    parser.add_argument("--validation", action="append", default=[], metavar="LABEL=PATH")
    args = parser.parse_args(argv)
    binaries, receipts = [], []
    for label, name in (("personalization", "SHZPERS.EXE"), ("elevate", "ELEVATE.EXE")):
        binary, receipt = getattr(args, label + "_binary"), getattr(args, label + "_receipt")
        if (binary is None) != (receipt is None):
            parser.error("--" + label + "-binary and --" + label + "-receipt must be supplied together")
        if binary is not None:
            binaries.append(BinarySpec(name, binary, label))
            receipts.append(ReceiptSpec(label, receipt))
    for argument in args.validation:
        if "=" not in argument:
            parser.error("Validation must use LABEL=PATH")
        label, path = argument.split("=", 1)
        receipts.append(ReceiptSpec(label, Path(path)))
    try:
        selection = select_inputs(args.root, binaries, receipts, epoch=args.epoch)
        result = build_iso(selection, args.output, args.work_dir)
    except PackageError as error:
        parser.exit(1, "ISO rejected: " + str(error) + "\n")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
