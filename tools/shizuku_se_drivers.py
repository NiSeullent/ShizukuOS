#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Driver store for the Windows 98 Shizuku Second Edition media.

Layout on the ISO (and on the raw disk image):

    DRIVERS\\README.TXT
    DRIVERS\\HWIDS.TXT                     index: hardware ID -> package and INF, sorted
    DRIVERS\\MANIFEST.JSON                 every package, file (size, sha256) and INF model
    DRIVERS\\<package>\\...                 the package files, byte for byte as shipped

Packages are only ever supplied by whoever runs the builder (`--driver-package
DIR`, repeatable, or `PACKAGE=DIR` to choose the folder name; the default is
the directory's own name). Third-party drivers are never part of this
repository; the staged copies live under build/ (git-ignored). The provider
named in the INF is recorded in the manifest.

The INF reader follows the SetupAPI INF syntax rules as documented by
Microsoft ("General Syntax Rules for INF Files", "INF Manufacturer Section",
"INF Models Section", "INF Strings Section"):
  - [section] names and keys are case-insensitive; repeated sections merge;
  - ';' starts a comment outside double quotes; '\\' at the end of a line
    continues it; "" inside a quoted string is one quote;
  - %strkey% is replaced from [Strings] (a [Strings.<LangID>] section may
    override it; the base [Strings] is used here), %% is a literal %;
  - [Manufacturer] entries name a models section, optionally followed by
    TargetOSVersion decorations (NTx86, NTamd64.10.0, ...); the decorated
    sections are <models>.<decoration>; Windows 9x uses the undecorated one;
  - a models-section line is  description = install-section[, hw-id[, compatible-id ...]].
Files are read as UTF-16 (BOM), UTF-8 (BOM) or ANSI (cp1252, undecodable
bytes replaced). Nothing is executed or installed.

CLI:
    shizuku_se_drivers.py scan DIR          print the hardware IDs of every INF under DIR (JSON)
    shizuku_se_drivers.py make-synthetic DIR  write a synthetic test package (not a real driver)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

STORE = "DRIVERS"
MANIFEST_FORMAT = "shizuku-se-driver-store/1"
NAME_OK = re.compile(r"[^A-Za-z0-9._-]+")
FAT_BAD = set('"*/:<>?\\|')
JOLIET_MAX = 64
RESERVED_NAMES = {"readme.txt", "hwids.txt", "manifest.json"}


# ---------------------------------------------------------------------------
# INF reader
# ---------------------------------------------------------------------------

def decode_inf(raw: bytes) -> tuple[str, str]:
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace"), "utf-16-le"
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace"), "utf-16-be"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace"), "utf-8"
    # UTF-16LE without BOM: every other byte of the ASCII text is zero.
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0 and raw[0] != 0:
        return raw.decode("utf-16-le", errors="replace"), "utf-16-le (no BOM)"
    return raw.decode("cp1252", errors="replace"), "cp1252"


def strip_comment(line: str) -> str:
    """Drop a ';' comment that is outside double quotes."""
    quoted = False
    for index, char in enumerate(line):
        if char == '"':
            quoted = not quoted
        elif char == ";" and not quoted:
            return line[:index]
    return line


def logical_lines(text: str) -> list[str]:
    """Physical lines joined at a trailing backslash, comments removed."""
    out: list[str] = []
    pending = ""
    for physical in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = strip_comment(physical).rstrip()
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        line = pending + line
        pending = ""
        if line.strip():
            out.append(line.strip())
    if pending.strip():
        out.append(pending.strip())
    return out


def split_fields(text: str) -> list[str]:
    """Comma-separated fields; quotes group, "" is a literal quote, surrounding blanks trimmed."""
    fields: list[str] = []
    current: list[str] = []
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if quoted and index + 1 < len(text) and text[index + 1] == '"':
                current.append('"')
                index += 2
                continue
            quoted = not quoted
        elif char == "," and not quoted:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    fields.append("".join(current).strip())
    return fields


def split_entry(line: str) -> tuple[str | None, str]:
    """key = value (the first '=' outside quotes), or a value-only line."""
    quoted = False
    for index, char in enumerate(line):
        if char == '"':
            quoted = not quoted
        elif char == "=" and not quoted:
            return line[:index].strip(), line[index + 1:].strip()
    return None, line.strip()


class Inf:
    def __init__(self, raw: bytes, name: str = "") -> None:
        self.name = name
        self.text, self.encoding = decode_inf(raw)
        self.sections: dict[str, list[tuple[str | None, str]]] = {}
        self.section_names: dict[str, str] = {}
        self.warnings: list[str] = []
        current: str | None = None
        for line in logical_lines(self.text):
            if line.startswith("["):
                end = line.find("]")
                if end < 0:
                    self.warnings.append(f"unterminated section header {line!r}")
                    current = None
                    continue
                title = line[1:end].strip()
                current = title.lower()
                self.section_names.setdefault(current, title)
                self.sections.setdefault(current, [])
                continue
            if current is None:
                self.warnings.append(f"line outside any section ignored: {line[:60]!r}")
                continue
            self.sections[current].append(split_entry(line))
        self.strings = self._strings()

    def _strings(self) -> dict[str, str]:
        table: dict[str, str] = {}
        for key, value in self.sections.get("strings", []):
            if key is None:
                continue
            fields = split_fields(value)
            table[unquote(key).lower()] = fields[0] if fields else ""
        return table

    def expand(self, value: str) -> str:
        def repl(match: re.Match) -> str:
            key = match.group(1)
            if key == "":
                return "%"
            found = self.strings.get(key.lower())
            if found is None:
                self.warnings.append(f"%{key}% is not defined in [Strings]")
                return match.group(0)
            return found.replace("%%", "%")  # a [Strings] value writes a literal percent sign as %%
        return re.sub(r"%([^%]*)%", repl, value)

    def entries(self, section: str) -> list[tuple[str | None, str]]:
        return self.sections.get(section.lower(), [])

    def value(self, section: str, key: str) -> str | None:
        for entry_key, value in self.entries(section):
            if entry_key is not None and entry_key.lower() == key.lower():
                fields = split_fields(value)
                return self.expand(fields[0]) if fields else ""
        return None

    def version(self) -> dict:
        info = {}
        for key in ("Signature", "Class", "ClassGUID", "Provider", "DriverVer", "CatalogFile", "LayoutFile"):
            info[key.lower()] = self.value("Version", key)
        decorated = {}
        for key, value in self.entries("Version"):
            if key and key.lower().startswith("catalogfile."):
                decorated[key.split(".", 1)[1]] = self.expand(split_fields(value)[0])
        info["catalogfile_decorated"] = decorated
        return info

    def models(self) -> list[dict]:
        out = []
        for key, value in self.entries("Manufacturer"):
            fields = split_fields(value)
            if key is None:  # "%Mfg%" alone: the models section has the manufacturer's (expanded) name
                manufacturer = self.expand(fields[0])
                base = manufacturer
                decorations: list[str] = []
            else:
                manufacturer = self.expand(unquote(key))
                base = fields[0]
                decorations = [d for d in fields[1:] if d]
            targets = [(base, "")] + [(f"{base}.{d}", d) for d in decorations]
            for section, decoration in targets:
                if section.lower() not in self.sections:
                    self.warnings.append(f"models section [{section}] named by [Manufacturer] is missing")
                    continue
                devices = []
                for dkey, dvalue in self.entries(section):
                    dfields = split_fields(dvalue)
                    if dkey is None:
                        self.warnings.append(f"[{section}] line without '=' ignored: {dvalue[:60]!r}")
                        continue
                    ids = [self.expand(f) for f in dfields[1:] if f]
                    devices.append({"description": self.expand(unquote(dkey)), "install": dfields[0] if dfields else "",
                                    "hardware_id": ids[0] if ids else None, "compatible_ids": ids[1:]})
                out.append({"manufacturer": manufacturer, "section": self.section_names.get(section.lower(), section),
                            "decoration": decoration or None, "windows9x": decoration == "", "devices": devices})
        return out

    def hardware_ids(self) -> list[str]:
        seen: dict[str, str] = {}
        for model in self.models():
            for device in model["devices"]:
                for hwid in ([device["hardware_id"]] if device["hardware_id"] else []) + device["compatible_ids"]:
                    seen.setdefault(hwid.upper(), hwid)
        return [seen[key] for key in sorted(seen)]

    def source_files(self) -> list[str]:
        names = set()
        for section in self.sections:
            if section == "sourcedisksfiles" or section.startswith("sourcedisksfiles."):
                for key, value in self.sections[section]:
                    name = key if key is not None else split_fields(value)[0]
                    if name:
                        names.add(unquote(name))
        return sorted(names, key=str.lower)

    def summary(self) -> dict:
        version = self.version()
        models = self.models()
        return {"path": self.name, "encoding": self.encoding, **version, "models": models,
                "hardware_ids": self.hardware_ids(), "source_disks_files": self.source_files(),
                "warnings": sorted(set(self.warnings))}


def unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1].replace('""', '"')
    return text


# ---------------------------------------------------------------------------
# store staging
# ---------------------------------------------------------------------------

class DriverPackageError(RuntimeError):
    pass


def safe_name(text: str, fallback: str) -> str:
    cleaned = NAME_OK.sub("_", text.strip()).strip("._") or fallback
    return cleaned[:48]


def package_files(root: Path) -> list[tuple[str, Path]]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in [*dirnames, *filenames]:
            if os.path.islink(os.path.join(dirpath, name)):
                raise DriverPackageError(f"{root}: {name} is a symbolic link; refusing to follow it")
        for name in sorted(filenames):
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            for part in relative.split("/"):
                if len(part) > JOLIET_MAX:
                    raise DriverPackageError(f"{relative}: name longer than {JOLIET_MAX} characters (Joliet limit)")
                if FAT_BAD & set(part) or any(ord(c) < 32 for c in part):
                    raise DriverPackageError(f"{relative}: name has characters FAT/Joliet cannot store")
            files.append((relative, path))
    if not files:
        raise DriverPackageError(f"{root} contains no files")
    return files


def parse_package_spec(spec: str) -> tuple[str | None, Path]:
    """DIR or PACKAGE=DIR."""
    if "=" in spec:
        package, directory = spec.split("=", 1)
        if not package.strip() or "/" in package or "\\" in package:
            raise DriverPackageError(f"--driver-package {spec!r}: use PACKAGE=DIR with a plain folder name")
        return package, Path(directory)
    return None, Path(spec)


def stage_packages(specs: list[str]) -> tuple[dict[str, bytes], dict]:
    """Payload (ISO/FAT path -> bytes) and the manifest for the given packages (may be empty)."""
    payload: dict[str, bytes] = {}
    packages = []
    used: set[str] = set()
    for spec in specs:
        package, root = parse_package_spec(spec)
        root = root.expanduser()
        if not root.is_dir():
            raise DriverPackageError(f"--driver-package {root}: not a directory")
        files = package_files(root)
        infs = []
        for relative, path in files:
            if relative.lower().endswith(".inf"):
                infs.append(Inf(path.read_bytes(), relative).summary())
        if not infs:
            raise DriverPackageError(f"{root}: no .inf file found; a driver package needs one")
        provider = next((i["provider"] for i in infs if i.get("provider")), None)
        package = safe_name(package or root.resolve().name, "package")
        key = package.lower()
        if key in used or key in RESERVED_NAMES:
            raise DriverPackageError(f"two packages (or a package and the index) would both be {STORE}/{package}")
        used.add(key)
        base = f"{STORE}/{package}"
        entries = []
        for relative, path in files:
            data = path.read_bytes()
            payload[f"{base}/{relative}"] = data
            entries.append({"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        present = {relative.lower().rsplit("/", 1)[-1] for relative, _ in files}
        for inf in infs:
            inf["missing_source_disks_files"] = [n for n in inf["source_disks_files"] if n.lower() not in present]
        packages.append({"package": package, "provider": provider, "path": base,
                         "source": "user-supplied (--driver-package)",
                         "files": entries, "infs": infs,
                         "hardware_ids": sorted({h for inf in infs for h in inf["hardware_ids"]}, key=str.upper)})
    manifest = {
        "format": MANIFEST_FORMAT,
        "layout": f"{STORE}/<package>/<files exactly as shipped>",
        "note": "Packages are supplied by whoever built this medium. Nothing here was installed or tested; "
                "hardware IDs are parsed from the INF text only.",
        "packages": packages,
    }
    return payload, manifest


def store_readme(manifest: dict) -> bytes:
    lines = [
        "DRIVERS - driver store of this medium",
        "=====================================",
        "",
        "Layout   DRIVERS\\<package>\\  files copied byte for byte as shipped",
        "         (.inf, .sys, .cat, .vxd, .dll ...). Nothing is renamed or patched.",
        "Index    DRIVERS\\HWIDS.TXT: one line per hardware or compatible ID found in",
        "         an INF: ID, package, INF path, models section, device description.",
        "         DRIVERS\\MANIFEST.JSON: every package, file (size, SHA-256) and INF",
        "         ([Manufacturer] -> models sections; undecorated sections are the",
        "         ones Windows 9x uses).",
        "Source   Packages are added by the person who builds the medium with",
        "         --driver-package DIR. The project ships none: third-party drivers",
        "         keep their own licences; check them before sharing this medium.",
        "Status   Nothing here was installed or tested by the builder. A hardware ID",
        "         in the manifest is text from the INF, not evidence that the driver",
        "         works on Windows 98 or on any machine.",
        "",
        f"Packages on this medium: {len(manifest['packages'])}",
    ]
    for package in manifest["packages"]:
        lines.append(f"  {package['package']} (provider {package['provider'] or 'not named'}): "
                     f"{len(package['files'])} files, {len(package['hardware_ids'])} hardware IDs")
    return ("\r\n".join(lines) + "\r\n").encode("ascii", errors="replace")


def hwid_index(manifest: dict) -> bytes:
    """HWIDS.TXT: every hardware/compatible ID of every INF model line, sorted by ID (case-insensitive)."""
    rows = []
    for package in manifest["packages"]:
        for inf in package["infs"]:
            for model in inf["models"]:
                for device in model["devices"]:
                    ids = [("compat", c) for c in device["compatible_ids"]]
                    if device["hardware_id"]:
                        ids.insert(0, ("hw", device["hardware_id"]))
                    for kind, hwid in ids:
                        rows.append((hwid.upper(), hwid, kind, package["package"], inf["path"], model["section"],
                                     device["description"]))
    rows.sort()
    lines = ["; Shizuku SE driver store index: hardware ID, kind (hw = first ID of the model line,",
             "; compat = compatible ID), package folder under DRIVERS, INF, models section, description.",
             "; Parsed from INF text only; nothing was installed or tested.",
             f"; {len(rows)} entries"]
    lines += ["\t".join(row[1:]) for row in rows]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def store_payload(specs: list[str]) -> tuple[dict[str, bytes], dict]:
    payload, manifest = stage_packages(specs)
    payload[f"{STORE}/MANIFEST.JSON"] = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    payload[f"{STORE}/HWIDS.TXT"] = hwid_index(manifest)
    payload[f"{STORE}/README.TXT"] = store_readme(manifest)
    return payload, manifest


# ---------------------------------------------------------------------------
# synthetic test package (never a real driver)
# ---------------------------------------------------------------------------

SYNTHETIC_INF = (
    "; Synthetic INF for the Shizuku SE driver-store tests. Not a real driver.\r\n"
    "[Version]\r\n"
    "Signature=\"$Windows NT$\"   ; comment after a value\r\n"
    "Class=Net\r\n"
    "ClassGUID={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
    "Provider=%ProviderName%\r\n"
    "DriverVer=09/29/2026,1.0.0.0\r\n"
    "CatalogFile=shzsynth.cat\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "%MfgName%=ShizukuModels,NTx86,NTamd64\r\n"
    "\r\n"
    "[ShizukuModels]\r\n"
    "%Dev.Desc%=Synth_Install, PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4, \\\r\n"
    "    PCI\\VEN_1AF4&DEV_1000\r\n"
    "[ShizukuModels.NTx86]\r\n"
    "%Dev.Desc%=Synth_Install, PCI\\VEN_1AF4&DEV_1000\r\n"
    "[shizukumodels.ntamd64]\r\n"
    "\"Quoted; description, with comma\"=Synth_Install, USB\\VID_1234&PID_5678\r\n"
    "\r\n"
    "[SourceDisksFiles]\r\n"
    "shzsynth.sys=1\r\n"
    "\r\n"
    "[Strings]\r\n"
    "ProviderName=\"Shizuku Synthetic\"\r\n"
    "MfgName=\"Shizuku Test Hardware\"\r\n"
    "Dev.Desc=\"Synthetic 100%% Test Device\"\r\n"
)


def make_synthetic(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "shzsynth.inf").write_bytes(SYNTHETIC_INF.encode("ascii"))
    (directory / "shzsynth.sys").write_bytes(b"MZ" + b"\0" * 62 + b"SYNTHETIC TEST FILE, NOT A DRIVER\r\n")
    (directory / "shzsynth.cat").write_bytes(b"SYNTHETIC CATALOG PLACEHOLDER, NOT SIGNED\r\n")
    return directory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("directory", type=Path)
    synth = sub.add_parser("make-synthetic")
    synth.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    if args.command == "make-synthetic":
        print(make_synthetic(args.directory))
        return 0
    out = []
    for path in sorted(args.directory.rglob("*")):
        if path.is_file() and path.suffix.lower() == ".inf":
            out.append(Inf(path.read_bytes(), str(path.relative_to(args.directory))).summary())
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
