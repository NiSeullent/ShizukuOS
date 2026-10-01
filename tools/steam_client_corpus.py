#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pin Valve's desktop Steam client and inspect PE dependencies without running it.

The win64 manifest is the current target; win32 is a separate historical corpus.
Downloads require --download. Only manifest-named, SHA-256/size-verified ZIPs are
accepted, with bounded total downloads and expansion. Target binaries are kept
under ignored build/, never packaged or executed by this tool. Static exports
are discovery evidence, not behavioral compatibility or a Steam launch pass.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import re
import shutil
import stat
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
CDN = "https://cdn.fastly.steamstatic.com/client/"
CORE_PACKAGES = (
    "steam_win64", "bins_win64", "bins_misc_win64", "bins_cef_win64",
    "bins_webhelpers_win64", "steamui_websrc_all", "public_all",
    "resources_all", "resources_misc_all", "resources_hidpi_all", "strings_en_all",
)
MAX_DOWNLOAD = 512 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_FILES = 20_000


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_vdf(text: str) -> dict:
    """Parse the quoted KeyValues subset used by Valve's client manifests."""
    tokens = []
    pos = 0
    token = re.compile(r'\s+|//[^\n]*|[{}]|"(?:\\.|[^"\\])*"')
    while pos < len(text):
        match = token.match(text, pos)
        if not match:
            raise ValueError(f"invalid manifest token at {pos}")
        word = match.group()
        pos = match.end()
        if word.isspace() or word.startswith("//"):
            continue
        tokens.append(word)
    index = 0

    def quoted(word):
        if not word.startswith('"'):
            raise ValueError("expected quoted manifest string")
        # ZIP names and hashes have no escapes; reject unknown ones explicitly.
        return re.sub(r'\\([\\"])', r'\1', word[1:-1])

    def obj(nested=False):
        nonlocal index
        result = {}
        while index < len(tokens):
            if tokens[index] == "}":
                if not nested:
                    raise ValueError("unexpected manifest closing brace")
                index += 1
                return result
            key = quoted(tokens[index])
            index += 1
            if key in result:
                raise ValueError(f"duplicate manifest key: {key}")
            if index >= len(tokens):
                raise ValueError("manifest value missing")
            if tokens[index] == "{":
                index += 1
                result[key] = obj(True)
            else:
                result[key] = quoted(tokens[index])
                index += 1
        if nested:
            raise ValueError("manifest closing brace missing")
        return result

    return obj()


def package_specs(manifest: dict, names: list[str]) -> list[dict]:
    branch = manifest.get("win64")
    if not isinstance(branch, dict) or not branch.get("version", "").isdigit():
        raise ValueError("a numeric-version win64 client manifest is required")
    specs = []
    for name in names:
        value = branch.get(name)
        if not isinstance(value, dict):
            raise ValueError(f"package missing from win64 manifest: {name}")
        filename, size, digest = value.get("file", ""), value.get("size", ""), value.get("sha2", "")
        if not re.fullmatch(r"[A-Za-z0-9_]+\.zip\.[0-9a-f]{40}", filename):
            raise ValueError(f"invalid package filename: {filename}")
        if not size.isdigit() or not 0 < int(size) <= MAX_DOWNLOAD:
            raise ValueError(f"invalid package size: {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid package SHA-256: {name}")
        specs.append({"name": name, "file": filename, "size": int(size), "sha256": digest,
                      "url": CDN + filename})
    if len(set(names)) != len(names):
        raise ValueError("duplicate package selection")
    if sum(spec["size"] for spec in specs) > MAX_DOWNLOAD:
        raise ValueError("selected packages exceed download limit")
    return specs


def checked_open(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "Win98-Modern Steam corpus inspection"})
    response = urllib.request.urlopen(request, timeout=60)
    final = urllib.parse.urlparse(response.url)
    if final.scheme != "https" or final.hostname != "cdn.fastly.steamstatic.com":
        response.close()
        raise ValueError("download redirected outside the selected Valve HTTPS CDN")
    return response


def download_package(spec: dict, archives: Path) -> Path:
    archives.mkdir(parents=True, exist_ok=True)
    dest = archives / spec["file"]
    if dest.exists():
        if dest.stat().st_size != spec["size"] or sha256_file(dest) != spec["sha256"]:
            raise ValueError(f"existing archive does not match pinned manifest: {dest}")
        return dest
    partial = dest.with_name(dest.name + ".partial")
    digest = hashlib.sha256()
    total = 0
    try:
        with checked_open(spec["url"]) as response, partial.open("xb") as stream:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) != spec["size"]:
                raise ValueError("publisher response size disagrees with manifest")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                total += len(chunk)
                if total > spec["size"]:
                    raise ValueError("package exceeds pinned size")
                digest.update(chunk)
                stream.write(chunk)
        if total != spec["size"] or digest.hexdigest() != spec["sha256"]:
            raise ValueError(f"package size/SHA-256 mismatch: {spec['name']}")
        partial.rename(dest)
    finally:
        partial.unlink(missing_ok=True)
    return dest


def safe_member_name(info: zipfile.ZipInfo) -> str:
    name = info.filename.replace("\\", "/")
    path = PurePosixPath(name)
    if (not name or name.startswith("/") or "\x00" in name or ":" in name
            or ".." in path.parts or not path.parts):
        raise ValueError(f"unsafe ZIP member: {info.filename!r}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ValueError(f"ZIP symlink is not a client file: {name}")
    return str(path)


def extract_packages(archives: list[Path], tree: Path, specs: list[dict]) -> list[dict]:
    """Validate all member paths and bounds before writing; require a fresh tree."""
    plan = []
    names = {}
    expanded = 0
    for archive, spec in zip(archives, specs, strict=True):
        with zipfile.ZipFile(archive) as zipped:
            for info in zipped.infolist():
                name = safe_member_name(info)
                if info.is_dir():
                    continue
                key = name.casefold()
                if key in names:
                    previous = names[key]
                    if name != previous["name"]:
                        raise ValueError(f"case-insensitive ZIP collision: {name} / {previous['name']}")
                    # Valve deliberately repeats resource/sourceinit.dat in two
                    # packages. Permit only the exact path and identical bytes,
                    # never a package-order overwrite or a case-folded alias.
                    def member_digest(stream):
                        digest = hashlib.sha256()
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                        return digest.digest()
                    with zipfile.ZipFile(previous["archive"]) as earlier:
                        with earlier.open(previous["member"]) as one, zipped.open(info) as two:
                            if member_digest(one) != member_digest(two):
                                raise ValueError(f"conflicting repeated ZIP member: {name}")
                    previous["packages"].append(spec["name"])
                    continue
                names[key] = {"name": name, "archive": archive, "member": info.filename, "packages": [spec["name"]]}
                expanded += info.file_size
                if expanded > MAX_EXPANDED or len(names) > MAX_FILES:
                    raise ValueError("client expansion exceeds bounds")
                plan.append((archive, spec["name"], info.filename, name, info.file_size))
    if tree.exists():
        raise ValueError("use a fresh output directory; extracted tree already exists")
    tree.mkdir(parents=True)
    records = []
    with contextlib.ExitStack() as stack:
        opened = {archive: stack.enter_context(zipfile.ZipFile(archive)) for archive in archives}
        for archive, package, member, name, size in plan:
            target = tree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            actual = 0
            with opened[archive].open(member) as source, target.open("xb") as dest:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    actual += len(chunk)
                    if actual > size:
                        raise ValueError("ZIP member exceeded declared size")
                    digest.update(chunk)
                    dest.write(chunk)
            if actual != size:
                raise ValueError("ZIP member was truncated")
            records.append({"path": name, "bytes": actual, "sha256": digest.hexdigest(), "package": package,
                            "shared_packages": names[name.casefold()]["packages"]})
    return records


def pe_record(path: Path, tree: Path) -> dict:
    import pefile
    pe = pefile.PE(str(path), fast_load=True)
    try:
        indices = [pefile.DIRECTORY_ENTRY[name] for name in (
            "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT")]
        pe.parse_data_directories(directories=indices)
        imports = []
        for kind, attribute in (("direct", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
            for descriptor in getattr(pe, attribute, []):
                for symbol in descriptor.imports:
                    # pefile can supply an automatic name hint even when the
                    # actual PE thunk imports by ordinal. Preserve the thunk.
                    by_ordinal = bool(getattr(symbol, "import_by_ordinal", symbol.name is None))
                    row = {"kind": kind, "dll": descriptor.dll.decode("ascii").lower(),
                           "symbol": f"#{symbol.ordinal}" if by_ordinal else symbol.name.decode("ascii")}
                    if by_ordinal and symbol.name:
                        row["ordinal_name_hint"] = symbol.name.decode("ascii")
                    imports.append(row)
        exports = {}
        for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            forwarder = symbol.forwarder.decode("ascii") if symbol.forwarder else None
            exports[f"#{symbol.ordinal}"] = forwarder
            if symbol.name:
                exports[symbol.name.decode("ascii")] = forwarder
        opt = pe.OPTIONAL_HEADER
        dirs = {name: {"rva": opt.DATA_DIRECTORY[idx].VirtualAddress, "size": opt.DATA_DIRECTORY[idx].Size}
                for name, idx in (("tls", 9), ("load_config", 10), ("delay_import", 13))}
        return {"path": path.relative_to(tree).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size,
                "machine": f"0x{pe.FILE_HEADER.Machine:04x}", "pe_magic": f"0x{opt.Magic:04x}",
                "os_version": [opt.MajorOperatingSystemVersion, opt.MinorOperatingSystemVersion],
                "subsystem_version": [opt.MajorSubsystemVersion, opt.MinorSubsystemVersion],
                "subsystem": opt.Subsystem, "dll_characteristics": f"0x{opt.DllCharacteristics:04x}",
                "directories": dirs, "imports": imports, "exports": exports}
    finally:
        pe.close()


def inspect_tree(tree: Path) -> list[dict]:
    records = []
    for path in sorted(tree.rglob("*")):
        if path.is_file() and path.suffix.lower() in (".exe", ".dll"):
            records.append(pe_record(path, tree))
    return records


def static_closure(images: list[dict], runtime_images: list[dict]) -> dict:
    """Report exact export presence. Do not invent API-set aliases or semantics."""
    app = {}
    runtime = {}
    for image in images:
        app.setdefault(PurePosixPath(image["path"]).name.lower(), []).append(image)
    for image in runtime_images:
        runtime.setdefault(PurePosixPath(image["path"]).name.lower(), []).append(image)
    misses = []
    present = 0
    deferred = 0
    for image in images:
        for imp in image["imports"]:
            candidates = app.get(imp["dll"], []) or runtime.get(imp["dll"], [])
            same_machine = [candidate for candidate in candidates if candidate["machine"] == image["machine"]]
            exported = [candidate for candidate in same_machine if imp["symbol"] in candidate["exports"]]
            if exported:
                # A forwarder requires another lookup, so do not count it as a bound function.
                forwarders = [candidate["exports"][imp["symbol"]] for candidate in exported]
                if all(forwarder is not None for forwarder in forwarders):
                    deferred += 1
                    misses.append({"image": image["path"], **imp, "reason": "forwarder_requires_resolution",
                                   "forwarders": forwarders})
                else:
                    present += 1
            else:
                if not candidates:
                    reason = "api_set_requires_loader_mapping" if imp["dll"].startswith(("api-ms-", "ext-ms-")) else "module_missing"
                elif not same_machine:
                    reason = "architecture_mismatch"
                else:
                    reason = "export_missing"
                misses.append({"image": image["path"], **imp, "reason": reason})
    return {"evidence_kind": "host PE static inspection", "export_names_present": present,
            "forwarder_lookups_deferred": deferred, "unresolved_imports": misses,
            "runtime_modules_inspected": len(runtime_images), "guest_startup_verified": False,
            "steam_desktop_functionality_verified": False,
            "limits": ["Import name presence is not behavior; dynamic GetProcAddress and runtime dependencies remain.",
                       "API-set mappings and forwarded exports need the actual loader; they are reported unresolved.",
                       "Duplicate module names are candidates, not proof of an actual Windows DLL search path."]}


def write_json(path: Path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True, help="unique ignored build directory")
    ap.add_argument("--manifest", type=Path, help="use a saved Valve win64 manifest; otherwise read official HTTPS")
    ap.add_argument("--packages", nargs="+", default=list(CORE_PACKAGES))
    ap.add_argument("--download", action="store_true", help="download, hash-verify and extract selected packages")
    ap.add_argument("--all-packages", action="store_true", help="select every top-level win64 package")
    ap.add_argument("--tree", type=Path, help="inspect an already extracted tree without downloading")
    ap.add_argument("--runtime", type=Path, help="compare against existing built runtime DLLs, read-only")
    args = ap.parse_args(argv)
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / "build").resolve()):
        ap.error("Steam publisher archives and receipts must remain in ignored build/")
    out.mkdir(parents=True, exist_ok=True)
    if args.manifest:
        raw = args.manifest.read_bytes()
        manifest_url = CDN + "steam_client_win64"
        manifest_read_from = str(args.manifest.resolve())
    else:
        manifest_url = CDN + "steam_client_win64"
        manifest_read_from = "publisher HTTPS"
        with checked_open(manifest_url) as response:
            raw = response.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError("manifest exceeds 128 KiB")
    manifest = parse_vdf(raw.decode("utf-8"))
    names = ([name for name, value in manifest["win64"].items()
              if isinstance(value, dict) and "file" in value] if args.all_packages else args.packages)
    specs = package_specs(manifest, names)
    (out / "steam_client_win64.manifest").write_bytes(raw)
    receipt = {"evidence_kind": "publisher manifest", "manifest_url": manifest_url, "manifest_read_from": manifest_read_from,
               "manifest_sha256": hashlib.sha256(raw).hexdigest(), "client_version": manifest["win64"]["version"],
               "publisher_os_type": manifest["win64"].get("ostype"),
               "retrieved_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "packages": specs,
               "download_bytes": sum(spec["size"] for spec in specs), "downloaded": False,
               "signature_verification": "not performed; inspect manifest_read_from for source; downloaded package SHA-256 verified",
               "guest_startup_verified": False, "steam_desktop_functionality_verified": False}
    write_json(out / "receipt.json", receipt)
    tree = args.tree
    if args.download:
        if tree:
            ap.error("--download and --tree are mutually exclusive")
        # Leave 1 GiB for host/session work beyond the maximum selected expansion.
        need = receipt["download_bytes"] + MAX_EXPANDED + 1024 * 1024 * 1024
        if shutil.disk_usage(out).free < need:
            raise ValueError(f"at least {need} free bytes required for bounded acquisition")
        paths = []
        for spec in specs:
            print(f"verifying {spec['name']} ({spec['size']} bytes)", flush=True)
            paths.append(download_package(spec, out / "archives"))
        tree = out / "client"
        files = extract_packages(paths, tree, specs)
        write_json(out / "files.json", files)
        receipt.update(downloaded=True, files=len(files), expanded_bytes=sum(row["bytes"] for row in files), tree=str(tree))
        write_json(out / "receipt.json", receipt)
    if tree:
        images = inspect_tree(tree)
        runtime_images = inspect_tree(args.runtime) if args.runtime else []
        write_json(out / "pe-images.json", images)
        closure = static_closure(images, runtime_images)
        write_json(out / "static-closure.json", closure)
        print(f"inspected {len(images)} desktop PE images; {len(closure['unresolved_imports'])} unresolved import rows")
    print(f"Valve win64 client {receipt['client_version']}; receipt: {out / 'receipt.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
