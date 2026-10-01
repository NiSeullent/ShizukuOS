#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare a pinned VLC Qt/local-media trial; never install or run guest code.

An export/table match is an availability candidate, not API behavior or native
application acceptance. Missing imports remain explicit in the receipt.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import re
import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath

import pefile

ROOT = Path(__file__).resolve().parents[1]
PIN = "8511356afd680817f3aea624c63032d0936f3d77b2175fb36c8fc16adf9744e8"
NPP_INPUT_PIN = "320154579f0d7be06a907225944d008ec45759d01682cba7cd558b1e1ef63561"
PREFIX = "vlc-3.0.24/"
FILE_LOGGER = "plugins/logger/libfile_logger_plugin.dll"
FILE_LOGGER_PIN = "d7ba17e37a9b494c58748c69f144f17f641f4cf34806eeae650d2b1b785f6644"
# This is a bounded Qt GUI and uncompressed local AVI/PCM-WAV profile. The
# original application's remaining codecs, network and GPU paths are not staged.
SELECTED = (
    "vlc.exe", "libvlc.dll", "libvlccore.dll", "COPYING.txt", "README.txt",
    "plugins/gui/libqt_plugin.dll", "plugins/access/libfilesystem_plugin.dll",
    "plugins/demux/libavi_plugin.dll", "plugins/demux/libwav_plugin.dll",
    "plugins/codec/librawvideo_plugin.dll", "plugins/codec/libaraw_plugin.dll",
    "plugins/video_output/libwingdi_plugin.dll",
    "plugins/video_chroma/libswscale_plugin.dll", "plugins/video_chroma/librv32_plugin.dll",
    "plugins/audio_output/libwaveout_plugin.dll",
    "plugins/audio_filter/libaudio_format_plugin.dll",
    "plugins/audio_filter/libtrivial_channel_mixer_plugin.dll",
    "plugins/audio_filter/libugly_resampler_plugin.dll",
    "plugins/audio_mixer/libfloat_mixer_plugin.dll",
    "plugins/audio_mixer/libinteger_mixer_plugin.dll",
    "plugins/stream_filter/libcache_read_plugin.dll",
    "plugins/stream_filter/libprefetch_plugin.dll", FILE_LOGGER,
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def logging_profile(selected: dict[str, bytes]) -> dict:
    """Bind the real option-owning module, rather than the obsolete interface.

    VLC 3.0.24 modules/logger/file.c registers file-logging and logfile;
    modules/misc/logger.c only reports that its old interface no longer exists.
    The native watcher supplies both options before the core logger starts.
    """
    raw = selected.get(FILE_LOGGER)
    if raw is None or sha(raw) != FILE_LOGGER_PIN:
        raise ValueError("exact official file-logging option plugin required")
    return {"member": FILE_LOGGER, "sha256": FILE_LOGGER_PIN,
            "required_options": ["file-logging", "logfile"],
            "upstream_source": "https://raw.githubusercontent.com/videolan/vlc/3.0.24/modules/logger/file.c",
            "native_option_registration_verified": False}


def file_record(path: Path) -> dict:
    raw = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(raw), "sha256": sha(raw)}


def archive_members(archive: zipfile.ZipFile) -> dict:
    """Reject ambiguous or escaping names before any selected file is written."""
    result, folded, total = {}, set(), 0
    infos = archive.infolist()
    if len(infos) > 2048:
        raise ValueError("archive member bound")
    for item in infos:
        name = item.filename
        path = PurePosixPath(name)
        if (not name.startswith(PREFIX) or "\\" in name or path.is_absolute()
                or any(p in (".", "..") for p in name.rstrip("/").split("/"))
                or "//" in name or len(name) > 240 or "\x00" in name):
            raise ValueError("archive member path")
        if name.upper() in folded:
            raise ValueError("case-colliding archive members")
        folded.add(name.upper())
        mode = item.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError("archive link or special member")
        if item.flag_bits & 1 or item.file_size > 32 * 1024**2:
            raise ValueError("encrypted or oversized archive member")
        total += item.file_size
        if total > 512 * 1024**2:
            raise ValueError("archive expansion bound")
        result[name] = item
    return result


def linked_kex_tables(raw: bytes, local_functions: bool = False, indexed: bool = False) -> dict | list:
    """Read compiled KernelEx tables without executing get_api_table or its init."""
    with pefile.PE(data=raw) as pe:
        if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
            raise ValueError("KernelEx table image must be PE32 x86")
        base = pe.OPTIONAL_HEADER.ImageBase

        def read(va: int, size: int) -> bytes:
            rva = va - base
            for section in pe.sections:
                off = rva - section.VirtualAddress
                if 0 <= off <= section.SizeOfRawData and size <= section.SizeOfRawData - off:
                    start = section.PointerToRawData + off
                    if start + size <= len(raw):
                        return raw[start:start + size]
            raise ValueError("KernelEx table pointer outside file-backed section")

        def string(va: int) -> str:
            chars = bytearray()
            for i in range(256):
                char = read(va + i, 1)[0]
                if char == 0:
                    if not chars:
                        raise ValueError("empty KernelEx table string")
                    return chars.decode("ascii")
                if char < 32 or char >= 127:
                    raise ValueError("invalid KernelEx table string")
                chars.append(char)
            raise ValueError("unterminated KernelEx table string")

        def function(va: int) -> None:
            if not local_functions:
                return
            rva = va - base
            if not any(section.Characteristics & 0x20000000 and
                       0 <= rva - section.VirtualAddress < section.SizeOfRawData
                       for section in pe.sections):
                raise ValueError("new provider API target outside local executable section")
            read(va, 1)

        exports = [s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"get_api_table"]
        if len(exports) != 1 or exports[0].forwarder:
            raise ValueError("unique local get_api_table export required")
        code = read(base + exports[0].address, 16)
        # Pinned original DLLs call their table initializer before returning the
        # static pointer; source-built project DLLs return the pointer directly.
        at = 5 if code[0] == 0xE8 else 0
        if code[at] != 0xB8 or code[at + 5] != 0xC3:
            raise ValueError("unrecognized static table-return function")
        table = struct.unpack_from("<I", code, at + 1)[0]
        initialized = []
        if at:
            # Original MSVC KernelEx constructs the BSS table by copying each
            # constant 20-byte descriptor. Decode only this exact finite copy
            # sequence; no target instruction or initializer is executed.
            delta = struct.unpack_from("<i", code, 1)[0]
            init = base + exports[0].address + 5 + delta
            if read(init, 2) != b"\x56\x57":
                raise ValueError("unrecognized KernelEx table initializer prologue")
            cursor = init + 2
            for index in range(128):
                if read(cursor, 3) == b"\x5f\x5e\xc3":
                    break
                copy = read(cursor, 17)
                if copy[:5] != b"\xb9\x05\0\0\0" or copy[5] != 0xBE or copy[10] != 0xBF or copy[15:] != b"\xf3\xa5":
                    raise ValueError("unrecognized KernelEx descriptor-copy instructions")
                source, destination = struct.unpack_from("<I", copy, 6)[0], struct.unpack_from("<I", copy, 11)[0]
                if destination != table + index * 20:
                    raise ValueError("noncontiguous KernelEx table copy destination")
                initialized.append(read(source, 20))
                cursor += 17
            else:
                raise ValueError("KernelEx initializer instruction bound")
            # The trailing descriptor must be actual loader-zeroed BSS, not
            # an assumed table terminator over arbitrary image memory.
            terminator_rva = table - base + len(initialized) * 20
            zeroed = False
            for section in pe.sections:
                off = terminator_rva - section.VirtualAddress
                if section.SizeOfRawData <= off and off + 20 <= section.Misc_VirtualSize:
                    zeroed = True
            if not initialized or not zeroed:
                raise ValueError("KernelEx table has no proven zeroed BSS terminator")
            initialized.append(bytes(20))
        result, tables = {}, []
        for index in range(128):
            descriptor = initialized[index] if initialized else read(table + index * 20, 20)
            library, names, count, ordinals, ordcount = struct.unpack("<IIIII", descriptor)
            if not library:
                if any((names, count, ordinals, ordcount)):
                    raise ValueError("incomplete table terminator")
                return tables if indexed else result
            if count > 8192 or ordcount > 8192:
                raise ValueError("KernelEx API count bound")
            target_library = string(library)
            module = target_library.upper()
            if not module.endswith(".DLL"):
                module += ".DLL"
            catalog = result.setdefault(module, set())
            named_values, ordinal_values = [], []
            for n in range(count):
                name, address = struct.unpack("<II", read(names + n * 8, 8))
                if indexed and not address:
                    raise ValueError("indexed KernelEx metadata cannot omit a null named variant")
                if address:
                    function(address)
                    value = string(name)
                    catalog.add(value)
                    named_values.append(value)
            for n in range(ordcount):
                ordinal, address = struct.unpack("<II", read(ordinals + n * 8, 8))
                if indexed and not address:
                    raise ValueError("indexed KernelEx metadata cannot omit a null ordinal variant")
                if address:
                    function(address)
                    value = ordinal & 0xFFFF
                    catalog.add("#" + str(value))
                    ordinal_values.append(value)
            if local_functions and not indexed and (len(set(named_values)) != len(named_values) or
                                    len(set(ordinal_values)) != len(ordinal_values)):
                raise ValueError("duplicate new provider API symbol")
            if indexed and (named_values != sorted(named_values) or ordinal_values != sorted(ordinal_values)):
                raise ValueError("KernelEx API variants must retain sorted declaration order")
            tables.append({"index": index, "module": module,
                           "target_library": target_library,
                           "names": named_values, "ordinals": ordinal_values})
        raise ValueError("KernelEx table terminator absent")


def provider_inputs(receipt_path: Path) -> tuple:
    """Read source-bound new providers, keeping availability distinct from behavior."""
    receipt_path = receipt_path.resolve(strict=True)
    if not receipt_path.is_relative_to(ROOT / "build"):
        raise ValueError("isolated repository provider build required")
    document = json.loads(receipt_path.read_text())
    if (document.get("schema") != "win98modern.vlc-prerequisite-build.v1" or
            document.get("status") != "PASS" or document.get("native_execution") is not False or
            document.get("application_success") is not False):
        raise ValueError("source-bound compile-only provider receipt required")
    for name, pin in document["sources"].items():
        current = ROOT / name
        frozen = receipt_path.parent / "frozen" / name
        if not current.resolve().is_relative_to(ROOT) or sha(current.read_bytes()) != pin or sha(frozen.read_bytes()) != pin:
            raise ValueError("current/frozen provider source changed")
    files, catalog, sources = {}, {}, []
    for name, item in document["artifacts"].items():
        if name not in ("M98VLC.DLL", "M98LOC.DLL", "M98CTX.DLL"):
            continue
        path = Path(item["path"]).resolve(strict=True)
        raw = path.read_bytes()
        if (path != receipt_path.parent / name or len(raw) != item["bytes"] or sha(raw) != item["sha256"] or
                item.get("native_import_gate") != "PASS" or item.get("native_execution") is not False):
            raise ValueError("exact native import-gated provider artifact changed")
        files["PROVIDE/" + name] = raw
        for module, names in linked_kex_tables(raw, local_functions=True).items():
            catalog.setdefault(module, set()).update(names)
        sources.append(file_record(path))
    if not files:
        raise ValueError("no new VLC provider in build receipt")
    return files, catalog, sources, file_record(receipt_path)


def riff_chunk(tag: bytes, data: bytes) -> bytes:
    return tag + struct.pack("<I", len(data)) + data + (b"\0" if len(data) & 1 else b"")


def avi_fixture() -> bytes:
    """Thirty-second standard uncompressed AVI with changing colored bars."""
    width, height, fps, frames = 160, 120, 2, 60
    size = width * height * 3
    avih = struct.pack("<14I", 1000000 // fps, size * fps, 0, 0x10, frames, 0, 1, size, width, height, 0, 0, 0, 0)
    strh = struct.pack("<4s4sIHH8I4h", b"vids", b"DIB ", 0, 0, 0, 0, 1, fps, 0, frames, size, 0xFFFFFFFF, 0, 0, 0, width, height)
    strf = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, size, 0, 0, 0, 0)
    hdrl = riff_chunk(b"LIST", b"hdrl" + riff_chunk(b"avih", avih) + riff_chunk(b"LIST", b"strl" + riff_chunk(b"strh", strh) + riff_chunk(b"strf", strf)))
    movi, index = bytearray(b"movi"), bytearray()
    for frame in range(frames):
        position = frame * width // frames
        pixels = bytearray()
        for y in range(height):
            for x in range(width):
                pixels += bytes((32, 180, 240)) if x <= position else bytes((120, 40, 24))
        index += struct.pack("<4sIII", b"00db", 0x10, len(movi), size)
        movi += riff_chunk(b"00db", bytes(pixels))
    return riff_chunk(b"RIFF", b"AVI " + hdrl + riff_chunk(b"LIST", bytes(movi)) + riff_chunk(b"idx1", bytes(index)))


def wav_fixture() -> bytes:
    rate, seconds = 22050, 5
    samples = b"".join(struct.pack("<h", int(6000 * math.sin(2 * math.pi * 440 * i / rate))) for i in range(rate * seconds))
    fmt = struct.pack("<HHIIHH", 1, 1, rate, rate * 2, 2, 16)
    return riff_chunk(b"RIFF", b"WAVE" + riff_chunk(b"fmt ", fmt) + riff_chunk(b"data", samples))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "benchmarks/media/vlc-3.0.24/vlc-3.0.24-win32.zip")
    parser.add_argument("--checksum", type=Path, default=ROOT / "benchmarks/media/vlc-3.0.24/vlc-3.0.24-win32.zip.sha256")
    parser.add_argument("--native-exports", type=Path, required=True)
    parser.add_argument("--kex-readback", type=Path, default=ROOT / "build/native-npp-controls/installed-core-20260930T1630/result.json")
    parser.add_argument("--prerequisites", type=Path, default=ROOT / "build/app-prerequisites-20260930/latest-npp-inputs/manifest.json")
    parser.add_argument("--provider-build", type=Path, action="append", default=[],
                        help="Additional source-bound VLC DLLs; compiled API tables are availability candidates only")
    parser.add_argument("--lab-root", choices=("NPPLAB", "VLCLAB"), default="NPPLAB",
                        help="An explicitly allowed new private tree; existing trees must remain absent before staging")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("use a new isolated repository build output")
    archive = args.archive.read_bytes()
    if sha(archive) != PIN or args.checksum.read_text("ascii").split()[0].lower() != PIN:
        parser.error("official archive/publisher/target hash mismatch")
    receipts = [file_record(p) for p in (args.native_exports, args.kex_readback, args.prerequisites,
                                        ROOT / "benchmarks/media/vlc-3.0.24/metadata.json")]
    native_doc = json.loads(args.native_exports.read_text())
    if native_doc.get("status") != "PASS" or native_doc.get("schema") != "win98modern.native-system-export-readback.v1":
        parser.error("successful actual system export readback required")
    native = {}
    frozen = [file_record(Path(__file__))]
    for item in native_doc["modules"]:
        record = file_record(Path(item["path"]))
        if record["sha256"] != item["sha256"]:
            parser.error("native system readback changed")
        with pefile.PE(data=Path(item["path"]).read_bytes()) as pe:
            native[item["module"].upper()] = {s.name.decode("ascii") if s.name else "#" + str(s.ordinal) for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}
        frozen.append(record)
    kex = {}
    for item in json.loads(args.kex_readback.read_text())["readback"]:
        if Path(item["host"]).name not in ("KEXBASES.DLL", "KEXBASEN.DLL"):
            continue
        raw = Path(item["host"]).read_bytes()
        if sha(raw) != item["sha256"] or item["returncode"]:
            parser.error("installed KernelEx readback changed")
        for module, names in linked_kex_tables(raw).items():
            kex.setdefault(module, set()).update(names)
        frozen.append(file_record(Path(item["host"])))
    if sha(args.prerequisites.read_bytes()) != NPP_INPUT_PIN:
        parser.error("frozen prerequisite manifest changed")
    prerequisite_files = {}
    for item in json.loads(args.prerequisites.read_text())["inputs"]:
        if "\\PROVIDE\\" not in item["guest"] and "\\SETUP\\" not in item["guest"]:
            continue
        raw = Path(item["source"]).read_bytes()
        if sha(raw) != item["sha256"] or len(raw) != item["bytes"]:
            parser.error("frozen prerequisite input changed")
        relative = item["guest"][len("C:\\NPPLAB\\"):].replace("\\", "/")
        prerequisite_files[relative] = raw
        if relative.startswith("PROVIDE/M98"):
            for module, names in linked_kex_tables(raw).items():
                kex.setdefault(module, set()).update(names)
        frozen.append(file_record(Path(item["source"])))
    vlc_providers = {}
    for build_receipt in args.provider_build:
        files, catalog, sources, receipt = provider_inputs(build_receipt)
        if set(files) & set(prerequisite_files):
            raise ValueError("duplicate additional provider would overwrite a frozen prerequisite")
        prerequisite_files.update(files)
        for module, names in catalog.items():
            vlc_providers.setdefault(module, set()).update(names)
        frozen.extend(sources)
        receipts.append(receipt)
    with zipfile.ZipFile(args.archive) as z:
        members = archive_members(z)
        selected = {name: z.read(members[PREFIX + name]) for name in SELECTED}
    logging = logging_profile(selected)
    images, bundled, inventory, unresolved = {}, {}, [], []
    for name, raw in selected.items():
        if not name.lower().endswith((".dll", ".exe")):
            continue
        pe = pefile.PE(data=raw)
        if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
            raise ValueError("selected VLC image is not PE32 x86")
        images[name] = pe
        bundled[Path(name).name.upper()] = {s.name.decode("ascii") if s.name else "#" + str(s.ordinal) for s in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", ())}
    for name, pe in images.items():
        imports = []
        for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            module = d.dll.decode("ascii").upper()
            for entry in d.imports:
                symbol = entry.name.decode("ascii") if entry.name else "#" + str(entry.ordinal)
                source = "bundled-export" if symbol in bundled.get(module, ()) else "actual-Win98-export" if symbol in native.get(module, ()) else "linked-KernelEx-table-candidate" if symbol in kex.get(module, ()) else "linked-VLC-provider-candidate" if symbol in vlc_providers.get(module, ()) else "unresolved"
                item = {"dll": module, "symbol": symbol, "availability": source}
                imports.append(item)
                if source == "unresolved":
                    unresolved.append({"image": name, **item})
        opt = pe.OPTIONAL_HEADER
        inventory.append({"image": name, "bytes": len(selected[name]), "sha256": sha(selected[name]),
                          "subsystem_version": [opt.MajorSubsystemVersion, opt.MinorSubsystemVersion],
                          "runtime_directories": {str(i): {"rva": opt.DATA_DIRECTORY[i].VirtualAddress, "bytes": opt.DATA_DIRECTORY[i].Size} for i in (9, 10, 13, 14)},
                          "imports": imports})
        pe.close()
    payload = {"VLC/" + name: raw for name, raw in selected.items()} | prerequisite_files
    payload.update({"MEDIA/VIDEO.AVI": avi_fixture(), "MEDIA/TONE.WAV": wav_fixture()})
    if len(payload) > 512 or sum(map(len, payload.values())) > 128 * 1024**2 or any(not 0 < len(raw) <= 32 * 1024**2 for raw in payload.values()):
        raise ValueError("existing application stager input bound exceeded")
    # Recheck every byte-frozen source before the first output effect.
    for item in frozen + receipts:
        if sha(Path(item["path"]).read_bytes()) != item["sha256"]:
            raise ValueError("input changed during preparation")
    out.mkdir(parents=True)
    frozen_tool = out / "frozen/tools/prepare_vlc_staging.py"
    frozen_tool.parent.mkdir(parents=True)
    frozen_tool.write_bytes(Path(__file__).read_bytes())
    inputs = []
    for name, raw in payload.items():
        path = out / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        inputs.append({"source": str(path), "guest": "C:\\" + args.lab_root + "\\" + name.replace("/", "\\"), "bytes": len(raw), "sha256": sha(raw)})
    result = {"schema": "win98modern.vlc-local-preparation.v1", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "PREPARED-WITH-UNRESOLVED-IMPORTS" if unresolved else "PREPARED-IMPORT-CANDIDATES",
              "native_execution": False, "application_success": False, "publisher_archive_sha256": PIN,
              "lab_root": args.lab_root,
              "source_inputs": frozen, "source_receipts": receipts, "selected_images": inventory,
              "additional_provider_tables": {module: sorted(names) for module, names in vlc_providers.items()},
              "logging_profile": logging,
              "unresolved_static_imports": unresolved, "input_files": len(inputs), "input_bytes": sum(i["bytes"] for i in inputs),
              "limitations": ["Availability does not prove API behavior or configured VLC/Qt KernelEx routing.",
                              "Dynamic GetProcAddress/LoadLibrary paths and native TLS/CRT behavior require guest execution.",
                              "Qt GUI + local uncompressed AVI/PCM-WAV profile only; no codec/network/GPU acceleration claim.",
                              "Fresh selected private tree on a new owned clone; installed prerequisites and guarded VLC module modes require separate evidence."]}
    result_path = out / "result.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    manifest = {"schema": 1, "kind": "isolated-native-application-inputs", "application": "VLC3.0.24 x86 Qt/local-media bounded trial",
                "lab_root": args.lab_root,
                "staging_prefix": args.lab_root,
                "upstream_archive": file_record(args.archive), "inputs": inputs,
                "source_receipts": receipts + [file_record(result_path)],
                "outputs": [],
                "expected_manual_outputs": [{"guest": "C:\\" + args.lab_root + "\\VLC.LOG", "max_bytes": 1048576,
                                             "scope": "Read from the quiescent private trial; assets-only stager collects no application output"}],
                "prerequisites_installed": False, "application_launched": False, "application_success": False}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "files": len(inputs), "bytes": result["input_bytes"], "unresolved_imports": len(unresolved), "receipt": str(result_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
