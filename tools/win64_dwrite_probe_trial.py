#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bound genuine private AMD64 DirectWrite/Latin/Korean acceptance.

Consumes immutable existing runtime bytes and the publisher-bound private font
corpus. Does not acquire assets, register host fonts, change peers or native VMs.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import uuid

import pefile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ntwddm/win64/dwrite_probe/probe.c"
EXE, VOLUME, APP = "DWRITEP64.EXE", "dwriteprobe", "private_dwrite_probe"
GUEST_TIMEOUT = 45
IMAGE_BYTES = 64 * 1024**2


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = load("private_dwrite_common", ROOT / "tools/win64_theme_probe_trial.py")
theme = common.overlay
handoff = common.handoff
font_corpus = load("private_dwrite_font_corpus", ROOT / "tools/dwrite_font_corpus.py")
require, digest = common.require, common.digest
RUNTIME_SOURCES = common.WAIT_SOURCES + ("shizukudos/kernel64/standalone/standalone64.c", "shizukudos/kcommon/standalone_dev.h")
FALSE_FLAGS = {"windows98_execution_verified": False, "directwrite_full_support_verified": False,
               "app_functionality_verified": False, "system_korean_font_fallback_verified": False,
               "os_wide_directwrite_verified": False, "direct2d_integration_verified": False}
MANDATORY = (
    "load_actual_archive_dwrite", "actual_dwrite_create_factory_export", "real_isolated_dwrite_factory",
    "factory_iunknown_identity", "factory_balanced_addref_release", "system_font_collection",
    "private_korean_latin_glyph_indices", "all_nine_glyph_ids_match_independent_publisher_cmap",
    "private_face_units_and_glyph_count_identity", "all_nine_advance_and_bearing_metrics_match_independent_hmtx",
    "actual_korean_glyph_run_analysis", "actual_korean_alpha_texture", "actual_korean_alpha_coverage",
    "korean_alpha_buffer_guards_unchanged", "release_actual_enumerator_allocation",
    "private_loader_factory_and_key_binding",
    "release_owned_alpha_buffer", "actual_private_custom_font_collection", "actual_private_family_name_identity",
    "real_private_face_outlives_original_file_reference", "private_collection_text_format",
    "actual_korean_layout_draw", "actual_latin_layout_draw", "actual_korean_dib_ink_coverage",
    "actual_latin_dib_ink_coverage", "all_layout_glyphs_use_exact_private_face_without_missing_glyphs",
    "all_korean_layout_positions_match_independent_cmap", "all_latin_layout_positions_match_independent_cmap",
    "release_renderer_owner_reference", "release_final_private_loader_reference",
    "release_final_bitmap_target_reference", "release_final_rendering_params_reference", "release_final_text_format_reference",
    "renderer_balanced_com_references", "independent_getpixel_matches_all_readback_samples",
    "all_49152_visible_pixels_match_real_directwrite_dib", "destroy_visible_window", "unregister_visible_class",
    "unregister_private_collection_loader", "all_private_loader_and_enumerator_refs_released",
    "delete_owned_readback_dib", "delete_owned_readback_dc", "release_final_isolated_factory_reference",
    "unload_actual_dwrite", "final_relocated_probe_anchor", "complete_console_writes",
)


def sources():
    paths = [SOURCE, Path(__file__).resolve(), ROOT / "tools/win64_theme_probe_trial.py",
             ROOT / "tools/required_theme_runtime.py", ROOT / "tools/required_app_runtime_handoff.py",
             ROOT / "tools/signal_desktop_corpus.py", ROOT / "tools/modern_app_inventory.py",
             ROOT / "tools/dwrite_font_corpus.py", ROOT / "tests/test_win64_dwrite_probe_trial.py", ROOT / "LICENSE",
             ROOT / "shizukudos/win64/wineport/modules.json",
             ROOT / "shizukudos/win64/wineport/patches/wine/0004-dwrite-static-freetype-and-font-registration.patch"]
    return {str(p.relative_to(ROOT)): digest(p) for p in paths}


def bound_file(path):
    data = theme.inventory.read_regular(path)
    return {"path": str(path.resolve(strict=True)), "bytes": len(data), "sha256": digest(path)}


def corpus_overlay_binding(receipt, overlay_path, runtime):
    historical = receipt["baseline_overlay"]
    old_path = Path(historical["path"]).resolve(strict=True)
    require(old_path.is_relative_to(ROOT / "build") and digest(old_path) == historical["sha256"], "historical corpus overlay receipt changed")
    old = handoff.read_json(old_path)
    require(old.get("schema") == 1 and old.get("stage") == "private-kernel64-theme-overlay" and old.get("status") == "PREPARED",
            "historical corpus overlay identity changed")
    expected = receipt["baseline_archive_sha256"]
    require(old["archive"]["sha256"] == runtime["archive"]["sha256"] == expected,
            "corpus and current runtime actual archive identities differ")
    for archive_row in (old["archive"], runtime["archive"]):
        actual = bound_file(Path(archive_row["path"]))
        require(actual["sha256"] == expected and actual["bytes"] == archive_row["bytes"], "historical/current archive bytes changed")
    # This consumes the old corpus as immutable font-table evidence only. The
    # current overlay is separately validated against all its current inputs;
    # this does not revive the old overlay's changed live packer-source gate.
    return {"historical_font_corpus_overlay":historical,"current_overlay":bound_file(overlay_path),
            "exact_unchanged_archive_sha256":expected,"historical_overlay_live_source_gate_revalidated":False}


def verified_corpus(path, overlay_path, runtime):
    path = path.resolve(strict=True)
    require(path.is_relative_to(ROOT / "build"), "font corpus must be in own immutable build")
    receipt = handoff.read_json(path)
    require(receipt.get("schema") == 1 and receipt.get("status") == "PASS" and receipt.get("license") == "OFL-1.1",
            "successful immutable publisher font corpus required")
    require(receipt["publisher_commit"] == font_corpus.COMMIT and receipt["repository"] == font_corpus.REPOSITORY,
            "unexpected publisher identity")
    require(receipt["recipe_sha256"] == digest(ROOT / "tools/dwrite_font_corpus.py"), "font recipe changed")
    corpus_overlay_binding(receipt, overlay_path, runtime)
    require(receipt.get("fonts_installed") is False and receipt.get("fonts_registered") is False,
            "private, uninstalled corpus required")
    require(len(receipt["assets"]) == len(font_corpus.ASSETS), "all font/license/readme bindings required")
    for row, expected in zip(receipt["assets"], font_corpus.ASSETS):
        p = Path(row["path"]).resolve(strict=True)
        require(p.parent == path.parent and (row["publisher_path"], row["bytes"], row["git_blob_sha1"]) == expected,
                "publisher asset identity/path differs")
        data = theme.inventory.read_regular(p)
        require(len(data) == row["bytes"] and digest(p) == row["sha256"], "font or notice bytes changed")
        require(font_corpus.hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["git_blob_sha1"],
                "font or notice publisher Git object differs")
    require("SIL OPEN FONT LICENSE Version 1.1" in Path(receipt["assets"][1]["path"]).read_text(), "OFL notice absent")
    profile = font_corpus.font_profile(Path(receipt["assets"][0]["path"]).read_bytes())
    require(profile == receipt["font_profile"] and profile["hangul_syllables"] == 11172,
            "independently parsed font profile differs")
    fonts = [(n, data) for n, data in theme.parse_archive(Path(runtime["archive"]["path"]).read_bytes())
             if n.lower().endswith((".ttf", ".otf"))]
    require(len(fonts) == 5 and len(receipt["baseline_fonts"]) == 5, "actual five baseline fonts required")
    for (name, data), row in zip(fonts, receipt["baseline_fonts"]):
        require(row == {"path": name, "sha256": font_corpus.digest(data), "bytes": len(data),
                        "profile": font_corpus.font_profile(data)}, "baseline actual font/profile differs")
        require(row["profile"]["hangul_syllables"] == 0, "unexpected baseline Korean coverage")
    return receipt


def layout_oracle(corpus):
    with font_corpus.TTFont(font_corpus.BytesIO(Path(corpus["assets"][0]["path"]).read_bytes())) as font:
        cmap=font.getBestCmap()
        def row(character):
            glyph=cmap.get(ord(character)); require(glyph is not None,"layout character missing from immutable publisher cmap")
            return {"codepoint":ord(character),"glyph_id":font.getGlyphID(glyph)}
        return {"latin":[row(c) for c in "AB"],"korean":[row(c) for c in "\ud55c\uae00 \ud604\ub300 \ubaa8\ub358"]}


def font_header(nonce, corpus):
    rows = corpus["font_profile"]["design_metrics"]
    require(len(rows) == 9 and all(row["glyph_id"] for row in rows), "exact independently parsed test glyphs required")
    array = lambda values: "{" + ",".join(str(v) for v in values) + "}"
    out = ['#define TRIAL_NONCE "' + nonce + '"', '#define EXPECTED_UNITS ' + str(corpus["font_profile"]["units_per_em"]),
           '#define EXPECTED_GLYPHS ' + str(corpus["font_profile"]["glyph_count"]), '#define BASELINE_COUNT 5']
    for ctype, name, key in (("UINT32", "expected_codepoints", "codepoint"), ("UINT16", "expected_glyphs", "glyph_id"),
                              ("UINT32", "expected_advances", "advance_width"), ("INT32", "expected_bearings", "left_side_bearing")):
        out.append("static const " + ctype + " " + name + "[9]=" + array(row[key] for row in rows) + ";")
    for name, layout in layout_oracle(corpus).items():
        out.append("static const UINT16 expected_"+name+"_layout["+str(len(layout))+"]="+array(row["glyph_id"] for row in layout)+";")
    baseline = corpus["baseline_fonts"]
    # Archive path is mounted under C:, while the new CJK font stays on D:.
    out.append('static const WCHAR *const baseline_paths[5]={' + ','.join('L"C:' + row["path"].replace('\\','\\\\') + '"' for row in baseline) + '};')
    for name, key in (("baseline_units", "units_per_em"), ("baseline_glyph_counts", "glyph_count")):
        out.append("static const UINT32 " + name + "[5]=" + array(row["profile"][key] for row in baseline) + ";")
    for name, key in (("baseline_latin_glyphs", "glyph_id"), ("baseline_advances", "advance_width")):
        out.append("static const UINT32 " + name + "[5][2]={" + ",".join(array(item[key] for item in row["profile"]["design_metrics"][:2]) for row in baseline) + "};")
    return "\n".join(out) + "\n"


def pe_gate(path, archive):
    gate = common.pe_gate(path, archive)
    with pefile.PE(data=theme.inventory.read_regular(path)) as pe:
        for index in (9, 10, 13, 14):
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
            require(directory.VirtualAddress == directory.Size == 0, "unexpected executable runtime directory")
        relocation = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        require(relocation.Size > 0 and getattr(pe, "DIRECTORY_ENTRY_BASERELOC", None), "parsed base relocations required")
        require(any(entry.type == 10 and pe.get_offset_from_rva(entry.rva) is not None
                    for block in pe.DIRECTORY_ENTRY_BASERELOC for entry in block.entries), "actual AMD64 DIR64 fixup required")
        require(any(s.Characteristics & 0x20000000 and s.VirtualAddress <= pe.OPTIONAL_HEADER.AddressOfEntryPoint <
                    s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections), "entry must reside in executable section")
    gate.update(parsed_dir64_relocations_verified=True, actual_entry_executable=True)
    return gate


def invoke(command, out, name, environment=None):
    handoff.check_space(out, handoff.METADATA_MARGIN)
    completed = subprocess.run(command, capture_output=True, env=environment, timeout=60)
    require(len(completed.stdout) + len(completed.stderr) <= 1024**2, "bounded preparation log exceeded")
    log = out / (name + ".log")
    log.write_bytes(completed.stdout + completed.stderr)
    require(completed.returncode == 0, name + " failed; preserved log " + str(log))
    return {"command": command, "returncode": completed.returncode, "log": bound_file(log)}


def prepare(overlay_path, corpus_path, out, nonce):
    require(common.nonce_ok(nonce), "fresh lowercase 32-hex nonce required")
    out = theme.owned_new_directory(out)
    require(out.is_relative_to(ROOT / "build"), "owned ignored build directory required")
    runtime = theme.verified_overlay(overlay_path)
    corpus = verified_corpus(corpus_path, overlay_path, runtime)
    archive = Path(runtime["archive"]["path"]).read_bytes()
    original = sources()
    productivity, peer_hashes = handoff.load_peer(Path(runtime["runtime_worktree"]))
    require(peer_hashes == runtime["runtime_source_hashes"], "frozen runtime helper differs")
    wait = {p: digest(Path(runtime["runtime_worktree"]) / p) for p in RUNTIME_SOURCES}
    handoff.check_space(out.parent, IMAGE_BYTES + 32 * 1024**2 + handoff.METADATA_MARGIN)
    out.mkdir()
    handoff.write_json(out / "attempt.json", {"schema":1,"stage":"private-amd64-dwrite-preparation-attempt","nonce":nonce,
                                             "source_hashes":original,"overlay_receipt":bound_file(overlay_path),
                                             "font_corpus_receipt":bound_file(corpus_path),"vm_started":False,**FALSE_FLAGS})
    for relative, checksum in original.items():
        target = out / "sources" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(theme.inventory.read_regular(ROOT / relative))
        require(digest(target) == checksum, "source changed during freeze")
        target.chmod(0o400)
    for relative, checksum in wait.items():
        target = out / "sources/runtime-wait" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(theme.inventory.read_regular(Path(runtime["runtime_worktree"]) / relative))
        require(digest(target) == checksum, "runtime evidence source changed during freeze")
        target.chmod(0o400)
    tree = out / "tree"; tree.mkdir()
    for row, name in zip(corpus["assets"], ("CJK.otf", "OFL.txt", "FONTREADME.md")):
        target = tree / name; target.write_bytes(theme.inventory.read_regular(Path(row["path"])))
        require(digest(target) == row["sha256"], "payload source changed during freeze")
        target.chmod(0o400)
    header = out / "trial_font.h"; header.write_text(font_header(nonce, corpus)); header.chmod(0o400)
    compiler = Path(subprocess.check_output(["which", "x86_64-w64-mingw32-gcc"], text=True).strip()).resolve(strict=True)
    executable = tree / EXE
    command = [str(compiler), "-std=c99", "-Os", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
               "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib", "-I", str(out),
               "-MD", "-MF", str(out / "compiler.d"), str(out / "sources" / SOURCE.relative_to(ROOT)),
               "-Wl,--no-insert-timestamp,--entry,DWriteProbeEntry,--subsystem,console,--nxcompat,--dynamicbase",
               "-Wl,--image-base,0x140000000", "-o", str(executable), "-lkernel32", "-luser32", "-lgdi32"]
    dependency_command = command[:command.index("-MD")]+["-M", "-MF", str(out / "compiler-before.d"),
                                                          str(out / "sources" / SOURCE.relative_to(ROOT))]
    steps = [invoke(dependency_command, out, "compiler-dependencies")]
    dependencies = (out / "compiler-before.d").read_text().replace("\\\n", " ").split(":", 1)[1].split()
    compiler_inputs = {str(Path(p).resolve(strict=True)): bound_file(Path(p)) for p in dependencies}
    toolchain = {"driver": bound_file(compiler)}
    for name in ("cc1", "as", "ld", "collect2"):
        path = subprocess.check_output([str(compiler), "-print-prog-name=" + name], text=True).strip()
        if not Path(path).is_absolute(): path = subprocess.check_output(["which", path], text=True).strip()
        toolchain[name] = bound_file(Path(path))
    for name in ("libkernel32.a", "libuser32.a", "libgdi32.a"):
        path = subprocess.check_output([str(compiler), "-print-file-name=" + name], text=True).strip()
        toolchain[name] = bound_file(Path(path))
    notices = {}
    for package in ("mingw64-gcc", "mingw64-headers", "mingw64-crt", "mingw-binutils-generic", "cross-binutils-common"):
        directory = Path("/usr/share/licenses") / package
        require(directory.is_dir(), "local toolchain license notices missing")
        for notice in sorted(directory.iterdir()):
            if not notice.is_file(): continue
            row = bound_file(notice); target = out / "toolchain-licenses" / package / notice.name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(notice.read_bytes()); target.chmod(0o400)
            require(digest(target) == row["sha256"], "toolchain notice changed while freezing")
            notices[str(notice)] = {**row,"frozen_copy":str(target)}
    steps.append(invoke(command, out, "compiler"))
    actual_dependencies = (out / "compiler.d").read_text().replace("\\\n", " ").split(":", 1)[1].split()
    require(set(str(Path(p).resolve(strict=True)) for p in actual_dependencies) == set(compiler_inputs), "actual compiler dependency set changed")
    for row in list(compiler_inputs.values()) + list(toolchain.values()):
        require(bound_file(Path(row["path"])) == row, "compiler input changed during compilation")
    gate = pe_gate(executable, archive)
    image = out / "dwrite-probe.img"
    with image.open("xb") as stream: stream.truncate(IMAGE_BYTES)
    steps.append(invoke(["mkfs.vfat", "-F", "32", "-s", "1", "-n", "DWRITE", "--invariant", str(image)], out, "fat-format"))
    steps.append(invoke(["mcopy", "-s", "-m", "-i", str(image), str(tree), "::" + VOLUME], out, "fat-payload", productivity.runner.mtools_env()))
    control = f"image=D:\\{VOLUME}\\{EXE}\r\ncmdline={EXE} \r\ncwd=D:\\{VOLUME}\r\ntimeout={GUEST_TIMEOUT}\r\n".encode("ascii")
    productivity.runner.put_file(image, control, "K64RUN.TXT", out)
    payload = {p.name: bound_file(p) for p in tree.iterdir()}
    # Read actual FAT members back, instead of treating the source tree as proof
    # that the guest volume really received the private font and executable.
    for name, row in payload.items():
        read = subprocess.run(["mtype", "-i", str(image), "::" + VOLUME + "/" + name], env=productivity.runner.mtools_env(),
                              capture_output=True, timeout=30)
        require(read.returncode == 0 and len(read.stdout) == row["bytes"] and font_corpus.digest(read.stdout) == row["sha256"],
                "actual FAT payload byte mismatch")
    image.chmod(0o400); executable.chmod(0o400)
    require(sources() == original and theme.verified_overlay(overlay_path) == runtime and
            verified_corpus(corpus_path, overlay_path, runtime) == corpus, "preparation inputs changed")
    dwrite = next((data for name, data in theme.parse_archive(archive) if name.casefold() == "\\shz\\sys64\\dwrite.dll"), None)
    require(dwrite is not None, "actual archive DWrite absent")
    result = {"schema": 1, "stage": "private-amd64-dwrite-probe", "status": "PREPARED", "nonce": nonce,
              "overlay_receipt": bound_file(overlay_path), "font_corpus_receipt": bound_file(corpus_path),
              "corpus_overlay_relationship":corpus_overlay_binding(corpus,overlay_path,runtime),
              "runtime_worktree": runtime["runtime_worktree"], "runtime_source_hashes": peer_hashes,
              "runtime_evidence_source_hashes": wait, "source_hashes": original, "compiler": toolchain,
              "compiler_inputs": compiler_inputs, "toolchain_license_notices": notices, "steps": steps, "executable": bound_file(executable),
              "font_header": bound_file(header), "payload": payload, "image": bound_file(image),
              "tree": str(tree), "control": control.decode(), "pe_gate": gate,
              "actual_dwrite": {"archive_member": "\\SHZ\\SYS64\\dwrite.dll", "bytes": len(dwrite), "sha256": font_corpus.digest(dwrite),
                                "reviewed_source_binary_identity_verified": False},
              "font_expectations": corpus["font_profile"], "layout_expectations":layout_oracle(corpus), "baseline_hangul_coverage": [0]*5,
              "actual_fat_payloads_read_back_verified": True, "fonts_installed": False, "fonts_registered": False,
              "vm_started": False, "network_attached": False, **FALSE_FLAGS}
    handoff.write_json(out / "prepared.json", result)
    return result


def verified_preparation(path):
    r = handoff.read_json(path)
    directory = path.parent.resolve(strict=True)
    require(directory.is_relative_to(ROOT / "build") and r.get("schema") == 1 and r.get("stage") == "private-amd64-dwrite-probe"
            and r.get("status") == "PREPARED" and common.nonce_ok(r.get("nonce", "")), "invalid owned probe preparation")
    require(r["source_hashes"] == sources(), "probe source changed; prepare a fresh trial")
    for p, h in r["source_hashes"].items(): require(digest(directory / "sources" / p) == h, "frozen source changed")
    require(set(r["runtime_evidence_source_hashes"]) == set(RUNTIME_SOURCES), "complete external exit-source lineage required")
    for p, h in r["runtime_evidence_source_hashes"].items():
        require(digest(directory / "sources/runtime-wait" / p) == digest(Path(r["runtime_worktree"]) / p) == h, "runtime evidence source changed")
    for field in ("overlay_receipt", "font_corpus_receipt"):
        row = r[field]; require(bound_file(Path(row["path"])) == row, "original receipt changed")
    runtime = theme.verified_overlay(Path(r["overlay_receipt"]["path"]))
    require(runtime["runtime_worktree"] == r["runtime_worktree"] and runtime["runtime_source_hashes"] == r["runtime_source_hashes"], "runtime differs")
    corpus = verified_corpus(Path(r["font_corpus_receipt"]["path"]), Path(r["overlay_receipt"]["path"]), runtime)
    require(r["corpus_overlay_relationship"] == corpus_overlay_binding(corpus,Path(r["overlay_receipt"]["path"]),runtime), "corpus/runtime lineage relation changed")
    require(font_header(r["nonce"], corpus) == Path(r["font_header"]["path"]).read_text(), "font expectations/nonce changed")
    require(r["layout_expectations"]==layout_oracle(corpus),"independent layout glyph expectations changed")
    for field in ("executable", "image", "font_header"):
        row = r[field]; p = Path(row["path"]); require(p.resolve(strict=True).is_relative_to(directory) and bound_file(p) == row, "prepared input changed")
    require(Path(r["tree"]).resolve(strict=True) == directory / "tree", "unowned payload tree")
    for name, row in r["payload"].items(): require(Path(row["path"]).resolve() == directory / "tree" / name and bound_file(Path(row["path"])) == row, "frozen payload changed")
    for row in list(r["compiler_inputs"].values()) + list(r["compiler"].values()): require(bound_file(Path(row["path"])) == row, "compiler input changed")
    for row in r["toolchain_license_notices"].values():
        require(bound_file(Path(row["path"])) == {k:row[k] for k in ("path","bytes","sha256")} and
                Path(row["frozen_copy"]).resolve(strict=True).is_relative_to(directory) and
                digest(Path(row["frozen_copy"])) == row["sha256"], "original/frozen compiler notices changed")
    require(pe_gate(Path(r["executable"]["path"]), Path(runtime["archive"]["path"]).read_bytes()) == r["pe_gate"], "actual PE gate differs")
    return r, runtime


def child_records(serial, nonce):
    require(common.nonce_ok(nonce), "invalid nonce")
    starts = list(re.finditer(r"^K64 autorun: starting ([^\r\n]+)", serial, re.M))
    require(len(starts) == 1 and starts[0][1] == f"D:\\{VOLUME}\\{EXE} (cwd D:\\{VOLUME}, timeout {GUEST_TIMEOUT} s)", "exact unique autorun required")
    tail = serial[starts[0].start():]
    pids = re.findall(r"^K64 autorun: started pid (\d+)\r?$", tail, re.M)
    require(len(pids) == 1, "unique child PID required")
    records = re.findall(r"^\[(?:win64|user) " + re.escape(EXE) + r" pid " + pids[0] + r"\] (DW64[^\r\n]*)\r?$", tail, re.M)
    require(records.count("DW64 BEGIN " + nonce) == 1, "fresh exact child nonce required")
    require(records[0] == "DW64 BEGIN " + nonce, "nonce must precede all child evidence")
    return records, tail, int(pids[0])


def parse_evidence(serial, nonce):
    records, tail, pid = child_records(serial, nonce)
    endings = [x for x in records if x.startswith("DW64 FINAL ")]
    require(len(endings) == 1 and endings[0] in ("DW64 FINAL PASS " + nonce, "DW64 FINAL FAIL " + nonce), "unique complete fresh verdict required")
    require(records[-1] == endings[0] and records[-2].startswith("DW64 COUNTS "), "FINAL must follow the complete child totals")
    totals = [re.fullmatch(r"DW64 COUNTS checks=(\d+) failures=(\d+) paints=(\d+)", x) for x in records if x.startswith("DW64 COUNTS")]
    require(len(totals) == 1 and totals[0], "unique exact assertion totals required")
    checks, failures, paints = map(int, totals[0].groups())
    passed = [x[10:] for x in records if x.startswith("DW64 PASS ")]
    failed = [x[10:] for x in records if x.startswith("DW64 FAIL ")]
    require(checks >= 3 and checks == len(passed) + len(failed) and failures == len(failed), "assertion totals differ")
    require(endings[0] == "DW64 FINAL " + ("FAIL " if failures else "PASS ") + nonce, "child verdict differs from assertions")
    all_results = re.findall(r"^K64 autorun: result [^\r\n]*", tail, re.M)
    results = re.findall(r"^K64 autorun: result (\S+) exit=([0-9a-f]+) faulted=(\d) reaped=(-?\d+) after \d+ ms\r?$", tail, re.M)
    expected_exit = "1" if failures else "0"
    require(len(all_results) == 1 and results == [("exited", expected_exit, "0", "0")], "external normal child exit and successful proc_wait required")
    require(not re.search(r"K64 EXCEPTION|K64: process .* killed|unhandled exception", tail), "guest process fault")
    raster = [re.fullmatch(r"DW64 RASTER latin_ink=(\d+) korean_ink=(\d+) runs=(\d+) glyphs=(\d+) missing=(\d+) wrong_faces=(\d+) hash=([0-9a-f]{8})", x) for x in records if x.startswith("DW64 RASTER")]
    alpha = [re.fullmatch(r"DW64 ALPHA nonzero=(\d+) bytes=(\d+)", x) for x in records if x.startswith("DW64 ALPHA")]
    gui = [re.fullmatch(r"DW64 GUI READY " + nonce + r" left=(\d+) top=(\d+) width=384 height=128 hash=([0-9a-f]{8})", x) for x in records if x.startswith("DW64 GUI READY")]
    shapes = [x for x in records if x.startswith("DW64 SHAPE ")]
    subset = all(x in passed for x in MANDATORY) and all(passed.count(x) == 5 for x in (
        "baseline_glyph_indices", "baseline_hangul_absent_as_independently_parsed", "baseline_latin_cmap_identity", "baseline_latin_design_advances", "baseline_real_face_outlives_file_reference"))
    subset = subset and len(raster) == len(alpha) == len(gui) == 1 and bool(raster[0]) and bool(alpha[0]) and bool(gui[0])
    subset = subset and shapes == ["DW64 SHAPE row=0 covered=3 expected=3 errors=0","DW64 SHAPE row=1 covered=255 expected=255 errors=0"]
    detail = {}
    if subset:
        latin, korean, runs, glyphs, missing, wrong, hash_value = raster[0].groups()
        ink, size = map(int, alpha[0].groups()); left, top, screen_hash = gui[0].groups()
        subset = (checks >= 100 and paints >= 1 and int(latin)>50 and int(korean)>150 and int(runs)>=2 and
                  int(glyphs)>=10 and missing==wrong=="0" and 100<ink<=size<=384*64*3 and hash_value==screen_hash and
                  int(left)+384<=1024 and int(top)+128<=768)
        detail = {"latin_ink_pixels": int(latin), "korean_ink_pixels": int(korean), "glyph_runs": int(runs),
                  "glyphs": int(glyphs), "missing_glyphs": int(missing), "wrong_font_faces": int(wrong),
                  "alpha_nonzero_bytes": ink, "alpha_buffer_bytes": size, "rgb_fnv1a32": hash_value,
                  "screen_rectangle": [int(left), int(top), int(left)+384, int(top)+128]}
    ok = subset and failures == 0
    return {"status": "PASS" if ok else "FAIL", "nonce": nonce, "pid": pid, "assertions": checks, "failures": failures,
            "failed_assertions": failed, "normal_exit_code": int(expected_exit), "proc_wait_return_code": 0,
            "kernel_child_reaped": True, "private_korean_latin_dwrite_subset_verified": ok,
            "baseline_five_fonts_hangul_absence_guest_verified": passed.count("baseline_glyph_indices")==5 and passed.count("baseline_hangul_absent_as_independently_parsed")==5,
            "raster": detail, "hresult_records": [x for x in records if x.startswith("DW64 HR ")]}


def rgb_hash(data):
    h = 2166136261
    for value in data: h = ((h ^ value) * 16777619) & 0xffffffff
    return f"{h:08x}"


def screenshot(path, record):
    from PIL import Image
    require(path.stat().st_size <= 4*1024**2, "bounded framebuffer capture required")
    left, top, checksum = int(record[1]), int(record[2]), record[3]
    require(0 <= left <= 1024-384 and 0 <= top <= 768-128, "live capture rectangle out of bounds")
    with Image.open(path) as image:
        require(image.format == "PPM" and image.mode == "RGB" and image.size == (1024,768), "actual expected framebuffer required")
        crop = image.crop((left,top,left+384,top+128))
        require(rgb_hash(crop.tobytes()) == checksum, "full actual framebuffer differs from live DirectWrite DIB hash")
        png = path.with_suffix(".png"); image.save(png)
    return {"status": "PASS", "source": bound_file(path), "preview": str(png), "screen_rectangle": [left,top,left+384,top+128],
            "checked_rgb_pixels": 49152, "rgb_fnv1a32": checksum, "actual_framebuffer_matches_live_dwrite_dib": True}


class Guard(common.CaptureGuard):
    def Popen(self, command, **kwargs):
        require("-nodefaults" in command and not any(x in command for x in ("-net","-netdev","-nic")), "strict no-NIC guest required")
        for index, value in enumerate(command):
            if value == "-device": require(command[index+1].split(",",1)[0] in ("isa-debug-exit","ahci","ide-hd"), "unexpected guest device")
        return super().Popen(command, **kwargs)

    def written_bytes(self, pid):
        written, output = super().written_bytes(pid)
        observed = self.record.setdefault("kvm_fd_evidence", [])
        try:
            for fd in (Path("/proc")/str(pid)/"fd").iterdir():
                try: target = str(fd.readlink())
                except OSError: continue
                if target == "/dev/kvm" or "kvm-vm" in target or "kvm-vcpu" in target:
                    row = {"pid":pid,"fd":fd.name,"target":target}
                    if row not in observed: observed.append(row)
        except OSError: pass
        return written, output

    def observe(self):
        connection = None
        try:
            while not self.stop.wait(.05):
                if self.child.poll() is not None: return
                path = self.out/"serial.log"
                serial = path.read_text(errors="replace") if path.exists() else ""
                try: records, _, _ = child_records(serial, self.nonce)
                except ValueError: continue
                marker = [re.fullmatch(r"DW64 GUI READY " + self.nonce + r" left=(\d+) top=(\d+) width=384 height=128 hash=([0-9a-f]{8})", x) for x in records if x.startswith("DW64 GUI READY")]
                if len(marker)!=1 or not marker[0] or "DW64 PASS all_49152_visible_pixels_match_real_directwrite_dib" not in records: continue
                connection = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); connection.settimeout(2); connection.connect(str(self.qmp))
                stream = connection.makefile("rwb"); require("QMP" in json.loads(stream.readline()), "owned QMP greeting absent")
                def command(name, args=None):
                    payload = {"execute":name,"id":name}
                    if args is not None: payload["arguments"]=args
                    stream.write(json.dumps(payload).encode()+b"\n"); stream.flush()
                    while True:
                        response = json.loads(stream.readline())
                        if response.get("id")==name:
                            require("return" in response, "owned QMP request failed"); return response["return"]
                command("qmp_capabilities"); capture = self.out/"theme-screen.ppm"
                command("screendump", {"filename":str(capture)}); self.capture=screenshot(capture,marker[0]); stream.close(); return
        except Exception as error: self.capture={"status":"FAIL","error":str(error)}
        finally:
            if connection is not None: connection.close()


def run_trial(prepared, out, qemu, firmware_dirs, timeout=75):
    require(qemu.is_absolute() and 15<=timeout<=120, "absolute QEMU and bounded timeout required")
    r, runtime = verified_preparation(prepared); preparation_sha = digest(prepared)
    out = theme.owned_new_directory(out); require(out.is_relative_to(ROOT/"build"), "own ignored run directory required")
    productivity, hashes = handoff.load_peer(Path(r["runtime_worktree"]))
    require(hashes == r["runtime_source_hashes"], "peer runner changed")
    runner = productivity.runner
    inputs = {"boot_stub":runner.K64S/"boot.elf", "kernel":runner.K64S/"KERNEL64S.BIN", "win64_initrd":Path(runtime["archive"]["path"]), "qemu":qemu}
    before = {key:digest(p) for key,p in inputs.items()}
    firmware = handoff.firmware_manifest(firmware_dirs)
    handoff.check_space(out.parent,sum(p.stat().st_size for p in inputs.values())+firmware["bytes"]+handoff.RUN_WRITE_BUDGET)
    out.mkdir(); sealed=handoff.seal_runtime_inputs(inputs,out/"runtime-inputs"); sealed_fw=handoff.seal_firmware(firmware,out/"runtime-firmware")
    require(all(sealed[k]["sha256"]==h for k,h in before.items()), "runtime changed during sealing")
    handoff.write_json(out/"runtime-seal.json",{"schema":1,"probe_preparation_sha256":preparation_sha,"runtime_source_hashes":hashes,
                                             "sealed_runtime_input_hashes":sealed,"sealed_firmware":sealed_fw})
    guard=Guard(Path(sealed["qemu"]["path"]),out,sealed_fw,r["nonce"])
    require(APP not in runner.APPS,"application key already owned")
    saved=runner.K64S,runner.WIN64,runner.subprocess,runner.build_image,runner.put_file,sys.argv
    image=Path(r["image"]["path"])
    def image_builder(selected,tree,volume,over=None):
        require(Path(selected).resolve()==image.resolve() and Path(tree).resolve()==Path(r["tree"]).resolve() and volume==VOLUME and not over,"runner requested another image")
        return [(name,row["bytes"]) for name,row in r["payload"].items()]
    def control_writer(selected,data,name,folder):
        require(Path(selected).resolve()==image.resolve() and name=="K64RUN.TXT" and data.decode()==r["control"],"runner requested another autorun")
    runner.K64S=runner.WIN64=out/"runtime-inputs";runner.subprocess=guard;runner.build_image=image_builder;runner.put_file=control_writer
    runner.APPS[APP]={"dir":VOLUME,"exe":EXE,"args":"","expect":"DW64 FINAL PASS "+r["nonce"]}
    sys.argv=[str(Path(runner.__file__)),"--app",APP,"--tree",r["tree"],"--image",str(image),"--out",str(out),"--qemu",sealed["qemu"]["path"],"--accel","kvm","--memory","1024","--timeout",str(timeout),"--guest-timeout",str(GUEST_TIMEOUT)]
    code,error=2,None
    try: code=runner.main()
    except Exception as failure: error=str(failure)
    finally:
        runner.K64S,runner.WIN64,runner.subprocess,runner.build_image,runner.put_file,sys.argv=saved;runner.APPS.pop(APP,None);guard.close()
    serial=(out/"serial.log").read_text(errors="replace") if (out/"serial.log").exists() else ""
    acceptance={"status":"FAIL"}
    try: acceptance=parse_evidence(serial,r["nonce"])
    except Exception as failure: acceptance["error"]=str(failure)
    preserved=False
    try:
        require(digest(prepared)==preparation_sha and verified_preparation(prepared)[0]==r,"preparation changed")
        require(all(digest(Path(row["path"]))==digest(Path(row["source_path"]))==row["sha256"] for row in sealed.values()),"original/sealed runtime changed")
        require(handoff.sealed_firmware_preserved(sealed_fw) and handoff.firmware_sources_preserved(firmware),"firmware changed")
        require({p:digest(Path(r["runtime_worktree"])/p) for p in handoff.PEER_FILES}==hashes,"peer source changed")
        preserved=True
    except Exception as failure: error=(error+"; " if error else "")+str(failure)
    fd_targets=[x["target"] for x in guard.record.get("kvm_fd_evidence",[])]
    kvm="/dev/kvm" in fd_targets and any("kvm-vm" in x for x in fd_targets) and any("kvm-vcpu" in x for x in fd_targets)
    host_exit=guard.child is not None and guard.child.returncode==1 and re.findall(r"^SHZ-EXIT:(\d+)\r?$",serial,re.M)==["0"]
    safe=preserved and kvm and not guard.record["termination_reason"] and error is None
    ok=safe and code==0 and acceptance["status"]=="PASS" and guard.capture["status"]=="PASS" and host_exit
    result={"schema":1,"stage":"standalone-kernel64-private-dwrite-korean-latin-acceptance","status":"PASS" if ok else "FAIL",
            "probe_nonce":r["nonce"],"probe_preparation":{"path":str(prepared.resolve()),"sha256":preparation_sha},
            "guest_os":"ShizukuDOS Kernel64 standalone","actual_dwrite":r["actual_dwrite"],"font_corpus_receipt":r["font_corpus_receipt"],
            "original_runner_return_code":code,"host_qemu_return_code":guard.child.returncode if guard.child else None,
            "qemu_isa_debug_exit_guest_zero_encoding_verified":host_exit,"acceptance":acceptance,"capture":guard.capture,
            "resource_guard":guard.record,"hardware_virtualization_fd_verified":kvm,"original_and_sealed_inputs_preserved":preserved,
            "error":error,"network_attached":False,"peer_sources_modified":False,"installation":"not_performed",
            "private_korean_latin_dwrite_subset_verified":safe and acceptance["status"]=="PASS",
            "actual_qemu_framebuffer_directwrite_pixels_verified":safe and guard.capture["status"]=="PASS",**FALSE_FLAGS}
    handoff.write_json(out/"dwrite-acceptance.json",result);return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__); stages=parser.add_subparsers(dest="stage",required=True)
    prep=stages.add_parser("prepare")
    for name in ("overlay","font-corpus","out"): prep.add_argument("--"+name,type=Path,required=True)
    prep.add_argument("--nonce",default=None)
    run=stages.add_parser("run")
    for name in ("prepared","out","qemu"): run.add_argument("--"+name,type=Path,required=True)
    run.add_argument("--firmware-dir",type=Path,action="append",required=True);run.add_argument("--timeout",type=int,default=75)
    args=parser.parse_args(argv)
    try:
        result=prepare(args.overlay,args.font_corpus,args.out,args.nonce or uuid.uuid4().hex) if args.stage=="prepare" else run_trial(args.prepared,args.out,args.qemu,args.firmware_dir,args.timeout)
    except Exception as error:
        failure={"schema":1,"status":"FAIL","error":str(error),"vm_started":False,**FALSE_FLAGS}
        if args.stage=="prepare" and args.out.is_dir() and args.out.resolve().is_relative_to(ROOT/"build") and (args.out/"attempt.json").is_file():
            failure["attempt"]=bound_file(args.out/"attempt.json")
            failure["retained_outputs"]={str(p.relative_to(args.out)):bound_file(p) for p in args.out.rglob("*") if p.is_file()}
            handoff.write_json(args.out/"failed-preparation.json",failure)
        print(json.dumps({key:failure[key] for key in ("status","error")}));return 2
    print(json.dumps({"status":result["status"],"stage":result["stage"]}));return 0 if result["status"] in ("PREPARED","PASS") else 1


if __name__=="__main__": raise SystemExit(main())
