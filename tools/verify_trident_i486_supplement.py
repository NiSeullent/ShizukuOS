#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Replay pinned historical CPU evidence; launch and execute nothing."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

ROOT = Path(__file__).resolve().parents[1]
BOOT_BUILD = Path("/root/Win98-Modern-boot/build")
SUPPLEMENT = ROOT / "build/i486-canonical-supplement-v1/result.json"
SUPPLEMENT_SHA = "e8005132e8f917adedb54b3b85e1d6bfbb0c46bfc432288db34016537bdf53c6"
HISTORICAL_SOURCES = {
    "tools/i486_instruction_gate.py": "3da2e3c04fce6a85b1d92ff3c398d43f3f6312c0a56c71c0b4d5f5b53c9f1f7d",
    "tests/test_i486_instruction_gate.py": "40ff19e18fb305dab4006f3e88dbcab3fae6f53b2140248e88d37d0fcda12667",
    "tools/audit_i486_native_inputs.py": "d4637da446ec7b8f8b703ee38c04e78304eb5cd880781c893e8ca9bf24ae1490"}
STAGES = {
    "trident-script-native-5abe-20261001-v1": {
        "component": "script", "inputs": ("M98QJS.DLL", "QJS13PR.EXE", "M98JSRUN.EXE"),
        "outputs": ("QJS13.LOG", "JSRUN.LOG", "JSOUT.LOG"),
        "receipts": ("runtime-build.json", "observer-build.json")},
    "trident-automation-native-5abe-20261001-v1": {
        "component": "automation", "inputs": ("M98AUTPR.EXE", "M98QJS.DLL", "M98AURUN.EXE"),
        "outputs": ("AUT13.LOG", "AURUN.LOG", "AUOUT.LOG"),
        "receipts": ("automation-build.json", "runtime-build.json", "observer-build.json")}}
PREFIX = "C:\\GOPLAB\\"
PARSER = "horizontal-lines-explicit-i486-x87-allowlist-v1"
FALSE_FLAGS = ("native_execution", "modern_web_standards", "native_styles",
               "native_paint", "modern_apps", "vm_operations")
OWN_SOURCES = ("tools/verify_trident_i486_supplement.py",
               "tests/test_verify_trident_i486_supplement.py", "docs/TRIDENT_I486_SUPPLEMENT.md")


class EvidenceError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise EvidenceError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(value):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256 pin")
    return value


def read(path, limit=8 << 20):
    """Read stable, bounded regular bytes without following any symlink."""
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical evidence path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, "unbounded/nonregular evidence")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        need(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
             "evidence changed while reading")
        return data
    finally:
        os.close(fd)


def unique(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(data):
    value = json.loads(data, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("nonfinite JSON number")))
    need(isinstance(value, dict), "receipt must be a JSON object")
    return value


def relative(name):
    need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_./-]{1,240}", name) and
         all(p not in {"", ".", ".."} for p in name.split("/")), "unsafe snapshot member")
    return name


def rows(values, keys, field):
    need(isinstance(values, list) and len(values) == len(keys), "wrong evidence record count")
    result = {}
    for value in values:
        need(isinstance(value, dict) and isinstance(value.get(field), str) and
             value[field] in keys and value[field] not in result, "unexpected/duplicate evidence record")
        result[value[field]] = value
    need(set(result) == set(keys), "incomplete evidence record set")
    return result


def historical_policy(data):
    """Extract five literal tables from pinned source; never execute that source."""
    policy = {}
    for node in ast.parse(data.decode("ascii")).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name not in {"BASE", "X87", "PREFIX", "EXACT", "SUFFIXABLE"}:
            continue
        need(name not in policy, "duplicate historical mnemonic table")
        value = node.value
        if isinstance(value, ast.Set):
            values = ast.literal_eval(value)
        else:
            need(isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and
                 value.func.id == "set" and len(value.args) == 1 and not value.keywords,
                 "unsupported historical mnemonic table")
            call = value.args[0]
            need(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and
                 call.func.attr == "split" and not call.args and not call.keywords and
                 isinstance(call.func.value, ast.Constant) and isinstance(call.func.value.value, str),
                 "nonliteral historical mnemonic table")
            values = set(call.func.value.value.split())
        need(isinstance(values, set) and 1 <= len(values) <= 256 and
             all(isinstance(v, str) and re.fullmatch(r"[a-z0-9]+", v) for v in values),
             "malformed historical mnemonic table")
        policy[name] = values
    need(set(policy) == {"BASE", "X87", "PREFIX", "EXACT", "SUFFIXABLE"}, "missing historical mnemonic table")
    # The later six BT/BSF/BSR suffix additions are deliberately not substituted.
    policy["ALLOWED"] = policy["BASE"] | policy["X87"] | policy["EXACT"] | {
        base + suffix for base in policy["SUFFIXABLE"] for suffix in ("b", "w", "l")} | {
        base + suffix for base in policy["X87"] for suffix in ("s", "l", "t", "ll")}
    return policy


def pe_sections(data):
    """Derive executable VirtualSize extents directly from bounded PE32 bytes."""
    need(isinstance(data, bytes) and 64 <= len(data) <= 1048576 and data[:2] == b"MZ", "invalid PE DOS header")
    nt = struct.unpack_from("<I", data, 0x3c)[0]
    need(64 <= nt <= len(data) - 24 and data[nt:nt + 4] == b"PE\0\0", "invalid PE NT header")
    machine, count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, nt + 4)
    optional = nt + 24
    need(machine == 0x14c and 1 <= count <= 96 and 96 <= optional_size <= 4096 and
         optional + optional_size + count * 40 <= len(data) and
         struct.unpack_from("<H", data, optional)[0] == 0x10b, "bounded PE32/i386 section table required")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    image_size, headers_size = struct.unpack_from("<II", data, optional + 56)
    need(0 < image_size <= 0xffffffff - image_base + 1 and
         optional + optional_size + count * 40 <= headers_size <= len(data), "invalid PE image/header extent")
    sections, names, virtual, raw = {}, set(), [], []
    for index in range(count):
        offset = optional + optional_size + index * 40
        encoded = data[offset:offset + 8]
        name = encoded.rstrip(b"\0").decode("ascii")
        flags = struct.unpack_from("<I", data, offset + 36)[0]
        plain_name = re.fullmatch(r"[A-Za-z0-9_.$-]{1,8}", name)
        # PE/COFF may store non-executable long names as string-table offsets.
        # The frozen DLL uses /4; no executable extent relies on that indirection.
        long_reference = re.fullmatch(r"/[1-9][0-9]{0,6}", name) and not flags & 0x20000000
        need((plain_name or long_reference) and name not in names and
             b"\0" not in encoded.rstrip(b"\0"), "ambiguous PE section name")
        names.add(name)
        size, address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        mapped_size = max(size, raw_size)
        need(mapped_size > 0 and headers_size <= address and address + mapped_size <= image_size,
             "invalid PE mapped section extent")
        virtual.append((address, address + mapped_size))
        if raw_size:
            need(headers_size <= raw_offset and raw_offset + raw_size <= len(data), "truncated PE raw section")
            raw.append((raw_offset, raw_offset + raw_size))
        if not flags & 0x20000000:
            continue
        need(0 < size <= raw_size <= 4 << 20 and image_base + address + size <= 1 << 32,
             "unsupported executable VirtualSize extent")
        sections[name] = dict(address=image_base + address, data=data[raw_offset:raw_offset + size])
    for extents in (virtual, raw):
        ordered = sorted(extents)
        need(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), "overlapping PE section extents")
    need(sections and sum(len(s["data"]) for s in sections.values()) <= 4 << 20, "executable section bound")
    return sections


def decode(raw, sections, policy, artifact_path=None):
    """Replay saved disassembly only, with strict rows and actual byte coverage."""
    need(isinstance(raw, bytes) and 0 < len(raw) <= 64 << 20, "unbounded/empty saved disassembly")
    text = raw.decode("ascii")
    positions, current, count, headers = {}, None, 0, 0
    for line in text.splitlines():
        need(len(line) <= 2048, "unbounded disassembly line")
        if not line.strip():
            continue
        if artifact_path is not None and line == str(artifact_path) + ":     file format pei-i386":
            headers += 1
            need(headers == 1 and not positions, "duplicate/misplaced disassembly file header")
            continue
        header = re.fullmatch(r"Disassembly of section ([^ \t:]+):", line)
        if header:
            current = header[1]
            need(current in sections and current not in positions, "unexpected/duplicate executable section")
            positions[current] = 0
            continue
        if re.fullmatch(r"[0-9a-f]+ <[^\r\n]{1,1024}>:", line):
            need(current in sections, "symbol label outside executable section")
            continue
        match = re.fullmatch(r"[ \t]*([0-9a-f]+):[ \t]+"
            r"((?:[0-9a-f]{2}[ \t]+)+)([^ \t]+)(?:[ \t]+(.*))?", line)
        need(match is not None, "unknown/truncated disassembly row")
        address, encoded, mnemonic, operands = match.groups()
        data, operands = bytes.fromhex(encoded), operands or ""
        need(1 <= len(data) <= 15, "invalid instruction length")
        for _ in range(15):
            if mnemonic not in policy["PREFIX"]:
                break
            more = re.fullmatch(r"([^ \t]+)(?:[ \t]+(.*))?", operands)
            need(more is not None, "prefix without actual instruction")
            mnemonic, operands = more[1], more[2] or ""
        need(mnemonic not in policy["PREFIX"] and mnemonic in policy["ALLOWED"], "non-i486/unknown mnemonic")
        need(not re.search(r"%(?:[xyz]mm\d+|mm[0-7])\b", operands), "SIMD operand")
        need(all(register in {"0", "2", "3"} for register in re.findall(r"%cr([0-9]+)\b", operands)),
             "non-i486 control register")
        need(current in sections, "instruction outside executable section")
        section, position = sections[current], positions[current]
        need(int(address, 16) == section["address"] + position and
             section["data"][position:position + len(data)] == data, "instruction byte/address gap or mismatch")
        positions[current] += len(data)
        count += 1
        need(count <= 1048576, "instruction count bound")
    need(count and (artifact_path is None or headers == 1) and set(positions) == set(sections) and
         all(positions[n] == len(s["data"]) for n, s in sections.items()), "incomplete executable byte coverage")
    return dict(instructions_decoded=count, post_i486_families="absent", parser=PARSER,
        executable_sections={n: dict(bytes=len(s["data"]), address=s["address"],
            sha256=sha(s["data"]), decoded_bytes=positions[n]) for n, s in sections.items()})


def verify(manifest, manifest_sha, supplement, supplement_sha):
    """Pure read-only guard for pre-launch AND final component acceptance."""
    manifest, supplement = Path(manifest), Path(supplement)
    stage = manifest.parent
    need(manifest.is_absolute() and manifest.name == "guest-files.json" and stage.parent == BOOT_BUILD and
         stage.name in STAGES and stage.resolve(strict=True) == stage, "exact canonical frozen stage required")
    need(supplement == SUPPLEMENT and pin(supplement_sha) == SUPPLEMENT_SHA,
         "exact caller-approved historical supplement required")
    observed = {}

    def checked(path, expected, limit=8 << 20):
        data = read(path, limit)
        digest = pin(expected)
        need(sha(data) == digest, "frozen evidence pin changed: " + str(path))
        need(str(path) not in observed or observed[str(path)][0] == digest, "conflicting evidence generation")
        observed[str(path)] = (digest, limit)
        return data

    plan = parse_json(checked(manifest, manifest_sha, 65536))
    proof = parse_json(checked(supplement, supplement_sha, 1 << 20))
    need(set(proof) == {"schema", "kind", "passed", "source_sha256", "input_sha256", "artifacts", "controls"} |
         set(FALSE_FLAGS) and type(proof["schema"]) is int and proof["schema"] == 1 and
         proof["kind"] == "pinned-i486-native-input-supplement" and proof["passed"] is True and
         all(proof[k] is False for k in FALSE_FLAGS), "wrong component-only supplemental receipt")
    need(proof["source_sha256"] == HISTORICAL_SOURCES, "historical source closure differs")
    source_data = {n: checked(supplement.parent / "source" / n, h, 65536) for n, h in HISTORICAL_SOURCES.items()}
    policy = historical_policy(source_data["tools/i486_instruction_gate.py"])
    control = proof["controls"]
    need(isinstance(control, dict) and set(control) == {"command", "returncode", "log", "sha256", "actual_modern_after_no_operand_cases"} and
         control["command"] == ["python3", "tests/test_i486_instruction_gate.py", "-v"] and
         type(control["returncode"]) is int and control["returncode"] == 0 and
         type(control["actual_modern_after_no_operand_cases"]) is int and
         control["actual_modern_after_no_operand_cases"] == 27 and
         control["log"] == str(supplement.parent / "parser-controls.log"), "historical controls differ")
    checked(Path(control["log"]), control["sha256"], 1 << 20)
    expected_paths = [str(BOOT_BUILD / n / member) for n, spec in STAGES.items() for member in spec["inputs"]]
    need(isinstance(proof["input_sha256"], dict) and isinstance(proof["artifacts"], dict) and
         set(proof["input_sha256"]) == set(proof["artifacts"]) == set(expected_paths), "exact six supplemental inputs required")
    spec = STAGES[stage.name]
    need(set(plan) == {"schema", "kind", "nonce", "command", "network_required", "inputs", "outputs", "source_receipts"} and
         type(plan["schema"]) is int and plan["schema"] == 1 and plan["kind"] == "isolated-guest-file-inputs" and
         plan["command"] == PREFIX + spec["inputs"][-1] and plan["network_required"] is False and
         isinstance(plan["nonce"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", plan["nonce"]) and
         plan["outputs"] == [PREFIX + n for n in spec["outputs"]], "wrong isolated component stage profile")
    planned = rows(plan["inputs"], {PREFIX + n for n in spec["inputs"]}, "guest")
    for name in spec["inputs"]:
        row = planned[PREFIX + name]
        need(set(row) == {"source", "guest", "bytes", "sha256"} and row["source"] == str(stage / name) and
             type(row["bytes"]) is int and 0 < row["bytes"] <= 1048576 and
             row["sha256"] == proof["input_sha256"][row["source"]], "manifest and CPU input generations differ")
    # Original build/verifier semantics stay independent; additionally retain all
    # selected build source/prepared/log pins and reject upgraded native claims.
    builds = rows(plan["source_receipts"], {str(stage / n) for n in spec["receipts"]}, "path")
    merged, stage_pins = {}, {}
    for original, row in builds.items():
        need(set(row) == {"path", "sha256"}, "unexpected original build receipt field")
        build = parse_json(checked(Path(original), row["sha256"], 16 << 20))
        stage_pins[Path(original).name] = row["sha256"]
        need(build.get("passed") is True and isinstance(build.get("source_sha256"), dict) and
             1 <= len(build["source_sha256"]) <= 128, "wrong original build evidence")
        role = Path(original).name.removesuffix("-build.json")
        flags = {"runtime": ("native_guest_execution_verified", "native_math_verified", "mshtml_dom_verified",
                 "html5_verified", "wasm_verified", "full_es2026_conformance_verified", "applications_verified", "user_objective_complete"),
                 "observer": ("native_execution", "native_mshtml", "native_visual_input", "full_web_standards", "vm_operations"),
                 "automation": ("native_mshtml_execution", "native_visual_input", "standard_browser_integration",
                 "html5_layout_wasm", "modern_app_operation", "vm_operations")}[role]
        need(all(build.get(k) is False for k in flags), "original build exceeds component-only scope")
        for name, digest in build["source_sha256"].items():
            name = relative(name)
            need(name not in merged or merged[name] == digest, "conflicting original source generations")
            merged[name] = pin(digest)
            checked(stage / "source" / name, digest)
            stage_pins["source/" + name] = digest
        steps = build.get("steps")
        need(isinstance(steps, list) and 1 <= len(steps) <= 256, "missing/bounded original build logs required")
        log_names = set()
        for step in steps:
            need(isinstance(step, dict) and type(step.get("returncode")) is int and step["returncode"] == 0 and
                 isinstance(step.get("log"), str) and Path(step["log"]).is_absolute(), "unsuccessful original build step")
            name = Path(step["log"]).name
            need(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.(?:txt|log)", name) and name not in log_names,
                 "ambiguous original build log")
            log_names.add(name)
            member = "build-logs/" + role + "/" + name
            checked(stage / member, step["sha256"])
            stage_pins[member] = step["sha256"]
        if role == "runtime":
            prepared = build.get("prepared_sha256")
            need(isinstance(prepared, dict) and 1 <= len(prepared) <= 128, "missing prepared engine closure")
            names, roots = set(), set()
            for original, digest in prepared.items():
                need(isinstance(original, str) and original.startswith("/") and original.count("/prepared/") == 1,
                     "unsupported prepared source path")
                source_root, name = original.split("/prepared/", 1)
                name = relative(name)
                need(name.startswith(("quickjs/", "math/")) and name not in names, "ambiguous prepared source")
                names.add(name); roots.add(source_root)
                member = "runtime-prepared/" + name
                checked(stage / member, digest)
                stage_pins[member] = digest
            need(len(roots) == 1 and "quickjs/quickjs.c" in names and
                 any(n.startswith("math/src/math/") for n in names), "incoherent engine/math source closure")
    provenance_bytes = read(stage / "provenance.json", 1 << 20)
    provenance_sha = sha(provenance_bytes)
    provenance = parse_json(checked(stage / "provenance.json", provenance_sha, 1 << 20))
    provenance_flags = (("native_execution", "native_mshtml_dom", "full_javascript", "modern_css", "wasm",
        "webgpu", "webgl", "applications", "vm_operations", "global_registration") if spec["component"] == "script" else
        ("native_execution", "native_visual_input", "browser_integration", "html5_wasm", "global_registration", "vm_operations"))
    provenance_keys = {"schema", "kind", "manifest_sha256", "source_sha256", "stage_sha256"} | set(provenance_flags)
    if spec["component"] == "script":
        provenance_keys.add("verifier_helper_sha256")
        pin(provenance.get("verifier_helper_sha256"))
    need(type(provenance.get("schema")) is int and provenance["schema"] == 1 and
         set(provenance) == provenance_keys and provenance.get("kind") == (
             "runtime-only-native-frozen-stage" if spec["component"] == "script" else "genuine-mshtml-native-frozen-stage") and
         provenance.get("manifest_sha256") == manifest_sha and provenance.get("source_sha256") == merged and
         isinstance(provenance.get("stage_sha256"), dict) and 1 <= len(provenance["stage_sha256"]) <= 512,
         "stage provenance generation differs")
    need(all(provenance[k] is False for k in provenance_flags),
         "stage provenance exceeds component-only scope")
    for member, digest in provenance["stage_sha256"].items():
        relative(member)
        checked(stage / member, digest, 16 << 20)
    need(all(provenance["stage_sha256"].get(n) == h for n, h in stage_pins.items()),
         "stage provenance omits original source/log evidence")
    verified = {}
    gate_keys = {"instructions_decoded", "post_i486_families", "parser", "executable_sections",
                "artifact_sha256", "artifact_bytes", "command", "disassembly_sha256", "log"}
    for index, original in enumerate(expected_paths):
        artifact = Path(original)
        gate = proof["artifacts"][original]
        need(isinstance(gate, dict) and set(gate) == gate_keys and
             type(gate["artifact_bytes"]) is int and 0 < gate["artifact_bytes"] <= 1048576 and
             type(gate["instructions_decoded"]) is int and 0 < gate["instructions_decoded"] <= 1048576 and
             gate["post_i486_families"] == "absent" and gate["parser"] == PARSER and
             gate["artifact_sha256"] == proof["input_sha256"][original] and
             gate["command"] == ["i686-w64-mingw32-objdump", "-d", "-z", "--show-raw-insn", "--insn-width=16", original] and
             gate["log"] == str(supplement.parent / (str(index) + "-" + artifact.name + "-disassembly.log")),
             "supplemental artifact metadata differs")
        data = checked(artifact, gate["artifact_sha256"], 1048576)
        need(len(data) == gate["artifact_bytes"], "supplemental PE byte size differs")
        sections = pe_sections(data)
        saved = checked(Path(gate["log"]), gate["disassembly_sha256"], 64 << 20)
        computed = decode(saved, sections, policy, artifact)
        need(all(computed[k] == gate[k] for k in computed), "replayed executable section metadata differs")
        need(isinstance(gate["executable_sections"], dict) and all(
            isinstance(s, dict) and set(s) == {"bytes", "sha256", "address", "decoded_bytes"} and
            all(type(s[k]) is int for k in ("bytes", "address", "decoded_bytes"))
            for s in gate["executable_sections"].values()), "wrong executable section field types")
        verified[original] = dict(computed, sha256=gate["artifact_sha256"], bytes=len(data),
            disassembly_sha256=gate["disassembly_sha256"])
    for name in spec["inputs"]:
        row = planned[PREFIX + name]
        need(row["bytes"] == verified[row["source"]]["bytes"] and
             provenance["stage_sha256"].get(name) == row["sha256"], "selected stage input size/provenance differs")
    # Re-read the complete closure so changes during a long raw-log replay fail.
    for name, (digest, limit) in observed.items():
        need(sha(read(Path(name), limit)) == digest, "evidence drift during CPU replay")
    return dict(schema="win98modern.trident-i486-supplement-guard.v1", passed=True,
        scope="saved historical executable VirtualSize CPU provenance only", component=spec["component"],
        manifest=str(manifest), manifest_sha256=manifest_sha, supplement=str(supplement),
        supplement_sha256=supplement_sha, historical_source_sha256=HISTORICAL_SOURCES,
        stage_provenance_sha256=provenance_sha,
        historical_controls_sha256=control["sha256"], historical_controls_rerun=False,
        selected_input_sha256={n: planned[PREFIX + n]["sha256"] for n in spec["inputs"]},
        supplemental_input_sha256=proof["input_sha256"], verified_artifacts=verified,
        checked_evidence_sha256={n: h for n, (h, _) in observed.items()},
        saved_cpu_provenance_verified=True, actual_cpu_execution_verified=False,
        native_execution=False, native_styles=False, native_paint=False, vm_operations=False,
        modern_web_standards=False, actual_child_exit_verified=False,
        full_javascript=False, full_html5=False, full_css=False, full_browser=False,
        wasm=False, webgpu=False, webgl=False, modern_apps=False,
        original_native_verifier_still_required=True, launch_input_copy_hash_check_still_required=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--supplement", required=True, type=Path)
    parser.add_argument("--supplement-sha256", required=True)
    parser.add_argument("--out", required=True, type=Path, help="Fresh direct child of this worktree's build")
    args = parser.parse_args()
    try:
        out = args.out
        need(out.is_absolute() and out.parent == ROOT / "build" and out.resolve() == out and not out.exists(),
             "fresh canonical owned direct build output required")
        source = {n: read(ROOT / n, 1 << 20) for n in OWN_SOURCES}
        result = verify(args.manifest, args.manifest_sha256, args.supplement, args.supplement_sha256)
        need(all(read(ROOT / n, 1 << 20) == data for n, data in source.items()), "guard source drift")
        result["guard_source_sha256"] = {n: sha(data) for n, data in source.items()}
        data = (json.dumps(result, indent=2, allow_nan=False) + "\n").encode()
        need(len(data) <= 1 << 20, "guard receipt exceeds output bound")
        out.mkdir()
        for name, content in source.items():
            target = out / "source" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(content)
            need(read(target, 1 << 20) == content, "guard source snapshot readback differs")
        target = out / "result.json"
        with target.open("xb") as stream:
            stream.write(data)
        need(read(target, 1 << 20) == data, "guard receipt readback differs")
        print(json.dumps(dict(passed=True, result=str(target), sha256=sha(data), native_execution=False)))
        return 0
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError, SyntaxError, struct.error) as error:
        print(json.dumps(dict(passed=False, saved_cpu_provenance_verified=False, native_execution=False,
                              error=str(error)[:512])))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
