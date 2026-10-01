#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate stopped canonical Win98 TLS-fixture evidence without running a VM.

PASS is scoped to the frozen executable's real TLS memory-record checks and
its observed post-CRT child exit. It never establishes the observer's own OS
exit, desktop/theme/app support, DLL loading, networking or OS provider support.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
BOOT_ROOT = Path("/root/Win98-Modern-boot")
GUEST = "C:\\GOPLAB\\"
INPUT_NAMES = ("TLS13PRB.EXE", "SRV.PEM", "SRV.KEY", "CA.PEM", "BADCA.PEM", "EXP.PEM", "EXP.KEY", "TLSWATCH.EXE")
OUTPUT_NAMES = ("TLS13.LOG", "TLSOBS.LOG")
FIXTURES = {"server.pem": "SRV.PEM", "server.key": "SRV.KEY", "ca.pem": "CA.PEM",
            "other-ca.pem": "BADCA.PEM", "expired.pem": "EXP.PEM", "expired.key": "EXP.KEY"}
CASES = ("zero_size_random_has_no_os_call", "valid_bidirectional_payload_and_close",
         "wrong_host_rejected", "untrusted_ca_rejected", "expired_certificate_rejected",
         "partial_write_and_truncation", "tls12_only_peer_rejected",
         "os_random_failure_during_handshake", "modified_ciphertext_rejected",
         "record_boundary_eof_rejected", "failed_os_random_rejected")
SUMMARY_FLAGS = ("passed", "tls13_handshake", "authenticated_payload", "wrong_host_rejected",
                 "untrusted_ca_rejected", "expired_rejected", "partial_io_and_truncation",
                 "random_failure_rejected", "tls12_downgrade_rejected", "late_random_failure_rejected",
                 "modified_ciphertext_rejected", "record_boundary_eof_rejected",
                 "zero_size_random_has_no_os_call")
SOURCE_NAMES = {"transport.h", "transport.c", "probe.c", "user_config.h", "native_time.c",
                "native_time_probe.c", "native_runtime.h", "native_runtime.c", "native_crt.c", "native.def", "build.py"}
HASH_RE = re.compile(r"[0-9a-f]{64}")
UNPINNED = object()
CHILD_ARGUMENTS = (GUEST + "TLS13PRB.EXE --server-cert SRV.PEM --server-key SRV.KEY "
                   "--ca CA.PEM --untrusted-ca BADCA.PEM --expired-cert EXP.PEM "
                   "--expired-key EXP.KEY --output TLS13.LOG --nonce ")


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def integer(value, label, minimum=0, maximum=0xFFFFFFFF):
    require(type(value) is int and minimum <= value <= maximum, f"Invalid integer: {label}")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def json_object(raw):
    try:
        value = json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=lambda value: require(False, f"Non-finite JSON constant: {value}"))
    except (ValueError, UnicodeError) as error:
        raise VerificationError(f"Invalid JSON evidence: {error}") from error
    require(type(value) is dict, "JSON evidence must be an object")
    return value


def validate_tls_log(raw, nonce):
    require(0 < len(raw) <= 65536 and raw.endswith(b"\n"), "TLS log missing, oversized or incomplete")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise VerificationError("TLS log is not ASCII JSONL") from error
    require(len(lines) == 14 and all(lines), "Native TLS log must have exactly fourteen rows")
    rows = [json_object(line) for line in lines]
    require(all(row.get("nonce") == nonce for row in rows), "TLS log nonce differs from the frozen trial")
    start, identity, summary = rows[0], rows[1], rows[-1]
    require(set(start) == {"case", "nonce", "epoch", "platform"} and start.get("case") == "start" and
            start.get("platform") == "windows-native-build", "TLS start is not a native Windows build")
    integer(start.get("epoch"), "TLS epoch", 1, 253402300799)
    require(set(identity) == {"case", "version_query_ok", "platform_id", "major", "minor", "build", "win98_identified", "nonce"} and
            identity.get("case") == "windows_identity" and identity.get("version_query_ok") is True and
            identity.get("win98_identified") is True, "TLS native identity missing or failed")
    require(integer(identity.get("platform_id"), "TLS platform") == 1 and
            integer(identity.get("major"), "TLS OS major") == 4 and
            integer(identity.get("minor"), "TLS OS minor") == 10, "TLS process is not Windows 98")
    build = integer(identity.get("build"), "TLS OS build")
    require(build & 0xFFFF == 2222, "TLS process is not the frozen Windows 98 SE build")
    cases = rows[2:-1]
    require(tuple(row.get("case") for row in cases) == CASES, "TLS cases missing, duplicated, reordered or unknown")
    keys = {"case", "passed", "client_status", "server_status", "version", "verify_flags", "engine_error", "steps", "nonce"}
    for row in cases:
        require(set(row) == keys and row.get("passed") is True, f"TLS case failed or changed schema: {row.get('case')}")
        for key in ("client_status", "server_status", "engine_error"):
            integer(row.get(key), f"{row['case']} {key}", -0x80000000, 0x7FFFFFFF)
        integer(row.get("verify_flags"), "TLS verify flags")
        integer(row.get("steps"), "TLS handshake steps")
        require(type(row.get("version")) is str, "Invalid TLS version diagnostic")
    valid = cases[1]
    require(valid["version"] == "TLSv1.3" and valid["verify_flags"] == 0 and valid["engine_error"] == 0 and
            valid["client_status"] == 0 and valid["server_status"] == 0 and valid["steps"] > 0,
            "Successful case does not establish authenticated TLS 1.3")
    for row, flag in zip(cases[2:5], (4, 8, 1)):
        require(row["client_status"] == -4 and row["verify_flags"] & flag and row["engine_error"] < 0,
                f"Certificate rejection evidence inconsistent: {row['case']}")
    for row in (cases[5], cases[8], cases[9]):
        require(row["version"] == "TLSv1.3" and row["verify_flags"] == 0 and row["engine_error"] == 0 and
                row["client_status"] == 0 and row["steps"] > 0,
                f"Established TLS record test lacks authenticated session: {row['case']}")
    require(cases[5]["server_status"] == 0 and cases[8]["server_status"] == -3 and cases[9]["server_status"] == -7,
            "Partial I/O, damaged MAC or unauthenticated EOF failure states inconsistent")
    require(cases[6]["client_status"] == -3 and cases[6]["server_status"] in (-28160, -28288) and
            cases[6]["version"] == "" and cases[6]["engine_error"] < 0,
            "TLS 1.2-only peer was not rejected by the actual handshake")
    require(cases[7]["client_status"] == -3 and cases[7]["version"] == "" and cases[7]["engine_error"] < 0,
            "Late OS random failure was not rejected by the actual handshake")
    for row in (cases[0], cases[10]):
        require(row["client_status"] == -1 and row["server_status"] == -1 and row["version"] == "" and
                row["verify_flags"] == 0xFFFFFFFF and row["engine_error"] == 0 and row["steps"] == 0,
                "Runtime RNG-only test unexpectedly reports a connection")
    require(set(summary) == set(SUMMARY_FLAGS) | {"random_calls", "nonce"} and
            all(summary.get(key) is True for key in SUMMARY_FLAGS), "TLS summary missing or failed")
    integer(summary.get("random_calls"), "TLS random source calls", 1)
    return {"cases": list(CASES), "epoch": start["epoch"], "os_build": build,
            "random_calls": summary["random_calls"], "authenticated_tls13": True}


def validate_observer_log(raw, nonce, build):
    require(0 < len(raw) <= 65536 and raw.endswith(b"\r\n"), "Observer log missing, oversized or incomplete")
    try:
        lines = raw.decode("ascii").split("\r\n")[:-1]
    except UnicodeError as error:
        raise VerificationError("Observer log is not ASCII") from error
    values = {}
    for line in lines:
        require("=" in line and "\n" not in line and "\r" not in line, "Invalid observer log line")
        key, value = line.split("=", 1)
        require(key not in values and key, "Duplicate observer log field")
        values[key] = value
    texts = {"schema": "win98modern.tls-owned-child-observer.v1",
             "scope": "fixed-native-TLS-fixture-actual-post-CRT-child-exit", "nonce": nonce,
             "observer.application": GUEST + "TLSWATCH.EXE", "child.application": GUEST + "TLS13PRB.EXE",
             "child.command": CHILD_ARGUMENTS + nonce, "child.directory": "C:\\GOPLAB"}
    numbers = {"os.query-ok": 1, "os.query-error": 0, "os.platform": 1, "os.major": 4, "os.minor": 10,
               "os.build": build, "os.build-low": 2222, "os.exact-win98se": 1, "child.timeout-ms": 90000,
               "child.output-absent-before-create": 1, "child.created": 1, "child.create-error": 0,
               "child.thread-handle-closed": 1, "child.thread-handle-close-error": 0, "child.wait": 0,
               "child.wait-error": 0, "child.exit-query": 1, "child.exit-query-error": 0, "child.exit-code": 0,
               "child.process-handle-closed": 1, "child.process-handle-close-error": 0, "child.terminated": 1,
               "child.post-crt-zero-exit-observed": 1, "observer.exit-candidate": 0,
               "observer.success-requires-report-close": 1}
    ids = {"observer.pid", "observer.tid", "child.pid", "child.tid"}
    require(set(values) == set(texts) | set(numbers) | ids, "Observer fields missing, unknown or contain guard termination")
    require(all(values[key] == value for key, value in texts.items()), "Observer command, identity or nonce differs from fixture")
    for key in set(numbers) | ids:
        require(re.fullmatch(r"0|[1-9][0-9]*", values[key]), f"Observer numeric field is malformed: {key}")
        actual = integer(int(values[key]), key, 1 if key in ids else 0)
        if key in numbers:
            require(actual == numbers[key], f"Observer acceptance failed: {key}")
    require(values["observer.pid"] != values["child.pid"] and values["observer.tid"] != values["child.tid"],
            "Observer and created child identities overlap")
    return {"child_pid": int(values["child.pid"]), "child_tid": int(values["child.tid"]),
            "child_actual_os_exit": 0, "child_post_crt_exit_observed": True,
            "observer_own_exit_observed": False,
            "observer_own_exit_limit": "Final log candidate precedes report CloseHandle and the observer's own ExitProcess"}


class CheckedFiles:
    def __init__(self):
        self.records = {}

    @staticmethod
    def identity(path):
        stat = path.stat()
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    def read(self, path, expected=UNPINNED, maximum=1024 ** 2, contents=True):
        path = Path(path)
        require(not path.is_symlink() and path.is_file(), f"Missing or symlinked evidence: {path}")
        path = path.resolve(strict=True)
        before = self.identity(path)
        require(0 < before[2] <= maximum, f"Evidence size outside bounds: {path}")
        if expected is not UNPINNED:
            require(type(expected) is str and HASH_RE.fullmatch(expected), f"Malformed pinned SHA: {path}")
        digest = hashlib.sha256()
        chunks = []
        with path.open("rb") as stream:
            while data := stream.read(4 * 1024 ** 2):
                digest.update(data)
                if contents:
                    chunks.append(data)
        got = digest.hexdigest()
        require(before == self.identity(path), f"Evidence mutated while reading: {path}")
        require(expected is UNPINNED or got == expected, f"Evidence SHA differs: {path}")
        previous = self.records.get(str(path))
        require(previous is None or previous["sha256"] == got, f"Evidence changed between reads: {path}")
        self.records[str(path)] = {"path": str(path), "sha256": got, "bytes": before[2], "identity": before}
        return b"".join(chunks) if contents else got

    def json(self, path, expected=UNPINNED):
        return json_object(self.read(path, expected))

    def finish(self):
        for row in self.records.values():
            require(tuple(row["identity"]) == self.identity(Path(row["path"])), f"Evidence mutated during verification: {row['path']}")
        return [{key: row[key] for key in ("path", "sha256", "bytes")} for row in self.records.values()]


def validate_manifest(reader, manifest_path, manifest_sha):
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest = reader.json(manifest_path, manifest_sha)
    require(integer(manifest.get("schema"), "manifest schema") == 1 and manifest.get("kind") == "isolated-guest-file-inputs", "Unknown fixture manifest")
    nonce = manifest.get("nonce")
    require(type(nonce) is str and re.fullmatch(r"[A-Za-z0-9-]{16,64}", nonce), "Nonce is unsafe or not typable by canonical runner")
    require(manifest.get("command") == GUEST + "TLSWATCH.EXE --nonce " + nonce and
            manifest.get("outputs") == [GUEST + name for name in OUTPUT_NAMES] and manifest.get("backups") == [] and
            manifest.get("post_crt_exit_required") is True and manifest.get("network_required") is False,
            "Fixture command/output/freshness contract changed")
    inputs = manifest.get("inputs")
    require(type(inputs) is list and len(inputs) == 8 and tuple(row.get("guest") for row in inputs) ==
            tuple(GUEST + name for name in INPUT_NAMES), "Fixture must contain exactly eight fixed unique inputs")
    expected_sources = {str(manifest_path): manifest_sha}
    for row, name in zip(inputs, INPUT_NAMES):
        path = manifest_path.parent / name
        require(row.get("source") == str(path) and integer(row.get("bytes"), name + " size", 1, 1024 ** 2) == path.stat().st_size,
                f"Staged input identity/size changed: {name}")
        reader.read(path, row.get("sha256"), contents=False)
        expected_sources[str(path)] = row["sha256"]
    receipts = manifest.get("source_receipts")
    require(type(receipts) is list and len(receipts) == 4, "Expected four retained source receipts")
    loaded = []
    for row in receipts:
        path = Path(row.get("path", ""))
        require(path.parent == manifest_path.parent and path.name.startswith("source-receipt-"), "Receipt outside staged fixture")
        raw = reader.read(path, row.get("sha256"))
        reader.read(Path(row.get("origin", "")), row["sha256"], contents=False)
        expected_sources[str(path)] = row["sha256"]
        loaded.append(raw)
    require(len({row["path"] for row in receipts}) == 4, "Duplicate retained receipt")
    parent, observer, native = json_object(loaded[0]), json_object(loaded[1]), json_object(loaded[3])
    require(manifest.get("parent_fixture_sha256") == receipts[0]["sha256"] and
            manifest.get("observer_receipt_sha256") == receipts[1]["sha256"], "Receipt pins differ from manifest")
    require(len(parent.get("source_receipts", [])) == 1 and parent["source_receipts"][0].get("sha256") == receipts[3]["sha256"],
            "Parent fixture does not identify this native build")
    require(type(parent.get("inputs")) is list and len(parent["inputs"]) == 8, "Parent fixture input count changed")
    for old, new in zip(parent["inputs"][:7], inputs[:7]):
        require(all(old.get(key) == new.get(key) for key in ("guest", "sha256", "bytes")), "Parent TLS input differs from observed fixture")
    require(observer.get("schema") == "win98modern.tls-native-observer.v1" and observer.get("status") == "PASS" and
            integer(observer.get("compile_returncode"), "observer compile code") == 0 and
            observer.get("binary", {}).get("pe_audit", {}).get("static_gate_passed") is True,
            "Observer build/static receipt failed")
    require(observer.get("source", {}).get("sha256") == receipts[2]["sha256"] == observer.get("source_snapshot", {}).get("sha256"),
            "Observer compiled source does not match retained C")
    for source in (observer["source"], observer["source_snapshot"]):
        reader.read(Path(source["path"]), source["sha256"], contents=False)
    for binary, row in ((observer.get("binary", {}), inputs[7]), (native.get("binary", {}), inputs[0])):
        require(binary.get("sha256") == row["sha256"] and integer(binary.get("bytes"), "compiled binary size", 1) == row["bytes"],
                "Staged executable differs from its compiled binary")
        reader.read(Path(binary.get("path", "")), row["sha256"], contents=False)
    require(native.get("schema") == "win98modern.secure-transport-build.v1" and native.get("target") == "win98-x86" and
            native.get("status") == "PASS" and native.get("pe_audit", {}).get("static_gate_passed") is True,
            "Native TLS build/static receipt failed")
    require(set(native.get("fixtures", {})) == set(FIXTURES), "Native fixture names changed")
    by_name = dict(zip(INPUT_NAMES, inputs))
    for source, name in FIXTURES.items():
        require(native["fixtures"][source] == by_name[name]["sha256"], "Staged certificate/key differs from native fixture")
    require(set(native.get("source_sha256", {})) == SOURCE_NAMES, "Native compiled source inventory changed")
    for name, sha in native["source_sha256"].items():
        reader.read(ROOT / "ntwin32/secure_transport" / name, sha, contents=False)
    return manifest, expected_sources


def stopped_disk(path):
    """Refuse disk inspection while any other process has this inode open."""
    stat = path.stat()
    target = stat.st_dev, stat.st_ino
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal() or int(proc.name) == os.getpid():
            continue
        try:
            descriptors = list((proc / "fd").iterdir())
        except FileNotFoundError:
            continue
        except PermissionError as error:
            raise VerificationError("Cannot establish disk quiescence from process descriptors") from error
        for descriptor in descriptors:
            try:
                opened = descriptor.stat()
            except FileNotFoundError:
                continue
            except PermissionError as error:
                raise VerificationError("Cannot establish disk descriptor ownership") from error
            require((opened.st_dev, opened.st_ino) != target, f"Disk remains open in process {proc.name}; no live-disk inspection")


def validate_run(reader, run, manifest_path, manifest_sha, runner_sha, boot_root=BOOT_ROOT):
    run = Path(run).resolve(strict=True)
    require(run.parent == (boot_root / "build/shizukudos/csm").resolve(strict=True) and "7707" in run.name,
            "Run must be a separate owned canonical 7707 CSM trial")
    result = reader.json(run / "result.json")
    require(result.get("profile") == "actual-win98-uefi-csmwrap" and result.get("status") == "NEEDS-VISUAL-REVIEW" and
            integer(result.get("qemu_exit_code"), "QEMU exit") == 0 and result.get("guest_status", {}).get("running") is True and
            not result.get("error") and not result.get("runtime_failure"), "Canonical run is incomplete or unhealthy")
    require(result.get("source_sha256") == runner_sha and result.get("source_snapshot") == str(run / "runner-source.py"),
            "Canonical runner source identity differs from launch pin")
    reader.read(run / "runner-source.py", runner_sha, contents=False)
    require(result.get("originals_unchanged") is True and result.get("prepared_source_unchanged") is True,
            "Canonical run reports immutable source mutation")
    budget = result.get("sparse_budget", {})
    reserve = integer(budget.get("reserve_bytes"), "reserve", 20 * 1024 ** 3, 64 * 1024 ** 3)
    require(integer(budget.get("dirty_budget_bytes"), "dirty budget") == 256 * 1024 ** 2 and
            integer(budget.get("free_before_vm"), "free before VM", 0, 2 ** 63 - 1) >= reserve + 256 * 1024 ** 2 and
            integer(result.get("minimum_free_bytes"), "minimum free bytes", 0, 2 ** 63 - 1) >= reserve,
            "Guest violated allocation/reserve policy")
    for label, count in (("firmware_checks", 7), ("firmware_gop_checks", 4)):
        rows = result.get(label)
        require(type(rows) is list and len(rows) == count and len({row.get("check") for row in rows}) == count and
                all(row.get("status") == "PASS" for row in rows), "Firmware path checks failed or missing")
    manifest, expected_sources = validate_manifest(reader, manifest_path, manifest_sha)
    files = result.get("guest_files", {})
    require(files.get("manifest") == str(Path(manifest_path).resolve()) and files.get("manifest_sha256") == manifest_sha and
            files.get("outputs") == manifest["outputs"] and files.get("backups") == [] and
            files.get("installed_gop_replacement") == [] and files.get("output_baseline") == "all absent before private injection" and
            files.get("immutable_sources_unchanged") is True and files.get("immutable_sources") == expected_sources,
            "Actual injected plan differs from frozen manifest or fresh-output contract")
    actual_inputs = files.get("inputs")
    require(type(actual_inputs) is list and len(actual_inputs) == 8, "Actual injected input count changed")
    for expected, actual in zip(manifest["inputs"], actual_inputs):
        require(all(actual.get(key) == value for key, value in expected.items()) and actual.get("private_copy_sha256") == expected["sha256"],
                "Guest preparation readback differs from frozen input")
        reader.read(run / ("prepared-guest-" + expected["guest"].split("\\")[-1]), expected["sha256"], contents=False)
    actions = result.get("gui_interaction", {})
    require(actions.get("mode") == "owned control queue; visually steered" and actions.get("all_actions_completed") is True,
            "Manual guest action receipt incomplete")
    launches = [row for row in actions.get("actions", []) if row.get("typed") == manifest["command"]]
    require(len(launches) == 1 and launches[0].get("status") == "sent; application effect requires screenshot/readback verification",
            "Expected exactly one acknowledged observer command")
    screenshot = Path(launches[0].get("screenshot", ""))
    require(screenshot.parent == run and re.fullmatch(r"screen-[0-9]{3}\.png", screenshot.name), "Launch screenshot belongs to another guest")
    require(reader.read(screenshot, maximum=16 * 1024 ** 2).startswith(b"\x89PNG\r\n\x1a\n"), "Launch capture is not native PNG")
    readback = files.get("readback")
    require(type(readback) is list and len(readback) == 2 and tuple(row.get("guest") for row in readback) == tuple(manifest["outputs"]),
            "Guest outputs missing, duplicate or unexpected")
    output = []
    for row, name in zip(readback, OUTPUT_NAMES):
        path = run / ("guest-output-" + name)
        require(row.get("status") == "captured" and row.get("freshness") == "new-in-owned-run" and row.get("path") == str(path) and
                integer(row.get("bytes"), "readback bytes", 1, 65536) == path.stat().st_size,
                "Readback output is stale, missing or from another run")
        output.append(reader.read(path, row.get("sha256"), maximum=65536))
    tls = validate_tls_log(output[0], manifest["nonce"])
    observer = validate_observer_log(output[1], manifest["nonce"], tls["os_build"])
    command = result.get("command")
    require(type(command) is list and command and all(type(value) is str for value in command), "Missing QEMU command identity")
    def values(option):
        return [command[i + 1] for i, word in enumerate(command[:-1]) if word == option]
    require(Path(command[0]).name in {"qemu-kvm", "qemu-system-x86_64"} and values("-nic") == ["none"] and
            not any(option in command for option in ("-net", "-netdev", "-blockdev", "-hda", "-hdb", "-incoming", "-loadvm", "-readconfig", "-kernel", "-initrd", "-bios", "-cdrom")),
            "Guest command has networking or alternate disk/boot paths")
    disk = run / "windows-uefi.raw"
    expected_drive = f"file={disk},format=raw,if=none,id=win98"
    drives = values("-drive")
    require(len(drives) == 3 and expected_drive in drives and
            f"if=pflash,unit=1,format=raw,file={run / 'OVMF_VARS.fd'}" in drives and
            sorted(values("-device")) == ["VGA", "ide-hd,drive=win98,bus=ide.0,bootindex=1"],
            "QEMU does not use this exact private disk/VARS/device set")
    code_drives = [value for value in drives if value.startswith("if=pflash,unit=0,format=raw,readonly=on,file=")]
    require(len(code_drives) == 1, "Read-only firmware drive identity missing")
    reader.read(Path(code_drives[0].split("file=", 1)[1]), result.get("firmware_code_sha256"), maximum=32 * 1024 ** 2, contents=False)
    immutable = result.get("immutable_sources")
    require(type(immutable) is dict and set(immutable) == {result.get("archive"), result.get("checkpoint_record")}, "Checkpoint immutable identities missing")
    for path, sha in immutable.items():
        reader.read(Path(path), sha, maximum=2 * 1024 ** 3 + 256 * 1024 ** 2, contents=False)
    reuse = result.get("prepared_reuse", {})
    source_run = Path(reuse.get("source_run", "")).resolve(strict=True)
    require(source_run.parent == run.parent and source_run != run and
            reuse.get("method") == "verified private sparse post-run disk copy; cold hardware, new VARS, no CPU/RAM state",
            "Run is not a separate cold sparse clone of a retained source")
    prior = reader.json(source_run / "result.json", reuse.get("source_receipt_sha256"))
    require(prior.get("owned_disk_sha256_after_run") == reuse.get("source_disk_sha256") and
            prior.get("originals_unchanged") is True and integer(prior.get("qemu_exit_code"), "source QEMU exit") == 0,
            "Retained cold source receipt differs from selected source")
    source_disk = source_run / "windows-uefi.raw"
    require(disk.stat().st_nlink == 1 and (disk.stat().st_dev, disk.stat().st_ino) !=
            (source_disk.stat().st_dev, source_disk.stat().st_ino), "Guest disk is not a private inode")
    stopped_disk(disk); stopped_disk(source_disk)
    reader.read(source_disk, reuse.get("source_disk_sha256"), maximum=2 * 1024 ** 3, contents=False)
    reader.read(disk, result.get("owned_disk_sha256_after_run"), maximum=2 * 1024 ** 3, contents=False)
    evidence = reader.finish()
    return {"schema": "win98modern.tls-observed-native-guest.v1", "status": "PASS", "run": str(run),
            "manifest": str(Path(manifest_path).resolve()), "manifest_sha256": manifest_sha,
            "runner_sha256": runner_sha, "nonce": manifest["nonce"], "tls": tls, "observer": observer,
            "scope": "Frozen native executable TLS memory-record cases and observed actual TLS child post-CRT exit only",
            "native_tls_fixture_verified": True, "observer_own_exit_observed": False,
            "native_library_load_verified": False, "system_schannel_verified": False,
            "application_functionality_verified": False, "system_theme_verified": False,
            "network_transport_verified": False, "evidence": evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--runner-sha256", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        require(HASH_RE.fullmatch(args.manifest_sha256) and HASH_RE.fullmatch(args.runner_sha256), "Explicit lowercase SHA256 pins required")
        result = validate_run(CheckedFiles(), args.run, args.manifest, args.manifest_sha256, args.runner_sha256)
        result["verifier_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except (VerificationError, OSError, KeyError, TypeError, AttributeError) as error:
        result = {"schema": "win98modern.tls-observed-native-guest.v1", "status": "FAIL", "error": str(error),
                  "native_tls_fixture_verified": False, "observer_own_exit_observed": False,
                  "system_schannel_verified": False, "application_functionality_verified": False}
    raw = json.dumps(result, indent=2) + "\n"
    if args.output:
        require(args.output.resolve().parent == args.run.resolve(), "Verification output must stay directly inside this run")
        with args.output.open("x") as stream:
            stream.write(raw)
    print(raw, end="")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
