#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Opt-in, post-proof PE32 handoff envelope; never native/TLS acceptance.

Only a fresh hosted runner may execute this sealer. The closed build receipt
is read unchanged. The new manifest and GITHUB_OUTPUT append are separate
observations: upload-action lifetime, archives and transient storage are not
covered by the build receipt or this sealer's held file descriptors.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]
SELF = "ntwin32/legacy_provider_bridge/seal_native_handoff_6970.py"
BASE = "ntwin32/legacy_provider_bridge/test_native_sspi_6970.py"
SCHEMA = "native-provider-pe32-handoff-v1"
MANIFEST = "native-handoff-6970.json"
LIMIT = 8 * 1024 * 1024
RESERVE = 20 * 1024 * 1024 * 1024
MANIFEST_LIMIT = 16 * 1024
INPUT_LIMIT = 2 * 1024 * 1024
GIT_TOTAL_LIMIT = 16 * 1024 * 1024
QUERY_SECONDS = 30
COMMAND_FILE_LIMIT = 1024 * 1024
FROZEN = {
    "benchmarks/win98se-ko-oem-native-exports-v1.json": (1866608, "3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d"),
    "ntwin32/legacy_provider_bridge/NTWPROV.def": (197, "bbc13ed2f636c04195232e3e409958e83a711419a7c7419ed59e7cb1fb9c0b50"),
    "ntwin32/legacy_provider_bridge/build.py": (10046, "b6372e074fec112558250a5675e090c217740c1c3ca7ca8c098d7f6b51a10c63"),
    "ntwin32/legacy_provider_bridge/build_native_pe32_guarded_6970.py": (76927, "b7d627c71076b6cbdb1e65d896ab798e4fe3688067ef7b0a1774243d2c3010d9"),
    "ntwin32/legacy_provider_bridge/native.c": (10295, "97a33c5292773ef949df251c7615eff259305b604f8d8d8d7f20b8039f98c301"),
    "ntwin32/legacy_provider_bridge/pe_link_script_6970.py": (26070, "9a98336d9c5a0bc417ed816454d3188e79dc4cf326a52bfabad73df8c903b55b"),
    "ntwin32/legacy_provider_bridge/probe.c": (3750, "63560ce5225069e3eae21fe77aae3480962b995ac40a394736f28e6ec41c2c41"),
    "ntwin32/legacy_provider_bridge/sspi_sdk_abi_6970.c": (5015, "714e1a3f42eb0241fa0a2f4df94ed0eb847743edd7ba58d8eef29d1e4386a0be"),
    "ntwin32/legacy_provider_bridge/table.c": (3424, "c6fbe91b0ba24a68b2fcaef1f265b82071a738036ac331fdc6eb6f3986d5004d"),
    "ntwin32/legacy_provider_bridge/table.h": (538, "58fbf58f784fabcebc1a1821a3f1080fa65a432e08178b58d3b3e50ad68079a1"),
    BASE: (41247, "1b52856e537b298ea253d564754afefc35eb340bd7f7090fc1b30786bfa4f44e"),
    "ntwin32/secure_transport/i486_gate.py": (8829, "85e976035c70478e9a2f021a37aa6925dd20ad85f089c7d06a18efadb7b9730f"),
    "ntwin32/secure_transport/i486_gate_test.py": (5194, "6e90e48f6f690efd29d2db7035478589bca4f140f3c28f05960c9bd0b5a4af69"),
    "tools/build_npp_prerequisites.py": (10627, "aab253717ad653f0b0ccbea37ddc0f9bd9b474e51cade3ff1f13d63844f48d84"),
}
POSITIVE = (
    "sdk_abi_compile_verified", "pe32_artifacts_build_verified", "oem_import_gate_verified",
    "i486_full_executable_sections_decode_verified", "original_i486_python_controls_verified",
    "structural_negative_controls_verified", "coff_object_structural_controls_verified",
    "generated_link_script_controls_verified", "actual_generated_link_script_inputs_hashed_before_after",
    "actual_empty_lifecycle_lists_in_readonly_rdata_verified",
    "actual_lifecycle_layout_negative_controls_verified", "receipt_accounting_verified",
)
FALSE_SCOPE = (
    "actual_native_load_verified", "application_compatibility_verified",
    "complete_PE_loader_acceptance_verified", "credential_execution_verified", "engine_link_verified",
    "full_relocation_block_validation_verified", "guest_execution_verified",
    "hosted_checkout_independently_verified_by_runner", "i486_executable_raw_padding_verified",
    "independent_export_clause_coverage", "kernel64_backend_verified", "native_execution_verified",
    "network_execution_verified", "original_i486_synthetic_PE_scan_control_verified",
    "os_registration_verified", "os_tls_provider_verified", "provider_policy_changed",
    "self_loaded_runner_binding_verified", "tls_execution_verified", "windows98_integration_verified",
    "windows_acceptance_verified",
)
LABELS = (
    "compiler-version", "objdump-version", "selected-linker-query", "kernel32-input-query",
    "i486-original-python-controls", "dll-ld-default-script", "probe-ld-default-script",
    "dll-native-dependencies", "dll-native-compile", "dll-table-dependencies", "dll-table-compile",
    "probe-dependencies", "probe-compile", "sdk-abi-dependencies", "sdk-abi-compile",
    "dll-link", "probe-link", "dll-objdump", "probe-objdump",
)
CONTROL_NAMES = (
    "receipt-native-flag", "receipt-wrong-head", "binary-digest-mismatch",
    "extra-source-path", "metadata-symlink", "metadata-hardlink", "command-output-source-path",
)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def safe_components(path):
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError("absolute non-symlink path required")
    if any(character in str(path) for character in "\n\r\0"):
        raise RuntimeError("newline/NUL path refused")


def regular_policy(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError("regular single-link inode required")


def command_namespace(destination, temporary):
    """Reject checkout/proof destinations before any command-file write."""
    if (not temporary.is_absolute() or destination.parent != temporary / "_runner_file_commands"
            or not re.fullmatch(r"set_output_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", destination.name)
            or temporary.is_relative_to(ROOT) or destination.is_relative_to(ROOT)):
        raise RuntimeError("exact external RUNNER_TEMP command-file namespace required")
    safe_components(temporary)
    safe_components(destination)
    for path in (temporary, destination.parent):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise RuntimeError("runner-owned command directory without other writers required")
    for path in destination.parent.parents:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022):
            raise RuntimeError("unsafe command directory ancestor owner/permissions")


def admission():
    free = shutil.disk_usage(ROOT).free
    if free < RESERVE + LIMIT:
        raise RuntimeError("20 GiB plus 8 MiB post-proof admission refused")
    return free


class Held:
    """Retain the same regular FD and rehash named identity at both boundaries."""
    def __init__(self, path, maximum=INPUT_LIMIT):
        safe_components(path)
        self.path, self.maximum = path, maximum
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(self.fd)
            regular_policy(info)
            if info.st_size > maximum:
                raise RuntimeError("held input byte bound exceeded")
            self.initial = self.scan()
        except BaseException:
            os.close(self.fd)
            raise

    def scan(self, collect=False, guard=None):
        safe_components(self.path)
        before = os.fstat(self.fd)
        regular_policy(before)
        if identity(before) != identity(self.path.lstat()) or before.st_size > self.maximum:
            raise RuntimeError("held FD/named identity changed")
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest, data, size = hashlib.sha256(), bytearray(), 0
        started = time.monotonic()
        while True:
            block = os.read(self.fd, 65536)
            if not block:
                break
            size += len(block)
            if size > self.maximum or time.monotonic() - started > QUERY_SECONDS:
                raise RuntimeError("held read byte/time bound exceeded")
            digest.update(block)
            if collect:
                data.extend(block)
            if guard is not None:
                guard.check()
        after = os.fstat(self.fd)
        regular_policy(after)
        if identity(before) != identity(after) or identity(after) != identity(self.path.lstat()):
            raise RuntimeError("held input changed during full read")
        pin = {"sha256": digest.hexdigest(), "identity": identity(after)}
        if hasattr(self, "initial") and pin != self.initial:
            raise RuntimeError("held input changed from admission")
        return (pin, bytes(data)) if collect else pin

    def close(self):
        os.close(self.fd)


def compare_pin(actual, expected):
    if (not isinstance(expected, dict) or actual.get("sha256") != expected.get("sha256")
            or actual.get("identity") != expected.get("identity")):
        raise RuntimeError("held identity/full SHA differs from closed proof")


def decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RuntimeError("duplicate JSON key refused")
            result[key] = value
        return result
    result = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    if not isinstance(result, dict):
        raise RuntimeError("JSON object required")
    return result


def validate_receipt(receipt, head, output):
    if (receipt.get("schema") != "native-provider-pe32-build-and-sdk-abi-v1"
            or receipt.get("result") != "PASS_BUILD_AND_SDK_ABI_ONLY"
            or receipt.get("reported_hosted_checkout_sha") != head
            or receipt.get("output_root") != str(output)
            or "resource_failure" not in receipt or receipt["resource_failure"] is not None):
        raise RuntimeError("closed build PASS/head/root/resource contract required")
    if any(receipt.get(key) is not True for key in POSITIVE):
        raise RuntimeError("closed positive build/ABI gates required")
    if any(receipt.get(key) is not False for key in FALSE_SCOPE):
        raise RuntimeError("closed native/TLS/app scope must remain false")
    before = receipt.get("source_inputs")
    if not isinstance(before, dict) or set(before) != set(FROZEN) or before != receipt.get("source_inputs_after"):
        raise RuntimeError("exact fourteen unchanged build sources required")
    for name, (size, digest) in FROZEN.items():
        pin = before[name]
        if (not isinstance(pin, dict) or pin.get("sha256") != digest
                or not isinstance(pin.get("identity"), list) or len(pin["identity"]) != 5
                or pin["identity"][2] != size):
            raise RuntimeError("closed frozen source pin differs")
    commands = receipt.get("commands")
    if (not isinstance(commands, list) or [row.get("label") for row in commands] != list(LABELS)
            or any(row.get("returncode") != 0 or row.get("reaped") is not True
                   or row.get("aborted") is not None for row in commands)):
        raise RuntimeError("nineteen actual zero/reaped/nonaborted build commands required")
    if (receipt.get("reserve_bytes") != RESERVE or receipt.get("output_limit_bytes") != LIMIT
            or type(receipt.get("final_output_bytes")) is not int
            or not 0 < receipt["final_output_bytes"] <= LIMIT
            or receipt.get("standard_header_inputs_before") != receipt.get("standard_header_inputs_after")
            or not receipt.get("standard_header_inputs_before")):
        raise RuntimeError("closed resource/header accounting contract required")
    if set(receipt.get("artifacts", {})) != {"NTWPROV.DLL", "NTWPRB.EXE"}:
        raise RuntimeError("exact two build artifacts required")
    if set(receipt.get("link_scripts", {})) != {"dll", "probe"}:
        raise RuntimeError("two actual linker script profiles required")
    for profile in ("dll", "probe"):
        for kind, name in (("raw_verbose", f"{profile}-ld-default-script.stdout"),
                           ("default", f"{profile}-default.ld"),
                           ("generated", f"{profile}-readonly-lifecycle.ld")):
            if receipt["link_scripts"][profile].get(kind, {}).get("path") != str(output / name):
                raise RuntimeError("exact profile linker input paths required")
    for name, artifact in receipt["artifacts"].items():
        if (artifact.get("path") != str(output / name) or artifact.get("native_load_verified") is not False
                or artifact.get("i486_decode", {}).get("status") != "PASS"
                or artifact.get("lifecycle_layout", {}).get("status") != "PASS"):
            raise RuntimeError("artifact path/scoped structural proof differs")


def controls(receipt, head, output, actual_bin):
    reports = []
    def rejection(name, operation, metadata_only=False):
        try:
            operation()
        except RuntimeError as error:
            reports.append({"case": name, "result": "PASS_REJECTION",
                            "error": str(error), "metadata_only": metadata_only})
        else:
            raise RuntimeError("handoff negative control accepted: " + name)
    changed = copy.deepcopy(receipt)
    changed["native_execution_verified"] = True
    rejection(CONTROL_NAMES[0], lambda: validate_receipt(changed, head, output))
    rejection(CONTROL_NAMES[1], lambda: validate_receipt(receipt, "0" * 40, output))
    wrong_pin = dict(actual_bin, sha256="0" * 64)
    rejection(CONTROL_NAMES[2], lambda: compare_pin(wrong_pin, actual_bin))
    changed = copy.deepcopy(receipt)
    changed["source_inputs"]["extra/path"] = dict(actual_bin)
    rejection(CONTROL_NAMES[3], lambda: validate_receipt(changed, head, output))
    rejection(CONTROL_NAMES[4], lambda: regular_policy(types.SimpleNamespace(
        st_mode=stat.S_IFLNK | 0o600, st_nlink=1)), True)
    rejection(CONTROL_NAMES[5], lambda: regular_policy(types.SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600, st_nlink=2)), True)
    rejection(CONTROL_NAMES[6], lambda: command_namespace(ROOT / SELF,
                                                        Path(os.environ.get("RUNNER_TEMP", ""))))
    return {"status": "PASS", "completed": len(reports), "cases": reports,
            "actual_kernel_link_creation_tested": False}


def git_query(argv, maximum, guard, command_records):
    """Separate bounded source-input stream, not closed compiler captures."""
    guard.check()
    child = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                             env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"})
    selector, streams = None, {"stdout": bytearray(), "stderr": bytearray()}
    started, observed, error, killed = time.monotonic(), False, None, False
    try:
        selector = selectors.DefaultSelector()
        for label, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while True:
            guard.check()
            if time.monotonic() - started > QUERY_SECONDS:
                raise RuntimeError("git source query exceeded 30 seconds")
            state = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            observed = observed or state is not None
            if observed and not selector.get_map():
                break
            for key, _ in selector.select(0.05):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                streams[key.data].extend(block)
                if len(streams["stdout"]) > maximum or len(streams["stderr"]) > 65536:
                    raise RuntimeError("git source query byte bound exceeded")
    except BaseException as failure:
        error = failure
    finally:
        # The WNOWAIT leader remains our group-identity ownership token until
        # this cleanup. Kill silent descendants on success as well as failure,
        # then reap the leader; pipe EOF alone does not establish group death.
        killed = True
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            if selector is not None:
                selector.close()
            child.stdout.close()
            child.stderr.close()
            code = child.wait(timeout=5)
            command_records.append({"argv": argv, "returncode": code, "reaped": True,
                                    "nonreaping_leader_exit_observed": observed, "group_kill_requested": killed,
                                    "stdout_bytes": len(streams["stdout"]),
                                    "stdout_sha256": hashlib.sha256(streams["stdout"]).hexdigest(),
                                    "stderr_bytes": len(streams["stderr"]),
                                    "elapsed_seconds": round(time.monotonic() - started, 6)})
    if error is not None:
        raise error
    if code or streams["stderr"]:
        raise RuntimeError("git source query failed or diagnosed")
    guard.check()
    return bytes(streams["stdout"])


def upload_paths(output, include_sources):
    paths = [output / name for name in ("NTWPROV.DLL", "NTWPRB.EXE", "result.json",
             "dll-default.ld", "dll-readonly-lifecycle.ld", "probe-default.ld",
             "probe-readonly-lifecycle.ld", MANIFEST)]
    if include_sources:
        paths.extend(ROOT / name for name in (*sorted(FROZEN), "LICENSE", SELF))
    if len(set(paths)) != len(paths) or len(paths) != (24 if include_sources else 8):
        raise RuntimeError("exact handoff allowlist cardinality differs")
    for path in paths:
        safe_components(path)
        if any(character in str(path) for character in "*?[]"):
            raise RuntimeError("upload allowlist must contain literal paths without glob syntax")
    return [str(path) for path in paths]


def encode_manifest(manifest, original_bytes):
    for _ in range(8):
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(data) > MANIFEST_LIMIT or original_bytes + len(data) > LIMIT:
            raise RuntimeError("self-inclusive 16 KiB manifest/8 MiB output limit exceeded")
        if manifest.get("post_proof_output_bytes") == original_bytes + len(data):
            return data
        manifest["post_proof_output_bytes"] = original_bytes + len(data)
    raise RuntimeError("manifest size accounting did not stabilize")


def write_all(fd, data):
    at = 0
    while at < len(data):
        written = os.write(fd, data[at:])
        if written <= 0:
            raise RuntimeError("short manifest/command-file write")
        at += written


def replace_owned(fd, info, data):
    current = os.fstat(fd)
    regular_policy(current)
    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
        raise RuntimeError("owned manifest inode changed")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    write_all(fd, data)


def verify_manifest(manifest, head, paths, pins, receipt_pin, original_bytes, actual_bytes):
    if (manifest.get("schema") != SCHEMA or manifest.get("result") != "PASS_HANDOFF_ENVELOPE_ONLY"
            or manifest.get("head") != head or manifest.get("upload_paths") != paths
            or manifest.get("input_pins") != pins or manifest.get("closed_result_pin") != receipt_pin
            or manifest.get("closed_output_bytes") != original_bytes
            or manifest.get("post_proof_output_bytes") != original_bytes + actual_bytes
            or manifest.get("observed_recursive_accounting_verified") is not True
            or manifest.get("closed_receipt_rewritten") is not False
            or any(manifest.get(key) is not False for key in FALSE_SCOPE)
            or manifest.get("upload_action_lifetime_verified") is not False
            or manifest.get("filesystem_quota_verified") is not False
            or manifest.get("loaded_code_attestation_verified") is not False):
        raise RuntimeError("existing handoff envelope/source/payload/accounting differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-root", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-manifest-sha256")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--retain", action="store_true")
    mode.add_argument("--verify-existing", action="store_true")
    parser.add_argument("--include-sources", action="store_true")
    args = parser.parse_args()
    head, output = args.expected_head, args.proof_root
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if (os.environ.get("GITHUB_ACTIONS") != "true" or not re.fullmatch(r"[0-9a-f]{40}", head)
            or os.environ.get("GITHUB_SHA") != head or not re.fullmatch(r"[1-9][0-9]*", run)
            or not re.fullmatch(r"[1-9][0-9]*", attempt)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or output != ROOT / "build/native-provider-pe32-6970" / f"actions-{run}-{attempt}"):
        raise RuntimeError("explicit fresh hosted source/head/proof namespace required")
    if ((args.verify_existing and not re.fullmatch(r"[0-9a-f]{64}", args.expected_manifest_sha256 or ""))
            or (args.retain and args.expected_manifest_sha256 is not None)):
        raise RuntimeError("verify-existing requires original manifest SHA; creation must not supply one")
    safe_components(output)
    if output.lstat().st_uid != os.getuid():
        raise RuntimeError("runner-owned proof root required")
    available_before = admission()
    held, pins, command_records = {}, {}, []
    guard, manifest_fd, manifest_inode = None, None, None
    manifest_path = output / MANIFEST
    try:
        def hold(path, key, expected=None, maximum=INPUT_LIMIT):
            item = Held(path, maximum)
            held[key] = item
            if expected is not None:
                compare_pin(item.initial, expected)
            pins[key] = item.initial
            return item
        for name, (size, digest) in FROZEN.items():
            item = hold(ROOT / name, name)
            if item.initial["sha256"] != digest or item.initial["identity"][2] != size:
                raise RuntimeError("current fourteen frozen sources differ")
        module = types.ModuleType("native_handoff_frozen_guard")
        module.__file__ = str(ROOT / BASE)
        raw_guard = held[BASE].scan(collect=True)[1]
        exec(compile(raw_guard, str(ROOT / BASE), "exec"), module.__dict__)
        guard = module.Guard(output)
        guard.check(MANIFEST_LIMIT if args.retain else 0)
        receipt_file = hold(output / "result.json", "result.json", maximum=256 * 1024)
        receipt_pin, receipt_raw = receipt_file.scan(collect=True, guard=guard)
        receipt = decode_json(receipt_raw)
        validate_receipt(receipt, head, output)
        for name in FROZEN:
            compare_pin(pins[name], receipt["source_inputs"][name])
        for name, record in receipt["artifacts"].items():
            hold(output / name, name, record)
        for profile in ("dll", "probe"):
            for kind in ("raw_verbose", "default", "generated"):
                record = receipt["link_scripts"][profile][kind]
                hold(Path(record["path"]), Path(record["path"]).name, record, 256 * 1024)
        # Extra sealer/LICENSE are committed envelope sources, not source14 in
        # the closed builder. Keeping both also makes verification reproducible.
        hold(ROOT / SELF, SELF)
        if args.include_sources:
            hold(ROOT / "LICENSE", "LICENSE")
        paths = upload_paths(output, args.include_sources)
        original_bytes = receipt["final_output_bytes"]
        existing = None
        if args.verify_existing:
            existing_file = hold(manifest_path, MANIFEST, maximum=MANIFEST_LIMIT)
            if existing_file.initial["sha256"] != args.expected_manifest_sha256:
                raise RuntimeError("sealed manifest SHA differs from creation output")
            existing = decode_json(existing_file.scan(collect=True, guard=guard)[1])
            if guard.count() - existing_file.initial["identity"][2] != original_bytes:
                raise RuntimeError("post-upload recursive bytes minus exact manifest differs from closed proof")
            # Manifest cannot include its own inode/digest in input_pins.
            pins.pop(MANIFEST)
        elif manifest_path.exists() or guard.count() != original_bytes:
            raise RuntimeError("manifest must be new and original closed recursive bytes unchanged")
        git_name = shutil.which("git")
        if not git_name:
            raise RuntimeError("git source-envelope query unavailable")
        git_path = Path(git_name).resolve(strict=True)
        git_file = hold(git_path, "selected_git", maximum=256 * 1024 * 1024)
        if not os.access(git_path, os.X_OK):
            raise RuntimeError("selected Git executable unavailable")
        actual_head = git_query([str(git_path), "rev-parse", "--verify", "HEAD"], 128, guard, command_records)
        if actual_head != (head + "\n").encode():
            raise RuntimeError("actual Git HEAD differs from hosted head")
        source_names = (*sorted(FROZEN), SELF, *(("LICENSE",) if args.include_sources else ()))
        blob_bytes, committed = 0, {}
        for name in source_names:
            data = git_query([str(git_path), "cat-file", "blob", head + ":" + name],
                             INPUT_LIMIT, guard, command_records)
            blob_bytes += len(data)
            if blob_bytes > GIT_TOTAL_LIMIT:
                raise RuntimeError("separate git source-input aggregate exceeded 16 MiB")
            if len(data) != pins[name]["identity"][2] or hashlib.sha256(data).hexdigest() != pins[name]["sha256"]:
                raise RuntimeError("held source differs from committed HEAD blob")
            committed[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        control_report = controls(receipt, head, output, pins["NTWPROV.DLL"])
        guard.check(MANIFEST_LIMIT if args.retain else 0)
        for item in held.values():
            item.scan(guard=guard)
        git_file.scan(guard=guard)
        admission()
        if args.verify_existing:
            verify_manifest(existing, head, paths, pins, receipt_pin, original_bytes,
                            held[MANIFEST].initial["identity"][2])
            if existing.get("committed_sources") != committed:
                raise RuntimeError("post-upload committed source envelope changed")
            if guard.count() != original_bytes + held[MANIFEST].initial["identity"][2]:
                raise RuntimeError("post-upload exact recursive accounting changed")
            print(json.dumps({"result": "PASS_EXISTING_HANDOFF_ENVELOPE_ONLY", "head": head,
                              "manifest_sha256": held[MANIFEST].initial["sha256"],
                              "observed_output_bytes": guard.count(), "available_after_bytes": admission(),
                              "upload_action_lifetime_verified": False}, sort_keys=True))
            return
        manifest = {
            "schema": SCHEMA, "result": "PASS_HANDOFF_ENVELOPE_ONLY", "head": head,
            "github_repository": repository, "github_run_id": run, "github_run_attempt": attempt,
            "closed_result_pin": receipt_pin, "closed_output_bytes": original_bytes,
            "closed_receipt_rewritten": False, "input_pins": pins, "committed_sources": committed,
            "closed_build_source_count": 14, "extra_envelope_source_count": 2 if args.include_sources else 1,
            "optional_uploaded_source_count": 16 if args.include_sources else 0,
            "upload_paths": paths, "controls": control_report,
            "git_query_summary": {
                "commands": len(command_records),
                "zero_returncodes": sum(row["returncode"] == 0 for row in command_records),
                "reaped": sum(row["reaped"] is True for row in command_records),
                "nonreaping_exit_observed": sum(row["nonreaping_leader_exit_observed"] is True for row in command_records),
                "group_kill_requests": sum(row["group_kill_requested"] is True for row in command_records),
                "stderr_bytes": sum(row["stderr_bytes"] for row in command_records),
                "maximum_observed_seconds": max(row["elapsed_seconds"] for row in command_records),
                "command_metadata_sha256": hashlib.sha256(json.dumps(command_records, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest(),
                "individual_command_metadata_retained": False,
            }, "git_source_input_bytes": blob_bytes,
            "git_source_input_limit_bytes": GIT_TOTAL_LIMIT,
            "git_query_limit_seconds": QUERY_SECONDS,
            "observed_recursive_accounting_verified": True, "available_before_bytes": available_before,
            "minimum_observed_free_bytes_through_manifest_finalization": guard.minimum_free,
            "reserve_bytes": RESERVE, "proof_output_limit_bytes": LIMIT,
            "manifest_limit_bytes": MANIFEST_LIMIT, "post_proof_output_bytes": original_bytes,
            "original_build_flags_preserved": True,
            "upload_action_lifetime_verified": False, "upload_archive_storage_verified": False,
            "filesystem_quota_verified": False, "all_transient_peaks_observed": False,
            "loaded_code_attestation_verified": False, "permissions_changed": False,
            "git_committed_source_bytes_verified_separately": True,
            **dict.fromkeys(FALSE_SCOPE, False),
        }
        data = encode_manifest(manifest, original_bytes)
        guard.check(len(data))
        if guard.count() != original_bytes:
            raise RuntimeError("original closed bytes changed before manifest creation")
        manifest_fd = os.open(MANIFEST, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=guard.root_fd)
        manifest_inode = os.fstat(manifest_fd)
        write_all(manifest_fd, data)
        for _ in range(4):
            guard.check()
            admission()
            for item in held.values():
                item.scan(guard=guard)
            if guard.count() != original_bytes + len(data):
                raise RuntimeError("separate post-proof recursive accounting differs")
            manifest["minimum_observed_free_bytes_through_manifest_finalization"] = guard.minimum_free
            updated = encode_manifest(manifest, original_bytes)
            if updated == data:
                break
            replace_owned(manifest_fd, manifest_inode, updated)
            data = updated
        else:
            raise RuntimeError("final post-proof observations did not stabilize")
        manifest_held = Held(manifest_path, MANIFEST_LIMIT)
        try:
            if manifest_held.initial["identity"][:2] != [manifest_inode.st_dev, manifest_inode.st_ino]:
                raise RuntimeError("named manifest differs from the exclusively created owned inode")
            if manifest_held.scan(collect=True, guard=guard)[1] != data:
                raise RuntimeError("final manifest named FD/full bytes differ")
            destination = Path(os.environ.get("GITHUB_OUTPUT", ""))
            temporary = Path(os.environ.get("RUNNER_TEMP", ""))
            command_namespace(destination, temporary)
            directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                directory = os.fstat(directory_fd)
                if identity(directory) != identity(destination.parent.lstat()):
                    raise RuntimeError("command directory changed before anchoring")
                command_fd = os.open(destination.name,
                                     os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=directory_fd)
                try:
                    info = os.fstat(command_fd)
                    regular_policy(info)
                    if (info.st_uid != os.getuid() or info.st_size > COMMAND_FILE_LIMIT
                            or identity(info) != identity(destination.lstat())):
                        raise RuntimeError("bounded runner-owned named GITHUB_OUTPUT required")
                    input_inodes = {tuple(item.initial["identity"][:2])
                                    for item in (*held.values(), manifest_held)}
                    if (info.st_dev, info.st_ino) in input_inodes:
                        raise RuntimeError("command output overlaps a held input inode")
                    command_namespace(destination, temporary)
                    if identity(directory) != identity(destination.parent.lstat()):
                        raise RuntimeError("command directory changed before append")
                    digest = manifest_held.initial["sha256"]
                    delimiter = "NTW6970_" + digest
                    payload = ("handoff_paths<<" + delimiter + "\n" + "\n".join(paths) + "\n" + delimiter
                               + "\nhandoff_manifest_sha256=" + digest
                               + "\nhandoff_result=PASS_HANDOFF_ENVELOPE_ONLY\n").encode()
                    if len(payload) > MANIFEST_LIMIT or info.st_size + len(payload) > COMMAND_FILE_LIMIT:
                        raise RuntimeError("GITHUB_OUTPUT separate metadata bound exceeded")
                    write_all(command_fd, payload)
                    after = os.fstat(command_fd)
                    regular_policy(after)
                    command_namespace(destination, temporary)
                    if ((after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)
                            or after.st_size != info.st_size + len(payload)
                            or identity(directory) != identity(destination.parent.lstat())):
                        raise RuntimeError("GITHUB_OUTPUT named append accounting changed")
                    if identity(after) != identity(destination.lstat()):
                        raise RuntimeError("GITHUB_OUTPUT path identity changed")
                finally:
                    os.close(command_fd)
            finally:
                os.close(directory_fd)
            for item in (*held.values(), manifest_held):
                item.scan(guard=guard)
            if guard.count() != original_bytes + len(data):
                raise RuntimeError("final post-proof output accounting changed")
            available_after = admission()
            print(json.dumps({"result": manifest["result"], "head": head,
                              "manifest_sha256": digest, "manifest_bytes": len(data),
                              "upload_path_count": len(paths), "available_after_bytes": available_after,
                              "minimum_observed_free_bytes": guard.minimum_free,
                              "observed_output_bytes": original_bytes + len(data),
                              "upload_action_lifetime_verified": False}, sort_keys=True))
        finally:
            manifest_held.close()
    except BaseException as error:
        if manifest_fd is not None:
            # Never leave a reusable PASS after any late guard/output failure.
            # This changes only our held, new manifest; the closed receipt stays.
            failure = (json.dumps({"schema": SCHEMA, "result": "FAIL",
                       "observed_recursive_accounting_verified": False,
                       "error": str(error)[:2048], "closed_receipt_rewritten": False}) + "\n").encode()
            replace_owned(manifest_fd, manifest_inode, failure)
        raise
    finally:
        if manifest_fd is not None:
            os.close(manifest_fd)
        for item in held.values():
            item.close()
        if guard is not None:
            guard.close()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"result": "FAIL", "error": str(error)[:2048]}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
