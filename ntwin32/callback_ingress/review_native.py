#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Review STOPPED own native ingress logs; no VM/disk/process operations."""
import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build/callback-ingress-c009-20261001-v4"
MANIFEST_SHA = "81ff086abc7fc7401fb5e9556dcb928450e12206d8de83f604b734497202112e"
BUILD_SHA = "f16035917f678a8020d394a1a93f958d2d21826f13512cb71490a252d9137f61"
RUNNER_SHA = "5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857"
COLD = ROOT / "build/shizukudos/csm/run-win98-gop-latest-npp-cold-v3-20260930T1807"
EXPECTED = {
    "NOTIFICATION_CURRENT_NATIVE_TLS": 4, "NOTIFICATION_REENTRY_REFUSED": 4,
    "MAPPED_THREAD_NOTIFICATION": 4, "ACTUAL_PROVIDER_WORKER_ADMITTED": 2,
    "REUSED_MAPPED_COMPILER_TLS_128_CALLS": 2, "PROVIDER_UNRELATED_NATIVE_TLS_PRESERVED": 2,
    "CLOSING_PREVENTS_NEW_CALLBACK": 2, "ACTUAL_PROVIDER_WORKER_RETIRED": 2,
    "RETIRED_HANDLE_REFUSED": 2, "PROVIDER_OWNED_NATIVE_TLS_CLEARED": 2,
    "ACTUAL_WIN98_TLS_BACKEND": 1, "UNRELATED_NATIVE_SLOT_ALLOCATED": 1,
    "MAIN_NATIVE_EXTERNAL_SLOT_SET": 1, "INGRESS_MANAGER_OPEN": 1,
    "REAL_NATIVE_PROVIDER_THREAD_CREATED": 2, "PERSISTENT_WORKERS_REGISTERED_ONCE": 1,
    "OTHER_THREAD_CANNOT_ENTER": 1, "OTHER_THREAD_CANNOT_RETIRE": 1,
    "LOGICAL_CLOSE_STARTED": 1, "CLOSE_RETAINS_LIVE_WORKERS": 1,
    "ACTUAL_PROVIDER_THREAD_EXIT_QUERIED": 2, "ACTUAL_PROVIDER_THREAD_EXIT_ZERO": 2,
    "ACTUAL_PROVIDER_THREAD_HANDLE_CLOSED": 2, "PROVIDER_READY_EVENT_CLOSED": 2,
    "PROVIDER_GATE_EVENT_CLOSED": 2, "PROVIDER_LOGICAL_RETIREMENT_COMPLETE": 1,
    "TLS_THREAD_NOTIFICATIONS_ONCE_EACH": 1, "DETACH_READS_ACTUAL_WORKER_TLS": 1,
    "MAPPED_NOTIFICATION_FAILURES_ZERO": 1, "MAIN_COMPILER_TLS_STILL_ISOLATED": 1,
    "MAIN_UNRELATED_NATIVE_TLS_PRESERVED": 1, "MAPPED_PROCESS_DETACH": 1,
    "MAIN_TLS_DETACHED": 1, "PLAN_DISPOSED_AFTER_REAL_WORKER_JOIN": 1,
    "ORIGINAL_MAPPED_TLS_INDEX_RESTORED": 1, "ORIGINAL_FIXTURE_UNCHANGED": 1,
    "MAPPED_CODE_UNCHANGED": 1, "UNRELATED_NATIVE_SLOT_CLEARED": 1,
    "UNRELATED_NATIVE_SLOT_FREED": 1, "MAPPED_IMAGE_RELEASED_AFTER_JOIN": 1,
    "ORIGINAL_FILE_STORAGE_RELEASED": 1,
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bounded(path, limit=1024 * 1024):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and 0 < p.stat().st_size <= limit, "bounded ordinary file required: " + str(p))
    raw = p.read_bytes()
    require(len(raw) <= limit, "file changed beyond budget")
    return raw


def exact_report(raw):
    require(0 < len(raw) <= 16384 and raw.endswith(b"\r\n"), "complete bounded native CRLF log required")
    rows = raw.decode("ascii").split("\r\n")[:-1]
    require(all("\r" not in r and "\n" not in r and "\x00" not in r for r in rows), "exact ASCII rows required")
    require(not any(r.startswith(("FAIL=", "REFUSAL=", "PREPARATION_FAILED=", "GUARD_")) for r in rows), "real native failure/refusal retained")
    return rows


def one(rows, key):
    values = [r[len(key) + 1:] for r in rows if r.startswith(key + "=")]
    require(len(values) == 1, "one exact field required: " + key)
    return values[0]


def hexadecimal(rows, key):
    value = one(rows, key)
    require(re.fullmatch(r"[0-9A-F]{8}", value) is not None, "exact hex value required: " + key)
    return int(value, 16)


def fnv(raw):
    value = 2166136261
    for byte in raw:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value


def parse_probe(raw, fixture):
    rows = exact_report(raw)
    require(one(rows, "SCOPE") == "OWN_MAPPED_TLS_PROVIDER_WORKER_INGRESS", "probe scope differs")
    require(one(rows, "APPLICATION_SUCCESS") == "0" and one(rows, "PRODUCTION_PROVIDER_INTEGRATED") == "0", "scope must not promote app/provider acceptance")
    require(one(rows, "STATUS") == "PASS" and hexadecimal(rows, "FAILURES") == 0, "native probe failed")
    observed = Counter(r[len("PASS="):] for r in rows if r.startswith("PASS="))
    require(observed == Counter(EXPECTED), "native semantic controls/counts differ")
    require(hexadecimal(rows, "CHECKS") == sum(EXPECTED.values()), "native aggregate count differs")
    require(hexadecimal(rows, "ORIGINAL_FIXTURE_BYTES") == len(fixture) and
            hexadecimal(rows, "ORIGINAL_FIXTURE_FNV1A") == fnv(fixture), "actual loaded own fixture identity differs")
    require(one(rows, "OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER") == "1", "probe self exit claim differs")
    return {"native_checks": sum(EXPECTED.values()), "persistent_workers": 2,
            "mapped_ms_abi_tls_calls": 256, "thread_notification_attach_detach_each": 2,
            "worker_os_exit_zero_count": 2, "real_provider_integrated": False}


def parse_suite(raw):
    rows = exact_report(raw)
    require(one(rows, "SCOPE") == "OWN_MAPPED_PROVIDER_INGRESS_OBSERVER" and one(rows, "APPLICATION_SUCCESS") == "0", "observer scope differs")
    require(hexadecimal(rows, "ACTUAL_CHILD_PID") != 0 and hexadecimal(rows, "ACTUAL_WAIT") == 0 and
            hexadecimal(rows, "ACTUAL_CHILD_OS_EXIT") == 0, "actual observed native child exit/wait differs")
    require(one(rows, "STATUS") == "SCOPED_NATIVE_INGRESS_PASS", "actual child/log aggregate failed")
    require(one(rows, "SUITE_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER") == "1", "suite own exit must stay unknown")
    return {"actual_probe_pid": hexadecimal(rows, "ACTUAL_CHILD_PID"),
            "actual_probe_os_exit": 0, "actual_probe_wait": 0,
            "suite_own_os_exit": None, "suite_own_os_exit_verified": False}


def ensure_stopped(run):
    # This reads process metadata only; no signal, monitor, image or guest tool.
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        if path.parent.name == str(os.getpid()):
            continue
        try:
            args = path.read_bytes().split(b"\0")
        except (OSError, PermissionError):
            continue
        joined = b" ".join(args)
        if ((b"qemu" in joined and str(run / "windows-uefi.raw").encode() in joined) or
                (b"test_win98_uefi.py" in joined and run.name.encode() in joined)):
            raise ValueError("owned native runner/VM is still live; stopped-log review refused")


def review(run, result_sha, launch_path, launch_sha):
    run = run.resolve(strict=True)
    require(run.parent == ROOT / "build/shizukudos/csm" and run.name.startswith("run-win98-gop-callback-c009-20261001-"), "only assigned own callback run allowed")
    ensure_stopped(run)
    pins = {}

    def json_file(path, expected=None):
        raw = bounded(path)
        digest = hashlib.sha256(raw).hexdigest()
        require(expected is None or digest == expected, "pinned JSON changed: " + str(path))
        pins[str(path)] = digest
        return json.loads(raw)

    result = json_file(run / "result.json", result_sha)
    require(result.get("qemu_exit_code") == 0 and result.get("manual_finish_requested") is True and
            result.get("originals_unchanged") is True and result.get("prepared_source_unchanged") is True,
            "completed genuine runner/preservation not established")
    require(result.get("status") in ("NEEDS-VISUAL-REVIEW", "PASS") and result.get("profile") == "actual-win98-uefi-csmwrap" and
            result.get("firmware_gop_opt_in") is True, "native GOP runner profile differs")
    require(result.get("minimum_free_bytes", 0) >= 20 * 1024 ** 3, "native guard floor was weakened")
    hardware = result["hardware"]
    require(hardware.get("network") == "none" and hardware.get("reserve_gib") == 20 and
            hardware.get("resume_owned_run") == str(COLD) and hardware.get("manual_purpose") == "diagnostic",
            "cold native private/no-network scope differs")
    command = result["command"]
    require("-nic" in command and command[command.index("-nic") + 1] == "none" and
            not any(x in command for x in ("-loadvm", "-incoming")), "cold QEMU/no-network command differs")
    require(sha(run / "runner-source.py") == RUNNER_SHA, "frozen actual runner source differs")
    pins[str(run / "runner-source.py")] = RUNNER_SHA
    launch_path = launch_path.resolve(strict=True)
    require(launch_path.parent == ROOT / "build" and launch_path.name.startswith("callback-native-c009-launch-"), "assigned parent launch receipt required")
    launch = json_file(launch_path, launch_sha)
    require(launch["runner_sha256"] == RUNNER_SHA and launch["manifest_sha256"] == MANIFEST_SHA and
            launch["frozen_build_receipt_sha256"] == BUILD_SHA and launch["native_lane_quiet_before_launch"] is True,
            "parent launch binding differs")
    require(run.name in launch["argv"] and str(BUILD / "manifest.json") in launch["argv"] and
            str(COLD) in launch["argv"] and launch["free_before"] >= launch["minimum_required_free"] >=
            20 * 1024 ** 3 + 256 * 1024 ** 2, "parent launch scope/reserve differs")
    manifest = json_file(BUILD / "manifest.json", MANIFEST_SHA)
    build = json_file(BUILD / "result.json", BUILD_SHA)
    require(build["status"] == "HOST_BUILD_PASS_NATIVE_PENDING" and
            build["sources_unchanged_during_validation"] is True, "frozen host/native compile prerequisite missing")
    require(manifest["command"] == "C:\\VXDLAB\\CISUIT.EXE" and len(manifest["inputs"]) == 3, "frozen native command/input scope differs")
    for name, digest in build["sources"].items():
        path = BUILD / "frozen" / name
        require(sha(path) == digest, "frozen actual source changed: " + name)
        pins[str(path)] = digest
    source = json_file(COLD / "result.json")
    reuse = result["prepared_reuse"]
    require(reuse["source_run"] == str(COLD) and reuse["source_receipt_sha256"] == pins[str(COLD / "result.json")] and
            reuse["source_disk_sha256"] == source["owned_disk_sha256_after_run"] and
            "cold hardware" in reuse["method"] and "no CPU/RAM state" in reuse["method"], "retained cold GOP clone lineage differs")
    require(source["qemu_exit_code"] == 0 and source["originals_unchanged"] is True and source["firmware_gop_opt_in"] is True,
            "prior cold GOP source result differs")
    files = result["guest_files"]
    require(files["manifest_sha256"] == MANIFEST_SHA and files["output_baseline"] == "all absent before private injection" and
            files["immutable_sources_unchanged"] is True, "fresh actual guest input/output ownership differs")
    require(len(files["inputs"]) == 3 and files["outputs"] == manifest["outputs"] and
            not files.get("backups") and not files.get("installed_gop_replacement"), "guest input/change scope differs")
    artifacts = {x["guest"]: x for x in manifest["inputs"]}
    fixture = None
    for item in files["inputs"]:
        expected = artifacts[item["guest"]]
        path = Path(item["source"])
        raw = bounded(path)
        require(len(raw) == expected["bytes"] == item["bytes"] and hashlib.sha256(raw).hexdigest() ==
                expected["sha256"] == item["sha256"] == item["private_copy_sha256"], "actual native binary/copy binding differs")
        pins[str(path)] = expected["sha256"]
        copy = run / ("prepared-guest-" + item["guest"].rsplit("\\", 1)[1])
        require(sha(copy) == expected["sha256"], "retained prepared guest readback differs")
        pins[str(copy)] = expected["sha256"]
        if item["guest"].endswith("\\CIFIX.DLL"):
            fixture = raw
    require(fixture is not None, "own mapped compiler TLS DLL absent")
    captures = {x["guest"]: x for x in files["readback"]}
    require(len(files["readback"]) == 2 and set(captures) == set(manifest["outputs"]), "two native output readbacks required")
    reports = {}
    for guest, item in captures.items():
        path = Path(item["path"]).resolve(strict=True)
        require(path.parent == run and path.name == "guest-output-" + guest.rsplit("\\", 1)[1] and
                item["status"] == "captured" and item["freshness"] == "new-in-owned-run", "stopped fresh native output capture differs")
        raw = bounded(path, 16384)
        require(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"], "actual native raw log binding differs")
        pins[str(path)] = item["sha256"]
        reports[guest] = raw
    probe = parse_probe(reports["C:\\VXDLAB\\CIWRK.LOG"], fixture)
    suite = parse_suite(reports["C:\\VXDLAB\\CISUIT.LOG"])
    # No archive/disk opens: exact hashes and preservation are runner evidence,
    # bound through its completed receipt and the cold-source receipt above.
    ensure_stopped(run)
    require(all(sha(path) == digest for path, digest in pins.items()), "bound evidence changed during stopped review")
    return {"schema": "win98modern.callback-ingress-native-review.v1",
            "status": "SCOPED_NATIVE_INGRESS_ACCEPTED",
            "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "run": str(run), "evidence_sha256": pins,
            "native_probe": probe, "native_observer": suite,
            "cold_gop_lineage": {"source": str(COLD), "source_receipt_sha256": reuse["source_receipt_sha256"],
                                 "source_disk_sha256_from_runner": reuse["source_disk_sha256"],
                                 "fresh_private_post_disk_sha256_from_runner": result["owned_disk_sha256_after_run"],
                                 "disk_rehashed_by_reviewer": False},
            "native_windows98_tls_verified_for_own_fixture": True,
            "gop_pixels_visually_verified_by_this_checker": False,
            "suite_own_os_exit_verified": False,
            "application_success": False, "production_provider_integrated": False,
            "production_loader_integration_accepted": False,
            "limitations": ["Only the own zero-import mapped MS-ABI TLS DLL and two cooperating persistent native workers are tested.",
                            "Provider hook installation, real thread-handle join ownership, other callback facilities and abrupt exits remain unsupported.",
                            "The suite observes CIWRK child exit; its own OS exit needs an independent outer observer.",
                            "Cold native/GOP lineage is bound to the actual runner; screenshots require separate visual review. No VM/disk was opened by this checker."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--result-sha256", required=True)
    parser.add_argument("--launch", required=True, type=Path)
    parser.add_argument("--launch-sha256", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build") or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (args.result_sha256, args.launch_sha256)):
        parser.error("new own build output and exact completed runner result SHA-256 required")
    try:
        outcome = review(args.run, args.result_sha256, args.launch, args.launch_sha256)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, IndexError) as error:
        outcome = {"status": "FAIL_NATIVE_EVIDENCE_NOT_ESTABLISHED", "error": str(error),
                   "application_success": False, "production_provider_integrated": False,
                   "production_loader_integration_accepted": False, "suite_own_os_exit_verified": False}
    outcome["reviewer_sha256"] = sha(__file__)
    out.mkdir(parents=True)
    result = out / "result.json"
    result.write_text(json.dumps(outcome, indent=2) + "\n")
    print(json.dumps({"status": outcome["status"], "result": str(result), "sha256": sha(result), "error": outcome.get("error")}))
    return 0 if outcome["status"] == "SCOPED_NATIVE_INGRESS_ACCEPTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
