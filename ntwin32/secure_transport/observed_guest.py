#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and freeze an exact native TLS exit observer; never starts a guest."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def build(output):
    output = output.absolute()
    require(not output.exists(), "Preserve earlier observer builds")
    source = HERE / "guest_observer.c"
    frozen = source.read_bytes()
    output.mkdir(parents=True, mode=0o700)
    snapshot = output / "guest_observer.c"
    snapshot.write_bytes(frozen)
    compiler = shutil.which("i686-w64-mingw32-gcc")
    require(bool(compiler), "Installed x86 MinGW compiler required")
    binary = output / "TLSWATCH.EXE"
    argv = [compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-Os", "-march=i486",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-nostdlib",
            "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400",
            "-Wl,--entry,_mainCRTStartup,--subsystem,windows:4.10,--no-insert-timestamp",
            "-Wl,--major-os-version,4,--minor-os-version,10", str(snapshot),
            "-lkernel32", "-o", str(binary)]
    result = subprocess.run(argv, capture_output=True, timeout=60)
    (output / "build.log").write_bytes(result.stdout + result.stderr)
    receipt = {"schema": "win98modern.tls-native-observer.v1",
               "source": {"path": str(source), "sha256": hashlib.sha256(frozen).hexdigest()},
               "source_snapshot": {"path": str(snapshot), "sha256": sha(snapshot)},
               "builder_sha256": sha(Path(__file__)), "compiler_argv": argv,
               "compile_returncode": result.returncode, "native_guest_verified": False}
    try:
        require(result.returncode == 0, "Observer compilation failed")
        spec = importlib.util.spec_from_file_location("transport_build", HERE / "build.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        receipt["binary"] = {"path": str(binary), "sha256": sha(binary),
                             "bytes": binary.stat().st_size, "pe_audit": helper.audit_pe(binary)}
        require(receipt["binary"]["pe_audit"]["static_gate_passed"], "Observer native PE gate failed")
        require(source.read_bytes() == frozen, "Observer source changed during build")
        receipt["status"] = "PASS"
    except Exception as error:
        receipt["status"] = "FAIL"
        receipt["error"] = str(error)
        raise
    finally:
        (output / "observer-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return {"receipt": str(output / "observer-result.json"), "sha256": sha(output / "observer-result.json"),
            "binary": receipt["binary"], "native_guest_verified": False}


def freeze(parent, parent_sha, observer, observer_sha, output, nonce):
    parent, observer, output = parent.resolve(), observer.resolve(), output.absolute()
    require(not output.exists(), "Require a new private frozen directory")
    require(re.fullmatch(r"[A-Za-z0-9_-]{16,64}", nonce), "Require safe fresh observer nonce")
    require(sha(parent) == parent_sha and sha(observer) == observer_sha, "Frozen receipt hash mismatch")
    old = json.loads(parent.read_text())
    obs = json.loads(observer.read_text())
    require(old["schema"] == 1 and old["kind"] == "isolated-guest-file-inputs" and
            len(old["inputs"]) == 8 and old["guest_execution"] == "NOT-VERIFIED", "Wrong parent fixture")
    require(obs["schema"] == "win98modern.tls-native-observer.v1" and obs["status"] == "PASS" and
            obs["native_guest_verified"] is False and obs["binary"]["pe_audit"]["static_gate_passed"],
            "Observer must have native build-only PASS")
    binary = Path(obs["binary"]["path"])
    require(sha(binary) == obs["binary"]["sha256"] and
            sha(Path(obs["source"]["path"])) == obs["source"]["sha256"], "Observer changed")
    rows = [row for row in old["inputs"] if row["guest"] != r"C:\GOPLAB\TLSRUN.BAT"]
    require(len(rows) == 7 and len({row["guest"] for row in rows}) == 7, "Wrong TLS fixture inputs")
    for row in rows:
        source = Path(row["source"])
        require(source.resolve().is_relative_to(parent.parent) and
                source.stat().st_size == row["bytes"] and sha(source) == row["sha256"], "Parent input changed")
    for row in old["source_receipts"]:
        require(sha(Path(row["path"])) == row["sha256"], "Parent source receipt changed")
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for row in rows + [{"source": str(binary), "guest": r"C:\GOPLAB\TLSWATCH.EXE",
                        "bytes": obs["binary"]["bytes"], "sha256": obs["binary"]["sha256"]}]:
        name = row["guest"].rsplit("\\", 1)[1]
        require(re.fullmatch(r"[A-Z0-9]{1,8}\.[A-Z0-9]{1,3}", name) and
                0 < row["bytes"] <= 1024 ** 2, "Guest input exceeds DOS8.3/size scope")
        target = output / name
        shutil.copyfile(row["source"], target)
        require(sha(target) == row["sha256"], "Frozen input copy changed")
        inputs.append(dict(row, source=str(target)))
    receipts = []
    for index, original in enumerate([parent, observer, Path(obs["source"]["path"])] +
                                     [Path(row["path"]) for row in old["source_receipts"]]):
        target = output / ("source-receipt-" + str(index) + "-" + original.name)
        target.write_bytes(original.read_bytes())
        receipts.append({"path": str(target), "sha256": sha(target), "origin": str(original)})
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                "outputs": [r"C:\GOPLAB\TLS13.LOG", r"C:\GOPLAB\TLSOBS.LOG"],
                "backups": [], "source_receipts": receipts, "nonce": nonce,
                "command": r"C:\GOPLAB\TLSWATCH.EXE --nonce " + nonce,
                "parent_fixture_sha256": parent_sha, "observer_receipt_sha256": observer_sha,
                "post_crt_exit_required": True, "guest_execution": "NOT-VERIFIED",
                "network_required": False,
                "scope": "Offline real TLS records/native OS entropy/clock and exact child exit only; no OS provider or app claim"}
    target = output / "guest-files.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    return {"manifest": str(target), "sha256": sha(target), "inputs": len(inputs),
            "nonce": nonce, "command": manifest["command"], "guest_execution": "NOT-VERIFIED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    b = sub.add_parser("build")
    b.add_argument("--output", type=Path, required=True)
    f = sub.add_parser("freeze")
    f.add_argument("--parent", type=Path, required=True)
    f.add_argument("--parent-sha256", required=True)
    f.add_argument("--observer", type=Path, required=True)
    f.add_argument("--observer-sha256", required=True)
    f.add_argument("--output", type=Path, required=True)
    f.add_argument("--nonce", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output) if args.action == "build" else
                     freeze(args.parent, args.parent_sha256, args.observer, args.observer_sha256,
                            args.output, args.nonce)))


if __name__ == "__main__":
    main()
