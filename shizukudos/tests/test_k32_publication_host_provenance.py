#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the actual host receipt runner against temporary project copies.

The drift control changes only a copied deadline header after successful host
compilation. No production files or kernel guest builds are modified.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEADLINE = "shizukudos/abi/shz_sched_deadline.h"
INPUTS = ("shizukudos/tests/run_k32_publication_host.py", "shizukudos/tests/test_k32_publication.c",
          "shizukudos/kernel32/user.c", "shizukudos/kernel32/sched.c", "shizukudos/kernel32/k32.h",
          "shizukudos/kcommon/khc.h", "shizukudos/abi/shz_abi.h", DEADLINE)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--cc", default="gcc")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which(args.cc)
    if not compiler:
        ap.error(f"compiler unavailable: {args.cc}")
    original = {name: digest(REPO / name) for name in INPUTS}
    checks = []
    for name in ("unchanged", "persistent-deadline-drift"):
        folder = args.out.resolve() / name
        fixture = folder / "fixture"
        if fixture.exists():
            ap.error(f"evidence already exists: {fixture}")
        for source in INPUTS:
            target = fixture / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / source, target)
        header = fixture / DEADLINE
        header_before = digest(header)
        wrapper = folder / "compiler.py"
        wrapper.write_text("#!/usr/bin/env python3\nimport subprocess, sys\nfrom pathlib import Path\n"
                           f"result = subprocess.run([{compiler!r}, *sys.argv[1:]])\n"
                           f"header = Path({str(header)!r})\n"
                           f"if {name == 'persistent-deadline-drift'!r} and '-MM' not in sys.argv and result.returncode == 0:\n"
                           "    header.write_bytes(header.read_bytes() + b'\\n/* controlled copied-header drift */\\n')\n"
                           "raise SystemExit(result.returncode)\n")
        wrapper.chmod(0o755)
        command = [sys.executable, "-B", str(fixture / INPUTS[0]), "--cc", str(wrapper),
                   "--out", str(folder / "run")]
        run = subprocess.run(command, capture_output=True, text=True, timeout=90)
        (folder / "console.log").write_text(run.stdout + run.stderr)
        receipt = json.loads((folder / "run/result.json").read_text())
        actual_pass = receipt["compile_exit"] == receipt["run_exit"] == 0 and len(receipt["checks"]) == 17 and all(
            check["status"] == "PASS" for check in receipt["checks"])
        header_pinned = receipt["sources_sha256"].get(DEADLINE) == header_before
        drifted = header_before != digest(header)
        if name == "unchanged":
            passed = actual_pass and header_pinned and run.returncode == 0 and receipt["status"] == "PASS" and receipt["inputs_stable"] and not drifted
        else:
            passed = actual_pass and header_pinned and drifted and run.returncode == 1 and receipt["status"] == "FAIL" and not receipt["inputs_stable"]
        check = {"case": name, "status": "PASS" if passed else "FAIL", "runner_exit": run.returncode,
                 "actual_host_checks_pass": actual_pass, "deadline_header_pinned": header_pinned,
                 "fixture_header_changed": drifted, "runner_inputs_stable": receipt["inputs_stable"],
                 "fixture_header_sha256_before": header_before, "fixture_header_sha256_after": digest(header),
                 "command": command, "compiler_control_sha256": digest(wrapper)}
        checks.append(check)
        print(f"[{check['status']}] {name}: exit={run.returncode} pinned={header_pinned} drift={drifted} stable={receipt['inputs_stable']}")
    stable = original == {name: digest(REPO / name) for name in INPUTS}
    okay = stable and all(check["status"] == "PASS" for check in checks)
    result = {"profile": "actual host runner with copied project and controlled compiler; no guest execution",
              "status": "PASS" if okay else "FAIL", "checks": checks, "production_inputs_stable": stable,
              "production_sources_sha256": original, "test_sha256": digest(Path(__file__)), "compiler": compiler}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
