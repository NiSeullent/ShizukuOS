#!/usr/bin/env python3
"""Memory-only Zetscape fixture syntax/inventory checks. No browser execution.

SPDX-License-Identifier: MIT
"""
import argparse
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess

HERE = Path(__file__).resolve().parent
APP = HERE.parent
ROOT = HERE.parents[2]
PAYLOAD = ("index.html", "harness.js", "layout.js", "canvas.js", "async.mjs", "counter.mjs", "fetch_payload.json")


def pin(path):
    path = path.resolve()
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("Fixture input changed during inspection")
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class FixtureHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.ids, self.csp, self.inline = [], [], None, False
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.append(values["id"])
        if any(key.lower().startswith("on") for key in values):
            raise ValueError("No inline event handlers in the strict fixture CSP")
        if tag == "script":
            self.in_script = True
            self.scripts.append(values)
        if tag == "meta" and values.get("http-equiv", "").lower() == "content-security-policy":
            self.csp = values.get("content")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script and data.strip():
            self.inline = True


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    receipt = args.receipt.resolve()
    if receipt.exists() or not receipt.is_relative_to(ROOT / "build"):
        raise ValueError("Require a new private build receipt")
    acceptance = APP / "fixtures/modern_web_acceptance.json"
    abi_pin = APP / "engine_abi_pin.json"
    files = [*[HERE / name for name in PAYLOAD], HERE / "README.md", HERE / "LICENSE", Path(__file__), acceptance, abi_pin]
    node = Path(shutil.which("node"))
    files.append(node)
    frozen = json.loads(abi_pin.read_text())
    for row in frozen["inputs"]:
        path = Path(row["local"])
        if pin(path)["sha256"] != row["sha256"]:
            raise ValueError("The real shared engine ABI/source snapshot changed")
        files.append(path)
    before = {str(path.resolve()): pin(path) for path in files}
    owned = [*[HERE / name for name in PAYLOAD], HERE / "README.md", HERE / "LICENSE", Path(__file__), acceptance]
    if sum(path.stat().st_size for path in owned) > 256 * 1024:
        raise ValueError("Fixture source exceeds its bounded256KiB scope")
    report = {"schema": "zetscape-fixture-source-checkpoint-v1", "inputs": list(before.values()),
              "acceptance_plan_path": str(acceptance),
              "commands": [], "source_checks_passed": False, "page_executed": False,
              "native_engine_executed": False, "provider_pass": False, "ordinary_win98se_pass": False,
              "gpu_pass": False, "full_modern_web_pass": False,
              "child_cpu_limit_seconds": 45, "child_file_output_limit_bytes": 0}
    try:
        plan = json.loads(acceptance.read_text())
        if plan["schema"] != "zetscape.modern-web-acceptance.v1" or any(plan[key] is not False for key in
                ("actual_native_run", "representative_fixture_pass", "ordinary_win98se_pass", "shizuku_gpu_pass", "full_modern_web_pass")):
            raise ValueError("Unexecuted source fixture cannot predeclare native/full-target acceptance")
        harness = (HERE / "harness.js").read_text(encoding="utf8")
        match = re.search(r"const expected = \[(.*?)\];", harness, re.S)
        if not match:
            raise ValueError("Missing explicit page assertion inventory")
        identifiers = re.findall(r"'([a-z_]+\.[a-z_]+)'", match[1])
        if identifiers != plan["fixture"]["expected_assertions"] or len(set(identifiers)) != len(identifiers):
            raise ValueError("Page assertion inventory differs from acceptance contract")
        html = FixtureHTML(); html.feed((HERE / "index.html").read_text(encoding="utf8")); html.close()
        if html.inline or not html.csp or "script-src 'self'" not in html.csp or "connect-src 'self'" not in html.csp:
            raise ValueError("Fixture does not keep its declared local-resource/CSP boundary")
        if len(html.ids) != len(set(html.ids)):
            raise ValueError("Duplicate fixture DOM IDs")
        for row in html.scripts:
            if not row.get("src") or row["src"] not in PAYLOAD:
                raise ValueError("Unfrozen or external script input")
        if html.scripts[0].get("type") != "module" or html.scripts[0].get("id") != "module-fixture" or \
                html.scripts[1].get("src") != "harness.js":
            raise ValueError("Real module element must exist when classic harness registers its error listener")
        for name in PAYLOAD:
            (HERE / name).read_text(encoding="utf8")
        payload = json.loads((HERE / "fetch_payload.json").read_text(encoding="utf8"))
        if payload != {"fixture": "zetscape-loopback-v1", "message": "한글 Ω", "number": 42}:
            raise ValueError("Local fetch bytes differ from the independent fixture expectation")
        for name in PAYLOAD:
            if not name.endswith((".js", ".mjs")):
                continue
            argv = [str(node), "--max-old-space-size=128", "--check", str(HERE / name)]
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       cwd=ROOT, start_new_session=True, preexec_fn=limits)
            try:
                data, _ = process.communicate(timeout=45)
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL); process.wait(); raise
            if len(data) > 65536:
                raise ValueError("Syntax check output exceeded memory bound")
            report["commands"].append({"argv": argv, "returncode": process.returncode,
                                       "output": data.decode("utf8", errors="replace")})
            if process.returncode:
                raise ValueError("Actual JavaScript syntax check failed: " + name)
        for key, row in before.items():
            if pin(Path(key)) != row:
                raise ValueError("Exact fixture/ABI/parser input changed during validation")
        report["source_checks_passed"] = True
        report["assertion_count"] = len(identifiers)
        report["frozen_payload_count"] = len(PAYLOAD)
        report["all_inputs_unchanged"] = True
    except BaseException as error:
        report["failure"] = str(error)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    report["children_cpu_seconds"] = usage.ru_utime + usage.ru_stime
    report["children_peak_resident_kib"] = usage.ru_maxrss
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with receipt.open("x") as stream:
        json.dump(report, stream, indent=2); stream.write("\n")
    print(json.dumps({"receipt": pin(receipt), "source_checks_passed": report["source_checks_passed"],
                      "failure": report.get("failure"), "children_cpu_seconds": report["children_cpu_seconds"]}))
    if not report["source_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
