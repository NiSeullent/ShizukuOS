#!/usr/bin/env python3
"""Retain only exact official Node/Electron public Node-API headers.

SPDX-License-Identifier: GPL-2.0-only
Downloads header archives into bounded memory, never app/runtime packages.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

SELECTED = ("node_api.h", "node_api_types.h", "js_native_api.h",
            "js_native_api_types.h", "node_version.h")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def get(url, limit):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Official header download exceeds its bounded scope")
        return data, response.url


def headers(base, name, mode):
    checks, checks_url = get(base + "SHASUMS256.txt", 65536)
    expected = next(line.split()[0] for line in checks.decode().splitlines()
                    if line.split()[-1] == name)
    data, url = get(base + name, 8 * 1024 ** 2)
    if digest(data) != expected:
        raise ValueError("Official complete header archive checksum differs")
    selected = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as archive:
        for member in archive:
            basename = Path(member.name).name
            if basename in SELECTED and member.name.endswith("/include/node/" + basename):
                if basename in selected or not member.isfile() or member.size > 65536:
                    raise ValueError("Public header inventory/type/size differs")
                selected[basename] = archive.extractfile(member).read()
    if set(selected) != set(SELECTED):
        raise ValueError("Exact public Node-API header set is incomplete")
    return selected, {"url": url, "bytes": len(data), "sha256": expected,
                      "checksums_url": checks_url, "checksums_sha256": digest(checks)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Preserve the existing exact header extraction")
    node, node_receipt = headers("https://nodejs.org/download/release/v24.18.0/",
                                "node-v24.18.0-headers.tar.xz", "r:xz")
    electron, electron_receipt = headers("https://electronjs.org/headers/v43.2.0/",
                                         "node-v43.2.0-headers.tar.gz", "r:gz")
    matching = [basename for basename in SELECTED[:4]
                if node[basename] == electron[basename]]
    differing = [basename for basename in SELECTED if node[basename] != electron[basename]]
    deps, deps_url = get("https://raw.githubusercontent.com/electron/electron/v43.2.0/DEPS", 65536)
    if b"'v24.18.0'" not in deps or b"'150.0.7871.129'" not in deps:
        raise ValueError("Exact Electron bundled runtime pins differ")
    license_data, license_url = get("https://raw.githubusercontent.com/nodejs/node/v24.18.0/LICENSE", 512 * 1024)
    # Retain the complete leading Node MIT notice, excluding the separately
    # licensed third-party components that are not extracted or linked here.
    end = license_data.find(b"\n\n- ")
    if end < 0:
        end = license_data.find(b"\n\nThe following")
    if not 0 < end <= 10000:
        raise ValueError("Official leading MIT notice delimiter changed")
    notice = license_data[:end] + b"\n"
    if sum(map(len, node.values())) + sum(map(len, electron.values())) + len(deps) + len(notice) > 180000:
        raise ValueError("Selected source evidence exceeds its small budget")
    args.output.mkdir(parents=True, mode=0o700)
    for name, mapping in (("node", node), ("electron", electron)):
        (args.output / name).mkdir()
        for basename, data in mapping.items():
            (args.output / name / basename).write_bytes(data)
    (args.output / "electron-DEPS").write_bytes(deps)
    (args.output / "Node-MIT-NOTICE").write_bytes(notice)
    files = [{"path": str(path.resolve()), "bytes": path.stat().st_size,
              "sha256": digest(path.read_bytes())}
             for path in sorted(args.output.rglob("*")) if path.is_file()]
    receipt = {"schema": "legcord-win9x-exact-node-api-header-extraction-v1",
               "node_archive": node_receipt, "electron_archive": electron_receipt,
               "electron_deps": {"url": deps_url, "sha256": digest(deps)},
               "license": {"url": license_url, "whole_sha256": digest(license_data),
                           "retained_MIT_notice_sha256": digest(notice)},
               "selected_headers_identical": matching,
               "selected_headers_different": differing,
               "addon_compile_headers": "Exact Electron43.2.0 generated headers; Node24.18.0 headers are an independent signature compile control",
               "files": files,
               "archives_saved": False, "runtime_downloaded_or_executed": False}
    path = args.output / "extraction.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"receipt": str(path), "sha256": digest(path.read_bytes()),
                      "retained_bytes": sum(row["bytes"] for row in files)}))


if __name__ == "__main__":
    main()
