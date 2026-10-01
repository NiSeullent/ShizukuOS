#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Package pinned public netbase catalogs without reading host configuration.

The source recipe is data, never executed. No network or host resolver settings
are changed. Guest Winsock and real application acceptance remain separate.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

CATALOGS = Path(__file__).resolve().parents[1] / "data/network-catalogs"
APORTS_COMMIT = "24f4ccc89d6da5b337c32460c5aec8b44146cadf"
APORTS_RECIPE_SHA256 = "f8b181ad7557e80ced0d45c060b54109a9416bd7d1c0a0a1de6b015d8b8ffaf9"
RECIPE_URL = f"https://raw.githubusercontent.com/alpinelinux/aports/{APORTS_COMMIT}/main/alpine-baselayout/APKBUILD"
FILES = {"services.txt", "protocols.txt", "hosts.txt", "alpine-APKBUILD.txt", "netbase-copyright.txt", "GPL-2.txt"}
GUEST_DIRECTORY = "\\SHZ\\SYS64\\DRIVERS\\ETC\\"


def _identity(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def _read_regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024:
        raise ValueError("bounded regular catalog source required: " + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if _identity(opened) != _identity(before) or not stat.S_ISREG(opened.st_mode):
            raise ValueError("catalog source identity changed: " + path.name)
        data = stream.read(1024 * 1024 + 1)
        if len(data) != before.st_size or _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError("catalog source changed while reading: " + path.name)
    return data, _identity(before)


def load_catalogs(directory=CATALOGS):
    directory = Path(directory)
    manifest_data, manifest_identity = _read_regular(directory / "manifest.json")
    manifest = json.loads(manifest_data)
    if not isinstance(manifest, dict) or (manifest.get("schema") != "shizuku-public-network-catalogs/1" or
            manifest.get("public_sources_only") is not True or
            manifest.get("alpine_aports_commit") != APORTS_COMMIT or
            manifest.get("debian_netbase_version") != "6.4" or
            not isinstance(manifest.get("files"), dict) or set(manifest["files"]) != FILES):
        raise ValueError("exact public catalog provenance required")
    data, identities = {}, {"manifest.json": manifest_identity}
    for name in sorted(FILES):
        row = manifest["files"][name]
        value, identities[name] = _read_regular(directory / name)
        if not isinstance(row, dict) or (type(row.get("bytes")) is not int or len(value) != row["bytes"] or
                hashlib.sha256(value).hexdigest() != row.get("sha256")):
            raise ValueError("public catalog pin mismatch: " + name)
        value.decode("ascii" if name in {"services.txt", "protocols.txt", "hosts.txt"} else "utf-8")
        if b"\0" in value:
            raise ValueError("catalog text contains NUL: " + name)
        data[name] = value
    recipe = data["alpine-APKBUILD.txt"]
    if (manifest["files"]["alpine-APKBUILD.txt"].get("source_url") != RECIPE_URL or
            hashlib.sha256(recipe).hexdigest() != APORTS_RECIPE_SHA256):
        raise ValueError("public recipe URL mismatch")
    for name in ("services", "protocols"):
        expected = re.search(rb"(?m)^([0-9a-f]{128})  " + name.encode() + rb"-6\.4$", recipe)
        row = manifest["files"][name + ".txt"]
        url = f"https://salsa.debian.org/md/netbase/-/raw/v6.4/etc/{name}"
        if not expected or (row.get("source_url") != url or row.get("sha512") != expected.group(1).decode() or
                hashlib.sha512(data[name + ".txt"]).hexdigest() != row["sha512"]):
            raise ValueError("upstream recipe catalog digest mismatch: " + name)
    lines = recipe.decode("utf-8").splitlines()
    marker = '\tcat > "$pkgdir"/etc/hosts <<-EOF'
    if lines.count(marker) != 1:
        raise ValueError("exact public hosts heredoc required")
    body = []
    for line in lines[lines.index(marker) + 1:]:
        line = line.lstrip("\t")
        if line == "EOF":
            break
        body.append(line)
    else:
        raise ValueError("unterminated public hosts heredoc")
    if data["hosts.txt"] != ("\n".join(body) + "\n").encode("ascii") or manifest["files"]["hosts.txt"].get("source_url") != RECIPE_URL:
        raise ValueError("hosts must equal the public package recipe; private host data is forbidden")
    if (manifest["files"]["netbase-copyright.txt"].get("source_url") !=
            "https://salsa.debian.org/md/netbase/-/raw/v6.4/debian/copyright" or
            manifest["files"]["GPL-2.txt"].get("source_url") != "https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt" or
            b"License: GPL-2" not in data["netbase-copyright.txt"] or
            b"GNU GENERAL PUBLIC LICENSE" not in data["GPL-2.txt"]):
        raise ValueError("upstream copyright and full GPL-2 license required")
    for name, identity in identities.items():
        current, current_identity = _read_regular(directory / name)
        original = manifest_data if name == "manifest.json" else data[name]
        if current != original or current_identity != identity:
            raise ValueError("public source changed during packaging: " + name)
    members = [(GUEST_DIRECTORY + name.upper(), data[name + ".txt"]) for name in ("services", "protocols", "hosts")]
    members += [(GUEST_DIRECTORY + "NETBASE-COPYRIGHT.TXT", data["netbase-copyright.txt"]),
                (GUEST_DIRECTORY + "NETBASE-GPL2.TXT", data["GPL-2.txt"])]
    receipt = {"manifest_sha256": hashlib.sha256(manifest_data).hexdigest(), "public_sources_only": True,
               "host_configuration_read": False, "host_configuration_modified": False, "network_access": False,
               "upstream_version": "Debian netbase 6.4", "alpine_aports_commit": APORTS_COMMIT,
               "guest_Winsock_verified": False,
               "files": {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                         for name, value in members}}
    return members, receipt
