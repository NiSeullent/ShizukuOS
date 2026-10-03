#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise exact socket-extension, IRP and handle bodies with injected TCP states.

Transport callbacks are adapters, not proof of a host/guest network connection.
The separate t_net_extensions.exe exercises the real loopback/TCP/IPv4 path.
"""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def function(source, name):
    import re
    match = re.search(r"(?m)^[^\n;{}]*\b" + re.escape(name) + r"\s*\([^;]*?\)\s*(?:/\*[^\n]*?\*/\s*)?\{", source)
    if not match:
        raise ValueError(name)
    start = source.index("{", match.start())
    depth, i, state = 1, start + 1, "code"
    while depth:
        c, following = source[i], source[i:i + 2]
        if state == "line":
            if c == "\n": state = "code"
        elif state == "block":
            if following == "*/": state, i = "code", i + 1
        elif state in ("'", '"'):
            if c == "\\": i += 1
            elif c == state: state = "code"
        elif following == "//": state, i = "line", i + 1
        elif following == "/*": state, i = "block", i + 1
        elif c in ("'", '"'): state = c
        elif c == "{": depth += 1
        elif c == "}": depth -= 1
        i += 1
    return source[match.start():i] + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--irp-prepare-source", type=Path, help="counterfactual irp_prepare body, all other production inputs unchanged")
    args = parser.parse_args()
    w64 = Path(__file__).resolve().parents[1]
    kernel = w64.parent / "kernel64"
    paths = [kernel / name for name in ("net.h", "net_sock.c", "net_sock_extensions.h", "ipc.h", "ipc_io.c", "ipc_core.c", "objects.c", "sysk32_auth.c")]
    steam = w64.parent.parent / "ntwin32/steam_socket"
    paths += [steam / name for name in ("accept_op.c", "accept_op.h", "accept_buffer.c", "accept_buffer.h", "acceptex_sockaddrs.c")]
    paths += [w64 / "dlls/ws2_32/ws2_extensions.c", w64 / "dlls/ws2_32/ws2_extensions.h", w64 / "tests/test_net_extensions_host.c"]
    snapshots = {path: path.read_bytes() for path in paths}
    sources = {path.name: data.decode("utf-8") for path, data in snapshots.items()}
    io = sources["ipc_io.c"]
    irp = io[io.index("static irp_t *all_irps;"):io.index("/* ---------------------------------------------------------------- I/O completion ports */")]
    if args.irp_prepare_source:
        before = args.irp_prepare_source.read_bytes()
        irp = irp.replace(function(io, "irp_prepare").rstrip(), function(before.decode("utf-8"), "irp_prepare").rstrip(), 1)
    irp += function(io, "ipc_set_completion_info") + function(io, "ipc_query_completion_info")
    # Real handle authorization gate (sysk32_auth.c) consulted by the real objects.c handle bodies.
    auth = function(sources["sysk32_auth.c"], "shz_auth_handle_allowed")
    objects = "".join(function(sources["objects.c"], n) for n in ("handle_insert", "handle_ref", "handle_close", "obj_signaled"))
    core = "".join(function(sources["ipc_core.c"], n) for n in ("ipc_handle_opened", "ipc_give_handle", "ipc_handle_closed"))
    sock = "".join(function(sources["net_sock.c"], n) for n in ("sock_close_locked", "net_socket_handle_closing", "net_socket_last_handle_closed", "get_sock", "read_sa", "sock_initial_flags"))
    net = sources["net.h"]
    types = net[net.index("enum { SK_STREAM"):net.index("/* ---- syscall front end ---- */")]
    ipc = sources["ipc.h"]
    types += ipc[ipc.index("enum { IRP_READ"):ipc.index("/* Posts a completion packet")]
    with tempfile.TemporaryDirectory(prefix="win98-net-extensions-") as folder:
        temp = Path(folder)
        # Compiler inputs must be immutable while other agents edit the checkout.
        for path, data in snapshots.items():
            # Repo-relative layout: net_sock_extensions.h includes ../../ntwin32/steam_socket/accept_op.c.
            target = temp / path.relative_to(w64.parent.parent)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for name, text in (("production_types.h", types), ("production_irp.h", irp), ("production_auth.h", auth),
                           ("production_objects.h", objects), ("production_core.h", core), ("production_sock.h", sock)):
            (temp / name).write_text(text)
        flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-parameter"]
        if args.sanitize: flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        executable = temp / "net-test"
        subprocess.run([args.cc, *flags, "-I", str(temp), str(temp / paths[-1].relative_to(w64.parent.parent)), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
        print(json.dumps({"compiler": args.cc, "sanitize": args.sanitize,
                          "counterfactual_prepare": str(args.irp_prepare_source) if args.irp_prepare_source else None,
                          "sources": {str(path.relative_to(w64.parent.parent)): hashlib.sha256(data).hexdigest() for path, data in snapshots.items()}}))


if __name__ == "__main__":
    main()
