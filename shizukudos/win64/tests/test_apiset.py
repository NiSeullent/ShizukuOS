#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests of the Kernel64 API-set contract table (kernel64/apiset_contracts.txt -> kernel64/apiset_table.h) and of
its resolver (kernel64/apiset.c):

  1. the checked-in header is what the generator produces from the source table;
  2. test_apiset.c (rules, table invariants, 200k-name mutation fuzz) passes under GCC and under Clang ASan/UBSan;
  3. the Python reading of the table (gen_apiset_table.lookup, used by import_coverage.py and the load simulator)
     agrees with the C resolver on every row, on version neighbours of every row and on a random corpus;
  4. every API-set contract imported by the target applications resolves (the list below was measured on Electron
     44.4.5, VSCodium 1.135 and Chromium 1706750 with pefile; extra trees can be scanned with SHZ_APP_TREES=dir:dir);
  5. when Wine's apisetschema.dll is installed, every row's Windows host equals the host Wine records for the same
     contract and level (Wine 9.0 mirrors the Windows 10/11 schema; rows Wine lacks must cite a source).
"""
import os
import random
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHZ = HERE.parents[1]
sys.path.insert(0, str(SHZ / "win64" / "tools"))
import gen_apiset_table as gen  # noqa: E402

BUILD = HERE.parents[2] / "build" / "shizukudos" / "win64" / "petest"
WINE_SCHEMA = [Path("/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/apisetschema.dll"),
               Path("/usr/lib/wine/x86_64-windows/apisetschema.dll"), Path("/opt/wine-stable/lib/wine/x86_64-windows/apisetschema.dll")]

# api-/ext- imports (load-time and delay-load) of every PE32+ image in the three target trees.
TARGET_CONTRACTS = [
    'api-ms-win-core-com-l1-1-0', 'api-ms-win-core-console-l1-1-0', 'api-ms-win-core-console-l3-2-0',
    'api-ms-win-core-datetime-l1-1-0', 'api-ms-win-core-debug-l1-1-0', 'api-ms-win-core-errorhandling-l1-1-0',
    'api-ms-win-core-fibers-l1-1-0', 'api-ms-win-core-file-l1-1-0', 'api-ms-win-core-file-l1-2-2',
    'api-ms-win-core-file-l2-1-0', 'api-ms-win-core-handle-l1-1-0', 'api-ms-win-core-heap-l1-1-0',
    'api-ms-win-core-heap-l2-1-0', 'api-ms-win-core-heap-obsolete-l1-1-0', 'api-ms-win-core-interlocked-l1-1-0',
    'api-ms-win-core-io-l1-1-0', 'api-ms-win-core-largeinteger-l1-1-0', 'api-ms-win-core-libraryloader-l1-2-0',
    'api-ms-win-core-libraryloader-l1-2-1', 'api-ms-win-core-localization-l1-2-0', 'api-ms-win-core-memory-l1-1-0',
    'api-ms-win-core-namedpipe-l1-1-0', 'api-ms-win-core-path-l1-1-0', 'api-ms-win-core-processenvironment-l1-1-0',
    'api-ms-win-core-processthreads-l1-1-0', 'api-ms-win-core-processthreads-l1-1-1',
    'api-ms-win-core-profile-l1-1-0', 'api-ms-win-core-psapi-l1-1-0', 'api-ms-win-core-realtime-l1-1-0',
    'api-ms-win-core-realtime-l1-1-1', 'api-ms-win-core-registry-l1-1-0', 'api-ms-win-core-registry-l2-1-0',
    'api-ms-win-core-rtlsupport-l1-1-0', 'api-ms-win-core-shlwapi-legacy-l1-1-0',
    'api-ms-win-core-sidebyside-l1-1-0', 'api-ms-win-core-string-l1-1-0', 'api-ms-win-core-string-l2-1-0',
    'api-ms-win-core-string-obsolete-l1-1-0', 'api-ms-win-core-synch-l1-1-0', 'api-ms-win-core-synch-l1-2-0',
    'api-ms-win-core-sysinfo-l1-1-0', 'api-ms-win-core-threadpool-l1-2-0', 'api-ms-win-core-timezone-l1-1-0',
    'api-ms-win-core-util-l1-1-0', 'api-ms-win-core-version-l1-1-0', 'api-ms-win-core-version-l1-1-1',
    'api-ms-win-core-winrt-error-l1-1-0', 'api-ms-win-core-winrt-l1-1-0', 'api-ms-win-core-winrt-string-l1-1-0',
    'api-ms-win-core-wow64-l1-1-1', 'api-ms-win-crt-convert-l1-1-0', 'api-ms-win-crt-heap-l1-1-0',
    'api-ms-win-crt-locale-l1-1-0', 'api-ms-win-crt-math-l1-1-0', 'api-ms-win-crt-runtime-l1-1-0',
    'api-ms-win-crt-stdio-l1-1-0', 'api-ms-win-crt-string-l1-1-0', 'api-ms-win-crt-utility-l1-1-0',
    'api-ms-win-devices-swdevice-l1-1-0', 'api-ms-win-eventing-provider-l1-1-0',
    'api-ms-win-ntuser-sysparams-l1-1-0', 'api-ms-win-power-base-l1-1-0', 'api-ms-win-power-setting-l1-1-0',
    'api-ms-win-security-base-l1-1-0', 'api-ms-win-security-base-l1-2-2', 'api-ms-win-security-sddl-l1-1-0',
    'api-ms-win-shcore-obsolete-l1-1-0', 'api-ms-win-shcore-scaling-l1-1-1', 'api-ms-win-shell-namespace-l1-1-0',
    'ext-ms-win-uiacore-l1-1-0', 'ext-ms-win-uiacore-l1-1-1',
]


def run(cmd, **kw):
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True, **kw)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"failed: {' '.join(map(str, cmd))}")
    return r.stdout


def wine_schema():
    """{contract-with-level: {hosts}} from Wine's apisetschema.dll (API_SET_NAMESPACE version 6), or None."""
    path = next((p for p in WINE_SCHEMA if p.exists()), None)
    if not path:
        return None
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    nsec, optsz = struct.unpack_from("<HH", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    blob = None
    for i in range(nsec):
        s = pe + 24 + optsz + i * 40
        if data[s:s + 8].rstrip(b"\0") == b".apiset":
            size, off = struct.unpack_from("<I", data, s + 16)[0], struct.unpack_from("<I", data, s + 20)[0]
            blob = data[off:off + size]
    if blob is None:
        return None
    version, _, _, count, eoff = struct.unpack_from("<5I", blob, 0)
    assert version == 6, f"unexpected API set schema version {version}"
    out = {}
    for i in range(count):
        _, no, nl, _, vo, vc = struct.unpack_from("<6I", blob, eoff + i * 24)
        name = blob[no:no + nl].decode("utf-16le").lower()
        hosts = set()
        for j in range(vc):
            _, _, _, hvo, hvl = struct.unpack_from("<5I", blob, vo + j * 20)
            hosts.add(blob[hvo:hvo + hvl].decode("utf-16le").lower())
        m = gen.NAME.match(name)
        if m:
            out.setdefault(m.group(1), set()).update(hosts)
    return out, path


def tree_contracts(dirs):
    import pefile  # optional dependency, only for SHZ_APP_TREES
    names = set()
    for d in dirs:
        for p in Path(d).rglob("*"):
            if p.suffix.lower() not in (".exe", ".dll"):
                continue
            try:
                pe = pefile.PE(str(p), fast_load=True)
            except pefile.PEFormatError:
                continue
            if pe.FILE_HEADER.Machine != 0x8664:
                continue
            pe.parse_data_directories(directories=[1, 13])
            for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
                for e in getattr(pe, attr, []):
                    n = e.dll.decode(errors="replace").lower()
                    if n.startswith(("api-", "ext-")):
                        names.add(n[:-4] if n.endswith(".dll") else n)
    return sorted(names)


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    rows = gen.parse()
    if gen.HEADER.read_text() != gen.render(rows):
        raise SystemExit("kernel64/apiset_table.h is stale: run shizukudos/win64/tools/gen_apiset_table.py")
    print(f"apiset_table.h matches apiset_contracts.txt ({len(rows)} contract rows)")

    src = [HERE / "test_apiset.c", SHZ / "kernel64" / "apiset.c"]
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", SHZ / "kernel64"]
    run(["gcc", "-O2", *flags, *src, "-o", BUILD / "test_apiset"])
    print(run([BUILD / "test_apiset"]).strip().splitlines()[-1])
    run(["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
         *flags, *src, "-o", BUILD / "test_apiset_asan"])
    print("ASan/UBSan:", run([BUILD / "test_apiset_asan"]).strip().splitlines()[-1])

    # C resolver vs the Python reading
    rng = random.Random(1)
    corpus = set(TARGET_CONTRACTS)
    for r in rows:
        for M, m in ((r.major, r.minor), (r.major, r.minor + 1), (r.major + 1, 0), (max(r.major - 1, 0), 9), (1, 0)):
            corpus.update({f"{r.contract}-{M}-{m}", f"{r.contract.upper()}-{M}-{m}.DLL", f"{r.contract}-{M}-{m}.dll"})
    alphabet = "abcdefghijklmnopqrstuvwxyzAZ0123456789-._l"
    for _ in range(30000):
        s = list(rng.choice(sorted(corpus)))
        for _ in range(rng.randint(0, 3)):
            op, at = rng.randrange(3), rng.randrange(len(s) + 1)
            if op == 0 and s:
                s[min(at, len(s) - 1)] = rng.choice(alphabet)
            elif op == 1 and s:
                del s[min(at, len(s) - 1)]
            else:
                s.insert(at, rng.choice(alphabet))
        corpus.add("".join(s))
    corpus.update({"kernel32.dll", "api-", "ext-ms-win-x-l1-1-0", "api-" + "a" * 130 + "-l1-1-0", "api-ms-win-core-synch-l1-2-123456"})
    names = sorted(n for n in corpus if n and "\n" not in n)
    out = run([BUILD / "test_apiset", "--cli"], input="\n".join(names) + "\n").splitlines()
    assert len(out) == len(names)
    mismatches = []
    for n, line in zip(names, out):
        code, whost, host = line.split(" ")
        pr, prow = gen.lookup(rows, n)
        want = (pr, prow.windows_host if prow else "-", prow.host if prow else "-")
        if (int(code), whost, host) != want:
            mismatches.append((n, line, want))
    assert not mismatches, f"C and Python resolvers disagree: {mismatches[:5]}"
    print(f"C resolver and gen_apiset_table.lookup agree on {len(names)} names")

    # target application coverage
    extra = [d for d in os.environ.get("SHZ_APP_TREES", "").split(":") if d]
    wanted = sorted(set(TARGET_CONTRACTS) | set(tree_contracts(extra) if extra else []))
    missing = [n for n in wanted if gen.lookup(rows, n)[0] != gen.OK]
    assert not missing, f"contracts imported by the target applications without a table row: {missing}"
    print(f"all {len(wanted)} API-set contracts imported by Electron/VSCodium/Chromium resolve"
          + (f" (+ scanned {len(extra)} tree(s))" if extra else ""))

    # Windows host vs Wine's schema
    ws = wine_schema()
    if ws is None:
        print("Wine apisetschema.dll not installed: Windows-host cross-check skipped")
        return
    schema, path = ws
    agree, absent, bad = 0, [], []
    for r in rows:
        hosts = schema.get(r.contract)
        if hosts is None:
            absent.append(r)
            if "src:" not in r.note:
                bad.append(f"{r.name}: not in Wine's schema and no '# src:' note")
        elif hosts != {r.windows_host}:
            bad.append(f"{r.name}: windows host {r.windows_host}, Wine records {sorted(hosts)}")
        else:
            agree += 1
    assert not bad, "\n".join(bad)
    print(f"Windows hosts agree with {path} for {agree} rows; {len(absent)} row(s) cite another source "
          f"({', '.join(r.name for r in absent)})")


if __name__ == "__main__":
    main()
