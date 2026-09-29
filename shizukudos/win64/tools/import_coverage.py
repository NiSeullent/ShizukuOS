#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""How much of a real Win64 application can the Shizuku Win64 runtime load today?

Static import audit: every PE32+ under the given paths is parsed for its import and delay-import tables; each imported
(DLL, function) is checked against the export tables of the ntdll.dll / kernel32.dll this repository builds
(shizukudos/win64/build.py) and of every extra module built from win64/dlls/, using the same API-set contract table and matching rules the Kernel64 loader uses (kernel64/apiset_contracts.txt through
gen_apiset_table.lookup, which the host tests keep identical to kernel64/apiset.c).
Imports of DLLs shipped with the application itself are internal and skipped. Everything else is a system DLL
that must exist for the image to load at all: those without a Shizuku implementation are listed as load blockers.

Several application directories may be given (one report per app plus a cross-app ranking); each may be labelled
NAME=PATH. Beyond the per-DLL table the tool reports, per application:
  * load-time versus delay-load imports (a delay-load import is resolved by the application's own helper through
    LoadLibrary/GetProcAddress at first call, so it blocks a feature, not the load);
  * imports by ordinal. The Shizuku .def files pin no ordinals, so an ordinal import into a Shizuku DLL would bind to
    whatever function the linker numbered at that position: such imports count as unresolved ("ordinal-unpinned");
    with --ordinal-ref (default: the Wine PE build directory, if installed) the ordinal is translated to the name
    it denotes on Windows, from that reference DLL's export table;
  * api-ms-*/ext-ms-* contract names the contract table does not serve ("apiset-unmapped"): the loader fails such an
    import with STATUS_DLL_NOT_FOUND even when the hosting DLL exists, so they are load blockers in their own right;
  * loader features each image needs, read from the PE headers (delay-load directory, TLS directory and callbacks,
    exception directory, load-config/guard flags, dependent-load flags, high-entropy VA, large SizeOfImage,
    CLR header, resources, bound imports, CET marker), so the loader work can be planned from facts;
  * the load-time closure of the application's root executables over the DLLs it ships (what must resolve for the
    process to start at all);
  * imports from an executable name (Node native addons import "node.exe"; an Electron host re-exports those symbols
    and redirects them to itself with a delay-load hook): checked against the exports of the application's root
    executables and reported as "host-exe" instead of as a missing system DLL.
With --matrix the full app x DLL x function matrix is written; with --summary-dir a small JSON per app; --next N
prints the N highest-ranked unresolved functions (rank: apps importing at load time, images importing at load time,
then the same for delay-load).

--startup-chain EXE (repeatable) runs tools/startup_chain.py on one executable (or DLL) and folds its result in: the
images the loader maps eagerly, the load-time imports that would fail per image and, distinct across the chain, per
DLL; plus what the static walk cannot catch (load-time imports by ordinal into a Shizuku DLL, whose numbering is not
pinned) and, per chain image, the system DLLs it delay-loads with their Shizuku coverage (the wall after the load).
Written to <summary-dir>/startup_chain.json; the union over all chains, ranked by the number of chains that need
each function, is the milestone-1 work list.

This measures loader-level coverage only. It says nothing about whether the functions behave correctly, and it is
not a claim that any of these applications runs.
"""
import argparse
import collections
import fnmatch
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import pefile
except ImportError:
    raise SystemExit("pip install pefile")

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_apiset_table as apiset  # noqa: E402
CHAIN_TOOL = Path(__file__).resolve().parent / "startup_chain.py"
SCHEMA_VERSION = "shz.import-coverage.v2"
CHAIN_SCHEMA_VERSION = "shz.startup-chain-summary.v1"
IMAGE_EXTS = (".exe", ".dll", ".node", ".cpl", ".drv", ".ocx")
LARGE_IMAGE = 64 << 20                                      # SizeOfImage above this is flagged (Kernel64 copies every page)
DEFAULT_ORDINAL_REF = Path("/usr/lib/x86_64-linux-gnu/wine/x86_64-windows")

D = pefile.DIRECTORY_ENTRY
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY = 0, 1, 2, 3, 4
DIR_RELOC, DIR_DEBUG, DIR_TLS, DIR_LOAD_CONFIG, DIR_BOUND, DIR_DELAY, DIR_CLR = 5, 6, 9, 10, 11, 13, 14
DLLCHAR = {"high_entropy_va": 0x0020, "dynamic_base": 0x0040, "force_integrity": 0x0080, "nx_compat": 0x0100,
           "no_seh": 0x0400, "appcontainer": 0x1000, "guard_cf": 0x4000, "terminal_server_aware": 0x8000}
GUARD_FLAGS = {"cf_instrumented": 0x100, "cfw_instrumented": 0x200, "cf_function_table_present": 0x400,
               "security_cookie_unused": 0x800, "protect_delayload_iat": 0x1000, "delayload_iat_in_its_own_section": 0x2000,
               "cf_export_suppression_info_present": 0x4000, "cf_enable_export_suppression": 0x8000,
               "cf_longjump_table_present": 0x10000, "rf_instrumented": 0x20000, "rf_enable": 0x40000,
               "rf_strict": 0x80000, "retpoline_present": 0x100000, "eh_continuation_table_present": 0x400000,
               "xfg_enabled": 0x800000}
MACHINES = {0x8664: "AMD64", 0x14c: "i386", 0xaa64: "ARM64", 0x1c4: "ARMNT", 0xa641: "ARM64EC"}
# Where a contract family's functions live, by the API-set naming convention and this runtime's convention that
# api-ms-win-core-* is hosted by kernel32. A suggestion for kernel64/apiset_contracts.txt, not a claim that the host
# exports the functions: a contract stays unmapped until the table has a row for it.
SUGGESTED_HOSTS = (("api-ms-win-crt-", "ucrtbase.dll"), ("api-ms-win-core-winrt-", "combase.dll"), ("api-ms-win-core-com-", "ole32.dll"),
                   ("api-ms-win-core-", "kernel32.dll"), ("api-ms-win-shcore-", "shcore.dll"), ("api-ms-win-power-", "powrprof.dll"),
                   ("api-ms-win-ntuser-", "user32.dll"), ("api-ms-win-shell-", "shell32.dll"), ("api-ms-win-security-", "advapi32.dll"),
                   ("api-ms-win-eventing-", "advapi32.dll"), ("api-ms-win-mm-", "winmm.dll"), ("ext-ms-win-uiacore-", "uiautomationcore.dll"))


def suggested_host(contract):
    for prefix, host in SUGGESTED_HOSTS:
        if contract.startswith(prefix):
            return host
    return None


def schema():
    """The loader's contract table (rows of kernel64/apiset_contracts.txt)."""
    return apiset.parse()


def exports(dll, with_ordinals=False):
    pe = pefile.PE(str(dll), fast_load=True)
    pe.parse_data_directories(directories=[D["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    syms = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    syms = syms.symbols if syms else []
    if with_ordinals:
        return {e.ordinal: (e.name.decode() if e.name else None) for e in syms}
    return {e.name.decode() for e in syms if e.name}


def contract_prefix(name):
    """api-ms-win-core-file-l2-1-0.dll -> api-ms-win-core-file-l2 (the granularity of the contract table)."""
    n = name.lower()
    if n.endswith(".dll"):
        n = n[:-4]
    return re.sub(r"-\d+-\d+$", "", n)


def resolve(name, api_schema):
    """-> (provider dll or None, kind). kind: direct | apiset | apiset-unmapped"""
    result, row = apiset.lookup(api_schema, name[:-4] if name.lower().endswith(".dll") else name)
    if result == apiset.NOT_APISET:
        return name.lower(), "direct"
    if result == apiset.OK:
        return row.host, "apiset"
    return None, "apiset-unmapped"


def read_tls_callbacks(pe):
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if not tls:
        return 0
    va = tls.struct.AddressOfCallBacks
    if not va:
        return 0
    rva, n = va - pe.OPTIONAL_HEADER.ImageBase, 0
    try:
        while n < 64 and pe.get_qword_at_rva(rva + 8 * n):
            n += 1
    except Exception:                                       # unreadable array: report what was counted
        pass
    return n


def image_features(pe, path):
    oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
    dd = oh.DATA_DIRECTORY
    dsize = lambda i: dd[i].Size if i < len(dd) else 0
    f = {
        "size": path.stat().st_size,
        "is_dll": bool(fh.Characteristics & 0x2000),
        "subsystem": {2: "GUI", 3: "CUI"}.get(oh.Subsystem, str(oh.Subsystem)),
        "image_base": f"0x{oh.ImageBase:x}",
        "size_of_image": oh.SizeOfImage,
        "sections": fh.NumberOfSections,
        "os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
        "subsystem_version": f"{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}",
        "stack_reserve": oh.SizeOfStackReserve,
        "stack_commit": oh.SizeOfStackCommit,
        "heap_reserve": oh.SizeOfHeapReserve,
        "entry_point": bool(oh.AddressOfEntryPoint),
        "dll_characteristics": f"0x{oh.DllCharacteristics:x}",
        "relocations": bool(dsize(DIR_RELOC)),
        "reloc_dir_size": dsize(DIR_RELOC),
        "exception_dir": bool(dsize(DIR_EXCEPTION)),
        "unwind_entries": dsize(DIR_EXCEPTION) // 12,
        "tls_dir": bool(dsize(DIR_TLS)),
        "tls_callbacks": read_tls_callbacks(pe),
        "delay_load_dir": bool(dsize(DIR_DELAY)),
        "resources": bool(dsize(DIR_RESOURCE)),
        "resource_dir_size": dsize(DIR_RESOURCE),
        "clr_header": bool(dsize(DIR_CLR)),
        "bound_imports": bool(dsize(DIR_BOUND)),
        "authenticode": bool(dsize(DIR_SECURITY)),
        "exports": bool(dsize(DIR_EXPORT)),
        "load_config": bool(dsize(DIR_LOAD_CONFIG)),
        "large_image": oh.SizeOfImage > LARGE_IMAGE,
    }
    for k, bit in DLLCHAR.items():
        f[k] = bool(oh.DllCharacteristics & bit)
    lc = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    if lc:
        s = lc.struct
        gf = getattr(s, "GuardFlags", 0) or 0
        f["guard_flags"] = f"0x{gf:x}"
        f["guard"] = sorted(k for k, bit in GUARD_FLAGS.items() if gf & bit)
        f["guard_cf_functions"] = getattr(s, "GuardCFFunctionCount", 0) or 0
        f["dependent_load_flags"] = f"0x{(getattr(s, 'DependentLoadFlags', 0) or 0):x}"
        f["security_cookie"] = bool(getattr(s, "SecurityCookie", 0))
        f["eh_continuation_entries"] = getattr(s, "GuardEHContinuationCount", 0) or 0
    f["cet_compat"] = False
    for e in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        if e.struct.Type == 20 and e.struct.PointerToRawData and e.struct.SizeOfData >= 4:      # EX_DLLCHARACTERISTICS
            off = e.struct.PointerToRawData
            f["cet_compat"] = bool(int.from_bytes(pe.__data__[off:off + 4], "little") & 1)
    return f


def scan(path):
    """-> (imports, features) or (None, {"machine": ...}) for a non-AMD64 image. imports: [(dll, fn, ordinal, delayed)]"""
    pe = pefile.PE(str(path), fast_load=True)
    if pe.FILE_HEADER.Machine != 0x8664:
        return None, {"machine": MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)), "size": path.stat().st_size}
    pe.parse_data_directories(directories=[D["IMAGE_DIRECTORY_ENTRY_IMPORT"], D["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                                           D["IMAGE_DIRECTORY_ENTRY_TLS"], D["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
                                           D["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    found = []
    for attr, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
        for entry in getattr(pe, attr, []) or []:
            dll = entry.dll.decode(errors="replace")
            for imp in entry.imports:
                if imp.name:
                    found.append((dll, imp.name.decode(errors="replace"), None, delayed))
                else:
                    found.append((dll, f"#{imp.ordinal}", imp.ordinal, delayed))
    return found, image_features(pe, path)


class OrdinalRef:
    """Translates DLL!#ordinal to the name that ordinal denotes, from a reference set of PE DLLs (e.g. Wine's)."""
    def __init__(self, directory):
        self.dir = directory
        self.cache = {}

    def name(self, dll, ordinal):
        if not self.dir:
            return None
        key = dll.lower()
        if key not in self.cache:
            p = self.dir / key
            try:
                self.cache[key] = exports(p, with_ordinals=True) if p.exists() else {}
            except pefile.PEFormatError:
                self.cache[key] = {}
        return self.cache[key].get(ordinal)


def collect_files(root, excludes):
    if root.is_file():
        return [root]
    out = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in IMAGE_EXTS or not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(p.name, pat) for pat in excludes):
            continue
        out.append(p)
    return out


class App:
    def __init__(self, name, root, files):
        self.name, self.root, self.files = name, root, files
        self.images = {}                                    # rel path -> features (AMD64) or {"machine": ...}
        self.local = set()                                  # basenames of shipped AMD64 images
        self.imports = collections.defaultdict(lambda: collections.defaultdict(dict))   # key -> fn -> image -> record
        self.internal_deps = collections.defaultdict(set)   # image basename -> {shipped DLL basename} (load-time)
        self.unmapped = collections.defaultdict(lambda: collections.defaultdict(set))   # contract prefix -> fn -> images
        self.skipped = {}                                   # rel path -> reason
        self.host_exports = {}                              # root exe basename -> exported names
        self.host_exe = collections.defaultdict(lambda: {"functions": set(), "images": set(), "missing_in_host": set()})


def analyse_app(app, api_schema, ours, ordinal_ref):
    OURS = set(ours)
    scanned = []
    for p in app.files:
        rel = p.relative_to(app.root).as_posix() if app.root.is_dir() else p.name
        try:
            imps, feat = scan(p)
        except pefile.PEFormatError as e:
            app.skipped[rel] = f"not a PE image ({e.__class__.__name__})"
            continue
        if imps is None:
            app.skipped[rel] = f"machine {feat['machine']} (not AMD64)"
            continue
        app.images[rel] = feat
        app.local.add(p.name.lower())
        scanned.append((rel, p.name.lower(), imps))
        if "/" not in rel and rel.lower().endswith(".exe") and feat["exports"]:
            try:
                app.host_exports[p.name.lower()] = exports(p)
            except pefile.PEFormatError:
                pass
    host_names = set().union(*app.host_exports.values()) if app.host_exports else set()
    for rel, base, imps in scanned:
        dlls_load, dlls_delay = set(), set()
        for dll, fn, ordinal, delayed in imps:
            provider, kind = resolve(dll, api_schema)
            key = provider or contract_prefix(dll)
            if kind == "apiset-unmapped":
                app.unmapped[key][fn].add(rel)
            if key.endswith(".exe") and key not in app.local:       # symbols of a host process, e.g. node.exe
                h = app.host_exe[key]
                h["functions"].add(fn)
                h["images"].add(rel)
                if fn not in host_names:
                    h["missing_in_host"].add(fn)
                continue
            if key in app.local:
                if not delayed:
                    app.internal_deps[base].add(key)
                continue                                    # shipped with the app
            (dlls_delay if delayed else dlls_load).add(key)
            rec = app.imports[key][fn].get(rel)
            if rec is None:
                rec = app.imports[key][fn][rel] = {"load": False, "delay": False}
            rec["delay" if delayed else "load"] = True
            if ordinal is not None:
                rec["ordinal"] = ordinal
                nm = ordinal_ref.name(provider or dll, ordinal)
                if nm:
                    rec["ordinal_name"] = nm
                if key in OURS:
                    rec["binds_to_in_shizuku"] = ours[key]["by_ordinal"].get(ordinal)
        app.images[rel]["system_dlls_load"] = sorted(dlls_load)
        app.images[rel]["system_dlls_delay"] = sorted(dlls_delay - dlls_load)
        app.images[rel]["ordinal_imports"] = sum(1 for _, _, o, _ in imps if o is not None)
        app.images[rel]["delay_imports"] = sum(1 for _, _, _, d in imps if d)
        app.images[rel]["load_imports"] = sum(1 for _, _, _, d in imps if not d)
    # load-time closure of the root executables over shipped DLLs
    roots = [rel for rel in app.images if "/" not in rel and rel.lower().endswith(".exe")]
    closure = {}
    for r in roots:
        seen, todo = set(), [Path(r).name.lower()]
        while todo:
            b = todo.pop()
            if b in seen:
                continue
            seen.add(b)
            todo.extend(app.internal_deps.get(b, ()))
        closure[r] = sorted(seen)
    app.load_closure = closure


def status_of(key, fn, recs, ours, api_schema):
    """-> 'provided' | 'ordinal-unpinned' | 'fn-missing' | 'dll-missing' | 'apiset-unmapped'"""
    if key.startswith(("api-", "ext-")):
        return "apiset-unmapped"
    if key not in ours:
        return "dll-missing"
    if any("ordinal" in r for r in recs.values()):
        return "ordinal-unpinned"
    return "provided" if fn in ours[key]["names"] else "fn-missing"


def dll_table(app, ours, api_schema):
    rows = {}
    for key, fns in app.imports.items():
        load_users, delay_users, ordinals, provided = set(), set(), 0, 0
        for fn, recs in fns.items():
            st = status_of(key, fn, recs, ours, api_schema)
            provided += st == "provided"
            for rel, r in recs.items():
                if r["load"]:
                    load_users.add(rel)
                if r["delay"]:
                    delay_users.add(rel)
                ordinals += "ordinal" in r
        rows[key] = {"imported": len(fns), "provided": provided, "have_dll": key in ours,
                     "load_time_images": sorted(load_users), "delay_only_images": sorted(delay_users - load_users),
                     "ordinal_imports": ordinals,
                     "kind": "apiset-unmapped" if key.startswith(("api-", "ext-")) else "dll"}
    return rows


def app_summary(app, ours, api_schema, top):
    rows = dll_table(app, ours, api_schema)
    total = sum(r["imported"] for r in rows.values())
    hit = sum(r["provided"] for r in rows.values())
    blockers = {k: r["load_time_images"] for k, r in rows.items() if not r["have_dll"] and r["load_time_images"]}
    missing = {}
    for key in sorted(app.imports):
        if key not in ours:
            continue
        m = []
        for fn, recs in app.imports[key].items():
            st = status_of(key, fn, recs, ours, api_schema)
            if st != "provided":
                m.append({"fn": fn, "status": st, "images": len(recs), "load_time": any(r["load"] for r in recs.values()),
                          **({"ordinal_name": next((r["ordinal_name"] for r in recs.values() if "ordinal_name" in r), None),
                              "binds_to_in_shizuku": next((r.get("binds_to_in_shizuku") for r in recs.values()), None)}
                             if st == "ordinal-unpinned" else {})})
        m.sort(key=lambda x: (-x["load_time"], -x["images"], x["fn"]))
        if m:
            missing[key] = m
    unmapped = {k: {"functions": len(v), "images": sorted({i for s in v.values() for i in s}),
                    "load_time": any(app.imports[k][fn][img]["load"] for fn in v for img in v[fn] if img in app.imports[k][fn]),
                    "suggested_host": suggested_host(k), "names": sorted(v)}
                for k, v in app.unmapped.items()}
    feats = feature_summary(app)
    closure_dlls = {}
    for exe, mods in app.load_closure.items():
        need = collections.defaultdict(set)
        for rel, f in app.images.items():
            if Path(rel).name.lower() in mods:
                for k in f.get("system_dlls_load", []):
                    need[k].add(rel)
        closure_dlls[exe] = {"shipped_modules": mods,
                             "system_dlls": {k: {"images": sorted(v), "have_dll": k in ours,
                                                 "functions": sum(1 for fn, recs in app.imports[k].items() if any(r["load"] and img in v for img, r in recs.items())),
                                                 "unresolved": sum(1 for fn, recs in app.imports[k].items()
                                                                   if any(r["load"] and img in v for img, r in recs.items())
                                                                   and status_of(k, fn, recs, ours, api_schema) != "provided")}
                                             for k, v in sorted(need.items())}}
    return {
        "schema": SCHEMA_VERSION, "app": app.name, "root": str(app.root),
        "images": len(app.images), "skipped": app.skipped,
        "distinct_imports": total, "resolved": hit, "coverage_pct": round(100.0 * hit / max(total, 1), 1),
        "image_list": {rel: {k: f[k] for k in f if k in ("size", "is_dll", "subsystem", "size_of_image", "sections",
                                                          "system_dlls_load", "system_dlls_delay", "load_imports",
                                                          "delay_imports", "ordinal_imports")}
                       for rel, f in sorted(app.images.items(), key=lambda kv: -kv[1]["size"])},
        "features": feats,
        "image_features": {rel: {k: v for k, v in f.items() if k not in ("system_dlls_load", "system_dlls_delay")}
                           for rel, f in sorted(app.images.items())},
        "load_closure": closure_dlls,
        "host_exe_imports": {k: {"functions": len(v["functions"]), "images": sorted(v["images"]),
                                 "exported_by": sorted(app.host_exports), "missing_in_host": sorted(v["missing_in_host"])}
                             for k, v in sorted(app.host_exe.items())},
        "system_dlls": dict(sorted(rows.items(), key=lambda kv: -kv[1]["imported"])),
        "load_blockers": dict(sorted(blockers.items(), key=lambda kv: -rows[kv[0]]["imported"])),
        "apiset_unmapped": dict(sorted(unmapped.items(), key=lambda kv: -kv[1]["functions"])),
        "missing": missing,
    }


def feature_summary(app):
    keys = ("delay_load_dir", "tls_dir", "exception_dir", "guard_cf", "high_entropy_va", "dynamic_base", "nx_compat",
            "large_image", "clr_header", "resources", "bound_imports", "authenticode", "cet_compat", "relocations",
            "load_config", "security_cookie", "appcontainer")
    out = {k: sorted(rel for rel, f in app.images.items() if f.get(k)) for k in keys}
    out["tls_callbacks_total"] = sum(f.get("tls_callbacks", 0) for f in app.images.values())
    out["unwind_entries_total"] = sum(f.get("unwind_entries", 0) for f in app.images.values())
    out["ordinal_imports"] = sorted(rel for rel, f in app.images.items() if f.get("ordinal_imports"))
    out["max_size_of_image"] = max((f["size_of_image"] for f in app.images.values()), default=0)
    out["max_stack_reserve"] = max((f["stack_reserve"] for f in app.images.values()), default=0)
    out["max_sections"] = max((f["sections"] for f in app.images.values()), default=0)
    out["dependent_load_flags"] = sorted({f.get("dependent_load_flags", "0x0") for f in app.images.values()} - {"0x0"})
    out["guard_flags_seen"] = sorted({g for f in app.images.values() for g in f.get("guard", [])})
    out["os_versions"] = sorted({f["os_version"] for f in app.images.values()})
    out["no_relocations"] = sorted(rel for rel, f in app.images.items() if not f["relocations"])   # cannot be moved if its base is taken
    return out


def rank_next(apps, ours, api_schema):
    """Every unresolved (dll, fn) across apps, ranked by (apps load-time, images load-time, apps delay, images delay)."""
    agg = {}
    for app in apps:
        for key, fns in app.imports.items():
            for fn, recs in fns.items():
                st = status_of(key, fn, recs, ours, api_schema)
                if st == "provided":
                    continue
                a = agg.setdefault((key, fn), {"dll": key, "fn": fn, "status": st, "apps_load": set(), "apps_delay": set(),
                                               "images_load": 0, "images_delay": 0, "apps": set()})
                a["apps"].add(app.name)
                for rel, r in recs.items():
                    if r["load"]:
                        a["apps_load"].add(app.name)
                        a["images_load"] += 1
                    elif r["delay"]:
                        a["apps_delay"].add(app.name)
                        a["images_delay"] += 1
                    if "ordinal_name" in r:
                        a["ordinal_name"] = r["ordinal_name"]
    rows = []
    for a in agg.values():
        a["apps_load"], a["apps_delay"], a["apps"] = len(a["apps_load"]), len(a["apps_delay"]), sorted(a["apps"])
        rows.append(a)
    rows.sort(key=lambda a: (-a["apps_load"], -a["images_load"], -a["apps_delay"], -a["images_delay"], a["dll"], a["fn"]))
    for i, a in enumerate(rows, 1):
        a["rank"] = i
    return rows


def print_app(app, summary, ours, top):
    print(f"== {app.name}: {summary['images']} PE32+ images scanned under {app.root}"
          + (f" ({len(app.skipped)} skipped: non-AMD64 or not PE)" if app.skipped else ""))
    print(f"{summary['distinct_imports']} distinct imported functions from {len(summary['system_dlls'])} system DLLs/contracts; "
          f"{summary['resolved']} resolve against the built Shizuku DLLs ({summary['coverage_pct']:.1f}%)\n")
    print(f"{'system DLL / contract':44} {'imported':>8} {'provided':>9} {'load-time':>10} {'delay':>6} {'ordinal':>8}")
    for dll, r in list(summary["system_dlls"].items())[:top]:
        mark = "" if r["have_dll"] else ("  <- contract not in the loader contract table" if r["kind"] == "apiset-unmapped" else "  <- no implementation")
        print(f"{dll:44} {r['imported']:8} {r['provided']:9} {len(r['load_time_images']):10} {len(r['delay_only_images']):6} {r['ordinal_imports']:8}{mark}")
    print(f"\nload blockers (DLLs/contracts imported at load time with no Shizuku implementation): {len(summary['load_blockers'])}")
    for dll, users in list(summary["load_blockers"].items())[:top]:
        print(f"  {dll:42} {summary['system_dlls'][dll]['imported']:5} functions, needed at load time by {len(users)} image(s)")
    if summary["apiset_unmapped"]:
        print(f"\napi-ms-*/ext-ms-* contracts not in the loader contract table (kernel64/apiset_contracts.txt): {len(summary['apiset_unmapped'])}")
        for c, r in list(summary["apiset_unmapped"].items())[:top]:
            print(f"  {c:42} {r['functions']:5} functions, {len(r['images'])} image(s){', load-time' if r['load_time'] else ', delay-load only'}"
                  f"; host by name family: {r['suggested_host'] or '?'}")
    for k, h in summary["host_exe_imports"].items():
        print(f"\nimports from host executable {k}: {h['functions']} functions in {len(h['images'])} image(s); "
              f"{'all exported by ' + ', '.join(h['exported_by']) if not h['missing_in_host'] else str(len(h['missing_in_host'])) + ' not exported by the root executable(s)'}")
    for exe, c in summary["load_closure"].items():
        unresolved = sum(v["unresolved"] for v in c["system_dlls"].values())
        missing_dlls = [k for k, v in c["system_dlls"].items() if not v["have_dll"]]
        print(f"\nload-time closure of {exe}: modules {', '.join(c['shipped_modules'])}; "
              f"{len(c['system_dlls'])} system DLLs, {unresolved} unresolved functions; DLLs absent: {', '.join(missing_dlls) or 'none'}")
    for dll in sorted(summary["missing"]):
        m = summary["missing"][dll]
        print(f"\nmissing from Shizuku {dll}: {len(m)} of {summary['system_dlls'][dll]['imported']} imported; most widely imported:")
        print("  " + ", ".join(x["fn"] + (f"(={x['ordinal_name']})" if x.get("ordinal_name") else "") for x in m[:top]))
    f = summary["features"]
    print(f"\nloader features: delay-load {len(f['delay_load_dir'])} images, TLS {len(f['tls_dir'])} ({f['tls_callbacks_total']} callbacks), "
          f"exception dir {len(f['exception_dir'])} ({f['unwind_entries_total']} unwind entries), CFG {len(f['guard_cf'])}, "
          f"high-entropy VA {len(f['high_entropy_va'])}, >64 MiB image {len(f['large_image'])}, CLR {len(f['clr_header'])}, "
          f"resources {len(f['resources'])}, ordinal imports {len(f['ordinal_imports'])}, CET {len(f['cet_compat'])}, "
          f"max SizeOfImage {f['max_size_of_image'] >> 20} MiB, max stack reserve {f['max_stack_reserve'] >> 20} MiB, "
          f"dependent-load flags {f['dependent_load_flags'] or 'none'}")
    print()


def run_startup_chain(exe, build):
    """startup_chain.py's JSON report for one executable and its exit status (0: every load-time import resolves)."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "chain.json"
        p = subprocess.run([sys.executable, str(CHAIN_TOOL), str(exe), "--build", str(build), "--json", str(out)],
                           capture_output=True, text=True)
        if not out.exists():
            raise SystemExit(f"startup_chain.py failed on {exe}: {(p.stderr or p.stdout).strip()}")
        return json.loads(out.read_text()), p.returncode


def chain_reason(why):
    """startup_chain.py's failure text -> the import_coverage status vocabulary."""
    if why.startswith("not exported"):
        return "fn-missing"
    if why.startswith("API-set"):                          # not in the table / version too new / host not built
        return "apiset-unmapped" if "host" not in why else "dll-missing"
    return {"DLL not found": "dll-missing", "api set contract not mapped": "apiset-unmapped"}.get(why, why)


def startup_chain_summary(exe, build, api_schema, ours, ordinal_ref):
    rep, rc = run_startup_chain(exe, build)
    appdir = {c.name.lower(): c for c in exe.parent.iterdir()}

    def where(name):                                        # the order startup_chain.py (and its docstring) uses
        n = name.lower()
        if n in appdir:
            return appdir[n], "app"
        return (build / n, "system") if (build / n).exists() else (None, None)

    images, distinct = {}, collections.defaultdict(lambda: {"reason": None, "functions": set(), "images": set()})
    ordinal_hazards, delay_walls, fn_images = [], {}, collections.defaultdict(set)
    for name, r in rep["images"].items():
        path, loc = where(name)
        per_dll = collections.Counter()
        for key, fns in r["by_dll"].items():
            dll, _, why = key.partition(" [")
            why = why.rstrip("]")
            d = distinct[dll]
            d["reason"] = chain_reason(why)
            d["functions"].update(fns)
            d["images"].add(name)
            per_dll[dll] += len(fns)
            for fn in fns:
                fn_images[(dll, fn)].add(name)
        images[name] = {"from": loc, "load_time_imports": r["load_time_imports"], "delay_imports": r["delay_imports"],
                        "missing": r["missing"], "missing_by_dll": dict(per_dll.most_common())}
        if loc != "app" or path is None:                    # Shizuku's own DLLs: their imports are in the chain report
            continue
        imps, _ = scan(path)
        wall = collections.defaultdict(lambda: {"functions": 0, "provided": 0, "have_dll": False, "kind": "dll"})
        for dll, fn, ordinal, delayed in imps or []:
            provider, kind = resolve(dll, api_schema)
            target = (provider or dll).lower()
            if target in appdir:
                continue                                    # shipped with the application
            if not delayed:
                if ordinal is not None and target in ours:
                    ordinal_hazards.append({"image": name, "dll": target, "ordinal": ordinal,
                                            "windows_name": ordinal_ref.name(target, ordinal),
                                            "binds_to_in_shizuku": ours[target]["by_ordinal"].get(ordinal)})
                continue
            key = provider or contract_prefix(dll)
            w = wall[key]
            w["functions"] += 1
            w["have_dll"] = key in ours
            w["kind"] = "apiset-unmapped" if kind == "apiset-unmapped" else "dll"
            w["provided"] += ordinal is None and key in ours and fn in ours[key]["names"]
        delay_walls[name] = dict(sorted(wall.items(), key=lambda kv: -kv[1]["functions"]))
    total = sum(r["load_time_imports"] for r in rep["images"].values())
    failing = sum(r["missing"] for r in rep["images"].values())
    return {
        "exe": exe.name, "path": str(exe), "loads": rc == 0 and not ordinal_hazards, "chain": rep["chain"],
        "load_time_imports": total, "failing_imports": failing,
        "failing_pct": round(100.0 * failing / max(total, 1), 1),
        "distinct_missing": sum(len(d["functions"]) for d in distinct.values()),
        "missing_by_dll": {k: {"reason": d["reason"], "count": len(d["functions"]), "images": sorted(d["images"]),
                               "functions": sorted(d["functions"])}
                           for k, d in sorted(distinct.items(), key=lambda kv: -len(kv[1]["functions"]))},
        "ordinal_hazards": ordinal_hazards,
        "images": images,
        "delay_loaded_system_dlls": delay_walls,
        "fn_images": fn_images,                             # (dll, fn) -> chain images; internal, not written
    }


def chain_worklist(chains):
    """Union of every chain's failing (dll, function), ranked by chains needing it, then chain images importing it."""
    agg = {}
    for c in chains:
        for dll, d in c["missing_by_dll"].items():
            for fn in d["functions"]:
                a = agg.setdefault((dll, fn), {"dll": dll, "fn": fn, "reason": d["reason"], "chains": [], "images": set()})
                a["chains"].append(c["exe"])
                a["images"].update(c["fn_images"][(dll, fn)])
    rows = sorted(agg.values(), key=lambda a: (-len(a["chains"]), -len(a["images"]), a["dll"], a["fn"]))
    for i, a in enumerate(rows, 1):
        a["rank"], a["images"] = i, len(a["images"])
    return rows


def print_chains(chains, worklist, top):
    for c in chains:
        print(f"== startup chain of {c['exe']}: {' -> '.join(c['chain'])}")
        print(f"   load-time imports {c['load_time_imports']}, failing {c['failing_imports']} ({c['failing_pct']:.1f}%), "
              f"distinct (DLL, function) failing {c['distinct_missing']}; ordinal hazards {len(c['ordinal_hazards'])}; "
              f"{'LOADS' if c['loads'] else 'does not load'}")
        for dll, d in c["missing_by_dll"].items():
            print(f"   {d['count']:5}  {dll} [{d['reason']}]")
        for name, wall in c["delay_loaded_system_dlls"].items():
            if wall:
                print(f"   delay-loaded by {name}: " + ", ".join(
                    f"{k} {w['provided']}/{w['functions']}{'' if w['have_dll'] else ' (absent)'}" for k, w in list(wall.items())[:top]))
    print(f"\nstartup-chain work list (union of {len(chains)} chains): {len(worklist)} distinct (DLL, function); "
          f"needed by every chain: {sum(1 for a in worklist if len(a['chains']) == len(chains))}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apps", nargs="+", metavar="APP",
                    help="directory (or file) of an application, scanned recursively for PE images; NAME=PATH labels it")
    ap.add_argument("--build", type=Path, default=REPO / "build/shizukudos/win64")
    ap.add_argument("--json", type=Path, help="combined report (single app: the per-app summary)")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--next", type=int, default=0, help="print the N highest-ranked unresolved functions across all apps")
    ap.add_argument("--matrix", type=Path, help="write the full app x DLL x function matrix")
    ap.add_argument("--summary-dir", type=Path, help="write <name>.json per app and next.json (ranking) here")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="skip images whose relative path or file name matches (repeatable)")
    ap.add_argument("--ordinal-ref", type=Path, default=DEFAULT_ORDINAL_REF if DEFAULT_ORDINAL_REF.is_dir() else None,
                    help="directory of reference PE DLLs used to name ordinal imports (default: Wine's PE build, if installed)")
    ap.add_argument("--startup-chain", action="append", default=[], type=Path, metavar="EXE",
                    help="also run startup_chain.py on this executable (repeatable); written to <summary-dir>/startup_chain.json")
    args = ap.parse_args()

    api_schema = schema()
    ours = {}
    for p in sorted(args.build.glob("*.dll")):               # ntdll, kernel32 and every extra module
        by_ord = exports(p, with_ordinals=True)
        ours[p.name.lower()] = {"names": {n for n in by_ord.values() if n}, "by_ordinal": by_ord}
    ordinal_ref = OrdinalRef(args.ordinal_ref if args.ordinal_ref and args.ordinal_ref.is_dir() else None)
    apps = []
    for spec in args.apps:
        name, _, path = spec.partition("=") if "=" in spec and not Path(spec).exists() else ("", "", spec)
        root = Path(path)
        if not root.exists():
            raise SystemExit(f"{root}: not found")
        app = App(name or root.name, root, collect_files(root, args.exclude))
        analyse_app(app, api_schema, ours, ordinal_ref)
        apps.append(app)
    summaries = {}
    for app in apps:
        summaries[app.name] = app_summary(app, ours, api_schema, args.top)
        print_app(app, summaries[app.name], ours, args.top)
    ranking = rank_next(apps, ours, api_schema)
    if args.next:
        print(f"next functions to provide (of {len(ranking)} unresolved; rank = apps at load time, images at load time, then delay-load):")
        print(f"{'#':>4} {'dll / contract':40} {'function':44} {'status':16} {'apps L':>6} {'img L':>5} {'apps D':>6} {'img D':>5}")
        for a in ranking[:args.next]:
            fn = a["fn"] + (f" (={a['ordinal_name']})" if a.get("ordinal_name") else "")
            print(f"{a['rank']:4} {a['dll']:40} {fn:44} {a['status']:16} {a['apps_load']:6} {a['images_load']:5} {a['apps_delay']:6} {a['images_delay']:5}")
    meta = {"schema": SCHEMA_VERSION, "build": str(args.build), "shizuku_dlls": {k: len(v["names"]) for k, v in ours.items()},
            "apiset_schema": {r.name: r.host for r in api_schema}, "ordinal_ref": str(ordinal_ref.dir) if ordinal_ref.dir else None,
            "excludes": args.exclude}
    chains = [startup_chain_summary(exe, args.build, api_schema, ours, ordinal_ref) for exe in args.startup_chain]
    worklist = chain_worklist(chains)
    if chains:
        print_chains(chains, worklist, args.top)
    for c in chains:
        c.pop("fn_images")
    if chains and args.summary_dir:
        args.summary_dir.mkdir(parents=True, exist_ok=True)
        (args.summary_dir / "startup_chain.json").write_text(json.dumps(
            {"schema": CHAIN_SCHEMA_VERSION, "tool": "shizukudos/win64/tools/startup_chain.py", "build": str(args.build),
             "shizuku_dlls": meta["shizuku_dlls"], "chains": {c["exe"]: c for c in chains},
             "worklist_distinct": len(worklist), "worklist": worklist}, indent=1) + "\n")
    if args.summary_dir:
        args.summary_dir.mkdir(parents=True, exist_ok=True)
        for name, s in summaries.items():
            (args.summary_dir / f"{name}.json").write_text(json.dumps(s, indent=1) + "\n")
        (args.summary_dir / "next.json").write_text(json.dumps({**meta, "apps": [a.name for a in apps], "unresolved": len(ranking),
                                                                 "listed": min(len(ranking), max(args.next, 300)),
                                                                 "next": ranking[:max(args.next, 300)]}, indent=1) + "\n")
    if args.matrix:
        matrix = {**meta, "apps": {a.name: {"root": str(a.root), "images": sorted(a.images)} for a in apps}, "dlls": {}}
        for app in apps:
            for key, fns in app.imports.items():
                d = matrix["dlls"].setdefault(key, {"have_dll": key in ours, "functions": {}})
                for fn, recs in fns.items():
                    e = d["functions"].setdefault(fn, {"status": status_of(key, fn, recs, ours, api_schema), "apps": {}})
                    e["apps"][app.name] = {"load": sorted(r for r, x in recs.items() if x["load"]),
                                           "delay": sorted(r for r, x in recs.items() if x["delay"] and not x["load"]),
                                           **({"ordinal": next(x["ordinal"] for x in recs.values() if "ordinal" in x)}
                                              if any("ordinal" in x for x in recs.values()) else {})}
                    for x in recs.values():
                        if "ordinal_name" in x:
                            e["ordinal_name"] = x["ordinal_name"]
                        if x.get("binds_to_in_shizuku"):
                            e["binds_to_in_shizuku"] = x["binds_to_in_shizuku"]
        args.matrix.write_text(json.dumps(matrix, indent=0) + "\n")
    if args.json:
        if len(apps) == 1:                                   # v1-compatible keys plus the new ones
            s = summaries[apps[0].name]
            out = {"images": s["images"], "distinct_imports": s["distinct_imports"], "resolved": s["resolved"],
                   "system_dlls": {d: {"imported": r["imported"], "provided": r["provided"]} for d, r in s["system_dlls"].items()},
                   "load_blockers": s["load_blockers"],
                   "missing": {d: [x["fn"] for x in m] for d, m in s["missing"].items()}, **s}
        else:
            out = {**meta, "apps": summaries, "next": ranking[:max(args.next, 300)]}
        args.json.write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    sys.exit(main())
