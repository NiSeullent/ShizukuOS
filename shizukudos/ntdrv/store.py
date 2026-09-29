#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ShizukuDOS 10 driver store (host side): media layout \\DRIVERS\\<package>\\ plus an index.

  store.py add <package-dir> [--name N]      copy a driver package, byte for byte, to <root>/DRIVERS/<N>/ and re-index
  store.py match <device> [<device> ...]     rank every INF model of the store against PCI devices
  store.py list | verify | index | remove <N>

<package-dir> is what a vendor ships (an INF, its .sys/.cat/.dll files, any sub-directories); nothing in it is
modified, renamed or re-encoded, so a package taken from the store is identical to the one that was added (verify
checks the recorded SHA-256 of every file). Packages are user-supplied: this repository never ships or downloads
vendor drivers; the corpus packages built from ReactOS (build/shizukudos/ntdrv/packages) are the test inputs.

Devices for `match`: 'VVVV:DDDD[:SSSSSSSS[:RR[:CCSSPP]]]' (hex; '-' for unknown; SSSSSSSS = PCI config dword 0x2C),
a full 'PCI\\VEN_...' hardware ID, a Kernel64 boot-log line 'K64 pci: b:d.f vvvv:dddd class ccsspp ...', or @FILE
with one device per line (a saved boot log works as is).

Index (<root>/DRIVERS/INDEX.TXT, UTF-8, tab-separated, read by the Win64 CLI shzpnp; INDEX.JSON has the same data):
  SHZDRV-INDEX<TAB>1<TAB><target os>
  PKG    name  files  bytes
  INF    name  inf-path  class  classguid  provider  driverver  catalog
  MODEL  name  inf-path  rules  install  ddinstall  sig  feature  service  binary  kmdf  hwid  compat;compat  description
  FILE   name  path  size  sha256
  MISS   name  inf-path  file  (a file the INF copies that is not in the package)
rules: W = the model applies under Windows x64 rules, L = only with the ReactOS-style undecorated fallback.
sig/feature: the signature and FeatureScore bytes of the rank (inf.py). Paths are package-relative with '\\'.
The root defaults to build/shizukudos/ntdrv/media; the ISO builder places <root>/DRIVERS on the medium as \\DRIVERS.
"""
import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path, PureWindowsPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import inf as I  # noqa: E402

REPO = HERE.parents[1]
DEFAULT_ROOT = REPO / "build" / "shizukudos" / "ntdrv" / "media"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_COMPONENT = 95                                          # Kernel64 fs node name: char name[96]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def drivers_dir(root):
    return Path(root) / "DRIVERS"


def package_files(pkg):
    return sorted(p for p in Path(pkg).rglob("*") if p.is_file())


def rel(pkg, p):
    return str(PureWindowsPath(*Path(p).relative_to(pkg).parts))


# ------------------------------------------------------------------------------------------------------ source files
def resolve_source(inf, pkg, fname, target):
    """Where a CopyFiles entry's source lives in the package: SourceDisksFiles(.arch) -> SourceDisksNames(.arch) path
    + subdir, else the INF's directory. Returns a Path or None."""
    files = inf.source_files(target)
    names = {}
    for nm in ("SourceDisksNames", f"SourceDisksNames.{target.arch}"):
        s = inf.section(nm)
        if s:
            for ln in s.lines:
                if ln.key:
                    names[ln.key.strip()] = ln.values[3] if len(ln.values) > 3 else ""
    base = inf.path.parent
    cands = []
    ent = files.get(fname.lower())
    if ent:
        disk, sub = ent
        diskpath = names.get(str(disk).strip(), "")
        cands.append(base / diskpath.strip("\\").replace("\\", "/") / sub.strip("\\").replace("\\", "/") / fname)
    cands.append(base / fname)
    for c in cands:
        if c.exists():
            return c
        # case-insensitive lookup (packages come from case-insensitive file systems)
        parent = c.parent
        if parent.is_dir():
            for x in parent.iterdir():
                if x.name.lower() == c.name.lower():
                    return x
    return None


# ------------------------------------------------------------------------------------------------------------ index
def index_package(root, name, target):
    pkg = drivers_dir(root) / name
    rec = {"name": name, "files": [], "infs": [], "models": [], "missing": [], "warnings": []}
    for p in package_files(pkg):
        rec["files"].append({"path": rel(pkg, p), "size": p.stat().st_size, "sha256": sha256(p)})
    legacy = I.Target(arch=target.arch, major=target.major, minor=target.minor, build=target.build,
                      product_type=target.product_type, suite=target.suite, legacy=True)
    for p in package_files(pkg):
        if p.suffix.lower() != ".inf":
            continue
        inf = I.Inf.load(p)
        v = inf.version
        rec["infs"].append({"path": rel(pkg, p), "class": v["Class"], "classguid": v["ClassGuid"], "provider": v["Provider"],
                            "driverver": v["DriverVer"], "catalog": v["CatalogFile"]})
        strict = {(m["install"], m["hwids"][0], m["lineno"]) for m in inf.models(target)}
        for m in inf.models(legacy):
            rules = "W" if (m["install"], m["hwids"][0], m["lineno"]) in strict else "L"
            t = target if rules == "W" else legacy
            inst = inf.install(m["install"], t)
            svc = next((s for s in inst["services"] if not s.get("delete") and s.get("flags", 0) & 2), None) \
                or next((s for s in inst["services"] if not s.get("delete")), None)
            decorated = bool(inst["section"]) and inst["section"].lower() != m["install"].lower()
            rec["models"].append({
                "inf": rel(pkg, p), "rules": rules, "install": m["install"], "ddinstall": inst["section"] or "",
                "sig": I.SIGNATURE_UNSIGNED_NT if decorated else I.SIGNATURE_UNSIGNED,
                "feature": inst["feature_score"] if inst["feature_score"] is not None else I.FEATURE_SCORE_DEFAULT,
                "service": svc["name"] if svc else "", "binary": (svc or {}).get("ServiceBinary") or "",
                "kmdf": (inst["wdf"] or {}).get("KmdfLibraryVersion") or "", "hwid": m["hwids"][0],
                "compat": m["compat_ids"], "description": m["description"]})
            for cf in inst["copyfiles"]:
                if resolve_source(inf, pkg, cf["source"], t) is None:
                    miss = {"inf": rel(pkg, p), "file": cf["source"]}
                    if miss not in rec["missing"]:
                        rec["missing"].append(miss)
        rec["warnings"] += inf.warnings[:20]
    return rec


def clean(s):
    return str(s).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def write_index(root, target):
    ddir = drivers_dir(root)
    ddir.mkdir(parents=True, exist_ok=True)
    pkgs = [index_package(root, d.name, target) for d in sorted(ddir.iterdir(), key=lambda x: x.name.lower()) if d.is_dir()]
    tdesc = f"NT{target.arch}.{target.major}.{target.minor}...{target.build}"
    lines = [f"SHZDRV-INDEX\t1\t{tdesc}"]
    for p in pkgs:
        lines.append("\t".join(["PKG", p["name"], str(len(p["files"])), str(sum(f["size"] for f in p["files"]))]))
        for i in p["infs"]:
            lines.append("\t".join(["INF", p["name"], i["path"], i["class"], i["classguid"], i["provider"], i["driverver"], i["catalog"]]))
        for m in p["models"]:
            lines.append("\t".join(clean(x) for x in ["MODEL", p["name"], m["inf"], m["rules"], m["install"], m["ddinstall"],
                                                      f"{m['sig']:02X}", f"{m['feature']:02X}", m["service"], m["binary"],
                                                      m["kmdf"], m["hwid"], ";".join(m["compat"]), m["description"]]))
        for f in p["files"]:
            lines.append("\t".join(["FILE", p["name"], f["path"], str(f["size"]), f["sha256"]]))
        for x in p["missing"]:
            lines.append("\t".join(["MISS", p["name"], x["inf"], x["file"]]))
    (ddir / "INDEX.TXT").write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    (ddir / "INDEX.JSON").write_text(json.dumps({"format": 1, "target": tdesc, "packages": pkgs}, indent=1))
    return pkgs


# ---------------------------------------------------------------------------------------------------------- commands
def check_package_dir(src):
    src = Path(src)
    if not src.is_dir():
        raise SystemExit(f"{src}: not a directory")
    files = package_files(src)
    if not any(p.suffix.lower() == ".inf" for p in files):
        raise SystemExit(f"{src}: no INF file: not a driver package")
    for p in files:
        for part in p.relative_to(src).parts:
            if len(part.encode()) > MAX_COMPONENT:
                raise SystemExit(f"{p}: path component longer than {MAX_COMPONENT} bytes (Kernel64 file system limit)")
    return files


def cmd_add(root, src, name, target):
    files = check_package_dir(src)
    name = name or Path(src).resolve().name
    if not NAME_RE.match(name):
        raise SystemExit(f"package name {name!r}: use 1-64 characters A-Z a-z 0-9 _ . - (starting alphanumeric)")
    ddir = drivers_dir(root)
    dest = ddir / name
    for existing in (ddir.iterdir() if ddir.is_dir() else []):
        if existing.name.lower() == name.lower() and existing.name != name:
            raise SystemExit(f"a package {existing.name} already exists (names are case-insensitive on the medium)")
    if dest.exists():
        shutil.rmtree(dest)
    for p in files:
        out = dest / p.relative_to(src)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, out)                                  # bytes only: no newline/encoding conversion
    pkgs = write_index(root, target)
    rec = next(p for p in pkgs if p["name"] == name)
    for f in rec["files"]:
        if f["sha256"] != sha256(Path(src) / Path(*PureWindowsPath(f["path"]).parts)):
            raise SystemExit(f"copy of {f['path']} differs from the source")
    w = sum(1 for m in rec["models"] if m["rules"] == "W")
    print(f"added {name}: {len(rec['files'])} files, {len(rec['infs'])} INF, {len(rec['models'])} models "
          f"({w} under Windows x64 rules, {len(rec['models']) - w} only with the undecorated fallback)")
    for x in rec["missing"]:
        print(f"  missing from the package: {x['file']} (copied by {x['inf']})")
    return rec


def load_store_infs(root):
    ddir = drivers_dir(root)
    out = []
    for d in sorted(ddir.iterdir()) if ddir.is_dir() else []:
        if d.is_dir():
            for p in package_files(d):
                if p.suffix.lower() == ".inf":
                    inf = I.Inf.load(p)
                    inf.package = d.name
                    out.append(inf)
    return out


def expand_devices(specs):
    out = []
    for s in specs:
        if s.startswith("@"):
            for line in Path(s[1:]).read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "K64 pci:" in line:
                    line = line[line.index("K64 pci:"):]
                elif not re.match(r"^(PCI\\|[0-9A-Fa-f]{4}:)", line):
                    continue
                out.append(line)
        else:
            out.append(s)
    return [I.Device.parse(x) for x in out]


def cmd_match(root, specs, target, show_all=False):
    infs = load_store_infs(root)
    legacy = I.Target(arch=target.arch, major=target.major, minor=target.minor, build=target.build, legacy=True)
    results = []
    for dev in expand_devices(specs):
        hits = I.rank_candidates(dev, infs, target)
        rules = "W"
        if not hits:
            hits, rules = I.rank_candidates(dev, infs, legacy), "L"
        results.append((dev, hits, rules))
        print(f"device {dev.instance}  ({dev.hwids[0]})")
        if not hits:
            print("  no driver in the store")
            continue
        for n, h in enumerate(hits if show_all else hits[:1]):
            inf = h["inf"]
            pkg = next((x.package for x in infs if x.name == inf), "?")
            svc = next((s for s in h["install"]["services"] if not s.get("delete")), {})
            print(f"  {'best' if n == 0 else '    '} rank {h['rank']:#010x} ({h['match']}, {rules}) {pkg}\\{inf} [{h['model']['install']}] "
                  f"'{h['model']['description']}' service={svc.get('name', '-')} binary={svc.get('ServiceBinary') or '-'}")
    return results


def cmd_verify(root):
    idx = json.loads((drivers_dir(root) / "INDEX.JSON").read_text())
    bad = 0
    for p in idx["packages"]:
        for f in p["files"]:
            path = drivers_dir(root) / p["name"] / Path(*PureWindowsPath(f["path"]).parts)
            if not path.exists() or sha256(path) != f["sha256"]:
                print(f"CHANGED or MISSING: {p['name']}\\{f['path']}")
                bad += 1
    print(f"verify: {sum(len(p['files']) for p in idx['packages'])} files in {len(idx['packages'])} packages, {bad} differ")
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="store root (contains DRIVERS/)")
    ap.add_argument("--os-build", type=int, default=I.Target.build)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add")
    p.add_argument("package", type=Path)
    p.add_argument("--name")
    p = sub.add_parser("match")
    p.add_argument("devices", nargs="+")
    p.add_argument("--all", action="store_true", help="show every candidate, not only the best")
    sub.add_parser("list")
    sub.add_parser("verify")
    sub.add_parser("index")
    p = sub.add_parser("remove")
    p.add_argument("name")
    args = ap.parse_args(argv)
    target = I.Target(build=args.os_build)
    if args.cmd == "add":
        cmd_add(args.root, args.package, args.name, target)
    elif args.cmd == "match":
        cmd_match(args.root, args.devices, target, args.all)
    elif args.cmd == "index":
        pk = write_index(args.root, target)
        print(f"indexed {len(pk)} packages")
    elif args.cmd == "list":
        for p in write_index(args.root, target):
            print(f"{p['name']:24} {len(p['files']):4} files  {len(p['models']):4} models  "
                  f"{', '.join(i['path'] + ' (' + i['class'] + ')' for i in p['infs'])}")
    elif args.cmd == "verify":
        return 1 if cmd_verify(args.root) else 0
    elif args.cmd == "remove":
        d = drivers_dir(args.root) / args.name
        if not d.is_dir():
            raise SystemExit(f"no package {args.name}")
        shutil.rmtree(d)
        write_index(args.root, target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
