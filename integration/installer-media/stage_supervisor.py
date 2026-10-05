#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stage-only Shizuku Supervisor producer (new producer epoch `stage-supervisor/1`).

Runs, in this exact order and nothing else, the existing producer functions of shizukudos/supervisor/build.py:
build_vbios(), build_ap_trampoline(), build_payload(), build_loader(payload, None).  It never calls main, build_esp,
guest_kernel_files, any ensure/upstream helper or a private profile.  build.py and shzlib.py are executed in
isolated in-memory module namespaces (nothing is imported into sys.modules permanently, no bytecode is written),
OUT is relocated to the explicit fresh --out directory and the real run() used by the producer is replaced by an
owned, bounded, fully recording runner.  See stage_supervisor.README.md for scope and limitations.

  stage_supervisor.py --help
  stage_supervisor.py --check --root ROOT                 # read-only: inputs, tools, source count; no tool executed
  stage_supervisor.py --root ROOT --out FRESH_DIR [--reference-efi-sha256 HEX]   # ACTUAL stage build (needs approval)
  stage_supervisor.py --self-test                          # modeled fixtures with fake tools, NOT an EFI compile

Success status is only BUILT_PENDING_GUEST_VALIDATION.  Every release/acceptance/source/licence/upstream/binary
binding claim in the receipt is false.
"""
import sys

sys.dont_write_bytecode = True  # before any local import: --check/--help/--self-test must not write __pycache__
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = "shizuku-efi-stage-supervisor/1"
EPOCH = "stage-supervisor/1"
RESULT_NAME = "stage-result.json"
AUTHORED_AGAINST = {  # actual files read when this helper was authored; recorded, never required
    "shizukudos/supervisor/build.py": "8796ccd8b418a9239aa3b643f01d380607990c89b89f1668d125ce82e73136a4",
    "shizukudos/tools/shzlib.py": "703ccf7b7eab8c109060d6a4ad510217562a7847b4abd54d0b78089fd7550369"}
TOOLS = ("nasm", "gcc", "ld", "nm", "readelf", "objcopy", "x86_64-w64-mingw32-gcc")
VERSION_ARGS = {"nasm": "-v"}
GENERATED = ("images.h", "vbios_image.h", "ap_trampoline_image.h")
ARTIFACTS = ("BOOTX64.EFI", "payload.elf", "payload.bin", "vbios.bin", "ap-trampoline.bin") + GENERATED
LOADER_SEEDS = ("shizukudos/supervisor/loader/loader.c", "shizukudos/supervisor/loader/bootini.c",
                "shizukudos/supervisor/loader/ap_prepare.c", "shizukudos/supervisor/src/ap_contract.c",
                "shizukudos/kernel64/smp_acpi.c", "shizukudos/supervisor/src/caps.c", "shizukudos/uefi/boot.c")
MIB = 1 << 20
ERROR_BUDGET = MIB  # own-output headroom reserved so a structured FAILED receipt can always be written
LIMITS = {"cmd_timeout": 180, "own_output": 32 * MIB, "per_log": MIB, "capture": 4 * MIB, "total_stream": 96 * MIB,
          "reserve": 17 << 30, "max_files": 400, "max_file": 2 * MIB, "max_source_total": 48 * MIB,
          "max_tool": 256 * MIB}
FALSE_CLAIMS = ("guest_acceptance", "boot_or_os_acceptance", "win98_acceptance", "release", "full_source_binding",
                "license_closure", "upstream_closure", "historical_closure", "historical_binary_identity",
                "compiler_dependency_closure", "system_header_closure", "toolchain_resource_closure")
LIMITATIONS = (
    "Source map is a conservative literal local include closure (all #if branches, comments included) plus direct "
    "inputs; it is NOT the compiler's actual dependency closure (no -MMD was added).",
    "System headers, compiler-internal headers, cc1/as/collect2 and linker support files used by gcc/mingw are not "
    "captured; only the seven primary tool executables are hashed.",
    "A successful stage is only BUILT_PENDING_GUEST_VALIDATION; no guest boot, installation, OS or Win98 claim.",
    "This is a new producer epoch; it does not repair, guess or bind any historical source pin or historical EFI.",
    "Optional reference EFI comparison is one external pin comparison; it does not establish historical binding.")


class StageError(RuntimeError):
    def __init__(self, kind, detail=""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind, self.detail = kind, detail


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        n = 0
        for chunk in iter(lambda: fh.read(MIB), b""):
            n += len(chunk)
            if limit is not None and n > limit:
                raise StageError("file-too-large", Path(path).name)
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _load_isolated(path, name, extra=None):
    """Execute `path` in a fresh, unregistered module namespace (no bytecode, no import-system side effects)."""
    data = Path(path).read_bytes()
    mod = types.ModuleType(name)
    mod.__file__ = str(path)
    saved = {k: sys.modules.get(k, None) for k in (extra or {})}
    saved_path = list(sys.path)
    sys.modules.update(extra or {})
    try:
        exec(compile(data, str(path), "exec", optimize=0), mod.__dict__)
    finally:
        sys.path[:] = saved_path
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod, sha256_bytes(data)


def load_guards():
    """Reuse the existing public path/content/read guards of source_capsule.py (in memory)."""
    mod, digest = _load_isolated(HERE / "source_capsule.py", "_shz_stage_guard")
    return mod, digest


def load_modules(root):
    if sys.flags.optimize:  # -O/PYTHONOPTIMIZE would strip build.py's asserts, its only artifact checks
        raise StageError("optimize-refused", f"interpreter optimize level {sys.flags.optimize}; run without -O")
    root = Path(root)
    shz_path = root / "shizukudos/tools/shzlib.py"
    build_path = root / "shizukudos/supervisor/build.py"
    for p in (shz_path, build_path):
        if not p.is_file() or p.is_symlink():
            raise StageError("root-invalid", f"missing/symlink {p.relative_to(root) if root in p.parents else p.name}")
    shz, shz_hash = _load_isolated(shz_path, "shzlib")
    if Path(shz.REPO).resolve() != root.resolve():
        raise StageError("root-invalid", "shzlib REPO differs from --root")
    build, build_hash = _load_isolated(build_path, "_shz_stage_build", {"shzlib": shz})
    for name in ("PAYLOAD_C", "PAYLOAD_ASM", "SRC", "SHZ", "build_vbios", "build_ap_trampoline", "build_payload",
                 "build_loader", "run"):
        if not hasattr(build, name):
            raise StageError("root-invalid", f"build.py lacks {name}")
    return shz, build, {"shizukudos/supervisor/build.py": build_hash, "shizukudos/tools/shzlib.py": shz_hash}


# ---------------------------------------------------------------- source map
_C_INC = re.compile(rb'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"\r\n]+)[>"]', re.M)
_ASM_INC = re.compile(rb'^[ \t]*(?:%include|incbin)[ \t]*"([^"\r\n]+)"', re.M | re.I)
_LD_INC = re.compile(rb"^[ \t]*INCLUDE[ \t]+(\S+)", re.M)


def _includes(rel, data):
    if rel.endswith((".c", ".h")):
        return [(m.group(1) == b"<", m.group(2).decode("latin-1")) for m in _C_INC.finditer(data)]
    if rel.endswith((".asm", ".inc")):
        return [(False, m.group(1).decode("latin-1")) for m in _ASM_INC.finditer(data)]
    if rel.endswith(".ld"):
        return [(False, m.group(1).decode("latin-1")) for m in _LD_INC.finditer(data)]
    return []


def _rel(root, path):
    return Path(os.path.normpath(path)).relative_to(root).as_posix()


def collect_sources(root, build, guards, seeds_extra=None, loader_seeds=LOADER_SEEDS, limits=LIMITS):
    """Return (map rel->sha256, info).  Direct inputs come from the real build module plus the loader seed list; the
    closure follows literal local includes, bounded, project-relative, symlink-free and through the public guards."""
    root = Path(root).resolve()
    src, shz = Path(build.SRC), Path(build.SHZ)
    direct = [_rel(root, src / "src" / n) for n in list(build.PAYLOAD_C) + list(build.PAYLOAD_ASM)]
    direct += [_rel(root, src / "guest/vbios.asm"), _rel(root, src / "src/ap_trampoline.asm"),
               _rel(root, src / "payload.ld")]
    direct += list(loader_seeds)
    direct = list(dict.fromkeys(direct))
    tools_files = ["shizukudos/supervisor/build.py", "shizukudos/tools/shzlib.py"]
    external = {}
    for name, path in (("stage_supervisor.py", Path(__file__).resolve()),
                       ("source_capsule.py", HERE / "source_capsule.py")):
        try:
            tools_files.append(path.relative_to(root).as_posix())
        except ValueError:
            external[name] = sha256_file(path, limits["max_file"] * 8)  # helper outside --root: hash only
    incdirs = [_rel(root, p) for p in (src / "src", shz / "abi", shz / "csmwrap", src / "loader", src)] + ["."]
    seen, order, info = {}, [], {"unresolved_includes": [], "stale_generated_in_source_tree": [],
                                 "generated_headers_expected": list(GENERATED)}
    total = 0

    def read(rel):
        nonlocal total
        why = guards._named_source_ok(rel)
        if why:
            raise StageError("source-refused", f"{rel}: {why}")
        data, why = guards.read_named_source(root, rel)
        if data is None or len(data) > limits["max_file"]:
            raise StageError("source-refused", f"{rel}: {why or 'too-large'}")
        why = guards.guard_content(data)
        if why:
            raise StageError("source-refused", f"{rel}: {why}")
        total += len(data)
        if len(seen) >= limits["max_files"] or total > limits["max_source_total"]:
            raise StageError("source-bound", "closure exceeds file/size bound")
        return data

    queue = list(dict.fromkeys(direct + tools_files))
    while queue:
        rel = queue.pop(0)
        if rel in seen:
            continue
        data = read(rel)
        seen[rel] = sha256_bytes(data)
        order.append(rel)
        here = os.path.dirname(rel) or "."
        for angle, name in _includes(rel, data):
            dirs = incdirs if angle else [here] + incdirs
            found = None
            for d in dirs:
                cand = os.path.normpath(os.path.join(d, name))
                if cand.startswith("..") or os.path.isabs(cand):
                    continue
                if (root / cand).is_file() and not (root / cand).is_symlink():
                    found = (d, cand)
                    break
            base = os.path.basename(name)
            if base in GENERATED:
                if found:  # old generated header present in the tree: never an input, shadowing is fatal
                    rec = {"path": found[1], "sha256": sha256_file(root / found[1]), "included_by": rel}
                    info["stale_generated_in_source_tree"].append(rec)
                    if found[0] == here and not angle:
                        raise StageError("generated-header-shadow", f"{found[1]} would shadow {base} in {rel}")
                continue
            if found:
                queue.append(found[1])
            else:
                info["unresolved_includes"].append({"in": rel, "name": name, "angle": angle})
    info.update(direct_inputs=len(direct), source_files=len(seen), source_bytes=total, direct_paths=direct,
                external_helper_hashes=external, closure_kind="conservative-literal-local-include-all-branches",
                complete_compiler_closure=False)
    info["unresolved_includes"] = info["unresolved_includes"][:200]
    return dict(sorted(seen.items())), info


def loaded_hash_map(root, module_hashes, guard_hash):
    """Hashes of the bytes actually compiled/executed, keyed like the source map (off-root helper by bare name)."""
    loaded = dict(module_hashes)
    cap = HERE / "source_capsule.py"
    try:
        loaded[cap.relative_to(Path(root).resolve()).as_posix()] = guard_hash
    except ValueError:
        loaded["source_capsule.py"] = guard_hash
    return loaded


def bind_hashes(loaded, source_map, info):
    """{key: True} when each executed module's bytes equal the authoritative source snapshot entry."""
    ext = info.get("external_helper_hashes", {})
    return {k: (source_map[k] if k in source_map else ext.get(k)) == h for k, h in sorted(loaded.items())}


def final_limit_problems(out, res, limits, total_stream):
    """Final own-output / receipt / disk-reserve / stream checks, evaluated before BUILT is declared."""
    problems = []
    receipt = len(json.dumps(res, indent=2, sort_keys=True).encode()) + 4096
    if _dir_size(out) + receipt > limits["own_output"] - ERROR_BUDGET:
        problems.append("own output plus receipt exceeds cap (error-receipt budget reserved)")
    if shutil.disk_usage(out).free < limits["reserve"]:
        problems.append("free disk below reserve at completion")
    if total_stream > limits["total_stream"]:
        problems.append("total stream cap exceeded")
    return problems


# ---------------------------------------------------------------- tools
def tool_table(path_env, hash_them=True):
    table = {}
    for name in TOOLS:
        p = shutil.which(name, path=path_env)
        ent = {"path": p, "realpath": os.path.realpath(p) if p else None, "version": None}
        if p and hash_them:
            ent["sha256"] = sha256_file(p, LIMITS["max_tool"])
        table[name] = ent
    return table


# ---------------------------------------------------------------- command guard and runner
def _under(path, base):
    return path == base or base in path.parents


def guard_command(argv, root, out, guards):
    """Refuse anything other than the seven primary tools touching only --root (read) / --out (write)."""
    root, out = Path(os.path.realpath(root)), Path(os.path.realpath(out))
    if not argv or argv[0] not in TOOLS:
        raise StageError("command-refused", f"tool not permitted: {argv[:1]}")
    suffixes = (".c", ".h", ".asm", ".ld", ".o", ".bin", ".elf", ".lst", ".img", ".iso", ".efi", ".vhd", ".qcow2")
    for i, arg in enumerate(argv[1:], 1):
        toks = re.split(r"[,=]", arg) if arg.startswith("-") else [arg]
        for tok in toks:
            if not ("/" in tok or tok.lower().endswith(suffixes)):
                continue
            real = Path(os.path.realpath(tok if os.path.isabs(tok) else os.path.join(root, tok)))
            writes = argv[i - 1] in ("-o", "-l") or (argv[0] == "objcopy" and i == len(argv) - 1)
            if real == out:
                why = None
            elif _under(real, out):
                why = guards.guard_path(real.relative_to(out).as_posix(), strict=False)
            elif _under(real, root) and not writes:
                why = guards.guard_path(real.relative_to(root).as_posix(), strict=False)
            else:
                why = "outside-root-or-out" if not writes else "write-outside-out"
            if why:
                raise StageError("command-refused", f"{argv[0]} argument {tok!r}: {why}")


def _dir_size(path):
    total = 0
    for base, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(base, f)).st_size
            except OSError:
                pass
    return total


def _exited(pid):
    """True once the child has exited, without reaping it (keeps the process-group id reserved)."""
    try:
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except ChildProcessError:
        return True


def _group_members(pgid, leader):
    """Live (non-zombie) processes of our own group other than the leader, from /proc."""
    found = []
    for ent in os.listdir("/proc"):
        if not ent.isdigit() or int(ent) == leader:
            continue
        try:
            fields = Path(f"/proc/{ent}/stat").read_text().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if fields[0] != "Z" and int(fields[2]) == pgid:
            found.append(int(ent))
    return found


def _pump(fd, state, cap):
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return
        state["total"] += len(chunk)
        state["hash"].update(chunk)
        if len(state["buf"]) < cap:
            state["buf"] += chunk[:cap - len(state["buf"])]
        if state["total"] > cap:
            state["over"] = True


class Runner:
    """Recording replacement for shzlib.run (same signature).  Every call, refused or not, is one record."""

    def __init__(self, root, out, guards, path_env=None, limits=LIMITS):
        self.root, self.out, self.guards, self.limits = Path(root).resolve(), Path(out), guards, dict(limits)
        self.path = path_env if path_env is not None else os.environ.get("PATH", "/usr/bin:/bin")
        self.records, self.phase, self.total = [], "stage", 0
        self.env = {"PATH": self.path, "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(self.out / "tmp")}

    def _record(self, argv, **kw):
        rec = {"index": len(self.records), "phase": self.phase, "argv": argv, "cwd": str(self.root)}
        rec.update(kw)
        self.records.append(rec)
        return rec

    def run(self, command, cwd=None, env=None, timeout=300, capture=False, check=True):
        argv = [str(x) for x in command]
        rec = self._record(argv, started_utc=utc(), status="refused", returncode=None, capture=bool(capture))
        if env is not None or (cwd is not None and Path(cwd).resolve() != self.root):
            raise StageError("command-refused", "custom env/cwd is not part of the stage recipe")
        guard_command(argv, self.root, self.out, self.guards)
        exe = shutil.which(argv[0], path=self.path)
        if not exe:
            raise StageError("tool-missing", argv[0])
        lim = self.limits
        timeout = min(lim["cmd_timeout"], timeout or lim["cmd_timeout"])
        if shutil.disk_usage(self.out).free < lim["reserve"]:
            raise StageError("disk-reserve", "free space below reserve before command")
        state = {"total": 0, "buf": bytearray(), "over": False, "hash": hashlib.sha256()}
        rec.update(status="running", executable=exe, timeout_s=timeout, env={k: self.env[k] for k in ("PATH", "LC_ALL", "TZ", "TMPDIR")})
        t0, reason, pump = time.monotonic(), None, None
        proc = subprocess.Popen(argv, executable=exe, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        pgid = proc.pid
        try:
            pump = threading.Thread(target=_pump, args=(proc.stdout.fileno(), state, lim["capture"]), daemon=True)
            pump.start()
            last = 0.0
            while not _exited(pgid):
                now = time.monotonic()
                if now - t0 > timeout:
                    reason = "timeout"
                elif state["over"]:
                    reason = "output-cap"
                elif now - last > 0.3:
                    last = now
                    if _dir_size(self.out) > lim["own_output"]:
                        reason = "own-output-cap"
                    elif shutil.disk_usage(self.out).free < lim["reserve"]:
                        reason = "disk-reserve"
                if reason:
                    break
                time.sleep(0.02)
        finally:
            survivors = bool(_group_members(pgid, pgid))
            try:
                os.killpg(pgid, signal.SIGKILL)  # owned group only; never anybody else's process
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
            if pump:
                pump.join(10)
            proc.stdout.close()
        self.total += state["total"]
        if not reason:  # the leader may exit before any in-loop poll: always evaluate the limits afterwards
            if state["over"] or state["total"] > lim["capture"]:
                reason = "output-cap"
            elif _dir_size(self.out) > lim["own_output"]:
                reason = "own-output-cap"
            elif shutil.disk_usage(self.out).free < lim["reserve"]:
                reason = "disk-reserve"
        text = bytes(state["buf"]).decode("utf-8", "replace")
        log = None
        try:
            (self.out / "logs").mkdir(exist_ok=True)
            log = f"logs/{rec['index']:03d}-{Path(argv[0]).name}.log"
            (self.out / log).write_bytes(bytes(state["buf"][:lim["per_log"]]))
        except OSError as exc:
            log = f"unwritten: {exc}"
        if self.total > lim["total_stream"] and not reason:
            reason = "total-stream-cap"
        rc = proc.returncode
        rec.update(ended_utc=utc(), duration_s=round(time.monotonic() - t0, 3), returncode=rc, log=log,
                   stream_bytes=state["total"], stream_sha256=state["hash"].hexdigest(),
                   log_truncated=state["total"] > lim["per_log"], leftover_group_killed=survivors,
                   status=reason or ("ok" if rc == 0 else "nonzero"))
        if reason:
            raise StageError("command-" + reason, " ".join(argv[:3]))
        if check and rc != 0:
            raise RuntimeError(f"command failed ({rc}): {' '.join(argv)}\n{text[-2000:]}")
        return subprocess.CompletedProcess(argv, rc, stdout=text if capture else None)


# ---------------------------------------------------------------- stage
def _write_json_atomic(path, doc):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def make_fresh_out(root, out):
    out = Path(os.path.abspath(out))
    root = Path(root).resolve()
    if not out.parent.is_dir() or out.parent.is_symlink() or out.is_symlink():
        raise StageError("output-refused", "parent missing or symlink")
    real = Path(os.path.realpath(out))
    if _under(real, root) and (real.relative_to(root).parts[:1] != ("build",)):
        raise StageError("output-refused", "inside --root outside build/")
    if _under(root, real):
        raise StageError("output-refused", "contains --root")
    try:
        os.mkdir(out, 0o700)
    except FileExistsError:
        raise StageError("output-exists", "fresh output directory required; nothing reused or deleted")
    (out / "tmp").mkdir()
    return out


def _file_entry(path):
    return {"sha256": sha256_file(path), "bytes": Path(path).stat().st_size}


def _forbid(name):
    def raiser(*_a, **_k):
        raise StageError("forbidden-call", name)
    return raiser


def _on_sigterm(_signo, _frame):
    raise StageError("terminated", "SIGTERM received; owned process group killed, partial receipt written")


def stage(root, out, reference=None, path_env=None, limits=LIMITS, loader_seeds=LOADER_SEEDS, guards=None):
    """`guards` may be the (module, loaded_sha256) pair returned by load_guards()."""
    root = Path(root).resolve()
    guards, guard_hash = guards if isinstance(guards, tuple) else (guards, None)
    if guards is None:
        guards, guard_hash = load_guards()
    out = make_fresh_out(root, out)  # StageError here: nothing exists to write evidence into
    t0 = time.monotonic()
    path_env = path_env if path_env is not None else os.environ.get("PATH", "/usr/bin:/bin")
    res = {"schema": SCHEMA, "producer_epoch": EPOCH, "status": "FAILED", "started_utc": utc(),
           "root": str(root), "out": str(out), "claims": {k: False for k in FALSE_CLAIMS},
           "guest_validation": "NOT_RUN: BUILT_PENDING_GUEST_VALIDATION is not guest acceptance",
           "limitations": list(LIMITATIONS), "authored_against": AUTHORED_AGAINST,
           "commands": [], "failure": None}
    runner = Runner(root, out, guards, path_env, limits)
    old_term = signal.signal(signal.SIGTERM, _on_sigterm) if threading.current_thread() is threading.main_thread() else None
    try:
        shz, build, hashes = load_modules(root)
        res["module_sha256"] = hashes
        res["module_matches_authored_against"] = {k: hashes.get(k) == v for k, v in AUTHORED_AGAINST.items()}
        before, info = collect_sources(root, build, guards, loader_seeds=loader_seeds, limits=limits)
        res.update(source_before=before, sources_sha256=before, source_map_info=info)
        loaded = loaded_hash_map(root, hashes, guard_hash)
        bound = bind_hashes(loaded, before, info)
        res["hash_binding"] = {"executed_module_sha256": loaded, "equals_source_before": bound, "bound": all(bound.values())}
        if not all(bound.values()):
            raise StageError("hash-binding", "executed module bytes differ from source snapshot: " +
                             ",".join(k for k, v in bound.items() if not v))
        tools_pre = tool_table(path_env)
        res["tools_pre"] = tools_pre
        missing = [k for k, v in tools_pre.items() if not v["path"]]
        if missing:
            raise StageError("tool-missing", ",".join(missing))
        build.OUT = out  # relocate OUT only; flags and recipe are untouched
        build.run = runner.run
        for name in ("main", "build_esp", "guest_kernel_files"):
            setattr(build, name, _forbid("build." + name))
        for name in ("ensure_upstream", "ensure_deb_upstream", "ensure_open_watcom", "_fetch_pinned"):
            if hasattr(shz, name):
                setattr(shz, name, _forbid("shzlib." + name))
        versions = {}
        runner.phase = "tool-version-pre"
        for name in TOOLS:
            versions[name] = runner.run([name, VERSION_ARGS.get(name, "--version")], capture=True).stdout.splitlines()[:1]
        res["tool_versions_pre"] = versions
        runner.phase = "stage"
        build.build_vbios()
        build.build_ap_trampoline()
        payload, _pcmds = build.build_payload()
        build.build_loader(payload, None)
        runner.phase = "tool-version-post"
        res["tool_versions_post"] = {n: runner.run([n, VERSION_ARGS.get(n, "--version")], capture=True).stdout.splitlines()[:1]
                                    for n in TOOLS}
        runner.phase = "post"
        res["tools_post"] = tool_table(path_env)
        res["tools_unchanged"] = all(tools_pre[n].get("sha256") == res["tools_post"][n].get("sha256") and
                                     tools_pre[n]["realpath"] == res["tools_post"][n]["realpath"] for n in TOOLS)
        after, info_after = collect_sources(root, build, guards, loader_seeds=loader_seeds, limits=limits)
        bound_after = bind_hashes(loaded, after, info_after)
        res["hash_binding"]["equals_source_after"] = bound_after
        res["hash_binding"]["bound_after"] = all(bound_after.values())
        res.update(source_after=after, source_unchanged=(before == after and
                   info["external_helper_hashes"] == info_after["external_helper_hashes"]))
        res["inputs_unchanged"] = bool(res["source_unchanged"] and res["tools_unchanged"])
        arts, problems = {}, []
        for name in ARTIFACTS:
            p = out / name
            if p.is_file() and not p.is_symlink():
                arts[name] = _file_entry(p)
            else:
                problems.append(f"artifact missing: {name}")
        res["artifacts"] = arts
        res["other_outputs"] = {p.relative_to(out).as_posix(): _file_entry(p) for p in sorted(out.glob("obj/*"))
                                if p.is_file()}
        res["other_outputs"].update({"vbios.lst": _file_entry(out / "vbios.lst")} if (out / "vbios.lst").is_file() else {})
        res["generated_headers"] = {n: arts[n] for n in GENERATED if n in arts}
        stray = []  # actual file inputs of the recorded commands must be in the source map
        for rec in runner.records:
            if rec["phase"] != "stage":
                continue
            for tok in rec["argv"][1:]:
                if tok.endswith((".c", ".h", ".asm", ".ld")):
                    p = Path(os.path.realpath(tok if os.path.isabs(tok) else root / tok))
                    if _under(p, root) and p.is_file() and p.relative_to(root).as_posix() not in before:
                        stray.append(p.relative_to(root).as_posix())
        res["command_inputs_outside_source_map"] = sorted(set(stray))
        if stray:
            problems.append("command inputs outside the source map")
        if not res["source_unchanged"]:
            problems.append("source mutated during build")
        if not res["tools_unchanged"]:
            problems.append("tool executable changed during build")
        if not res["hash_binding"]["bound_after"]:
            problems.append("executed module bytes differ from post-run source")
        if reference is not None:
            actual = arts.get("BOOTX64.EFI", {}).get("sha256")
            res["reference_efi"] = {"pinned_sha256": reference, "actual_sha256": actual,
                                    "match": actual == reference,
                                    "scope": "one external comparison only; no historical source/binary binding"}
        res["commands"] = runner.records
        problems += final_limit_problems(out, res, limits, runner.total)
        if problems:
            res["failure"] = {"kind": "post-check", "detail": problems}
        else:
            res["status"] = "BUILT_PENDING_GUEST_VALIDATION"
    except StageError as exc:
        res["failure"] = {"kind": exc.kind, "detail": exc.detail}
    except BaseException as exc:  # preserve partial evidence for any failure
        res["failure"] = {"kind": type(exc).__name__, "detail": str(exc)[-4000:]}
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            if old_term is not None:
                signal.signal(signal.SIGTERM, old_term)
            res["commands"] = runner.records
            res["ended_utc"] = utc()
            _write_json_atomic(out / RESULT_NAME, res)
            raise
    if old_term is not None:
        signal.signal(signal.SIGTERM, old_term)
    res["commands"] = runner.records
    res["stream_bytes_total"] = runner.total
    res.update(ended_utc=utc(), duration_s=round(time.monotonic() - t0, 3))
    if "reference_efi" not in res and reference is not None:
        res["reference_efi"] = {"pinned_sha256": reference, "actual_sha256": None, "match": False,
                                "scope": "no artifact produced"}
    _write_json_atomic(out / RESULT_NAME, res)
    return res


def check(root, out=None, path_env=None):
    root = Path(root).resolve()
    guards, guard_hash = load_guards()
    shz, build, hashes = load_modules(root)
    before, info = collect_sources(root, build, guards)
    bound = bind_hashes(loaded_hash_map(root, hashes, guard_hash), before, info)
    path_env = path_env if path_env is not None else os.environ.get("PATH", "/usr/bin:/bin")
    tools = tool_table(path_env)
    free = shutil.disk_usage(root).free
    problems = [f"tool missing: {k}" for k, v in tools.items() if not v["path"]]
    if not all(bound.values()):
        problems.append("executed module bytes differ from source snapshot")
    if free < LIMITS["reserve"]:
        problems.append("free disk below 17 GiB reserve")
    if out is not None and os.path.lexists(out):
        problems.append("output path already exists (fresh directory required)")
    return {"schema": SCHEMA, "mode": "check-only", "writes": "none", "tools_executed": False,
            "module_sha256": hashes, "module_matches_authored_against": {k: hashes.get(k) == v for k, v in AUTHORED_AGAINST.items()},
            "hash_binding": {"equals_source_snapshot": bound, "bound": all(bound.values())}, "source_files": len(before), "direct_inputs": info["direct_inputs"], "source_bytes": info["source_bytes"],
            "unresolved_include_count": len(info["unresolved_includes"]),
            "stale_generated_headers_in_tree": info["stale_generated_in_source_tree"],
            "tools": tools, "free_bytes": free, "problems": problems, "ok": not problems,
            "claims": {k: False for k in FALSE_CLAIMS}, "limitations": list(LIMITATIONS)}


# ---------------------------------------------------------------- self-test (modeled; fake tools, no compile)
_FAKE_BUILD = '''
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import shzlib
from shzlib import BUILD, REPO, SHZ, run, sha256_file
SRC = SHZ / "supervisor"; OUT = BUILD / "supervisor"
PAYLOAD_C = ["main.c"]; PAYLOAD_ASM = []
def build_vbios():
    run(["nasm", "-o", OUT / "vbios.bin", SRC / "guest" / "vbios.asm"]); (OUT / "vbios_image.h").write_text("v")
    return (OUT / "vbios.bin").read_bytes()
def build_ap_trampoline():
    c = ["nasm", "-o", OUT / "ap-trampoline.bin", SRC / "src" / "ap_trampoline.asm"]; run(c)
    (OUT / "ap_trampoline_image.h").write_text("a"); return (OUT / "ap-trampoline.bin").read_bytes(), c
def build_payload():
    OUT.joinpath("obj").mkdir(exist_ok=True)
    run(["gcc", "-I", OUT, "-c", SRC / "src" / "main.c", "-o", OUT / "obj" / "main.o"])
    run(["ld", "-T", SRC / "payload.ld", "-o", OUT / "payload.elf", OUT / "obj" / "main.o"])
    assert not run(["nm", "-u", OUT / "payload.elf"], capture=True).stdout.strip()
    run(["objcopy", "-O", "binary", OUT / "payload.elf", OUT / "payload.bin"])
    return (OUT / "payload.bin").read_bytes(), []
def build_loader(payload, private_profile=None):
    (OUT / "images.h").write_text("p")
    c = ["x86_64-w64-mingw32-gcc", "-I", OUT, SRC / "loader" / "loader.c", "-o", OUT / "BOOTX64.EFI"]; run(c)
    return OUT / "BOOTX64.EFI", c
def build_esp(*a): raise RuntimeError("must not be called")
def main(): raise RuntimeError("must not be called")
def guest_kernel_files(): raise RuntimeError("must not be called")
'''
_FAKE_SHZ = ('from pathlib import Path\nimport hashlib\nREPO = Path(__file__).resolve().parents[2]\nSHZ = REPO / "shizukudos"\n'
             'BUILD = REPO / "build" / "shizukudos"\ndef run(*a, **k): raise RuntimeError("original run must be replaced")\n'
             'def sha256_file(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()\n')
_FAKE_TOOL = '''#!/bin/sh
d=$(dirname "$0"); name=$(basename "$0"); mode=$(head -n1 "$d/mode")
case "$1" in --version|-v) echo "fake $name 1"; exit 0;; esac
out=""; prev=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; last="$a"; done
[ "$name" = objcopy ] && out="$last"
case "$mode" in
 hang) sleep 300 & echo $! > "$d/childpid"; wait;;
 mutate) echo "// changed" >> "$(sed -n 2p "$d/mode")";;
esac
[ -n "$out" ] && [ "$name" != nm ] && printf 'fake %s' "$name" > "$out"
exit 0
'''


def _fixture(tmp):
    tmp = Path(tmp)
    sup = tmp / "root/shizukudos/supervisor"
    for d in ("src", "guest", "loader"):
        (sup / d).mkdir(parents=True)
    (tmp / "root/shizukudos/tools").mkdir(parents=True)
    (tmp / "root/shizukudos/uefi").mkdir(parents=True)
    (tmp / "root/shizukudos/tools/shzlib.py").write_text(_FAKE_SHZ)
    (sup / "build.py").write_text(_FAKE_BUILD)
    (sup / "src/main.c").write_text('#include "local.h"\n#include "images.h"\n#include <stdint.h>\n')
    (sup / "src/local.h").write_text("/* h */\n")
    (sup / "src/ap_trampoline.asm").write_text("; a\n")
    (sup / "guest/vbios.asm").write_text("; v\n")
    (sup / "payload.ld").write_text("/* ld */\n")
    for seed in LOADER_SEEDS:
        (tmp / "root" / seed).parent.mkdir(parents=True, exist_ok=True)
        (tmp / "root" / seed).write_text("/* seed */\n")
    (sup / "loader/loader.c").write_text('#include "vbios_image.h"\n')
    (tmp / "bin").mkdir()
    for name in TOOLS:
        (tmp / "bin" / name).write_text(_FAKE_TOOL)
        os.chmod(tmp / "bin" / name, 0o755)
    (tmp / "bin/mode").write_text("ok\n")
    return tmp / "root", tmp / "bin"


def self_test():
    results = []
    guards_pair = load_guards()
    guards = guards_pair[0]
    seeds = LOADER_SEEDS

    def case(name, fn):
        try:
            fn()
            results.append({"test": name, "outcome": "PASS"})
        except BaseException as exc:  # noqa: BLE001 - every failure is evidence
            results.append({"test": name, "outcome": "FAIL", "detail": f"{type(exc).__name__}: {exc}"})

    def need(cond, msg="assertion failed"):
        if not cond:
            raise AssertionError(msg)

    with tempfile.TemporaryDirectory(prefix="stage-selftest-") as t:
        t = Path(t)
        root, bindir = _fixture(t)
        path = f"{bindir}:/usr/bin:/bin"
        small = dict(LIMITS, reserve=1 << 20, cmd_timeout=3)

        def run_stage(name, **kw):
            return stage(root, t / name, path_env=path, limits=kw.pop("limits", small), loader_seeds=seeds, guards=guards_pair, **kw)

        def happy():
            a = run_stage("out-a", reference="0" * 64)
            b = run_stage("out-b")
            need(a["status"] == "BUILT_PENDING_GUEST_VALIDATION", str(a["failure"]))
            need(a["source_unchanged"] and a["source_before"] == a["source_after"] and a["sources_sha256"])
            need(not any(a["claims"].values()), "claims must all be false")
            need(a["reference_efi"]["match"] is False, "reference mismatch recorded")
            names = [Path(c["argv"][0]).name for c in a["commands"] if c["phase"] == "stage"]
            need(names == ["nasm", "nasm", "gcc", "ld", "nm", "objcopy", "x86_64-w64-mingw32-gcc"], names)
            need(all(c["status"] == "ok" and c["returncode"] == 0 and c["stream_sha256"] for c in a["commands"]))
            need({k: v["sha256"] for k, v in a["artifacts"].items()} == {k: v["sha256"] for k, v in b["artifacts"].items()},
                 "deterministic artifacts")
            need(a["source_map_info"]["stale_generated_in_source_tree"] == [] and a["source_map_info"]["unresolved_includes"][0]["name"] == "stdint.h")
            need(not any(p for p in (out for out in t.rglob("*.pyc"))), "no bytecode written")
            need(json.loads((t / "out-a" / RESULT_NAME).read_text())["status"] == a["status"])

        def mutation():
            (bindir / "mode").write_text(f"mutate\n{root}/shizukudos/supervisor/src/local.h\n")
            r = run_stage("out-mut")
            (bindir / "mode").write_text("ok\n")
            need(r["status"] == "FAILED" and r["source_unchanged"] is False, r["status"])
            need(r["source_before"] != r["source_after"] and (t / "out-mut" / RESULT_NAME).is_file())
            (root / "shizukudos/supervisor/src/local.h").write_text("/* h */\n")

        def refusals():
            r = Runner(root, t / "out-a", guards, path, small)
            for argv in (["mcopy", "-i", "x", "y"], ["nasm", "-o", "/tmp/escape.bin", "a.asm"],
                         ["gcc", "-c", "/etc/passwd"], ["gcc", "-o", str(t / "out-a/esp.img")],
                         ["objcopy", "-O", "binary", "x", str(root / "shizukudos/supervisor/src/main.c")]):
                try:
                    r.run(argv)
                except StageError as exc:
                    need(exc.kind == "command-refused", exc.kind)
                else:
                    raise AssertionError(f"not refused: {argv}")
            need(len(r.records) == 5 and all(x["status"] == "refused" for x in r.records), "refusals recorded")
            # shadowing generated header in the includer's directory is fatal, not silently used
            (root / "shizukudos/supervisor/src/images.h").write_text("old")
            r2 = run_stage("out-shadow")
            (root / "shizukudos/supervisor/src/images.h").unlink()
            need(r2["failure"]["kind"] == "generated-header-shadow", str(r2["failure"]))

        def collision():
            for existing in (t / "out-a", t / "empty"):
                existing.mkdir(exist_ok=True)
                try:
                    stage(root, existing, path_env=path, limits=small, guards=guards_pair)
                except StageError as exc:
                    need(exc.kind == "output-exists")
                else:
                    raise AssertionError("existing output reused")
            try:
                make_fresh_out(root, root / "shizukudos/x")
            except StageError as exc:
                need(exc.kind == "output-refused")
            else:
                raise AssertionError("output inside source tree accepted")

        def cleanup():
            (bindir / "mode").write_text("hang\n")
            t0 = time.monotonic()
            r = run_stage("out-hang")
            (bindir / "mode").write_text("ok\n")
            need(r["status"] == "FAILED" and r["failure"]["kind"] == "command-timeout", str(r["failure"]))
            need(time.monotonic() - t0 < 30, "bounded")
            pid = int((bindir / "childpid").read_text())
            time.sleep(0.3)
            try:
                os.kill(pid, 0)
                alive = "Z" not in Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1][:3]
            except (ProcessLookupError, FileNotFoundError):
                alive = False
            need(not alive, "child of the owned process group was killed")
            need(r["commands"][-1]["leftover_group_killed"] is True, "group survivor recorded")

        def readonly():
            helper = str(Path(__file__).resolve())
            before = {p for p in HERE.rglob("__pycache__")}
            env = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
            h = subprocess.run([sys.executable, helper, "--help"], capture_output=True, text=True, env=env, timeout=30)
            c = subprocess.run([sys.executable, helper, "--check", "--root", str(root)], capture_output=True, text=True,
                               env=dict(env, PATH=path), timeout=30)
            need(h.returncode == 0 and "--check" in h.stdout, "help")
            doc = json.loads(c.stdout)
            need(doc["mode"] == "check-only" and doc["tools_executed"] is False and doc["source_files"] >= 14 and doc["direct_inputs"] == 11, c.stdout[-300:])
            need({p for p in HERE.rglob("__pycache__")} == before and not list(t.rglob("*.pyc")), "no pycache written")
            need(not (t / "out-new").exists())

        def failure_json():
            (bindir / "mode").write_text("ok\n")
            os.chmod(bindir / "nm", 0o644)  # tool no longer executable -> shutil.which misses it
            r = stage(root, t / "out-missing", path_env=str(bindir), limits=small, loader_seeds=seeds, guards=guards_pair)
            os.chmod(bindir / "nm", 0o755)
            need(r["status"] == "FAILED" and r["failure"]["kind"] == "tool-missing", str(r["failure"]))
            need(json.loads((t / "out-missing" / RESULT_NAME).read_text())["failure"]["kind"] == "tool-missing")

        def optimize_refused():
            helper = str(Path(__file__).resolve())
            c = subprocess.run([sys.executable, "-O", helper, "--check", "--root", str(root)], capture_output=True,
                               text=True, timeout=30)
            need(c.returncode == 2 and "optimize-refused" in c.stderr, c.stderr[-200:])
            s = subprocess.run([sys.executable, "-O", helper, "--root", str(root), "--out", str(t / "out-opt")],
                               capture_output=True, text=True, timeout=30, env=dict(os.environ, PATH=path))
            doc = json.loads((t / "out-opt" / RESULT_NAME).read_text())
            need(s.returncode == 1 and doc["status"] == "FAILED" and doc["failure"]["kind"] == "optimize-refused"
                 and not doc["commands"], s.stderr[-200:])

        def sigterm_receipt():
            (bindir / "mode").write_text("hang\n")
            (bindir / "childpid").unlink(missing_ok=True)
            p = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--root", str(root), "--out",
                                  str(t / "out-term")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 env=dict(os.environ, PATH=path))
            try:
                for _ in range(300):
                    if (bindir / "childpid").exists() and (bindir / "childpid").read_text().strip():
                        break
                    time.sleep(0.1)
                need((bindir / "childpid").exists(), "hanging tool never started")
                pid = int((bindir / "childpid").read_text())
                p.terminate()
                p.communicate(timeout=30)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
                (bindir / "mode").write_text("ok\n")
            doc = json.loads((t / "out-term" / RESULT_NAME).read_text())
            need(doc["status"] == "FAILED" and doc["failure"]["kind"] == "terminated", str(doc["failure"]))
            time.sleep(0.3)
            need(not Path(f"/proc/{pid}").exists() or "Z" in Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1][:3],
                 "gcc-side group child survived SIGTERM")

        def load_to_snapshot_mutation():
            real = globals()["load_modules"]

            def mutating(r):
                out3 = real(r)
                with open(Path(r) / "shizukudos/supervisor/build.py", "a") as fh:
                    fh.write("# appended after load, before snapshot\n")
                return out3
            globals()["load_modules"] = mutating
            try:
                r = run_stage("out-bind")
            finally:
                globals()["load_modules"] = real
            need(r["status"] == "FAILED" and r["failure"]["kind"] == "hash-binding", str(r["failure"]))
            need(r["commands"] == [] and r["hash_binding"]["bound"] is False, "refused before any tool command")
            (root / "shizukudos/supervisor/build.py").write_text(_FAKE_BUILD)
            ok = run_stage("out-bind-ok")
            need(ok["status"] == "BUILT_PENDING_GUEST_VALIDATION" and ok["hash_binding"]["bound_after"], str(ok["failure"]))

        def fast_finish_caps():
            r = run_stage("out-cap", limits=dict(small, capture=4))  # nasm -v prints 12 bytes and exits at once
            need(r["status"] == "FAILED" and r["failure"]["kind"] == "command-output-cap", str(r["failure"]))
            need(r["commands"][0]["status"] == "output-cap" and (t / "out-cap" / RESULT_NAME).is_file())
            r = run_stage("out-budget", limits=dict(small, own_output=ERROR_BUDGET + 100))
            need(r["status"] == "FAILED" and r["failure"]["kind"] == "post-check" and
                 any("own output" in x for x in r["failure"]["detail"]), str(r["failure"]))
            need(json.loads((t / "out-budget" / RESULT_NAME).read_text())["status"] == "FAILED", "error receipt kept")

        for name, fn in (("happy-path-order-hashes-determinism", happy), ("source-mutation-refused", mutation),
                         ("path-tool-refusals-and-generated-shadow", refusals), ("output-collision-and-placement", collision),
                         ("owned-process-group-cleanup", cleanup), ("readonly-help-check-no-bytecode", readonly),
                         ("structured-failure-json", failure_json),
                         ("optimize-level-refused", optimize_refused), ("sigterm-kills-group-writes-receipt", sigterm_receipt),
                         ("load-to-snapshot-hash-binding", load_to_snapshot_mutation),
                         ("fast-finish-capture-and-final-budget", fast_finish_caps)):
            case(name, fn)
    ok = all(r["outcome"] == "PASS" for r in results)
    print(json.dumps({"self_test": "PASS" if ok else "FAIL", "modeled": "fake shell tools; NOT an EFI compile and not "
                      "evidence about the real toolchain", "results": results}, indent=2))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", help="project root containing shizukudos/ (explicit; no default)")
    ap.add_argument("--out", help="FRESH output directory (explicit; no default, must not exist)")
    ap.add_argument("--check", action="store_true", help="read-only validation; no tool executed, nothing written")
    ap.add_argument("--self-test", action="store_true", help="modeled fixtures with fake tools (not a compile)")
    ap.add_argument("--reference-efi-sha256", help="optional external pin compared once with the produced BOOTX64.EFI")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.root:
        ap.error("--root is required")
    if a.reference_efi_sha256 and not re.fullmatch(r"[0-9a-f]{64}", a.reference_efi_sha256):
        ap.error("--reference-efi-sha256 must be 64 lowercase hex")
    try:
        if a.check:
            doc = check(a.root, a.out)
            print(json.dumps(doc, indent=2, sort_keys=True))
            return 0 if doc["ok"] else 1
        if not a.out:
            ap.error("--out FRESH_DIR is required for an actual stage build")
        res = stage(a.root, a.out, reference=a.reference_efi_sha256)
    except StageError as exc:
        print(json.dumps({"status": "REFUSED", "kind": exc.kind, "detail": exc.detail}), file=sys.stderr)
        return 2
    print(json.dumps({k: res.get(k) for k in ("status", "failure", "artifacts", "source_unchanged", "reference_efi")},
                     indent=2, sort_keys=True))
    return 0 if res["status"] == "BUILT_PENDING_GUEST_VALIDATION" else 1


if __name__ == "__main__":
    sys.exit(main())
