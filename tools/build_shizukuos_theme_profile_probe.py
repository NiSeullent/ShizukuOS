#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build static-only SHZTPRO.EXE and pure helper controls; never run a guest.

The provider epoch is caller-approved v4. Every declared original source,
artifact, CPU listing and command log is read, pinned, copied and checked again.
An explicitly pinned, preserved helper RED stage may precede the final build.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PROVIDER_RECEIPT = "c9d8fdc57d4b5986297f44edbcbdc88b107088768ea39accac7c800d80b0af28"
PROVIDER_DLL = "721e3700b978f12cf7d535cb9ff8ed02bc0262a464a88011aa86804d845308b4"
BUILDER_SOURCE = "d5f7e2e70caf5529a922dbf316af1675d620987d69dfc7fa507c97ceb9cb5271"
UTILITY_SOURCE = "84b36a92d9b50fe6988c9e7c6bbd8dde65468dd3a023159858a0bc443b03e6e2"
RESERVE, BUDGET, RAM, RSS_LIMIT = 20 * 1024**3, 8 * 1024**2, 6 * 1024**3, 512 * 1024**2
OWNED = ("tests/shizukuos_theme_profile_guest.c", "tests/shizukuos_theme_profile_helpers_host.c",
         "tools/build_shizukuos_theme_profile_probe.py")
FALSE = dict(native_execution=False, native_gui_verified=False, OS_wide_theme_verified=False,
             reboot_persistence_verified=False, modern_app_functionality_verified=False,
             Microsoft_DOS_replacement_verified=False)


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=16 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical input: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "nonregular/unbounded input")
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(maximum + 1)
        after = os.fstat(fd)
        need(len(data) == before.st_size and identity(before) == identity(after), "input changed while reading")
        return data
    finally:
        os.close(fd)


def identity(value):
    return tuple(getattr(value, field) for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))


def json_object(data):
    def unique(rows):
        value = {}
        for key, child in rows:
            need(key not in value, "duplicate JSON key")
            value[key] = child
        return value
    value = json.loads(data, object_pairs_hook=unique)
    need(isinstance(value, dict), "receipt must be an object")
    return value


def module(data, path, name):
    result = types.ModuleType(name)
    result.__file__ = str(path)
    exec(compile(data, str(path), "exec", optimize=2), result.__dict__)
    return result


def file_hash(path):
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_size <= 256 * 1024**2, "unbounded tool input")
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024**2), b""):
            digest.update(block); size += len(block)
    need(identity(before) == identity(path.stat()) and size == before.st_size, "tool changed during hashing")
    return digest.hexdigest()


class Build:
    def __init__(self, directory, utility, red_seconds):
        self.directory, self.utility = directory, utility
        self.steps, self.samples, self.pins = [], [], {}
        self.command_seconds = red_seconds

    def guard(self, group=None):
        row = dict(free_bytes=shutil.disk_usage(ROOT).free,
                   available_bytes=self.utility.mem_available(),
                   own_bytes=self.utility.own_bytes(self.directory),
                   group_RSS_bytes=self.utility.rss(group) if group else 0)
        self.samples.append(row)
        need(row["free_bytes"] >= RESERVE, "disk floor breached")
        need(row["available_bytes"] >= RAM, "available memory floor breached")
        need(row["own_bytes"] <= BUDGET, "own output budget breached")
        need(row["group_RSS_bytes"] <= RSS_LIMIT, "owned RSS limit breached")

    def write(self, path, data):
        self.guard()
        need(self.utility.own_bytes(self.directory) + len(data) <= BUDGET, "copy exceeds aggregate budget")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        need(read(path) == data, "copy differs from original")
        self.pins[str(path)] = sha(data)
        self.guard()

    def command(self, argv, title, env=None):
        self.guard()
        need(self.command_seconds < 90, "aggregate command limit exhausted")
        timeout = min(60, 90 - self.command_seconds)
        row = dict(command=argv, timeout_seconds=timeout, stdout=title + ".stdout", stderr=title + ".stderr")
        self.steps.append(row)
        start, process = time.monotonic(), None
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (BUDGET, BUDGET))
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            # ASan needs large virtual shadow mappings; the 512MiB limit is RSS,
            # measured across only the newly owned process group.
        try:
            with (self.directory / row["stdout"]).open("xb") as out, (self.directory / row["stderr"]).open("xb") as err:
                settings = dict(os.environ, LC_ALL="C", LANG="C", PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(self.directory))
                if env: settings.update(env)
                process = subprocess.Popen(argv, cwd=ROOT, stdout=out, stderr=err,
                                           start_new_session=True, preexec_fn=limits, env=settings)
                row["owned_group"] = process.pid
                while process.poll() is None:
                    self.guard(process.pid)
                    need(time.monotonic() - start <= timeout, "owned command timeout")
                    time.sleep(0.05)
                row["returncode"] = process.wait()
        except BaseException as error:
            if process is not None:
                self.utility.stop_owned(process)
            row["error"] = str(error)
            raise
        finally:
            elapsed = time.monotonic() - start
            self.command_seconds += elapsed
            row["elapsed_seconds"] = elapsed
            for field in ("stdout", "stderr"):
                path = self.directory / row[field]
                if path.exists():
                    data = read(path, BUDGET)
                    row[field + "_sha256"] = sha(data)
                    self.pins[str(path)] = sha(data)
        self.guard()
        need(row["returncode"] == 0, "command failed: " + title)
        need(self.command_seconds <= 90, "aggregate command limit breached")
        return read(self.directory / row["stdout"])


def relative(value):
    need(isinstance(value, str) and value and not Path(value).is_absolute() and
         all(part not in ("", ".", "..") for part in value.split("/")), "unsafe relative input")
    return Path(value)


def dependencies(path):
    text = read(path).decode().replace("\\\n", " ")
    need(text.startswith("SHZTPRO:"), "unexpected dependency target")
    return {str((ROOT / name if not Path(name).is_absolute() else Path(name)).resolve(strict=True))
            for name in shlex.split(text.split(":", 1)[1])}


def sections(data, pefile):
    result = {}
    with pefile.PE(data=data) as pe:
        need(pe.FILE_HEADER.Machine == 0x14c and pe.OPTIONAL_HEADER.Magic == 0x10b, "i386 PE32 required")
        for section in pe.sections:
            if section.Characteristics & 0x20000000:
                name = section.Name.rstrip(b"\0").decode("ascii")
                size = section.Misc_VirtualSize
                need(name not in result and 0 < size <= section.SizeOfRawData <= 4 * 1024**2,
                     "invalid executable section")
                raw = section.get_data()[:size]
                need(len(raw) == size, "truncated executable section")
                result[name] = dict(data=raw, address=pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress)
    need(result and sum(len(row["data"]) for row in result.values()) <= 4 * 1024**2, "executable section bound")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-dir", type=Path, default=Path("build/shizukuos-theme-v4"))
    parser.add_argument("--output-dir", type=Path, default=Path("build/shizukuos-profile-native-v1"))
    parser.add_argument("--resume-red-sha256", help="Exact caller pin of this owned directory's preserved helper RED receipt")
    parser.add_argument("--nonce", default="shizukuos-profile-5abe-v1")
    args = parser.parse_args()
    build = None
    try:
        need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.nonce), "invalid frozen nonce")
        origin = args.provider_dir if args.provider_dir.is_absolute() else ROOT / args.provider_dir
        target = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
        need(origin.resolve(strict=True) == origin and origin.is_relative_to(ROOT / "build"), "provider outside canonical own build")
        need(target.parent.resolve(strict=True) == target.parent and target.is_relative_to(ROOT / "build") and
             not target.is_symlink() and not target.is_relative_to(origin), "invalid owned output directory")
        original, copies = {}, {}
        def source(path, expected=None, maximum=16 * 1024**2):
            data = read(path, maximum)
            if expected is not None: need(sha(data) == expected, "approved input drift: " + str(path))
            original[str(path)] = sha(data)
            return data
        receipt_path = origin / "result.json"
        provider_data = source(receipt_path, PROVIDER_RECEIPT)
        provider = json_object(provider_data)
        need(provider.get("passed") is True and provider.get("native_win98") == "not_tested", "provider receipt scope/status")
        copies[Path("provider-build/result.json")] = provider_data
        for name, expected in provider["source_sha256"].items():
            name = relative(name)
            copies[Path("source/provider") / name] = source(ROOT / name, expected)
        builder_data = source(ROOT / "tools/build_theme_engine.py", BUILDER_SOURCE)
        need(set(provider["artifacts"]) == {"M98THEME.DLL", "M98THPRO.EXE", "M98THSTA.EXE", "SHZAPPEAR.EXE"}, "provider artifact closure")
        for name, row in provider["artifacts"].items():
            data = source(origin / name, row["sha256"], 1024**2)
            need(len(data) == row["bytes"], "provider artifact size")
            copies[Path("provider-build") / name] = data
            listing = source(origin / (name + ".i486.log"), row["i486"]["disassembly_sha256"])
            copies[Path("provider-build") / (name + ".i486.log")] = listing
        need(provider["artifacts"]["M98THEME.DLL"]["sha256"] == PROVIDER_DLL, "approved provider differs")
        copies[Path("M98THEME.DLL")] = copies[Path("provider-build/M98THEME.DLL")]
        for step in provider["steps"]:
            need(step["returncode"] == 0, "original provider command failed")
            for row in step["logs"].values():
                name = relative(row["path"])
                need(len(name.parts) == 1, "provider log must be direct")
                data = source(origin / name, row["sha256"])
                need(len(data) == row["bytes"], "original log size")
                copies[Path("provider-build") / name] = data
        cpu = provider["cpu_controls"]
        need(cpu["returncode"] == 0, "original CPU controls failed")
        name = relative(cpu["log"])
        copies[Path("provider-build") / name] = source(origin / name, cpu["sha256"])
        for name in OWNED:
            copies[Path("source/new") / name] = source(ROOT / name)
        utility_path = ROOT / "tests/test_theme_engine_build_gate.py"
        utility_data = source(utility_path, UTILITY_SOURCE)
        copies[Path("source/dependencies/test_theme_engine_build_gate.py")] = utility_data
        utility = module(utility_data, utility_path, "profile_build_utilities")
        red_seconds, red_sha = 0.0, None
        if target.exists():
            need(args.resume_red_sha256 is not None, "existing output requires explicit preserved RED pin")
            red_data = source(target / "red-result.json", args.resume_red_sha256)
            red = json_object(red_data)
            need(red.get("schema") == "shizukuos.profile-probe-helper-red.v1" and
                 red.get("status") == "EXPECTED_HELPER_RUNTIME_RED" and red.get("native_execution") is False,
                 "only original helper RED may precede this build")
            need([step["returncode"] for step in red["steps"]] == [0, 1], "RED compile/runtime outcomes differ")
            wanted = {"red-result.json"} | set(red["output_sha256"])
            actual = {str(path.relative_to(target)) for path in target.rglob("*") if path.is_file()}
            need(actual == wanted, "existing output contains unexpected files")
            for name, expected in red["output_sha256"].items(): source(target / relative(name), expected)
            need(red["original_provider_receipt_sha256"] == PROVIDER_RECEIPT and
                 red["original_source_sha256"] == provider["source_sha256"], "RED used different original provider")
            red_seconds, red_sha = red["aggregate_seconds"], sha(red_data)
        need(shutil.disk_usage(ROOT).free >= RESERVE + BUDGET and utility.mem_available() >= RAM,
             "8MiB output admission/resource floor failed")
        need(sum(len(data) for data in copies.values()) + (utility.own_bytes(target) if target.exists() else 0) < BUDGET,
             "declared copy closure exceeds budget before creation")
        target.mkdir(exist_ok=True)
        build = Build(target, utility, red_seconds)
        for name, data in copies.items(): build.write(target / name, data)
        sys.path.insert(0, str(target / "source/provider/tools"))
        gates = module(builder_data, target / "source/provider/tools/build_theme_engine.py", "profile_provider_gates")
        gates.BUILD = target
        need(set(gates.SOURCES) == set(provider["source_sha256"]), "provider source list drift")
        need(gates.STDCALL_BYTES["ShizukuOSLoadUserTheme"] == 0 and gates.STDCALL_BYTES["ShizukuOSSaveUserTheme"] == 4
             and gates.STDCALL_BYTES["M98GetThemeStyle"] == 0, "private profile stdcall ABI mismatch")
        import i486_instruction_gate as instruction_gate
        import pefile
        source(Path(pefile.__file__).resolve())
        tools = {}
        for name in ("clang", "i686-w64-mingw32-gcc", "i686-w64-mingw32-objdump"):
            found = shutil.which(name)
            need(found is not None, "missing tool: " + name)
            path = Path(found).resolve(strict=True)
            tools[name] = str(path); original[str(path)] = file_hash(path)
        helper = target / "source/new/tests/shizukuos_theme_profile_helpers_host.c"
        common = [tools["clang"], "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", str(helper)]
        build.command(common + ["-o", str(target / "helpers-host")], "helpers-compile")
        host = build.command([str(target / "helpers-host")], "helpers-run").decode().strip()
        need(re.fullmatch(r"PASS_HOST_HELPERS_ONLY: [0-9]+ literal CLI/OS/path assertions; no native API execution", host), "helper result missing")
        build.command(common + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-o", str(target / "helpers-sanitize")], "helpers-sanitize-compile")
        sanitizer = build.command([str(target / "helpers-sanitize")], "helpers-sanitize-run",
                                  dict(ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")).decode().strip()
        need(host == sanitizer, "ordinary/sanitized helper outcomes differ")
        guest = target / "source/new/tests/shizukuos_theme_profile_guest.c"
        memory = target / "source/provider/platform/freestanding/memory.c"
        native = [tools["i686-w64-mingw32-gcc"], "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
                  "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float", "-fno-builtin",
                  "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib", '-DM98_PROFILE_NONCE="' + args.nonce + '"']
        sdk, per_TU = set(), {}
        for title, translation_unit in (("guest", guest), ("memory", memory)):
            depfile = target / ("native-" + title + "-dependencies.d")
            build.command(native + ["-M", "-MF", str(depfile), "-MT", "SHZTPRO", str(translation_unit)],
                          "native-" + title + "-dependencies")
            per_TU[title] = dependencies(depfile)
            sdk.update(per_TU[title])
        need(any(path.endswith("/uxtheme.h") for path in sdk), "actual official SDK header not consumed")
        for path in sdk: source(Path(path))
        executable = target / "SHZTPRO.EXE"
        objects = []
        for title, translation_unit in (("guest", guest), ("memory", memory)):
            actual_depfile = target / ("native-" + title + "-actual.d")
            object_file = target / ("SHZTPRO-" + title + ".o")
            build.command(native + ["-MD", "-MF", str(actual_depfile), "-MT", "SHZTPRO",
                          "-c", str(translation_unit), "-o", str(object_file)], "native-" + title + "-compile")
            need(dependencies(actual_depfile) == per_TU[title], "actual compilation header closure differs: " + title)
            objects.append(str(object_file))
            build.pins[str(object_file)] = sha(read(object_file))
        build.command(native + [
                      "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
                      "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
                      "-Wl,--no-insert-timestamp", "-Wl,--entry,_mainCRTStartup"] + objects + [
                      "-lkernel32", "-ladvapi32", "-luser32", "-lgdi32", "-o", str(executable)], "native-compile-link")
        native_data = read(executable, 1024**2)
        pe = gates.pe_gate(executable, False)
        need("M98THEME.DLL" not in pe["imports"] and not pe["exports"], "probe must dynamically bind genuine local provider")
        need(gates.pe_gate(target / "M98THEME.DLL", True) ==
             {key: provider["artifacts"]["M98THEME.DLL"][key] for key in ("imports", "exports", "pe98_gate")}, "copied provider gate differs")
        argv = [tools["i686-w64-mingw32-objdump"], "-d", "-z", "--show-raw-insn", "--insn-width=16", str(executable)]
        listing = build.command(argv, "native-full-byte-i486")
        need(not read(target / "native-full-byte-i486.stderr"), "objdump diagnosed a failure")
        cpu = instruction_gate.decode(listing.decode("ascii"), sections(native_data, pefile))
        cpu.update(artifact_sha256=sha(native_data), artifact_bytes=len(native_data), command=argv, disassembly_sha256=sha(listing))
        build.write(target / "SHZTPRO.EXE.i486.log", listing)
        for path, expected in original.items():
            actual = file_hash(Path(path)) if path in tools.values() else sha(read(Path(path)))
            need(actual == expected, "late original source/input drift: " + path)
        for path, expected in build.pins.items(): need(sha(read(Path(path))) == expected, "late copied source/log drift")
        need(read(executable) == native_data, "probe changed after actual full-byte gate")
        build.guard()
        files = {str(path.relative_to(target)): dict(bytes=path.stat().st_size, sha256=sha(read(path)))
                 for path in target.rglob("*") if path.is_file()}
        result = dict(schema="shizukuos.theme-profile-probe-static.v1", passed=True, status="HOST_STATIC_READY_NATIVE_PENDING",
                      provider_receipt_sha256=PROVIDER_RECEIPT, provider_DLL_sha256=PROVIDER_DLL,
                      original_input_sha256=original, copies_and_outputs=files, original_and_copied_inputs_checked_after=True,
                      preserved_red_sha256=red_sha, helper_host=host, helper_sanitizer=sanitizer,
                      artifacts={"SHZTPRO.EXE": dict(pe, sha256=sha(native_data), bytes=len(native_data), i486=cpu),
                                 "M98THEME.DLL": provider["artifacts"]["M98THEME.DLL"]}, nonce=args.nonce,
                      modes=["default-shizukuos","save-classic","check-classic","save-shizukuos","check-shizukuos"],
                      guest_syntax="C:\\GOPLAB\\SHZTPRO.EXE <one exact mode>", steps=build.steps,
                      native_EXE_executed=False, SDK_headers_measured_before_after=len(sdk),
                      resources=dict(output_budget_bytes=BUDGET, reserve_bytes=RESERVE, available_memory_floor_bytes=RAM,
                          owned_RSS_limit_bytes=RSS_LIMIT, aggregate_seconds_including_RED=build.command_seconds,
                          sampled_output_high_water_bytes=max(row["own_bytes"] for row in build.samples),
                          sampled_RSS_high_water_bytes=max(row["group_RSS_bytes"] for row in build.samples),
                          lowest_sampled_free_bytes=min(row["free_bytes"] for row in build.samples),
                          sampling_limit="50ms samples are not atomic; transient overshoot is possible. FSIZE8MiB perchild plus aggregate output/RSS/disk/memory guards; only new owned group is terminated/reaped."), **FALSE)
        payload = (json.dumps(result, indent=2) + "\n").encode()
        build.write(target / "result.json", payload)
        print(json.dumps(dict(passed=True, receipt=str(target / "result.json"), sha256=sha(payload),
                             actual_output_bytes=utility.own_bytes(target), **FALSE)))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        result = dict(passed=False, error=str(error), steps=build.steps if build else [], **FALSE)
        if build is not None:
            payload = (json.dumps(result, indent=2) + "\n").encode()
            if build.utility.own_bytes(build.directory) + len(payload) <= BUDGET:
                with (build.directory / "failed-result.json").open("xb") as output: output.write(payload)
        print(json.dumps(result))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
