#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and run a genuine AMD64 theme ABI/pixel acceptance in a private guest.

Uses the immutable theme archive and the original peer runner/resource guards.
Only the small original probe is executed. Native Win98, OS themes and modern
application functionality are separate, unverified claims.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
import uuid

import pefile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ntwddm/win64/theme_probe/probe.c"
spec = importlib.util.spec_from_file_location("theme_probe_overlay", ROOT / "tools/required_theme_runtime.py")
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)
handoff = overlay.handoff
FALSE_FLAGS = {"windows98_execution_verified": False, "os_wide_theme_verified": False,
               "app_functionality_verified": False}
EXE = "THEMEP64.EXE"
VOLUME = "themeprobe"
APP = "private_theme_probe"
WAIT_SOURCES = ("shizukudos/kernel64/proc.c", "shizukudos/kernel64/tests.c")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return handoff.digest_file(path)


def sources() -> dict:
    paths = [SOURCE, Path(__file__).resolve(), ROOT / "tools/required_theme_runtime.py",
             ROOT / "tools/required_app_runtime_handoff.py", ROOT / "tools/signal_desktop_corpus.py",
             ROOT / "tools/modern_app_inventory.py", ROOT / "LICENSE"]
    return {str(path.relative_to(ROOT)): digest(path) for path in paths}


def owned_new(path: Path) -> Path:
    return overlay.owned_new_directory(path)


def nonce_ok(nonce: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{32}", nonce))


def pe_gate(path: Path, archive: bytes) -> dict:
    data = overlay.inventory.read_regular(path)
    modules = overlay.archive_modules(overlay.parse_archive(archive))
    rows = []
    with pefile.PE(data=data) as pe:
        require(not pe.is_dll() and pe.FILE_HEADER.Machine == 0x8664
                and pe.OPTIONAL_HEADER.Magic == 0x20B, "probe must be an AMD64 PE32+ executable")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and pe.OPTIONAL_HEADER.AddressOfEntryPoint
                and pe.OPTIONAL_HEADER.Subsystem == 3, "probe requires a timestamp-free console entry")
        for index in (9, 10, 13, 14):
            require(not pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress,
                    "probe has unexpected TLS/load config/delay/CLR runtime")
        require(pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress, "probe must have relocations")
        for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
            dll = descriptor.dll.decode("ascii")
            require(dll.upper() in ("KERNEL32.DLL", "USER32.DLL", "GDI32.DLL"), "unexpected probe dependency")
            for item in descriptor.imports:
                require(item.name is not None, "named imports required")
                name = item.name.decode("ascii")
                rows.append({"module": dll, "symbol": name,
                             "resolution": overlay.resolve_export(modules, dll, name)})
    require(rows, "probe has no checked imports")
    return {"status": "STATIC_NAMES_RESOLVED", "architecture": "AMD64 PE32+", "imports": rows,
            "abi_execution_verified": False}


def prepare(overlay_path: Path, out: Path, nonce: str) -> dict:
    require(nonce_ok(nonce), "fresh nonce must have 32 lowercase hexadecimal characters")
    out = owned_new(out)
    receipt = overlay.verified_overlay(overlay_path)
    require(receipt["provider_default_style"]["selection"] == "modern", "probe expects the explicit Modern candidate")
    original_hashes = sources()
    archive = overlay.inventory.read_regular(Path(receipt["archive"]["path"]))
    productivity, peer_hashes = handoff.load_peer(Path(receipt["runtime_worktree"]))
    require(peer_hashes == receipt["runtime_source_hashes"], "peer helper source binding changed")
    wait_hashes = {p: digest(Path(receipt["runtime_worktree"]) / p) for p in WAIT_SOURCES}
    handoff.check_space(out.parent, 300 * 1024**2 + handoff.METADATA_MARGIN)
    out.mkdir()
    frozen = out / "sources"
    frozen.mkdir()
    for relative, checksum in original_hashes.items():
        target = frozen / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(overlay.inventory.read_regular(ROOT / relative))
        require(digest(target) == checksum, "source changed while freezing")
        target.chmod(0o400)
    for relative, checksum in wait_hashes.items():
        target = frozen / "runtime-wait" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(overlay.inventory.read_regular(Path(receipt["runtime_worktree"]) / relative))
        require(digest(target) == checksum, "runtime wait source changed while freezing")
        target.chmod(0o400)
    tree = out / "tree"
    tree.mkdir()
    header = out / "trial_nonce.h"
    header.write_text('#define TRIAL_NONCE "' + nonce + '"\n')
    compiler = Path(subprocess.check_output(["which", "x86_64-w64-mingw32-gcc"], text=True).strip()).resolve(strict=True)
    executable = tree / EXE
    command = [str(compiler), "-std=c99", "-Os", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
               "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib", "-I", str(out), str(frozen / SOURCE.relative_to(ROOT)),
               "-Wl,--no-insert-timestamp,--entry,ThemeProbeEntry,--subsystem,console,--nxcompat,--dynamicbase",
               "-Wl,--image-base,0x140000000", "-o", str(executable), "-lkernel32", "-luser32", "-lgdi32"]
    built = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (out / "compiler.log").write_text(built.stdout + built.stderr)
    require(built.returncode == 0, "probe compiler failed; see compiler.log")
    gate = pe_gate(executable, archive)
    image = out / "theme-probe.img"
    productivity.runner.build_image(image, tree, VOLUME)
    control = f"image=D:\\{VOLUME}\\{EXE}\r\ncmdline={EXE} \r\ncwd=D:\\{VOLUME}\r\ntimeout=30\r\n".encode("ascii")
    productivity.runner.put_file(image, control, "K64RUN.TXT", out)
    image.chmod(0o400)
    require(sources() == original_hashes and overlay.verified_overlay(overlay_path) == receipt,
            "input source or overlay changed during preparation")
    require({p: digest(Path(receipt["runtime_worktree"]) / p) for p in handoff.PEER_FILES} == peer_hashes,
            "peer helper changed during preparation")
    result = {"schema": 1, "stage": "private-amd64-theme-probe", "status": "PREPARED", "nonce": nonce,
              "overlay_receipt": {"path": str(overlay_path.resolve()), "sha256": digest(overlay_path)},
              "provider_sha256": digest(overlay_path.parent / "UXTHEME.DLL"),
              "runtime_worktree": receipt["runtime_worktree"], "runtime_source_hashes": peer_hashes,
              "runtime_wait_source_hashes": wait_hashes,
              "kernel_reaped_field_semantics": "raw proc_wait return code: 0 means successful teardown and reaping; -1 failure",
              "source_hashes": original_hashes, "compiler": {"path": str(compiler), "sha256": digest(compiler), "command": command},
              "executable": {"path": str(executable), "bytes": executable.stat().st_size, "sha256": digest(executable)},
              "image": {"path": str(image), "bytes": image.stat().st_size, "sha256": digest(image)},
              "tree": str(tree), "control": control.decode("ascii"), "pe_gate": gate,
              "network_attached": False, "payload_executed": False, **FALSE_FLAGS}
    handoff.write_json(out / "prepared.json", result)
    return result


def verified_preparation(path: Path) -> tuple[dict, dict]:
    receipt = handoff.read_json(path)
    require(receipt.get("schema") == 1 and receipt.get("status") == "PREPARED"
            and receipt.get("stage") == "private-amd64-theme-probe" and nonce_ok(receipt.get("nonce", "")), "invalid probe preparation")
    require(receipt["source_hashes"] == sources(), "probe source changed; prepare a fresh trial")
    directory = path.parent.resolve(strict=True)
    require(directory.is_relative_to((ROOT / "build").resolve(strict=True)), "probe preparation is outside own build")
    for relative, checksum in receipt["source_hashes"].items():
        require(digest(directory / "sources" / relative) == checksum, "frozen probe source changed")
    require(set(receipt["runtime_wait_source_hashes"]) == set(WAIT_SOURCES), "runtime wait source bindings absent")
    for relative, checksum in receipt["runtime_wait_source_hashes"].items():
        require(digest(directory / "sources/runtime-wait" / relative) == checksum
                and digest(Path(receipt["runtime_worktree"]) / relative) == checksum, "runtime wait source changed")
    opath = Path(receipt["overlay_receipt"]["path"])
    require(digest(opath) == receipt["overlay_receipt"]["sha256"], "theme overlay receipt changed")
    theme = overlay.verified_overlay(opath)
    require(theme["runtime_worktree"] == receipt["runtime_worktree"] and theme["runtime_source_hashes"] == receipt["runtime_source_hashes"],
            "probe and overlay runtime bindings differ")
    require(digest(opath.parent / "UXTHEME.DLL") == receipt["provider_sha256"], "theme provider changed")
    for key in ("image", "executable"):
        row = receipt[key]
        p = Path(row["path"])
        require(p.resolve(strict=True).is_relative_to(directory) and p.stat().st_size == row["bytes"]
                and digest(p) == row["sha256"], "prepared " + key + " changed")
    return receipt, theme


def parse_acceptance(serial: str, nonce: str) -> dict:
    """Only the fresh autorun child's records count; require external normal exit."""
    require(nonce_ok(nonce), "invalid proof nonce")
    starts = list(re.finditer(r"^K64 autorun: starting ([^\r\n]+)", serial, re.M))
    require(len(starts) == 1 and f"D:\\{VOLUME}\\{EXE}" in starts[0].group(1), "exact probe autorun missing or ambiguous")
    tail = serial[starts[0].start():]
    pids = re.findall(r"^K64 autorun: started pid (\d+)\r?$", tail, re.M)
    require(len(pids) == 1, "unique autorun PID required")
    pid = pids[0]
    app = re.findall(r"^\[(?:win64|user) " + re.escape(EXE) + r" pid " + pid + r"\] (TP64[^\r\n]*)\r?$", tail, re.M)
    require(app.count("TP64 BEGIN " + nonce) == 1 and app.count("TP64 FINAL PASS " + nonce) == 1,
            "fresh unique complete probe nonce required")
    require(not any("TP64 FAIL" in line or "TP64 FINAL FAIL" in line for line in app), "probe reported failed assertions")
    counts = [re.fullmatch(r"TP64 COUNTS checks=(\d+) failures=(\d+) paints=(\d+)", line) for line in app if line.startswith("TP64 COUNTS")]
    require(len(counts) == 1 and counts[0], "unique checked assertion totals required")
    checks, failures, paints = map(int, counts[0].groups())
    require(checks >= 80 and failures == 0 and paints >= 1, "insufficient theme assertions or window painting")
    require(sum(line.startswith("TP64 PASS ") for line in app) == checks, "individual assertions and totals differ")
    required = ("frozen_provider_defaults_modern", "gdi_and_dib_memory_agree", "actual_dib_renderer", "all_interior_pixels",
                "all_border_pixels", "clip_state_restored_after_draw", "amd64_upper_handle_bits_rejected", "stale_cookie_rejected",
                "independent_gradient_endpoints", "delete_dib", "delete_memory_dc", "destroy_visible_window", "unload_theme_provider")
    require(all("TP64 PASS " + name in app for name in required), "mandatory real-theme acceptance absent")
    require(not re.search(r"K64 EXCEPTION|K64: process .* killed|unhandled exception|K64 ldr: .* (?:failed|rejected|not loaded)", tail),
            "guest process fault or loader failure")
    # autorun.c stores the C return value of proc_wait in `reaped`: success
    # is 0, failure -1. Its early still-alive diagnostic also prints 0, so
    # accept only the final exact grammar, never that parenthesized branch.
    all_results = re.findall(r"^K64 autorun: result [^\r\n]*", tail, re.M)
    results = re.findall(r"^K64 autorun: result (\S+) exit=([0-9a-f]+) faulted=(\d) reaped=(-?\d+) after \d+ ms\r?$", tail, re.M)
    require(len(all_results) == 1 and results == [("exited", "0", "0", "0")], "external kernel normal exit 0 and successful proc_wait required")
    return {"status": "PASS", "nonce": nonce, "pid": int(pid), "assertions": checks, "paint_events": paints,
            "normal_exit_code": 0, "proc_wait_return_code": 0, "kernel_child_reaped": True,
            "theme_windows_abi_memory_painting_verified": True}


def screenshot_pixels(path: Path) -> dict:
    from PIL import Image
    require(path.stat().st_size <= 4 * 1024**2, "QEMU screenshot exceeds bounded framebuffer size")
    with Image.open(path) as img:
        require(img.format == "PPM" and img.size == (1024, 768) and img.mode == "RGB", "expected actual 1024x768 RGB QEMU framebuffer")
        rows = []
        for name, left, color, border in (("classic",124,(192,192,192),(128,128,128)),
                                          ("modern",314,(240,240,240),(0,120,215))):
            right, top, bottom = left + 140, 153, 213
            count = 0
            for y in range(top,bottom):
                for x in range(left,right):
                    expected = border if x in (left,right-1) or y in (top,bottom-1) else color
                    require(img.getpixel((x,y)) == expected, f"{name} framebuffer pixel ({x},{y}) differs from shared theme palette")
                    count += 1
            rows.append({"style": name, "rectangle": [left,top,right,bottom], "checked_pixels": count,
                         "fill_rgb": list(color), "border_rgb": list(border)})
        png = path.with_suffix(".png")
        img.save(png)
    return {"status": "PASS", "source": str(path), "sha256": digest(path), "preview": str(png),
            "rectangles": rows, "actual_qemu_framebuffer_theme_pixels_verified": True}


class CaptureGuard(handoff.GuardedSubprocess):
    """The original resource guard owns one child; only its socket is observed."""
    def __init__(self, qemu: Path, out: Path, firmware: dict, nonce: str):
        super().__init__(qemu,out,firmware)
        self.nonce = nonce
        self.qmp = out / "qmp.sock"
        require(len(str(self.qmp).encode()) < 100, "owned QMP socket path too long")
        self.stop = threading.Event()
        self.capture_thread = None
        self.capture = {"status": "NOT_CAPTURED"}

    def written_bytes(self, pid: int) -> tuple[int, int]:
        written, stderr = super().written_bytes(pid)
        serial = self.out / "serial.log"
        serial_bytes = serial.stat().st_size if serial.exists() else 0
        captures = sum(p.stat().st_size for p in (self.out / "theme-screen.ppm", self.out / "theme-screen.png") if p.exists())
        # Original write/reserve guards remain; additionally bound all own
        # host log and capture outputs to the existing 16 MiB limit.
        return written + captures, stderr + serial_bytes + captures

    def Popen(self, command, **kwargs):
        require("-qmp" not in command and "-monitor" not in command, "caller cannot override own QMP socket")
        child = super().Popen(command + ["-qmp",f"unix:{self.qmp},server=on,wait=off"], **kwargs)
        self.capture_thread = threading.Thread(target=self.observe, daemon=True)
        self.capture_thread.start()
        return child

    def observe(self):
        connection = None
        try:
            while not self.stop.wait(.1):
                if self.child.poll() is not None:
                    return
                serial = self.out / "serial.log"
                text = serial.read_text(errors="replace") if serial.exists() else ""
                if "TP64 GUI READY " + self.nonce not in text:
                    continue
                connection = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                connection.settimeout(2)
                connection.connect(str(self.qmp))
                stream = connection.makefile("rwb")
                greeting = json.loads(stream.readline())
                require("QMP" in greeting, "owned guest did not supply QMP greeting")
                def command(name, arguments=None):
                    payload = {"execute":name,"id":name}
                    if arguments is not None:
                        payload["arguments"] = arguments
                    stream.write(json.dumps(payload).encode() + b"\n"); stream.flush()
                    while True:
                        response = json.loads(stream.readline())
                        if response.get("id") == name:
                            require("return" in response, "QMP command failed: " + name)
                            return response["return"]
                command("qmp_capabilities")
                destination = self.out / "theme-screen.ppm"
                command("screendump", {"filename":str(destination)})
                self.capture = screenshot_pixels(destination)
                stream.close()
                return
        except Exception as error:
            self.capture = {"status":"FAIL", "error":str(error)}
        finally:
            if connection is not None:
                connection.close()

    def close(self):
        super().close()
        self.stop.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=3)


def run_trial(prepared_path: Path, out: Path, qemu: Path, firmware_dirs: list[Path], timeout: int=60) -> dict:
    require(qemu.is_absolute() and 10 <= timeout <= 180, "absolute QEMU and bounded timeout required")
    receipt, theme = verified_preparation(prepared_path)
    out = owned_new(out)
    preparation_hash = digest(prepared_path)
    productivity, hashes = handoff.load_peer(Path(receipt["runtime_worktree"]))
    require(hashes == receipt["runtime_source_hashes"], "peer runner changed")
    runner = productivity.runner
    inputs = {"boot_stub":runner.K64S / "boot.elf", "kernel":runner.K64S / "KERNEL64S.BIN",
              "win64_initrd":Path(theme["archive"]["path"]), "qemu":qemu}
    before = {key:{"path":str(path.resolve()),"sha256":digest(path)} for key,path in inputs.items()}
    firmware = handoff.firmware_manifest(firmware_dirs)
    handoff.check_space(out.parent,sum(p.stat().st_size for p in inputs.values()) + firmware["bytes"] + handoff.RUN_WRITE_BUDGET)
    out.mkdir()
    sealed = handoff.seal_runtime_inputs(inputs,out / "runtime-inputs")
    require(all(sealed[k]["sha256"] == v["sha256"] for k,v in before.items()), "runtime changed while sealing")
    sealed_firmware = handoff.seal_firmware(firmware,out / "runtime-firmware")
    handoff.write_json(out / "runtime-seal.json", {"schema":1,"stage":"sealed-theme-acceptance-runtime",
                       "probe_preparation_sha256":preparation_hash, "theme_overlay_sha256":receipt["overlay_receipt"]["sha256"],
                       "runtime_source_hashes":hashes,"sealed_runtime_input_hashes":sealed,"sealed_firmware":sealed_firmware})
    guard = CaptureGuard(Path(sealed["qemu"]["path"]),out,sealed_firmware,receipt["nonce"])
    spec = {"dir":VOLUME,"exe":EXE,"args":"","expect":"TP64 FINAL PASS " + receipt["nonce"]}
    require(APP not in runner.APPS, "probe application key already owned")
    saved = runner.K64S,runner.WIN64,runner.subprocess,runner.build_image,runner.put_file,sys.argv
    runner.K64S=runner.WIN64=out / "runtime-inputs"
    runner.subprocess=guard
    runner.APPS[APP]=spec
    image = Path(receipt["image"]["path"])
    def image_builder(selected,tree,volume,over=None):
        require(Path(selected).resolve()==image.resolve() and Path(tree).resolve()==Path(receipt["tree"]).resolve()
                and volume==VOLUME and not over, "runner attempted another image")
        return [(EXE,receipt["executable"]["bytes"])]
    def control_writer(selected,data,name,folder):
        require(Path(selected).resolve()==image.resolve() and name=="K64RUN.TXT" and data.decode("ascii")==receipt["control"],
                "runner attempted another autorun control")
    runner.build_image=image_builder;runner.put_file=control_writer
    sys.argv=[str(Path(runner.__file__)),"--app",APP,"--tree",receipt["tree"],"--image",str(image),"--out",str(out),
              "--qemu",sealed["qemu"]["path"],"--accel","kvm","--memory","1024","--timeout",str(timeout),
              "--guest-timeout","30"]
    runner_code,error=2,None
    try:
        runner_code=runner.main()
    except Exception as failure:
        error=str(failure)
    finally:
        runner.K64S,runner.WIN64,runner.subprocess,runner.build_image,runner.put_file,sys.argv=saved
        runner.APPS.pop(APP,None)
        guard.close()
    serial = (out / "serial.log").read_text(errors="replace") if (out / "serial.log").exists() else ""
    acceptance={"status":"FAIL"}
    try:
        require(error is None and runner_code==0, error or "original runner did not pass")
        acceptance=parse_acceptance(serial,receipt["nonce"])
    except Exception as failure:
        acceptance["error"]=str(failure)
    preserved=False
    try:
        require(digest(prepared_path)==preparation_hash and verified_preparation(prepared_path)[0]==receipt, "probe preparation changed")
        require(all(digest(Path(row["path"]))==row["sha256"] and digest(Path(row["source_path"]))==row["sha256"]
                    for row in sealed.values()), "original or sealed runtime changed")
        require(handoff.sealed_firmware_preserved(sealed_firmware) and handoff.firmware_sources_preserved(firmware), "firmware changed")
        require({p:digest(Path(receipt["runtime_worktree"])/p) for p in handoff.PEER_FILES}==hashes, "peer source changed")
        preserved=True
    except Exception as failure:
        error=(error + "; " if error else "") + str(failure)
    ok=acceptance["status"]=="PASS" and guard.capture["status"]=="PASS" and preserved and not guard.record["termination_reason"]
    result={"schema":1,"stage":"standalone-kernel64-theme-abi-and-framebuffer-acceptance","status":"PASS" if ok else "FAIL",
            "probe_nonce":receipt["nonce"],"probe_preparation":{"path":str(prepared_path.resolve()),"sha256":preparation_hash},
            "theme_provider_sha256":receipt["provider_sha256"],"guest_os":"ShizukuDOS Kernel64 standalone",
            "original_runner_return_code":runner_code,"acceptance":acceptance,"capture":guard.capture,"resource_guard":guard.record,
            "original_and_sealed_inputs_preserved":preserved,"error":error,"network_attached":False,
            "peer_sources_modified":False,"installation":"not_performed",
            "theme_windows_abi_memory_painting_verified":acceptance["status"]=="PASS" and preserved,
            "actual_qemu_framebuffer_theme_pixels_verified":guard.capture["status"]=="PASS" and preserved,
            **FALSE_FLAGS}
    handoff.write_json(out / "theme-acceptance.json",result)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest="stage",required=True)
    prep=commands.add_parser("prepare")
    prep.add_argument("--overlay",type=Path,required=True);prep.add_argument("--out",type=Path,required=True)
    prep.add_argument("--nonce",default=None)
    run=commands.add_parser("run")
    for flag in ("prepared","out","qemu"):
        run.add_argument("--"+flag,type=Path,required=True)
    run.add_argument("--firmware-dir",type=Path,action="append",required=True)
    run.add_argument("--timeout",type=int,default=60)
    args=parser.parse_args(argv)
    try:
        result=prepare(args.overlay,args.out,args.nonce or uuid.uuid4().hex) if args.stage=="prepare" else run_trial(
            args.prepared,args.out,args.qemu,args.firmware_dir,args.timeout)
    except Exception as error:
        print(json.dumps({"status":"FAIL","error":str(error)}));return 2
    print(json.dumps({key:result[key] for key in ("status","stage")}))
    return 0 if result["status"] in ("PREPARED","PASS") else 1


if __name__=="__main__":
    raise SystemExit(main())
