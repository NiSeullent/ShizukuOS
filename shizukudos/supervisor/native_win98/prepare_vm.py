#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare fresh private ESP/firmware copies and an exact QEMU argv; never run it.

Root must perform and observe the actual isolated native-Win98 VMX boot next.
Preparing an argv or booting standalone K64 is never Windows98 acceptance.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("native_input_guards", HERE / "build.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def firmware_geometry(code, variables):
    if not 0 < code < (4 << 20) or not 0 < variables < (4 << 20) or code + variables != 4 << 20:
        raise ValueError("the supported OVMF CODE/VARS pair must total exactly 4 MiB")


def recipe(qemu, out, epoch_binding=None):
    # Reject QEMU option delimiters, even though no shell is involved.
    if any("," in str(p) or "\n" in str(p) for p in (qemu, out)):
        raise ValueError("QEMU file option paths cannot contain commas or newlines")
    if len(os.fsencode(out / "qmp.sock")) >= 104:
        raise ValueError("use a shorter private output path for the Unix QMP socket")
    result = [str(qemu), "-name", "shz-native-installed-win98", "-machine", "q35", "-accel", "kvm",
            "-cpu", "host,+vmx", "-m", "4096M", "-smp", "1", "-nodefaults", "-nic", "none",
            "-display", "none", "-device", "VGA", "-no-reboot",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={out / 'OVMF_CODE.fd'}",
            "-drive", f"if=pflash,format=raw,unit=1,file={out / 'OVMF_VARS.fd'}",
            "-drive", f"if=none,id=esp,format=raw,file={out / 'esp.img'}",
            "-device", "virtio-blk-pci,drive=esp,bootindex=1",
            "-serial", f"file:{out / 'serial.log'}", "-qmp", f"unix:{out / 'qmp.sock'},server=on,wait=off"]

    if epoch_binding is not None:
        if type(epoch_binding) is not dict or set(epoch_binding) - {'modern_persistence_low32'} != {'policy_fd','listener_path'} or \
                epoch_binding.get('modern_persistence_low32', True) is not True:
            raise ValueError('exact live owner recipe binding required')
        fd,path = epoch_binding['policy_fd'],Path(epoch_binding['listener_path'])
        if type(fd) is not int or fd < 3 or path != out/'epoch.sock' or path.resolve() != path or len(os.fsencode(path)) >= 104:
            raise ValueError('actual owner policy FD and exact private COM2 path required')
        result += ['-S','-fw_cfg','name=opt/shizuku/native-device-epoch,file=/proc/self/fd/%d'%fd,
                   '-chardev','socket,id=shz-epoch,path=%s,server=off'%path,'-serial','chardev:shz-epoch']
        # Selected W98PERS: disable OVMF's 64-bit PCI aperture so the modern
        # virtio-blk BAR4 (64-bit prefetchable) is placed below 4 GiB, as
        # observed in the owned firmware-only probe; HostGrant pins this pair.
        if 'modern_persistence_low32' in epoch_binding:
            result += ['-fw_cfg','name=opt/ovmf/X-PciMmio64Mb,string=0']
    return result



def preparation_budget(inputs):
    """Budget metadata plus complete 4 MiB firmware, not a second dense ESP.

    Each copy must actually acquire FICLONE on its read-leased descriptor. If
    clone support is unavailable, copy_fd separately reserves the measured
    source allocation before its sparse fallback. The 17 GiB reserve remains.
    """
    return inputs["firmware_code"]["bytes"] + inputs["firmware_vars"]["bytes"] + (64 << 20)


def main(argv=None, *, receipt_sink=None, epoch_binding=None):
    if receipt_sink is not None and not callable(receipt_sink):
        raise TypeError("receipt_sink must be callable")
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("esp", "build-receipt", "firmware-code", "firmware-vars", "qemu"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = {}
    esp_bytes = BUILDER.ESP_MIB << 20
    for key, maximum, exact in (("esp", esp_bytes, esp_bytes), ("build_receipt", 16 << 20, None),
                                ("firmware_code", 4 << 20, None), ("firmware_vars", 4 << 20, None),
                                ("qemu", 64 << 20, None)):
        path = BUILDER.safe_path(getattr(args, key))
        pin = BUILDER.pin_format(getattr(args, key + "_sha256"))
        size = BUILDER.pinned_hash(path, pin, exact, maximum)
        inputs[key] = {"path": path, "sha256": pin, "bytes": size}
    firmware_geometry(inputs["firmware_code"]["bytes"], inputs["firmware_vars"]["bytes"])
    item = inputs["build_receipt"]
    with BUILDER.read_leased(item["path"], item["sha256"], item["bytes"]) as (fd, checkpoint):
        with os.fdopen(os.dup(fd), "rb") as stream:
            built = json.loads(stream.read(16 << 20))
        checkpoint()
    if built.get("status") != "PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN" or built.get("private") is not True or \
       built.get("VM_executed") is not False or not built.get("source_before_after_match") or not built.get("originals_before_after_match"):
        raise ValueError("a successful private native-domain builder receipt without VM execution is required")
    if built["artifact"]["sha256"] != inputs["esp"]["sha256"] or built["artifact"]["bytes"] != esp_bytes:
        raise ValueError("private ESP differs from its source-bound builder receipt")
    members = built["members"]
    for name, size in (("DISK.IMG", BUILDER.DISK_BYTES), ("SEABIOS.BIN", BUILDER.ROM_BYTES), ("WIN98CFG.BIN", 16)):
        entry = members["SHZDOS/" + name]
        if entry["bytes"] != size:
            raise ValueError("native input member geometry mismatch")
        BUILDER.pin_format(entry["sha256"])
    if not os.access(inputs["qemu"]["path"], os.X_OK):
        raise ValueError("the pinned QEMU file must be executable")
    out = BUILDER.fresh_output(args.out)
    command = recipe(inputs["qemu"]["path"], out, epoch_binding)
    budget = preparation_budget(inputs)
    BUILDER.space(out, budget)
    out.mkdir()
    result = {"status": "FAIL_PREPARATION_PRESERVED", "private": True, "VM_executed": False,
              "Windows98_boot_verified": False, "MS_DOS_replaced": False,
              "preparation_budget_bytes": budget, "retained_free_space_bytes": BUILDER.RESERVE, "copies": {},
              "input_pins": {k: {**v, "path": str(v["path"])} for k, v in inputs.items()},
              "native_members": {k: v for k, v in members.items() if k.startswith("SHZDOS/")}}
    if epoch_binding is not None:result["prospective_native_epoch_recipe"] = dict(epoch_binding)
    try:
        for key, name in (("esp", "esp.img"), ("firmware_code", "OVMF_CODE.fd"), ("firmware_vars", "OVMF_VARS.fd")):
            item = inputs[key]
            with BUILDER.read_leased(item["path"], item["sha256"], item["bytes"], maximum=esp_bytes) as (fd, checkpoint):
                result["copies"][name] = BUILDER.copy_fd(fd, checkpoint, out / name, item["sha256"], item["bytes"], maximum=esp_bytes, prefer_reflink=True)
            if (out / name).stat().st_ino == item["path"].stat().st_ino and (out / name).stat().st_dev == item["path"].stat().st_dev:
                raise ValueError("owned VM input must use a distinct inode")
        for item in inputs.values():
            BUILDER.pinned_hash(item["path"], item["sha256"], item["bytes"], max(esp_bytes, item["bytes"]))
        result.update(status="PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN", qemu_argv=command,
                      originals_before_after_match=True, source_bound_ESP=True,
                      guest_RAM_bytes=4 << 30, OVMF_total_bytes=4 << 20,
                      required_next_gate="Run this exact argv as a bounded owned VM; inspect actual WIN98 domain/Windows/VMM/GUI evidence")
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        (out / "vm-plan.json").write_text(json.dumps(result, indent=2) + "\n")
    if receipt_sink is not None:
        receipt_sink((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({"status": result["status"], "private_plan": str(out / "vm-plan.json"), "VM_executed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
