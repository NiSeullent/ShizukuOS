# SPDX-License-Identifier: GPL-2.0-only
"""Python mirror of shz_info_t (shizukudos/supervisor/include/shz_info.h).

Test harnesses read the info page straight out of guest-physical memory (QMP
pmemsave), so the layout is checked against the C compiler's view in
`selfcheck()` before any result is trusted.
"""
import ctypes
import subprocess
import tempfile
from pathlib import Path

REGION_BASE = 0x04000000
MAGIC = 0x3031505553485A53
STAGES = {0: "NONE", 1: "LOADER", 2: "SUPERVISOR", 3: "CAPS", 4: "VMXON", 5: "LAUNCHED", 6: "GUEST_EXIT",
          0xdead: "FAILED"}
CAP_BITS = {"LONG_MODE": 0, "VMX": 1, "VMX_ENABLED": 2, "EPT": 3, "UNRESTRICTED": 4, "SVM": 5,
            "SVM_ENABLED": 6, "NPT": 7, "VPID": 8, "BACKEND_VMX": 16, "BACKEND_SVM": 17}
u32, u64 = ctypes.c_uint32, ctypes.c_uint64


class Snapshot(ctypes.Structure):
    _fields_ = [(n, u64) for n in ("rip", "rflags", "cr0", "cr4", "efer", "cs_sel", "cs_base", "cs_ar",
                                    "exit_reason", "exit_qual", "valid")]


class Blob(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char * 16), ("base", u64), ("size", u64)]


class DomainInfo(ctypes.Structure):
    _fields_ = [("state", u32), ("kind", u32), ("generation", u32), ("exit_code", u32),
                ("exits", u64), ("hypercalls", u64), ("irqs_injected", u64), ("run_slices", u64),
                ("last_cr0", u64), ("last_cr3", u64), ("last_cr4", u64), ("last_efer", u64),
                ("last_rip", u64), ("last_cs", u64), ("evidence", u64 * 32),
                ("error", ctypes.c_char * 96), ("reserved", u64 * 4)]


DOMAIN_NAMES = {2: "DOS16", 3: "KERNEL32", 4: "KERNEL64", 5: "WIN98"}
DOMAIN_STATES = {0: "UNUSED", 1: "RUNNABLE", 2: "WAITING", 3: "EXITED", 4: "FAILED"}


class Info(ctypes.Structure):
    _fields_ = [
        ("magic", u64), ("version", u32), ("size", u32),
        ("fb_base", u64), ("fb_size", u64), ("fb_width", u32), ("fb_height", u32),
        ("fb_pitch_pixels", u32), ("fb_format", u32), ("acpi_rsdp", u64), ("tsc_hz", u64),
        ("guest_ram_base", u64), ("guest_ram_size", u64), ("disk_base", u64), ("disk_size", u64),
        ("memmap_base", u64), ("memmap_bytes", u64), ("memmap_desc_size", u64),
        ("region_base", u64), ("region_size", u64), ("boot_path", u32), ("loader_flags", u32),
        ("k32_ram_base", u64), ("k32_ram_size", u64), ("k64_ram_base", u64), ("k64_ram_size", u64),
        ("ipc_base", u64), ("ipc_size", u64), ("blobs", Blob * 8), ("reserved_in", u64 * 4),
        ("stage", u32), ("status", u32), ("cap_bits", u32), ("cpu_vendor", u32 * 3),
        ("feature_control", u64), ("vmx_basic", u64), ("vmx_ept_vpid_cap", u64),
        ("vmx_pin", u64), ("vmx_proc", u64), ("vmx_proc2", u64), ("vmx_exit", u64), ("vmx_entry", u64),
        ("host_cr0", u64), ("host_cr3", u64), ("host_cr4", u64), ("host_efer", u64), ("host_cs", u64),
        ("hv_instance_id", u64), ("first_exit", Snapshot), ("last_exit", Snapshot),
        ("exit_count", u64 * 64), ("total_exits", u64), ("hypercalls", u64), ("io_exits", u64),
        ("io_unhandled", u64), ("injected_irqs", u64), ("guest_console_bytes", u64),
        ("guest_exit_code", u32), ("guest_exit_requested", u32), ("domain_generation", u64),
        ("last_error", ctypes.c_char * 128), ("domains", DomainInfo * 8), ("pad", u32 * 8),
    ]

    @classmethod
    def parse(cls, raw):
        if len(raw) < ctypes.sizeof(cls):
            raise ValueError("short info page")
        return cls.from_buffer_copy(raw)

    def caps(self):
        return sorted(n for n, b in CAP_BITS.items() if self.cap_bits >> b & 1)

    def stage_name(self):
        return STAGES.get(self.stage, hex(self.stage))

    def vendor(self):
        # CPUID.0 returns the vendor string in EBX, EDX, ECX order; the Supervisor stores it that way.
        return b"".join(int(v).to_bytes(4, "little") for v in self.cpu_vendor).decode("ascii", "replace")

    def to_dict(self):
        out = {}
        for name, _ in self._fields_:
            value = getattr(self, name)
            if isinstance(value, Snapshot):
                value = {n: getattr(value, n) for n, _ in Snapshot._fields_}
            elif name == "domains":
                value = {DOMAIN_NAMES[i]: {n: (list(getattr(d, n)) if hasattr(getattr(d, n), "_length_") else
                                               getattr(d, n).split(b"\0", 1)[0].decode("ascii", "replace")
                                               if isinstance(getattr(d, n), bytes) else getattr(d, n))
                                           for n, _ in DomainInfo._fields_}
                         for i, d in enumerate(value) if i in DOMAIN_NAMES and d.state}
            elif name == "blobs":
                value = [{"name": b.name.decode("ascii", "replace"), "base": b.base, "size": b.size}
                         for b in value if b.name]
            elif hasattr(value, "_length_"):
                value = list(value)
            elif isinstance(value, bytes):
                value = value.split(b"\0", 1)[0].decode("ascii", "replace")
            out[name] = value
        out["stage_name"] = self.stage_name()
        out["caps"] = self.caps()
        return out


INFO_BYTES = 8192


def selfcheck(repo):
    """Compile a probe against the real header and compare sizes/offsets."""
    header = repo / "shizukudos/supervisor/include"
    names = [n for n, _ in Info._fields_]
    program = ["#include <stddef.h>", "#include <stdio.h>", '#include "shz_info.h"', "int main(void){",
               'printf("%zu\\n", sizeof(shz_info_t));']
    program += [f'printf("{n} %zu\\n", offsetof(shz_info_t, {n}));' for n in names]
    program.append("return 0;}")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "p.c"
        src.write_text("\n".join(program))
        subprocess.run(["gcc", "-I", str(header), str(src), "-o", str(Path(tmp) / "p")], check=True)
        out = subprocess.run([str(Path(tmp) / "p")], capture_output=True, text=True, check=True).stdout.split("\n")
    sizeof = int(out[0])
    offsets = {line.split()[0]: int(line.split()[1]) for line in out[1:] if line}
    assert sizeof == ctypes.sizeof(Info), f"sizeof mismatch C={sizeof} py={ctypes.sizeof(Info)}"
    assert sizeof <= INFO_BYTES
    for n in names:
        assert offsets[n] == getattr(Info, n).offset, f"offset mismatch for {n}"
    return sizeof
