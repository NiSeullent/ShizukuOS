# Explicit shared Core clock provider

`NtwQueryCoreClock(counter, frequency)` in NTW32.DLL selects the Core clock
before the call. Counter is required; frequency is optional. Both outputs are
Win32 `LARGE_INTEGER` values and must have writable storage, four-byte alignment
and disjoint ranges. The separate `NtQueryPerformanceCounter` export implements
the NTDLL-level counter-required/frequency-optional contract; it permits output
overlap, publishing counter followed by frequency. It preserves caller
LastError and reports NTSTATUS. Load NTW32.DLL and explicitly resolve these
exports. They are absent from the KERNEL32 routing table. Existing standard
QueryPerformanceCounter/QueryPerformanceFrequency provider selection stays as
it was; no native call is silently redirected to Core.

The version-1 readonly `SHZ_HC_CLOCK_SPLIT` (15) uses the existing Supervisor
boot TSC origin and measured TSC frequency. It reads the TSC once and checks the
conversion to signed elapsed-nanosecond counts, returning low32 in EBX and high32
in ECX from that one sample. Old SHZ_HC_TIME (6), native GOP operation (14) and
IPC ABI 1.1 are unchanged. Zero frequency, overflowing conversion, wrong
version or reserved input fail without publishing either half. A frequency
above the checked multiplication bound is refused. The output frequency is
1,000,000,000 normalized counts/second; this does not mean one-nanosecond
hardware resolution or establish hardware-wide monotonicity.

The Win98 VxD clock DIOC uses the existing admission/rundown gate and pinned
alias/PTE checks. It validates synchronous no-input buffers, Supervisor presence
and ABI major, then asks for the new opcode. An old Supervisor returns a real
unsupported error. There is no truncated HC6 fallback and no guest pointer is
sent through VMCALL. The reply is exactly 32 bytes with magic, size, version,
reserved, counter and frequency. Publication checks both writable aliases under
the existing IRQ discipline. Failed unpins remain owned and block subsequent
admission/unload until real release.

The DLL admits one synchronous Core query at a time, opens an owned VxD handle,
checks the entire paired reply, and closes the handle before publishing caller
outputs. Failure leaves caller outputs unchanged. A failed close remains owned;
a later admitted call attempts its cleanup before opening anything new. The
original transport failure takes precedence over a later cleanup failure.
There is no cached counter and no other-provider retry after an error. A retained
lease includes its original close callback/opaque owner and a separate held bit,
so a valid handle value of zero remains owned. Detach stops new admission only:
no device open/query/close happens under the loader lock. Explicit
`NtwShutdownCoreClock()` stops admission and drains the owned handle outside the
loader lock, reporting a real busy/cleanup error until the caller can retry.
After successful shutdown this DLL instance stays stopped. Callers must keep
the DLL loaded until calls quiesce and shutdown succeeds, and must not FreeLibrary
concurrently. Stop alone cannot prevent Windows from unloading a DLL; terminal
cleanup failure can leave a process-owned handle until cleanup or process exit.
The native facade checks argument shape and committed writable ranges through
VirtualQuery before transport and again before publication. Callers must keep
the storage alive throughout the call; concurrent unmapping can still fault.
There is no SEH boundary or replacement of NTDLL's kernel-mode pointer probing.

`platform/build.py` builds CORECLK.EXE and NTW32.DLL; `ntwrapper/vxd/build.py`
builds NTWRAP9X.VXD. CORECLK.EXE explicitly resolves all three APIs and logs about
ten seconds of samples, constant frequency, an observed interval beyond the old
low32 wrap, optional frequency, NT output aliasing, LastError preservation,
required-counter rejection and stopped admission to CORECLK.LOG. Its version
check observes the reported Windows98SE profile; it does not establish original
licensed Windows code identity. That identity comes from the owner's licensed
input/source cohort. This phase's profile is not a permanent Core constraint. Only the VM
owner may run that probe in the actual Windows98 guest with matching newly
built Supervisor/VxD/DLL. A host build is not native execution proof.

Run bounded source tests in this clone with:

```
python3 ntwin32/tests/test_core_clock.py --out build/core-clock-check --components
```

The tests run production conversion/split/client and native facade code with
modeled TSC, Win32 imports, VMM pages and hypervisor callbacks under GCC/Clang
ASan/UBSan. Component builds check real PE32/i486 VxD and the real 64-bit domain
translation unit. They do not run QEMU, read private inputs or establish guest
clock behavior, native boot, driver installation or Windows application support.
If the installed GCC sanitizer runtime is absent, the explicit
`--gcc-without-sanitizers` option runs strict GCC host checks and records that
limitation while retaining Clang ASan/UBSan. Historical failure outputs are kept.
The runner refuses prior build/platform output to prevent stale artifacts from
being attributed to a new cohort.
