# Windows 98 foundation runtime profile

The Supervisor publishes `shz.foundation=win98` after constructing live native
Windows 98, Kernel32 and Kernel64 domains and their real service channels.
Kernel32 requires channel 0 to Kernel64; Kernel64 requires channel 0 to Kernel32
and channel 2 to Windows. The writer validates both complete candidates before
changing either command line. Missing backing, dead domains, wrong identities,
truncated boot information and malformed channel geometry stop initialization.
The Windows low-memory boot information location is never written.

Both entries validate the original declared command-line tail before copying
or forcing a terminator. The exact profile cannot be combined with desktop,
installer, autorun or other diagnostic commands, or manufactured by a standalone
boot. Existing diagnostic workloads retain their normal entry path. The earlier
reviewed `shz.k32-service=win98` profile remains supported by Kernel32; its owner
lifetime loop is reused from the tested a41a956 replacement-boot source merge.

Kernel64 initializes its ordinary architecture, memory, filesystem, scheduler
and timer, binds the shared IPC doorbell semaphore, then immediately serves the
actual Windows channel. Startup no longer runs the lengthy diagnostic application
suite or terminates the Kernel32 test session before reaching the Windows service.
Kernel32 serves while the actual Windows domain is runnable or waiting, regardless
of its diagnostic 20-second limit or SESSION_END flag. Both workers distinguish
normal Windows owner termination, failure and invalid Supervisor state. The native
Kernel64 service stops admission and uses its existing bounded completion drain
when that owner ends. Standalone subsystem regression behavior is unchanged.
Reaping waits for completed process teardown before entering `proc_wait`, so
an unfinished teardown cannot block the outer drain in that call. The native
hypercall helper declares the actual RAX/RBX/RCX return registers as read-write
operands, preserving caller values while the Supervisor returns owner generation.

These are runtime connections for actual Windows 98 on ShizukuDOS. Selecting the
profile, compiling kernels or running host fixtures does not establish a DOS-to-VMM
boot, a loaded VxD, Windows event delivery, integrated SMP or a completed product.

Reproducible component commands:

```text
python3 -B shizukudos/boot_profile/test.py --out build/foundation-policy-fresh
python3 -B shizukudos/boot_profile/test_entry.py --out build/foundation-entry-fresh
python3 -B shizukudos/boot_profile/test_hcall_registers.py --out build/foundation-hcall-fresh
python3 -B shizukudos/boot_profile/test_native_worker_reap_fada.py --out build/foundation-worker-fresh
python3 -B -m unittest discover -s shizukudos/supervisor/native_win98/tests -p test_compile_source_binding.py
python3 -B shizukudos/kbuild.py --out /absolute/new/owned/kernel-output
```

The last command builds both native and standalone kernel profiles into a fresh
explicit output while retaining the 17 GiB storage reserve. The consumed policy
and PE parser headers are included in kernel source hashes; ordinary and native
Supervisor receipts also include the policy dependency.

Actual production-entry RED evidence is preserved: the old K32 entry rejected
the new service at time zero; the old K64 entry ran its diagnostic workload before
the service; and its forced NUL hid malformed input. The new entry harness passed
100 cases and 4,556 assertions under GCC and Clang ASan/UBSan. Privileged operations,
initialization and workers are explicitly substituted in that fixture. Policy
tests passed 2,449 assertions per compiler/profile and four freestanding compiles.
The actual Supervisor publisher passed 65,662 checks per compiler with domain and
mapping state modeled; an independent reviewer also exercised RAM overflow and
second-worker atomic rejection. Six source-binding controls passed, including
actual copied-policy mutation rejection. Native owner polling and real service
execution still require the source-bound guest producer.

The hypercall fixture executes the real VMCALL instruction at an optimized host
callsite and substitutes its privileged return through a Linux signal handler.
Old GCC/Clang O2/O3 callers lost live RCX values; the corrected helper passed 25
host cases and eight i486/x64 native/standalone compile/disassembly checks. The
native worker fixture executes the actual `pump_slot` and PMA completion body
with scheduler, reap and interrupt boundaries modeled. It keeps teardown 0/1
pending, admits completed teardown exactly once, and preserves cancellation on
a full ring until it can publish. Neither fixture establishes a native VM or a
wall-clock shutdown measurement. The private native ESP builder now requires
both explicit SHA-pinned worker binaries before reading media.
