# Kernel32 lifetime for the actual Windows 98 system

ShizukuDOS replaces MS-DOS underneath the actual Microsoft Windows 98 system. Kernel32, Kernel64 and Supervisor are components for that Windows 98 goal. This proposal removes a prerequisite lifetime obstacle in Kernel32. It does not complete Windows 98 startup, DOS replacement, native application compatibility or a public installer/ISO.

The proposal is based on immutable commit `8508c5e360fe8c24c659b719f1ed21831cbdbd4c`. Its four-path diff has SHA256 `4d3fa27d77b7701a7512957f0656f39d02f8e41d68a497ccd24cf475e4dba0ba`. No primary worktree, Git index, boot disk, ABI layout/flag, Kernel64 source or Win64 runtime was changed by this checkpoint. The primary integration owner reviews and adopts the proposal separately.

## What changes

Previously Kernel32 always ran its diagnostic suite, then exited after a peer's `SESSION_END` or a 20,000 ms wait. Kernel64's IPC diagnostics send that request. Keeping the component alive for the Windows 98 lifetime therefore needs a separate service policy.

The existing ABI1.1 command line carries the exact opt-in `shz.k32-service=win98`. Supervisor writes it only for Kernel32 when its explicit native-Windows98 loader flag is exactly selected. The reader requires the complete command-line tail, exact bytes and NUL, compatible ABI/domain identity, nonzero generation, zero direct-boot flags, and one actual Kernel64 channel descriptor with the reviewed GPA/size. IPC initialization additionally checks the real channel's ID, generation and Kernel32/Kernel64 domain pair.

The service profile initializes CPU/memory/scheduler/timer and the actual IPC server, then skips the diagnostic workload and its completion markers. It serves until Supervisor reports the actual Windows 98 owner has ended: RUNNABLE/WAITING continue; EXITED ends normally; FAILED ends with failure; unused/unknown states or an unavailable state hypercall fail closed. The ABI's Windows 98 domain ID is **5**; DOS16 is 2. The implementation and host check use the actual Windows 98 domain, not DOS16.

In service mode `SESSION_END` returns `SHZ_E_UNSUPPORTED` and does not terminate the component. It does not acknowledge a shutdown it did not perform. The reviewed Kernel64 source ignores the final request's return status; earlier protocol checks determine its diagnostic failure count. No Kernel64 adaptation is included. Its native Win64 subsystem loop subsequently serves the actual Windows 98 channel until `W64_SHUTDOWN`.

Default and older ABI writers retain the existing diagnostic behavior: self-tests, the 20-second cap, successful actual `SESSION_END`, final evidence and exit. No new ABI flag, companion register, opcode or process/driver RPC is introduced.

## Actual evidence and limits

The host fixture compiles and runs the actual proposed `main.c` and `ipc.c`, actual channel/ring/pool helpers and actual message handlers. It substitutes CPU setup, hardware hypercalls and scheduler sleeps. Its clock sample is synthetic. The bootinfo-writer fixture extracts and compiles the actual Supervisor writer block. Twelve test methods cover 25 boot scenarios plus writer contexts, including malformed handoffs, real channel identity, all terminal/error owner states, default/legacy behavior, and usable ECHO/SUM32/CRC32/TIME handlers after a refused session-end request.

The host's **25,000/30,000 ms are simulated scheduler time**. They prove control flow survives the previous cap; they are not real guest timer or Windows evidence. The original source first failed the new lifecycle checks; `baseline.log` retains that 11-method/22-failure run. A separate zero-length/nonempty command-line case failed before its correction in `empty-policy-red.log`. `tests.log` records the closed 12-method passing run. The baseline's earlier fixture/test revision differs from the final reproducible runner and is not relabeled as a final-code execution.

The actual native compiler also produced these three freestanding objects:

| Object | Bytes | SHA256 | Format |
| --- | ---: | --- | --- |
| Kernel32 main | 2,820 | `120cc6b09d00ef4db8b30591c8b5704ce063832c2cf9c91ed51ef1914ee720e5` | ELF32/i386 |
| Kernel32 IPC | 6,732 | `3a1b5525f7c4e72f9aa7544498a0cb843ce2ffd7d303abf14faa00fa84a6f942` | ELF32/i386 |
| Supervisor kernel-domain writer | 7,960 | `fa6f104195b6ba71abb37474d3ab290108900751ea6af2dfd04365bfe54a37ea` | ELF64/AMD64 |

`evidence.json` binds exact compiler commands, 52 original committed source pins, 53 proposed source pins, unchanged before/after inventories and compiler-derived project dependency pins: 5/6/12 consumed project files for those objects. These are object builds, not a complete native kernel link. Reproduction in a different workspace may change object hashes because assertions embed source filenames; every new run records its own physical output hashes.

The current 32-bit `khc.h` time helper exposes only the low 32 bits of the hypercall nanoseconds. It wraps after approximately **4.29 seconds**. This proposal leaves that limitation intact and proves no TIME accuracy or long-term monotonicity. Scheduler jiffies and owner-state queries determine service lifetime, so that clock value does not drive this loop. A timestamp protocol fix requires a separate primary-owner ABI review.

This service still supplies only ECHO, SUM32, CRC32 and TIME to its Kernel64 peer. It adds no direct Windows 98 Kernel32 RPC/channel, Win32 PE loader, filesystem/GUI/driver service, general capability negotiation or peer-restart recovery. Windows 98 live VMM requests, keyboard/mouse/GUI, Chromium/Firefox/Discord/Steam/Office and MS-DOS replacement remain unverified. No VM, Windows binary, installed disk, media, product key or compiled binary is included here.

## Reproduce from public source

Use a modern x86-64 Linux host with Python3, Git, GNU patch and GCC that supports freestanding i486 and x86-64 objects. No dependencies are downloaded or installed. The output parent must exist, its child must be new, and 17GiB plus a bounded16MiB budget must remain available. The executable aliases below are explicit examples for the host. Paths are workspace placeholders.

```sh
git clone https://github.com/NiSeullent/Win98-Modern.git /workspace/Win98-Modern
mkdir -p /workspace/Win98-Modern/build/modern-apps
python3 -B /workspace/Win98-Modern/docs/shizukudos10/reports/kernel32-service-lifetime-cb43-20261001/reproduce.py \
  --source-root /workspace/Win98-Modern \
  --source-commit 8508c5e360fe8c24c659b719f1ed21831cbdbd4c \
  --out /workspace/Win98-Modern/build/modern-apps/kernel32-lifetime-reproduction \
  --gcc /usr/bin/gcc --patch-tool /usr/bin/patch
```

The reproducer reads immutable Git blobs and checks all manifest preimages before writing the owned stage. Dirty working files are not consumed. It checks the exact four-path patch, applies it without fuzzy context or offsets, verifies the complete proposed inventory, runs the real production-C suite and compiles three native objects with the pinned source builders' flags. It preserves executable aliases while binding actual target bytes. It starts no VM and modifies no original source or Git state.

Current main may already contain later changes. Adopting those sources requires a new reviewed rebase epoch with actual preimages and ABI checks. Do not bypass a refusal by refreshing hashes without review. A passing host reproduction is not acceptance of Windows 98 execution or product completion.
