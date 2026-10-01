# Explicit SSPI child exit observer

The four new `sspi_guest_observer*` files are an original GPL-2.0-only project
adaptation of the retained `guest_observer.c`, its host fault model and native
observer recipe. Those originals remain unchanged. This observer never invokes
a shell, network, arbitrary executable, trust-store mutation or global setting.
It does not stage a fixture, launch a VM or register an OS provider.

## Fixed native contract

- Observer: `C:\GOPLAB\SSPWATCH.EXE --nonce <nonce>`.
- Exclusively owned child: `C:\GOPLAB\TLS13PRB.EXE --nonce <nonce>`.
- Working directory: `C:\GOPLAB`; inherited handles disabled.
- Fresh child log: `C:\GOPLAB\SSPI13.LOG`.
- Fresh observer log: `C:\GOPLAB\SSPIOBS.LOG`, opened with `CREATE_NEW` and no
  sharing. Only `ERROR_FILE_NOT_FOUND` establishes absence; missing directories
  and access failures are rejected. Child-log absence is checked again directly
  before child creation. The child independently uses its own `CREATE_NEW`.
- Nonce: 16–64 ASCII letters, digits or `-`, matching the current child probe.
  Whole-token quotes accepted by the observer are removed from the fixed child
  command; underscores, fragments, extra options and arbitrary paths fail.
- Actual self path and argv0 must match the fixed observer path, case-insensitively.
- Actual target must be Windows 98 SE platform 1, version 4.10, low build 2222.
- Wait 90,000 ms on the exact `CreateProcessA` process handle. Timeout/wait
  failure requests termination with DWORD `0x77070001`, then waits 5,000 ms on
  the same handle. Reaping does not convert the failed initial wait into success.

The probe has a cooperative 70-second deadline, seven TLS-pair cases with
8-second/50,000-step limits, and a nominal 56-second pair budget. Native API or
cryptographic calls can block past its cooperative deadline; the outer observer
remains the independent timeout authority. It records the full unsigned DWORD
returned by `GetExitCodeProcess` after a signaled wait. A signaled exit 259 is
nonzero failure, not a running-state claim. PID/TID fields are descriptive; the
observer never opens a process by PID or terminates an unrelated process.

Both owned thread/process handles have close-result fields. Every complete log
row is flushed. `observer.exit-candidate` is provisional, followed by the
flushed `observer.success-requires-report-close=1` row. Failed write, flush or
final report close makes the **actual observer exit** 29. Consequently a log
candidate of zero alone is insufficient. The root-owned outer process observer
must independently record SSPWATCH's actual zero exit, and the stopped-disk
verifier must bind the returned fresh logs to the nonce and frozen inputs.

Exit codes: 20 invalid arguments/self; 21 report creation; 22 freshness;
23 wrong/unqueried OS; 24 child creation; 25 wait/timeout; 26 exit query;
27 nonzero child DWORD; 28 owned-handle close; 29 report I/O/close. Zero requires
the child actually signaled and exited zero, owned-handle cleanup and final
report close. The existing `child.post-crt-zero-exit-observed` field describes
the child observation; it does not observe SSPWATCH's own final process exit.

## Reproducible local checks

Run only in the authorized Windows98 worktree, with new ignored output paths:

```text
python3 -B ntwin32/secure_transport/sspi_guest_observer_host_test.py --output build/secure-transport/sspi-observer-v1/host-normal --cc gcc
python3 -B ntwin32/secure_transport/sspi_guest_observer_host_test.py --output build/secure-transport/sspi-observer-v1/host-ubsan-clang --cc clang --sanitize ubsan
python3 -B ntwin32/secure_transport/sspi_guest_observer_build.py --output build/secure-transport/sspi-observer-v1/native --host-normal build/secure-transport/sspi-observer-v1/host-normal/result.json --host-ubsan build/secure-transport/sspi-observer-v1/host-ubsan-clang/result.json
```

The two host checks compile and execute the actual frozen observer C against
mock Win32 APIs. The 45 named cases cover parser boundaries, fixed-child
ownership, freshness/create races, OS mismatch, partial/zero/oversized writes,
I/O before/after child creation, full crash DWORD/259, timeouts/reaping, failed
queries and all closes. Additional assertions reject underscores and verify
the final flushed row precedes report closure. These checks execute no Windows
API or SSPI/TLS cryptography. The failed GCC UBSan attempt is retained under
`host-ubsan/`: the system libubsan linker target is absent. Installed Clang's
local static UBSan runtime requires no download or system repair.

The separate native recipe freezes all four files, binds passing model receipts
and model artifacts, prequeries all system/user headers with `-M`, and requires
the actual `-MD` dependency set to agree. It hashes selected compiler/cc1/as/ld/
collect2 and the explicit kernel32 import archive before/after compile/link.
The link map must contain only that archive and the retained actual object as
disk inputs, plus the exact GNU PE linker-generated `dll stuff` in-memory BFD
used for relocation/export sections. Its definition is in the upstream GNU
[PE linker source](https://gnu.googlesource.com/binutils-gdb/%2B/aa1ee363bce1eac43bf9824069e231d7113f7453/ld/pe-dll.c).
Its receipt also binds the OEM export inventory and PE parser source.

The PE gate requires i386 PE32 executable, GUI subsystem, OS/subsystem 4.10,
nonzero entry, zero timestamp, original-OEM KERNEL32 imports only, HIGHLOW
relocations, no exports and absent static TLS/load-config/delay-import/CLR
directories (both RVA and size zero). The observer has no CRT startup or
formatting dependency. Its native build retains an object, link map, compiler
logs, header identities and `observer-result.json`; it preserves a 20 GiB disk
reserve plus an 8 MiB build allowance.

## Native acceptance remains separate

No SSPWATCH or explicit-loading SSPI probe has been executed in a Windows guest
by these checks. ROOT-store flags/behavior, native ABI/crypto execution, guest
fixture freezing/staging, control, actual outer process exit and stopped-disk
readback remain with root. No existing v5 fixture, VM, provider, OS store,
service or configuration is changed. A successful observer build/model does
not prove OS-wide Schannel/SSPI/WinINet support or any browser/app requirement.
