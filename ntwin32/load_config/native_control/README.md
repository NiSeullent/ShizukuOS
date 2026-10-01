# Native DLL API observation

This companion loads the existing, separately frozen NTWLDC.DLL with genuine
Windows LoadLibrary/GetProcAddress and invokes its eight exact PE32 cdecl exports.
It checks the original DLL metadata, bounded private parser fixtures, cookie
mutation, refusal paths, output clearing and immutable input storage. Private
image copies are data buffers; their code, TLS and CRT are never executed.

`build.py --out build/load-config-c009-native-control-20261001-v1` compiles classic
i486 Windows 4.10 executables using the installed compiler, real KERNEL32 import
library and existing freestanding memory primitives. It freezes sources, pins
the original DLL, its 20-method host receipt and the exact callback v4 artifacts,
and checks actual imports against the original Korean OEM export inventory.
Compilation does not execute either Windows executable.

The generated manifest stages six frozen inputs in C:\VXDLAB. In a new isolated
native trial with all five output files absent, run `C:\VXDLAB\LCJOIN.EXE`.
That one observer first launches the unmodified callback v4 CISUIT.EXE, waits for
its real process exit zero and validates its two fresh logs. It then launches
LCWORK.EXE, waits for its real process exit zero and validates every expected
semantic row. CIWRK.LOG, CISUIT.LOG, LCWORK.LOG, LCOBS.LOG and LCJOIN.LOG are raw
outputs. LCOBS and LCJOIN are written by the same process, with its actual PID;
they do not constitute an additional observer. Each child has a 60-second wait.
Timeouts fail and record guarded termination; descendant exit stays unverified.

Host SHA256 manifests bind artifact identity; the guest FNV checks are bounded
accidental-change checks, not cryptographic authentication. Caller entropy is a
declared fixture value. Execution remains pending until a stopped genuine guest
trial supplies complete raw logs and independently observed exits. LCJOIN's own
OS exit remains unknown unless separately captured. This adds no production
loader/provider integration, mitigation enforcement or application acceptance.
