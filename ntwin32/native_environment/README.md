# Native Windows 98 process-field compatibility

NTWPENV.EXE is a separate, classic i486/Kernel32 debugger. It keeps the official
application file, loaded code, native FS selector, native TIB and native PDB
unchanged. The executable identity, two executable-section RVAs and every byte
of the two supported UCRT chains are bound before launch. The entry points are
checked again at the actual hardware exception.

The selected desktop model represents an ordinary Windows 98 process, without
an NT secure-process creation attribute or a registered NT application verifier.
It describes only these two fields, rather than advertising a complete NT PEB
or another operating system. A separately hashed owned fixture has nonzero
fields, proving the original shifts and AND execute rather than returning a
fixed success value.

At CREATE_PROCESS and CREATE_THREAD events, the helper installs local hardware
execution breakpoints in DR0/DR1 and reads them back. It refuses existing enabled
breakpoints and the single-step flag. Only an exact first-chance hardware event
at a validated chain interprets its MOV instructions. It sets EAX to the modeled
field and resumes at the original SHR; the original AND/RET and application
policy, cleanup, destructors and exit APIs still execute. No instruction-cache,
code-write, FS replacement or PDB rewrite is performed. Unknown exceptions pass
to Windows. The initial debugger loader breakpoint is accepted only at the
pinned native Kernel32 DebugBreak export, with its actual CC/C3 bytes verified.
Another loader location must be separately established by a real fixture trace.

Debug-event thread/process handles are borrowed until the OS closes them after
their continued exit event. Image-file handles and distinct CreateProcess-owned
handles are closed explicitly. Every target thread is tracked within a bounded
128-record registry. Fixture execution has a 30-second deadline and the NPP
desktop experiment a five-minute deadline; timeout terminates only the owned
child and fails. A bounded failure drain requires the owned EXIT_PROCESS event
and continued OS handle retirement; an unconfirmed reap is recorded separately.
The helper cannot prove GUI/save behavior from an exit code.

Build only into a fresh explicit directory:

```
python3 ntwin32/native_environment/test.py --out build/shizukudos/native-environment-host-NEW
python3 ntwin32/native_environment/build.py --out build/shizukudos/native-environment-NEW
```

First native command (parent owns all isolated VM trials):

```
C:\VXDLAB\NTWPENV.EXE --fixture --log C:\VXDLAB\ENVDBG.LOG C:\VXDLAB\ENVFIX.EXE
```

Require the fresh ENVFIX.LOG controls, actual DR0/DR1 events on both main and
worker, context readback, original bytes/TIB checks and real child exit zero.
Compilation and host tests alone do not prove Win98 hardware breakpoint support.
Only after that proof, launch the unchanged pinned latest NPP:

```
C:\VXDLAB\NTWPENV.EXE --npp --log C:\VXDLAB\ENVNPP.LOG C:\NPPLAB\APP\NPP.EXE
```

The initial NPP target SHA256 is
`986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5`.
This helper relies on the existing separately validated import providers and
KernelEx loader for normal process startup; it does not replace either. Debugged
execution is a deliberate compatibility mode and is not a claim of ordinary
unassisted native application execution.

Primary contracts:

- [Microsoft UCRT original peb_access.cpp, preserved by ReactOS](https://raw.githubusercontent.com/reactos/reactos/master/sdk/lib/ucrt/internal/peb_access.cpp)
- [Microsoft UCRT process policy implementation](https://raw.githubusercontent.com/reactos/reactos/master/sdk/lib/ucrt/internal/win_policies.cpp)
- [Microsoft UCRT exit/destructor path](https://raw.githubusercontent.com/reactos/reactos/master/sdk/lib/ucrt/startup/exit.cpp)
- [Archived Microsoft GetThreadContext, Windows 95+](https://techshelps.github.io/MSDN/WINBASE/devdoc/live/pdwbase/debug_2jqs.htm)
- [Archived Microsoft SetThreadContext, Windows 95+](https://techshelps.github.io/MSDN/WINBASE/devdoc/live/pdwbase/debug_4f04.htm)
- [Microsoft debugger event handle ownership](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)

GPL-2.0-only original project source. No Microsoft application/OS binaries are
vendored or included in helper packages.
