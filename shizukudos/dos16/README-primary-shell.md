# Resident primary-shell parameters

The ordered `0007-primary-shell-parameters.patch` implements INT2F AX1611 from
the actual primary shell selected by the kernel. The original author's
[RBIL release 61](https://www.cs.cmu.edu/~ralf/files.html) describes this as the
CONFIG.SYS SHELL executable and its counted command line. It describes the
primary shell, rather than the currently executing Windows program.

The existing CONFIG parser selects `cfgInit` and `cfgInitTail`, including the
kernel's existing default when SHELL is absent. The existing `P_0` code then
builds the actual primary EXEC arguments. The patch copies those exact final
arguments into independent resident buffers before the loader can reuse
SecPathName or reclaim initialization data. It validates a terminated nonempty
name within NAMEMAX and the actual counted tail with its CR terminator, refusing
source segment wrap and a tail exceeding 126 bytes. It introduces no executable
name, command line, fallback pointer or application setter service.

Staging does not acknowledge AX1611. Only the loader's actual LOADNGO transfer
from the staged parent PSP publishes the carrier. Unrelated child transfers and
load-only requests cannot publish it. Failed execution, primary-process exit and
the next primary-shell attempt withdraw publication. Later EXEC operations may
overwrite the loader's scratch area without changing the resident copies.

When published, AX1611 returns AX/BX zero and a common resident DS with DX pointing
to the ASCIIZ shell executable and SI pointing to the actual counted command
line. CX, DI, BP and ES retain the existing dispatch behavior. Until publication,
AX1611 remains unsupported. The kernel's existing interrupt dispatcher owns its
normal FLAGS behavior. Undocumented BL alternatives in RBIL have no verified
semantics here; this implementation returns zero with real published pointers.

`tests/test_primary_shell.py` compiles the actual patched C with AddressSanitizer
and UndefinedBehaviorSanitizer. It executes the actual configuration parser,
primary argument preparation and loader transfer with explicitly modeled process
switches. It also assembles the existing interrupt/stack transport and runs it in
Unicorn with a modeled C callback, checking the changed DS and returned caller
frame. Input bounds, scratch reuse, failure, unrelated processes and withdrawal
have explicit controls. These are host component checks. They do not establish
a Windows desktop, DOS-to-VMM compatibility or a completed ShizukuOS release.
