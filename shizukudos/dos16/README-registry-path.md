# Explicit Windows registry pathname contract

The source-written `0006-win98-registry-path.patch` implements the MS-DOS7
INT2F AX1613/1614 pathname contract in resident kernel data under WIN31SUPPORT.
It stores and returns a real supplied pathname. It never reads, modifies,
repairs or clears status bits in a registry file, and it does not announce
Windows startup success. There is no implicit registry pathname.

The installed-source producer derives `WINREG=C:\<selected>\SYSTEM.DAT`
from its explicit selected short Windows directory, independently checks
MSDOS.SYS WinDir/WinBootDir, and requires the actual SYSTEM.DAT source member.
That member's hash and metadata remain in observed_members. CONFIG pass1
sends the supplied path through the actual `init_call_intr` NASM transport to
AX1614 before device initialization. The runtime state lives outside reclaimed
INIT storage. Producer receipt registry_path_configuration has only path,
origin=validated_source, and runtime_verified=false.

AX1614 validates the complete input into temporary storage before committing
resident state. Input is an ASCII absolute DOS8.3 pathname using letters,
digits, underscore and hyphen, at most78 bytes plus NUL. Relative paths,
controls, ambiguous components, extensions exceeding3 and segment crossing
are rejected; previous state remains intact. This intentionally supports the
producer's observed short-name paths rather than arbitrary LFN paths.
Success returns AX0; invalid input returns AX004E. No host authorization is
created by registering a guest pathname.

AX1613 copies the complete configured pathname including NUL only when the
buffer and segment bounds admit it. Before configuration it returns AX1613;
an insufficient buffer or crossing segment returns AX004E without writing.
Successful queries preserve caller CX, matching the actual original DOS
control's80-byte capacity observation. The original RBIL description instead
labels CX as copied bytes; this implementation's CX behavior is explicitly
based on the observed Windows98 control. Other frame registers are preserved.
No AX1611 shell parameter implementation or guessed INIT pointers are added.

References: original author [Ralf Brown Interrupt List](https://www.cs.cmu.edu/~ralf/files.html),
release61 [partC](https://www.cs.cmu.edu/~ralf/interrupt-list/inter61c.zip),
and [FreeDOS INT2F source](https://github.com/FDOS/kernel/blob/master/kernel/inthndlr.c).
No Microsoft code or disassembly is included.

Build the normal DOS16 producer with the ordered0006 patch. Narrow tests:
`SHIZUKUDOS_REGISTRY_SOURCE=<actual-built-kernel-tree> <isolated-python> tests/test_registry_path.py`
from this directory. Tests compile actual patched C functions with sanitizers
and execute the production NASM init-interrupt macro in bounded Unicorn with
modeled INT2F responses. These checks and a compiled kernel are prerequisites;
actual Windows98 boot on ShizukuDOS remains a separate guest acceptance test.
