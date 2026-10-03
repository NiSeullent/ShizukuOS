# Read-only INT2F frame observer

`probes/mux_frame.asm` builds a small DOS COM observer. It makes exactly four
queries, in this order: AX1611 with input CF0, AX1611 with CF1, AX1613 with CF0,
AX1613 with CF1. There is no AX1614 path, file open/create, vector replacement,
EXEC, registry repair or Windows startup operation. Arguments other than spaces
and tabs are refused. It writes its text report only to existing stdout handle1.
Shell redirection, if explicitly selected by the operator, creates the output
file through the shell; the observer itself names or opens no file.

The report begins with `MUXFRAME V1 AX BX CX DX SI DI BP DS ES FLAGS`. Each query
has three rows, each value exactly four uppercase hexadecimal digits:

* `IN`: ten raw input words in the header's register order.
* `OUT`: ten raw returned words in the same order.
* `BUF`: validity mask, leading canary word, trailing canary word, first NUL
  index within the 80-byte buffer, number of bytes different from fill byte A6.

The BUF mask has bit0 for intact leading5AA5, bit1 for intact trailingA55A and
bit2 for a NUL inside the buffer. NUL indexFFFF means none was found. The buffer
is reset before every call, including1611. Its metadata in a1611 row concerns
only this own unused buffer; returned DS:DX/DS:SI shell pointers are never read.
The report ends with `END 0004` only after all four rows were emitted. A complete
report with exit0 confirms observation integrity, not DOS compatibility or
Windows boot success. Damaged canaries produce exit1 while retaining the raw
rows. Failed or short stdout writes stop with exit1 and an incomplete report.
Absence of a NUL or any particular returned AX/CF does not determine exit status.

RBIL defines only AX as an input for1611. This observer chooses DX0 for a
deterministic shell query; DX0 is our probe policy, not an RBIL requirement.
Other unspecified input registers use visible sentinels. For1613, DX retains
sentinelD3D3, and real ES:DI identifies an owned paragraph-aligned80-byte buffer
between both canaries and CX is80. DS, ES and SS are distinct owned segments.
Input FLAGS are0202/0203: IF enabled, DF/TF clear, only CF differs. Each IN capture
uses flag-preserving instructions directly before INT2F. Each OUT capture starts
with PUSHF immediately after INT2F, stores through CS overrides, and completes
before the observer repairs its own DS/ES/FLAGS for reporting. Returned pointers
and pathname contents are never printed or dereferenced. Only this owned buffer
is scanned, at most80 bytes. SS/SP preservation is required to return from any
real-mode interrupt; the probe does not attempt recovery from a broken stack.

Build in an explicitly owned output directory:

```text
nasm -f bin -Wall -Werror -o <output>/MUXFRAME.COM probes/mux_frame.asm
<existing-isolated-python> -B tests/test_mux_frame.py
```

The tests execute that actual assembled COM in bounded Unicorn (100000
instructions, one second/emulation, ten seconds/assembly). All INT2F/DOS replies
are modeled. Arbitrary register/FLAGS patterns, unsupported/error statuses,
changed DS/ES/BP/DF, canaries, NUL bounds, short stdout and argument refusal prove
the observer records what the model returned. They do not set expected Windows
values, execute the FreeDOS handler, boot a VM or modify Windows files. An actual
guest comparison must independently pin the COM, DOS runtime and disposable
disk, then retain the complete raw report and actual exit status. Same-row CF and
register differences must be measured before changing the DOS implementation.

Provenance: source-written GPL-2.0-only observer/tests. Protocol concepts only
from Ralf Brown's author-published [RBIL Release61](https://www.cs.cmu.edu/~ralf/files.html),
[PartC](https://www.cs.cmu.edu/~ralf/interrupt-list/inter61c.zip), `INTERRUP.L`
entries2F1611/2F1613 (lines512–553 in the original member). That listing permits
use/redistribution with attribution; cached archive SHA256
`d7a059a1700c765adb9d4bf9dbe6289621aca6ff09c0583192764ee47e2b690a`.
No third-party implementation, Microsoft source, disassembly, registry contents
or product key is copied into these files. FreeDOS source behavior is a subject
for future comparison and is deliberately not the test's expected reply.
