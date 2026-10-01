# Complete native executable-byte audit

`tools/i486_instruction_gate.py` parses one horizontal instruction row at a time
from actual Binutils raw-byte disassembly with zero-byte elision disabled. It
checks contiguous addresses and exact original bytes over every PE executable
section's declared VirtualSize. Unsupported section extents, gaps, changed input,
bad/unknown/truncated rows and out-of-bound instruction lengths/counts fail closed.
The explicit i486/x87 opcode list checks nested prefixes, SIMD operands and control
registers; only i486 CR0/CR2/CR3 are admitted. It does not establish Win98 API,
loader, numeric semantics, native execution or browser/application support.

Actual assembled controls include27 combinations of operandless nop/ret/fldz
followed by modern fence, SIMD, CPUID, UD2, CMOV, FCOMIP, FXSAVE, TZCNT or CR4.
No control object is executed. Original base prefix, x87 and suffixed BT/BSF/BSR
controls pass; malformed/prefix-only/truncated/coverage controls reject.

Earlier builders used a cross-newline whitespace regex that could hide an
instruction after an operandless predecessor. Their frozen source and receipts
are retained; old partial counts are historical build evidence. Corrected
supplement `build/i486-canonical-supplement-v1/result.json` binds all six actual
canonical Script/Automation staged EXE/DLL paths and hashes, actual disassembly
logs and parser/control source. All executable bytes pass. Its frozen helper
predates only the legitimate base-op suffix extension and is preserved unchanged.
Our next native launch must consume this corrected supplemental proof.

`build/i486-tls-supplement-v1/result.json` is an actual failure. The latest TLS DLL
contains modern CMOV in both upstream X509 verification and linked prebuilt MinGW
formatting. Exact original failed bytes/disassembly are retained in
`failed-readback.json`. Old TLS v7 must not launch as i486-compatible; the isolated
corrective port recompiles every upstream unit and replaces unsupported formatting
before fresh full PE/import/ISA checks and staging. Historical protocol and disk
preparation failures remain separate.
