# Frozen numeric WAMR native stage

This stage prepares the original `M98WASM.DLL`, the literal numeric probe
`WAS13PR.EXE` and the owned-child observer `M98WARUN.EXE` for a separate,
offline Windows 98 SE Korean test. It launches no VM, executes no guest,
downloads nothing and changes no system or client configuration. A successful
stage is preparation evidence only. Native numeric execution, actual child and
supervisor completion, standard browser WebAssembly and modern apps remain false.

The exact approved generations are runtime v24 (`26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91`),
numeric probe v6 (`8db17f7ec0db13f2b265617c66755621661b9c16ac3431d0d901b10783fe8629`),
and observer v3 (`c94de5b5458ab9f1945e4f8421c425c9d1422a62b9b9fb57e3200a2c9eae0c18`).
The probe and observer share nonce `wasm-numeric-5abe-20261001-v5`.
The actual host and full ASan/UBSan numeric logs each contain 244 ordered checks;
the observer models each contain 3,022 assertions across 18 injected scenarios.
These host logs are never represented as guest execution.

`tools/wasm_native_stage_evidence.py` reads the complete approved closure. It
does not import or run old builders or the scanner. It replays the scanner's
approved literal instruction tables against saved raw listings and each actual
PE's complete executable VirtualSize, verifies PE32/4.10 loader flags, relocations,
stack limits, exact exports and original Korean OEM imports. The closure
also rechecks the actual 114 engine preprocessor macros for each of host,
sanitizer and native, and the six real original-CRT formatting macros.
Each of the three inputs is bounded to 1 MiB. Every source evidence file is bounded to 64 MiB;
the measured complete stage including metadata is bounded to 128 MiB.

The closure includes the probe's 707 actual input pins, runtime current/frozen
sources, all 392 prepared files, 93 actual cache object/metadata pairs and their
contexts, real host engine objects, successful and deliberately failing sanitizer
control logs, original fixtures, original upstream archive and all 2,001 regular
upstream files. Apache/LLVM and original per-file notices are retained. Original
build receipts, generated files, source snapshots, saved raw listings and the
stage/verifier/helper/test sources are copied as evidence. All members are
rehash-checked before and after copying, and checked again from the fresh stage.
Duplicate JSON fields, symlinks, nonregular files, escaping/noncanonical paths,
wrong generations, mismatched source pins, unknown instructions, missing code
bytes, wrong totals and late evidence/provenance drift fail closed.

The stager writes one fresh direct directory below
`/root/Win98-Modern-boot/build`. Every original closure member is retained under
`evidence/<project-relative-path>`; the three approved receipts and inputs also
have fixed root names. `guest-files.json` declares only those inputs and fresh
`WA13.LOG`, `WARUN.LOG`, `WAOUT.LOG` outputs. `provenance.json` binds the manifest
and exact source/member maps. Its SHA-256 is an independent mandatory caller
approval pin alongside the manifest and three build receipts; matching changed
source copies and a rewritten provenance cannot reuse the old manifest approval.
Existing stages are never reused or overwritten.
If a copy fails, its fresh partial directory is retained as failed evidence.
The stopped-run verifier must call `check_stage` and independently require the
approved provenance hash, actual fresh native numeric log, actual child DWORD exit and flushed/closed
observer handles. Requested supervisor exit is separate from actual supervisor
completion; QEMU exit alone proves neither child nor supervisor completion.

The frozen WAMR cache proves compiler-version strings, flags, local headers,
prepared source bytes and actual object bytes. It does not prove the complete
external compiler or system-header byte closure. The private QuickJS/WAMR seam
also exposed a real standard-memory gap: a module with no `memory.grow`/size
operations may retain WAMR's memory coalescing, reporting one page and rejecting
growth; a declared two-page variant can report one page while its last declared
byte remains readable. The original grow/size-containing probe fixture does
not fix those backend semantics. They remain mandatory browser-Wasm work.

This bounded profile is not full JavaScript, CSS, HTML5, WebAssembly, WebGL or
WebGPU support. SIMD, shared memory/threads, exception handling, Memory64 and
browser-standard Wasm bindings remain separate mandatory goals. The original
numeric fixtures are project-owned binaries rather than official spec modules.
