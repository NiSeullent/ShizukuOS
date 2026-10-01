# Genuine Mesa GLSL compiler frontend

**DRAFT / UNVERIFIED checkpoint.** The current source generation has not been
built or run. An earlier generation matched all 608 normal glcpp comparisons
(152 unchanged pairs in four newline modes), but its full sanitizer link failed.
The later typed build failed during wrapper compilation; its corrections and
the new resource guard controls remain unexecuted. Native i486 and browser
acceptance remain false. All failed builds and the held-v4 snapshot are retained.

This profile prepares a port of the pinned Mesa 26.2.3 preprocessing, syntax parser and
AST-to-typed-HIR semantics into a compiler-only host process. It creates no
`gl_context`, dummy `pipe_screen`, driver, device, browser context or renderer.
The prepared copies use immutable compiler resources with an ES 3.00 policy;
the original archive and selected source remain unchanged.

The required first milestone runs all 152 unchanged original glcpp input/expected pairs
under each of their four prescribed newline modes, in normal and full
ASan/UBSan builds. Original argument directives and expected outputs are retained.
The 33 original GLSL 1.50 warning fixtures require program linking; they are
distinct from ES 3.00 and are not counted as ES300 success.

The typed milestone requires the actual original Bison/Flex grammars, original
Mako-based type and expression generators, real builtin/type-cache locks and
constructors, genuine semantic diagnostics, and literal ES300 positive/negative
cases. A missing generator dependency or any compiler/test failure remains a
failed receipt. No handwritten generator or semantic shader substitute exists.

The owned host process bounds source, output and allocation sizes. Allocation
exhaustion exits the process without publishing a shader; graceful in-process
OOM recovery, a browser-safe API, and a Win98 native DLL lifecycle are unproved.
Host numeric parsing must use the C numeric locale and actual `strtof_l`, not a
double-to-float fallback; original diagnostic formatting uses a real host C99
provider. Native numeric/formatting/math providers require separate validation.

Native i486 C++ must be compiled without exceptions/RTTI and without prebuilt
libstdc++/libsupc++ dependencies. Real constructors, Win98 locks and every
discovered runtime symbol must be accounted for, followed by OEM import, PE98
and complete linked raw-byte CPU gates. No native success is inferred from host
execution or compiler flags. The external whole toolchain is not fully proved.

The budget-only revision changes the recipe reservation from 2 GiB to a bounded
512 MiB experiment. It preserves the Mesa archive, prepared semantic patch,
original generators, all 152 expected pairs/four newline modes, and sanitizer
controls. Fresh admission requires at least **22,595,387,392 free bytes**:
the unchanged 22,058,516,480-byte shared floor plus 536,870,912 bytes for this
recipe. `MemAvailable` must be at least 6 GiB. Complete typed/sanitizer output
growth remains unmeasured; this reservation is a limit, not an estimated pass.

Own logical and allocated (`st_blocks`) output footprints are checked before
and after copies, commands and final evidence. Sixteen MiB of the 512 MiB budget
is reserved for the final/failure receipt. During every command the supervisor
samples shared free space, shared `MemAvailable`, own-tree output and its newly
created process group plus builder RSS. A limit breach kills/reaps only that
new group and preserves partial files/logs. Per-file `RLIMIT_FSIZE` is 64 MiB;
non-sanitized child address space is limited to 6 GiB. ASan's virtual mapping
requires RSS monitoring instead of an address-space limit.

The target polling interval is 50 ms, with rejection when a measured polling
gap exceeds one second. Actual scan duration, polling gaps, footprint/RSS high
water and free-space/memory minima are recorded. Samples are not atomic:
scheduler delay, transient/deleted compiler files, filesystem metadata and
unrelated writers can produce unobserved peaks or overshoot. No zero-overshoot
claim exists. Final receipt writing is refused if its checks cannot fit; command
logs/partial files remain and the console records the refusal. A receipt is
accepted only with the observed zero process exit and final console guard,
including the case where a post-write check refuses a just-written receipt.
Small guard controls use reduced/injected thresholds with real owned children,
kill/reap and preserved outputs; they do not prove production output growth or
real six-GiB exhaustion.

Typed HIR is not consumed by the existing private TGSI/raster API yet. Future
lowering must explicitly reject unsupported operations before publication and
prove literal frame output from a real compiled program. WebGL, GLES, WebGPU,
compute, WGSL validation, browser integration and modern applications remain
unfinished. Full WebKit is optional; the modern APIs are still required.
