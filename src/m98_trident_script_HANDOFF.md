# Local bounded Trident script extension

This opt-in `M98QJS.DLL` embeds the actual QuickJS 2026-06-04 interpreter. It
does not replace registered JScript, MSHTML, a browser provider, or system files.
The separate Automation adapter can bind actual document/window roots through
the public callback ABI. This runtime does not invent a DOM or implement HTML5
layout, WebAssembly, WebGPU/WebGL rendering, modern networking, or current
application compatibility. Latest JavaScript (including the remaining Intl and
shared-memory gaps), modern CSS parsing/layout, current Wasm Core and JS APIs,
WebGPU and WebGL are mandatory project targets with separate unimplemented
acceptance gates. Full WebKit porting remains optional.

Build a fresh checkpoint (no guest launch, staging, installation or networking):

```
python3 -B tools/build_trident_script.py --output build/trident-script-v1 --nonce trident-script-v1-20261001
```

The builder verifies pinned primary QuickJS and musl archives, prepares only the
needed sources in the ignored build directory, and keeps exact original notices
and COPYRIGHT alongside generated sources. It never executes their build
scripts. It records compiler identities, flags, prepared input hashes and object
hashes for every reused cache entry. Compilation uses at most two jobs. Host sanitizer instrumentation is compiled
with the same GCC/x87 profile, then linked to the already installed Clang
ASan/UBSan runtime because this host lacks GCC libasan. Runtime archive hashes
and deliberate ASan/UBSan fault rejections are required evidence for that mix.

QuickJS's upstream language coverage is mostly ES2025, with selected newer
operations. The root-owned 34 selected ES2026 and 24 numeric fixtures are real
interpreter inputs, without polyfills. Their exact JSON results retain false
full-conformance/browser/native-math flags. They are not a full standards suite.
Upstream Intl, tail calls and Atomics.waitAsync remain unavailable. Our prepared
profile disables Atomics and shared-memory objects, retains stack checks, and
exposes no std/os/worker/filesystem or external module loader. Math.random keeps
upstream non-cryptographic behavior; it is not a cryptographic host service.

The same prepared interpreter and portable C99 math subset run in host tests
and native builds. Native basic math dynamically binds original system MSVCRT;
host tests bind the host libc instead, so their success does not certify the
native CRT, x87 execution, current time or local timezone. Native UTC uses real
GetSystemTimeAsFileTime; local timezone conversion uses the original 32-bit
MSVCRT gmtime/localtime/mktime ABI after a system-path and export gate. The
upstream 32-bit time_t local-time clamp remains a documented limitation. No
locale, current time, time zone or trust data is fabricated.

Each successful entry saves the entire caller x87 environment/register stack
with FNSAVE, sets precision64 / nearest rounding / all six exception masks, and
restores the entire caller state with FRSTOR before releasing the entry guard.
This preserves pending exception flags as well as the caller control word.
Every synchronous host callback, cleanup and finalizer gets its own full
x87 guard so native Automation changes cannot corrupt subsequent interpreter
arithmetic. Host callbacks observe PC64/nearest/masked mode; state preservation
refers to the public API boundary. It makes no global control-word change and
does not rely on CRT startup defaults.
Host tests exercise actual x87 state with a53-bit/upward caller mode and sticky
invalid flag; native probe must independently observe the configured state.

Native compilation targets i486 with x87 hard float, binary64 doubles and an
80-bit extended long-double type, standard excess precision and no contraction.
Portable math notices include the applicable Sun/FreeBSD/Arm notices, not just
musl's umbrella MIT licence. Original `_vsnprintf` is wrapped for C99 required
length, size-zero, truncation and termination semantics with bounded workspace
charged to the active runtime. The audited format grammar is narrow; unsupported
wide, %n, hexadecimal-float and long-double conversions reject explicitly.
JavaScript number printing/parsing retains QuickJS's actual dtoa implementation.
Native MinGW classification imports are supplied by our directly tested IEEE
binary32/binary64 bit helpers (NaN, infinities, signed zeros, normal/subnormal
and signaling-NaN inputs), not prebuilt modern helper libraries. The reachable C99 round helper in upstream
memory diagnostics also uses the pinned portable musl implementation; it is
checked through an actual function pointer including ties and signed zero. Host libc
classification macros differ, so these helpers also have explicit host contract
checks; neither those checks nor host language tests are native execution proof.

All contexts belong to one UI thread established at the first open. An atomic
guard rejects reentry through host callbacks and finalizers. Memory, stack,
interrupt-check and job budgets are explicit; interrupt checks are not an exact
instruction counter. Generation-tagged contexts/functions/results never alias
older handles. Four contexts, 128 canonical retained host objects, 256 canonical
function identities, 16 copied result leases, 32 arguments, 256 member-name units
and 65536 value-string UTF-16 units are finite limits. Strings preserve embedded
NUL and lone surrogates. Host result cleanup occurs exactly once on success and
failure; object retention ends exactly once at runtime close. Full result slots
reject eval/invoke before script or host side effects occur.

The nine cdecl exports and value/host field order are defined in
`m98_trident_script.h`. `m98_script_invoke_this` preserves an explicit Automation
DISPID_THIS receiver; existing invoke uses undefined. Event wrappers queue
copied arguments in the separate adapter and invoke only outside COM callbacks
on the owner UI thread. Close the Automation bridge and detach native events
before closing this context. Context-owned function cookies stay valid until
context close; native wrappers must reject callbacks after that boundary.

Both native PEs require GUI/OS 4.10, relocations, exact exports, original OEM
imports, no TLS directory/load-config/delay imports/CLR, and no post-i486
instructions. The explicit stack profile is 2 MiB reserve / 512 KiB commit;
the runtime-only probe requests a 256 KiB JS stack limit. This is a new profile,
not reuse of an earlier 64 KiB receipt. Stripping removes only symbols after the
unstripped artifact is preserved; each staged candidate must remain <=1 MiB.

Future actual acceptance uses absolute `C:\GOPLAB\QJS13PR.EXE`, adjacent
`M98QJS.DLL`, fresh CREATE_NEW `QJS13.LOG`, the frozen per-run nonce/runtime
hash expectation and actual Win98SE 4.10.2222 identity. The separate runner must
observe actual child DWORD exit 0, full semantic/check evidence, flushed and
closed fresh log readback and the staged hashes. A component PASS or requested
supervisor exit is insufficient. Native execution, actual MSHTML/UI behavior,
HTML5/WASM, full ES2026, and Legcord/Signal/Office remain pending until separate
real guest tests establish those claims.
