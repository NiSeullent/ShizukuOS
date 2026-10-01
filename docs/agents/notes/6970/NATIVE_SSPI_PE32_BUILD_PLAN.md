# Native provider bridge: actual PE32 and SDK ABI build

Windows 98 remains the product OS. ShizukuDOS replaces MS-DOS, with Kernel32
and Kernel64 serving Windows. Canonical owns the DOS/VMM/startup path, 7707
owns secure_transport, cb43 owns the native loader and the existing publisher
owns main/site/ISO activation. This scoped build adds evidence for the bridge
that was already tested on the host; it does not transfer those owners' work.

The completed host fixture covers the provider binding and lifetime logic.
It has not compiled the new binding against a real Windows SDK or linked its
actual PE32 DLL. The next proof uses the existing NTWPROV build flags and
source, the original Korean OEM export inventory and the existing complete
executable-section i486 instruction gate. M98SSPI is loaded at runtime, so
this bridge build does not require another TLS engine or MbedTLS archive.

The existing build.py recipe imports tools/build_npp_prerequisites.py, which
was missing from this checkout. Restore that helper exactly from committed
canonical 3a9f0c4bc840075971797edaa42fdb65f1672cab:
10,627 B, SHA256 aab253717ad653f0b0ccbea37ddc0f9bd9b474e51cade3ff1f13d63844f48d84.
Import its existing gate function; do not run the helper's KernelEx builder.

The reused OEM helper is a header/name filter, not a complete PE structural
validator. Its DLL-only predicate cannot be applied to the EXE probe. The
guarded build must also check actual declared/parsed imports, duplicate
descriptors, section bounds and unique executable non-forwarded bridge exports.
Complete relocation-block and Windows loader acceptance remain separate unless
they are actually validated; a nonzero relocation directory alone is not that
proof. Record these limits explicitly in the receipt.

1. Freeze the bridge source, real-SDK ABI compile fixture, guarded runner,
   OEM helper/inventory, instruction gate and any actual control-test inputs.
   Review source and resource boundaries before a hosted run.
2. Prepare an isolated hosted Ubuntu runner with actual i686 MinGW GCC,
   Windows SDK/import library, objdump and pefile. Do not assume MinGW is
   preinstalled. Package preparation has its own observed 1 GiB disk-change
   budget above the unchanged 20 GiB reserve, bounded timeout and owned
   process-group cleanup. Record actual package/tool identities. The local
   host remains below compiler/VM admission; no local build is authorized by
   a successful hosted preparation.
3. Under the existing 20 GiB plus 8 MiB compile/output guard, compile a real
   SDK fixture that includes the production bridge. Assert x86 pointer and
   function-pointer sizes, table-prefix field offsets and the typed WINAPI
   initialization ABI. This is compile-only evidence, with no SSPI calls.
4. Compile and link actual NTWPROV.DLL and its existing NTWPRB.EXE probe.
   Bind source, SDK includes, direct compiler/linker/decoder and kernel32
   import-library inputs before/after. Keep full implicit toolchain/runtime
   attestation false unless the actual proof binds that closure.
5. Reuse the OEM PE32/i386/Windows 4.10 import and export gate and verify the
   exact three bridge exports. Decode every declared executable-section byte
   of both linked images through the existing i486 gate, preserving actual
   decode diagnostics and negative controls. Compiler flags alone do not
   establish instruction acceptance. A parse/build/resource failure is FAIL,
   never prospective feature RED or a successful native result.
6. Print a bounded self-inclusive receipt and actual diagnostics in the hosted
   job log. Independently reconstruct and review that actual evidence before
   making a build claim or offering scoped adoption to another chat.

All temporaries and proof output use a new guarded directory. Preserve old
fixtures, failures, receipts and gates. If new raw evidence is retained in RAM,
a new complete RAM inventory is required before physical persistence; do not
extend the historical 21:44 gate retroactively.

The intended result is PE32 build and SDK ABI acceptance only. Actual Windows
load, provider DLL execution, credentials, TLS handshake, OS TLS 1.3, Kernel64
forwarding, VMM callbacks, application compatibility and the final ISO remain
false. Native_loader's disabled provider execution policy stays in place.

Root owns this plan, the exact helper restore and workflow. The disk agent
owns the new guarded build runner; the modern-app agent owns the SDK ABI C
fixture; the coordination agent independently reviews the reused gates.

## Actual first attempt: hosted directory ownership failure

Commit 9a4b6d6212e375d86c792a216d9b76cebc35c7e1 ran in
[run 36933131506](https://github.com/NiSeullent/Win98-Modern/actions/runs/36933131506),
job 110607041508. Hosted prerequisite installation and version recording
passed all three commands. Preparation receipt 2,520 B SHA256:
1a9e862aed80191714e4f936c37c6de4923288f25d4914817461a679957298c9.
Minimum observed free space was 91,844,296,704 B. The actual job log is
53,630 B, SHA256:
47cc80c0f84acb36ba6c739e46125a03468a42f6b4c983f3d14b697ec6654708.

The build stopped while creating its new counted output directory:
the sudo preparation had created the previously absent shared build parent
with root ownership. The ordinary runner could not create the proof namespace.
No counted build receipt, compiler, SDK ABI or linked-artifact result was
produced. This is a real infrastructure failure, not feature RED or acceptance.
The narrow workflow successor prepares and validates writable namespace
parents as the ordinary runner before sudo creates its private preparation
child. Source pins, compiler flags, fixtures, resource limits and old evidence
remain unchanged. A fresh actual hosted result is required.

## Actual second attempt: COFF object metadata rejection

Commit 1599ddc82b84c979b4cc5671a4178f672f5b4a76 ran in
[run 36933745116](https://github.com/NiSeullent/Win98-Modern/actions/runs/36933745116),
job 110609008553. Writable output creation succeeded. Preparation passed
three commands, followed by ten successful guarded commands through
probe-compile. The four original i486 Python control methods passed.
The build then returned FAIL: `compiled COFF section bytes outside object`.
The SDK fixture, linking and linked-image decoding were not reached.

Actual build receipt 63,495 B SHA256:
48babe3f2f7bf3926063fd473510577cafcddf39d00b3922a89af4fcce250697.
Actual job log 174,666 B SHA256:
93c962d6648495e1039e11ef274f847342dbef79ceefd198131e6f5868fa4074.
Preparation receipt 2,525 B SHA256:
ee429eaa57b64f2ea0668da59732e12a6038bb161a8d923d49a81e8aae928cb0.
Minimum observed build free space was 91,853,332,480 B; resource failure
was null and final self-inclusive output accounting was 97,309 B.

The failed checker required every nonzero object section size to have
file-backed bytes. The actual object headers were not printed in this
attempt, so its exact section fields are not reconstructed. A narrow
successor will distinguish uninitialized, nonexecuting BSS allocation
from file-backed data, preserve initialized-data and relocation bounds,
and retain bounded actual header rows before rejecting an object.
Meaningful synthetic object controls must pass in a fresh guarded hosted
run. This failure is preserved separately from any later result; it is
neither feature RED nor native acceptance.

The object-only successor is 67,964 B SHA256:
dbbdb60436fe9030aa8e8e05f5f2c1a0b8f1e1e1ef30e19e5a92f22119d9b247.
It accepts uninitialized allocation only with flag 0x80, zero raw pointer,
and no code, initialized-data or executable flags. Each object's sum of
declared section allocations is bounded by the existing 8 MiB limit; this
is not a memory quota or a sum across all objects. Initialized
spans and relocation records remain file bounded; relocation-header overlap
and uninterpreted extended relocation counts are rejected. Actual object
pins and at most 96 section rows are attached to the incremental receipt
before validation, including a failed validation.

Twenty-two prepared memory-only format controls cover five accepted and
seventeen rejected cases; these are not execution results yet. They are
invoked only inside the admitted hosted runner. The linked PE scanner,
original i486 methods, SDK fixture, twelve frozen inputs, compiler flags
and resource limits remain unchanged. Root compared exact ASTs and source
pins without invoking a local compiler or the build runner.

Format provenance: [GNU binutils 2.42 COFF writer](https://gnu.googlesource.com/binutils-gdb/+/c7f28aad0c99d1d2fec4e52ebfa3735d90ceb8e9/bfd/coffcode.h),
release commit c7f28aad0c99d1d2fec4e52ebfa3735d90ceb8e9, file
bfd/coffcode.h, blob4170b630b4db39501e3509846c226d6745125f76,
GPL-3.0-or-later, and [Microsoft section flags](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags).
Only the distinction between allocation and stored section bytes was studied;
no upstream implementation was copied. This does not attest the entire
installed compiler/backend or establish Windows loader acceptance.

## Actual third attempt: SDK and links completed, strict ISA gate failed

Commit dc4a0c989bfc89cab6d16d7adb431ddef727ab8a ran in
[run 36935339096](https://github.com/NiSeullent/Win98-Modern/actions/runs/36935339096),
job110614155068. Fifteen actual commands exited zero, were reaped, and had
no stderr. The 22 COFF controls passed; the new actual probe object recorded
12 B of uninitialized `.bss`, raw pointer zero, flags0xc0300080. This does
not reconstruct the prior attempt's missing object headers.

All four objects compiled, including the real SDK fixture with 36 static
assertions. Both DLL and probe linked against the frozen selected kernel32
import library. Actual -M/-MD manifests matched for all four translation
units, with discovery counts93/13/88/98 and a 100-path initial union.
Final source/header/tool/library snapshots were not reached, so this is
partial command evidence, not a completed build acceptance.

The DLL instruction gate returned FAIL. It covered all3,744 bytes of `.text`
with zero coverage errors, but rejected eight decodes in the linker-generated
`__CTOR_LIST__` and `__DTOR_LIST__`. Actual objdump bytes show two final
8-byte lists, each `ffffffff00000000`, in that executable section. No newer
instruction is inferred from these data bytes, and no scanner exception is
introduced to accept them. Actual receipt108,368 B SHA256:
40bdf49d1921fd84407cfae202e1d3cae40073c05fd804acf1b56844be394357.
Actual raw log378,557 B SHA256:
7110204bbc8f5e0e9e77d52dfe802c9775531058e24348745559579b32245181.
Minimum observed free91,853,144,064 B; resource failure null; final
self-accounted275,068 B. Independent review reconstructed the receipt,
all30 command captures and the complete DLL disassembly correspondence.

The successor will reuse the actual selected GNU linker's default script
separately for DLL and probe, moving only its two constructor/destructor
blocks to the aligned beginning of nonexecuting `.rdata`. Every other
default-script byte and notice must be preserved. A unique signature mismatch
fails closed. The moved blocks must precede the runtime pseudo-relocation
tail, whose following aliases depend on the location counter.

The ordinary recipe and guarded proof must share one independently authored
transform helper. Actual linker/default/generated inputs will be bounded,
hashed and checked before/after explicit-script linking. Linked-image checks
must confirm both double/triple-underscore aliases, their distinct aligned
8-byte empty lists, and readonly nonexecuting placement. Nonempty constructor
inputs are unsupported by these C/no-CRT entry points and must be rejected.
The existing full executable-byte i486, OEM import and Windows4.10 header
checks remain unchanged. This is a real recipe correction, not PE rewriting
or an instruction-data exception. Fresh actual execution remains required.

Independent source review withheld the provisional helperd965d534 and
guardf81c7482 before any fourth run. Checking only the first8 bytes of the
destructor table does not prove its complete length: a zero-leading extra
destructor contribution could pass that prefix check. The correction adds
retained internal end symbols after each original terminating LONG(0), then
checks both actual retained-symbol spans are exactly8 bytes. These marker
assignments add no table or code bytes and do not become public DLL exports.
The transformed-script scope is therefore the aligned placement plus two
internal marker assignments, with every original command and notice retained.
A selective extra-destructor-span control must also reject this case. The
provisional source is not treated as tested, accepted or deployed.

The final source candidate was independently reviewed twice before the
fourth hosted attempt. Helper 26,070 B SHA256:
9a98336d9c5a0bc417ed816454d3188e79dc4cf326a52bfabad73df8c903b55b.
Ordinary recipe 10,046 B SHA256:
b6372e074fec112558250a5675e090c217740c1c3ca7ca8c098d7f6b51a10c63.
Guarded runner 76,927 B SHA256:
b7d627c71076b6cbdb1e65d896ab798e4fe3688067ef7b0a1774243d2c3010d9.
It requires six unique retained symbols, both exact 8-byte spans and a
16-byte combined end. Public exports at either marker name or marker RVA
are rejected, including renamed and ordinal-only exports.

Fifteen text controls and five selective actual-image layout controls are
prepared. The extra-destructor-span control changes only the retained end
value from 16 to 20 while preserving the first 16 sentinel bytes. Those
controls have not yet run in the fourth hosted attempt. Root checked ASTs,
exact source hashes and unchanged prior guard functions without executing
the helper, compiler or build runner locally. The recipe modification is
explicitly reported; no Windows, TLS, application or ISO acceptance follows
from this source review.
