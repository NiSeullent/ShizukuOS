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
