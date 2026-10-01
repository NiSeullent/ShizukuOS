# Chromium core DLL parsing budgets

The original Chromium 157.0.8080.0 Windows snapshot 1707946 contains a
283,207,168-byte `chrome.dll` with a 284,966,912-byte PE image. The previous
32 MiB file and 64 MiB image bounds prevented inspection of this core module.
Those default bounds still apply to `np_parse` and the native loader.

`np_parse_limited` adds explicit file, image and combined budgets. Each file
and image budget has a 512 MiB ceiling; their combined budget has a 1 GiB
ceiling. It checks the combined size by subtraction to prevent overflow.
The exact original module requires 568,174,080 bytes under the existing
file-buffer-plus-image model. This is a logical allocation budget, not evidence
that a guest has sufficient physical or virtual memory.

The core also contains 4,664,381 HIGHLOW relocations. `np_relocations_limited`
accepts an explicit work limit up to 8,388,608 entries and retains the existing
page-order, overlap, cross-page overlap, target and block bounds. The default
`np_relocations` limit remains 262,144. The parser calls no target code.

The frozen original archive SHA-256 is
`af0a1a5eb80a21ff2364b4974ca254d3a3af0bf087db9f5af4232672cb3a53df`.
The unchanged extracted core SHA-256 is
`f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158`.

Run the host controls against a prepared immutable input record and the exact
linked fixture from a completed native build:

```text
python3 ntwin32/native_loader/test_large_images.py \
  --input-record build/chromium-large-image-20260930T2336/input.json \
  --artifact-dir build/shizukudos/ntwpe32-native-stage2-20260930-v7 \
  --out build/chromium-large-image-budget-controls-new
```

The first completed opt-in work-budget receipt reports 55 Clang AddressSanitizer
and UndefinedBehaviorSanitizer controls. It validates all 1,301 ordinary/delay
import records, TLS structure and all 4,664,381 relocations in the original DLL.
These import records are structurally valid; their runtime addresses and API
semantics are not established by this inspection. One-byte/one-entry budget
deficits, invalid policies, truncation and overflow controls fail as intended.
The unchanged default parser also passes its existing 65 host regressions.

The native execution source, file-reading limits and runtime admission gates
have not been changed to admit this module. Classic and runtime execution
profiles still reject its unsupported runtime directories. No target entry,
TLS callback, Chromium window or web page has been executed by these controls.
The current fixed 128 MiB Windows 98 test profile has not been validated for
this module. Native read-only mapping, total module-graph memory accounting,
resource identity, load configuration, delay imports and process/thread
lifecycle integration remain separate work.

The original console query/driver trials, earlier parser receipts and the
initial GCC sanitizer-link failure are preserved; the successful controls use
the existing Clang runtime in private build directories.


A separate native read-only diagnostic is now compiled in
`build/chromium-large-native-probe-20261001T0036-v2`. Both helper EXEs have the
classic i486 GUI4.10 profile and only imports present in the actual Korean OEM
Kernel32 export inventory. The fixed original core is held read-only during
SHA-256/EOF verification and native file mapping. The diagnostic walks structural
imports and HIGHLOW entries and inspects TLS metadata; it never loads the target,
resolves target imports, or calls its entry point or callbacks. It also requires
the original execution profiles to continue rejecting the module. Its parent
records actual child wait/OS exit, separately from the helper's selected status.

This diagnostic has not executed in Windows 98. The separate CHRLAB staging
policy accepts exactly three pinned inputs, including the original
283,207,168-byte core, and two absent output logs. Its 30 host controls include
actual FAT copies and full readback hashes for the original core and both helpers.
The cold-boot runner now requires an explicit `--large-chromium-inputs` option,
an owned diagnostic clone and these exact sources. It refuses driver replacement,
other staging workflows and boot-configuration changes. It accounts for both
the FAT copy and host readback before copying, while retaining the selected
reserve and VM write budget. Another 34 controls verify the actual legacy FAT
path, CLI exclusions, validation before cloning, and the space boundary.

The default GOPLAB/VXDLAB scope remains eight inputs of at most 1 MiB each;
normal application staging limits also remain unchanged. This policy grants
no general large-file exception or target runtime admission. Native mapping,
child OS exit and the complete Chromium application remain unverified.
