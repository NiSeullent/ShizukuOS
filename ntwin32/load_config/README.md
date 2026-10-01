# Native PE32 Load Config prerequisite

This portable module validates the original `IMAGE_LOAD_CONFIG_DIRECTORY32`
and prepares a mapped x86 `/GS` security cookie. It addresses metadata present
in the current official Chromium and Electron binaries. It does not start an
application or change the native loader's existing execution profile.

`load_config.c` is independently authored. Its source comment records the exact
Wine and ReactOS loader revisions compared, and the Microsoft format and CRT
contracts. No upstream implementation body, Windows header or target application
binary is copied into this directory.

## Integration contract

1. Parse the immutable original file with `np_parse` from
   `../native_loader/pe.c`, retaining the original bytes for all validation.
2. Call `np_load_config`. A successful result identifies validated metadata and
   **outstanding** runtime prerequisites. It never means CFG, SafeSEH, XFG or
   another mitigation is implemented.
3. Map, relocate and own the complete image separately. Before any TLS callback,
   CRT entry or protected application code, obtain entropy from the reviewed
   native runtime and call `np_load_config_cookie`. The helper receives entropy
   explicitly; it gathers none and does not establish randomness quality.
4. Resolve the reported mitigation and legacy-configuration requirements before
   admitting execution. Read-only guard-pointer storage requires the loader's
   temporary protection change, correct target setup and restoration. This
   module does not install guard functions or alter page protection.

The static `np_load_config_execution_profile` conservatively rejects outstanding
requirements, including cookie initialization. The existing native loader also
continues independently to refuse Load Config. An integrator must not remove
either gate merely because parsing or cookie preparation passed.

Large images require the matching `np_parse_limited` and
`np_load_config_limited` calls. An explicit `np_load_config_limits` bounds the
original file bytes, mapped image bytes, their combined size, records per table
and records across all five tables plus lock-prefix entries. The existing APIs
retain their32MiB file,64MiB image and262144 per-table defaults. Explicit limits
cannot exceed the PE parser's512MiB file/image and1GiB combined ceilings, or
8388608 records per table/aggregate. The matching cookie and execution-profile
variants enforce the same caller-supplied limits. Limits are immutable inputs;
output or mapping aliases are rejected before writing them.

The preserved Chromium157.0.8080.0 core has267868 CFG records and268177 total
known table records. The default APIs still reject it. An explicitly bounded
structural read accepts the original tables and continues to require SafeSEH,
CFG, CastGuard and cookie initialization before execution. No table is removed,
rewritten or treated as an implemented mitigation.

The cookie helper mutates only the validated four-byte mapped cookie when its
value is zero or the default `0xbb40e64e`. It preserves a nondefault cookie and
reports a nondefault highword-zero value as requiring CRT reinitialization.
Mapped memory and the immutable file must be distinct, the image must fit the
supplied mapping, and the caller exclusively owns initialization before entry.
It does not guess an adjacent cookie complement or overwrite guard slots.

## Metadata versus runtime storage

Metadata, function tables and initial pointer values are read from original
file-backed bytes. A writable cookie may instead reside in a section's virtual
zero-filled tail. RVA validation and file-offset conversion are distinct.

The parser bounds directory and table lengths, checks VA-to-RVA conversion,
sorted unique executable SafeSEH/CFG/long-jump/EH targets and address-taken IAT
storage, and detects metadata/write-slot overlap. CFG metadata stride comes
from GuardFlags for GFIDS, address-taken IAT and long-jump tables. Unknown
nonzero extension data and unimplemented nested structures fail explicitly.

Known mitigation flags remain visible as prerequisites. The table-entry
extension bytes are limited to their documented meanings. Future semantics
are not silently treated as enforced features.

## Focused host validation

Run from `/root/Win98-Modern-boot`, choosing a fresh ignored output directory:

```sh
python3 -B ntwin32/load_config/test.py --out build/load-config-c009-host-check
python3 -B -m unittest discover -s ntwin32/tests -p 'test_*.py' -v
```

The first command compiles this portable C module and the existing PE parser
into a host shared library with UndefinedBehaviorSanitizer traps. It writes
that library, build/test logs and a hash-bound JSON receipt only to the new
output directory. It checks inert synthetic images, malformed metadata,
cookie mutation bounds and the locally retained exact Chromium157 roots/core.
No target code, guest, network request or service is executed.

The second command runs memory-only import-routing and PE preparation
regressions. These tests prove host contracts. Native callback ordering,
entropy acquisition, mitigation enforcement, GUI functionality and app
acceptance require their own Windows98 receipts.

## Peer handoff

The existing native-loader owner keeps `../native_loader/` and its guest runs.
This module is available for reviewed integration without replacing those
files. Current ownership and approved test effects are recorded in
`../../docs/MODERN_APPS_COORDINATION_C009.md`.
