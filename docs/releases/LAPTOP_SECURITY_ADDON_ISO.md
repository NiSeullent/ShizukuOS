# Windows 98 laptop/security integration add-on ISO

This image is a **nonbootable source and component add-on**, built for integration
with actual Windows 98 on ShizukuDOS. Windows 98 VMM, USER/GDI and Explorer remain
the target environment. It is not the complete ShizukuOS installer and contains
no Microsoft installation media or installed guest image.

The builder is `tools/build_laptop_security_iso.py`. It uses installed `xorriso`
only, stages in `/dev/shm`, caps the public payload at 24 MiB and the image at
30 MiB, and creates a new output without overwriting an existing file. It does
not run project build recipes, download dependencies, start VMs, mount disks,
install components, or publish the image. Public ISO distribution remains the
separate release owner's responsibility through `https://m98.nyase.kr` and nginx.

## Payload and source coverage

`SOURCE/` contains allowlisted public text under `drivers/`, `shizukudos/`,
`ntwddm/` and `platform/freestanding/`, explicit public ABI/build metadata,
component licenses and architecture/release documentation. This includes the
project's own static CRT, freestanding runtime, headers, assembly, C/C++ source
and build recipes used by the two shipped executables. The actual repository
GPLv2 `LICENSE` is required. Existing component notices are preserved.

Only explicit `SHZPERS.EXE` and `ELEVATE.EXE` inputs below the project's `build/`
directory can appear in `BIN/`. There is no search for executable files:

| File | Validated packaging type | Integration limitation |
| --- | --- | --- |
| `SHZPERS.EXE` | i486 PE32, Windows GUI | Native Windows 98 wallpaper/Explorer behavior still requires guest and physical validation. |
| `ELEVATE.EXE` | x86_64 PE32+, console | Auxiliary component requiring project DLL/token services; cannot execute directly as a Windows 98 program. |

External compiler and runtime closure flags are retained in the original
receipts and manifest. The public project source and own static runtime are
included; packaging does not independently establish complete external
toolchain closure or silently turn an incomplete receipt into a complete one.
GCC runtime notices are included when present. Ordinary public certificate-only
fixtures have an exact path allowlist and content check. The compiled
`shizukudos/win64/tests/res/shzmsg.bin` message-resource test fixture is omitted.

The builder excludes known generated, validation, evidence, third-party, data
and build directories from source traversal. It rejects unexpected symlinks,
media, executable files, private-key material and credential configuration in
the public source roots. It selects public JSON only at known ABI/build paths.
Public install answer-file examples remain source under `SOURCE/`; the ISO has
no autorun or installation action. Unselected private files outside the public
roots are neither read nor copied.

## Source-bound validation and deterministic construction

Each explicitly selected JSON receipt must declare a scope, a successful
validation verdict and a nonempty `sources_sha256` or `source_sha256` map. Every
listed source must be included and match its current hash. The AP receipt
`status: PASS` dialect requires unchanged `sources_before`/`sources_after`,
`inputs_stable: true` and a nonempty successful result array. Explicit failure,
unstable source and missing import-provider verdicts are rejected. Binary
receipts must also pin the executable's production and own runtime sources,
match its hash, and match any declared path/length. This accepts the GUI
`executable.sha256` dialect and the companion `exe_sha256` dialect without
assuming a fixed source count.

Original account/token/auth/sandbox receipts can instead declare
`source_stable: true` with successful `results` rows. Recognized rows carry
integer `exit`/`run_exit` zero and any optional `compile_exit` zero, a declared
MinGW `object_only` compile success with an object hash, or the portable KDF
reference's `status: PASS`, 57 vectors and binary hash. Missing verdicts, mixed
failures, malformed rows, Boolean exit values and timeout flags reject the
receipt. No synthetic passed wrapper replaces an original record.

`select_inputs(root, binaries, receipts, epoch=...)` freezes source hashes and
bytes; it does not construct an image. `build_iso(selection, output, work_dir)`
checks the entire source selection and all inputs again before and after
construction. Added files, removed files, changed source/receipt/binary bytes
and new symlinks reject the release.

The builder normalizes modes, owner IDs and timestamps, disables xorriso startup
configuration with `-no_rc`, and uses a fixed UTC epoch (default
2026-10-02 00:00:00). It builds twice in independent staging directories and
requires identical SHA-256 hashes. It then extracts the image and compares all
files with the frozen payload, including `MANIFEST.json`. The manifest records
every payload hash except its own self-reference. ISO9660 descriptors are
checked to reject boot records. Reproducibility covers construction from the
selected bytes; it does not prove upstream executable builds reproducible.

See the [GNU xorriso manual](https://www.gnu.org/software/xorriso/man_1_xorriso.html)
for `SOURCE_DATE_EPOCH`, fixed file dates and explicit `stdio:` image inputs.

## Tests and final build

Run the filesystem and real xorriso fixtures without selecting the live source
tree:

```sh
python3 tools/tests/test_laptop_security_iso.py
```

For an additional public source-bound fixture receipt, pass
`--receipt /dev/shm/fd5c-iso-builder-validation.json` with a new output path.
The integration owner can copy it unchanged below the project and select it
with `--validation iso-builder=PATH`. It records only the builder/test/release
document hashes and fixture execution scope; it does not freeze live project
sources. Optional `BLOCKED_NOT_RUN` GUI suites remain visible in original
component receipts and are not represented as passing.

After the integration owner freezes **all** source and validation inputs, run
the builder with explicit paths. The example paths below are component outputs,
not a claim that their existing receipts remain valid after other agents edit
their inputs. Use final source-bound receipts and append each final validation
receipt with a distinct label.

```sh
python3 tools/build_laptop_security_iso.py \
  --root "$PWD" \
  --output /dev/shm/SHZ-LAPTOP-SECURITY-ADDON.iso \
  --work-dir /dev/shm/fd5c-addon-final \
  --personalization-binary build/personalization-fd5c/final-v5/SHZPERS.EXE \
  --personalization-receipt build/personalization-fd5c/final-v5/result.json \
  --elevate-binary build/fd5c2-elevate/ELEVATE.EXE \
  --elevate-receipt build/fd5c2-elevate/build-result.json \
  --validation drivers=drivers/shz_laptop/validation/test-result.json
```

The JSON result contains image size/hash, manifest hash, exact selected binary
and receipt labels, reproducibility and extraction results. Native DLL/auth
bindings, ACPI/EC/I2C/driver provider bindings, physical laptop behavior, system
suspend and the complete Windows 98 installer remain release gates. Host and
compiler checks establish only the scope declared by their receipts.
