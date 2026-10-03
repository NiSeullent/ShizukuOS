# Independent build-owned native release admission

The public installer has no native private release. `setup_native_release_*`
refuses until the separately owned real producer is independently anchored.
A caller hash, installation INI, raw receipt or successful RAM snapshot cannot
install release authority. The default source has no generated record.

The optional `kbuild.py --native-release-manifest /private/manifest.json
--out /private/new-component-output` route requires a fresh directory outside
Git. It emits a private 128-byte versioned record only into **KERNEL64S.BIN**.
Ordinary target **KERNEL64.BIN** has no record. Thus the target ESP/SIM hash does
not depend on the installer hash that authenticates it. Every generated record,
receipt and fingerprint stays in private output. Never publish these outputs.

The generator checks the independently reviewed original DOS receipt and exact
DOS binaries, the actual Watcom archive anchor, an independently approved exact
native source map and component byte anchors, and independently owned actual
installed-source custody. It re-runs the pinned original ingestion validator
against held original receipts, producer source files and full disk/ESP bytes.
It reconstructs the exact canonical saved manifest and independently expands
the actual encoded SIM back to the raw ESP hash. Booleans in the saved manifest
are not approval. Current geometry is a 2304 MiB expanded ESP; the actual encoded
SIM, rather than expanded geometry, must fit the existing 256 MiB sealed-source
limit. Manifest is bounded to 4 MiB. Oversized real inputs refuse explicitly.

One Linux read-lease union retains source/request/receipts/media, all kernel
source files, actual compiler executables including GCC cc1 and assembler, and
the generated C through compilation. Final full hash readback and mandatory
lease release/close finish before a successful build receipt is written. The
receipt records source/tool bytes, private producer custody and generated record
bytes. It does not claim a whole dynamic compiler/library closure or a Windows
boot. Ordinary development builds retain their existing before/after source
checks and now record selected compiler executable bytes.

The kernel requires magic/version/size/reserved and bounded nonzero SHA fields,
then checks role 0 (manifest) and role 1 (encoded SIM) against the single compiled
record. Both roles must match before a claim. Existing sealed source identity,
process ownership, physical device provenance, generation, boot/source/current
exclusion and exclusive claim remain required by the actual syscall service.
The record is not a process-visible registration interface.

## Remaining positive production gates

1. Independent actual native producer compilation/readback must provide the
   complete approved source-map digest and actual native EFI/kernel/optional
   Win64 byte anchors. Ordinary Supervisor EFI is not a native EFI substitute.
2. The control installer must finish, show the real Windows desktop, stop, and
   independently read back the exact original disk and required system files.
   Its producer custody verifier must be connected to
   `native_release_policy.verify_private_source_custody`. Private source anchors
   remain outside Git. That verifier currently always refuses; the public
   `GENUINE_BASELINE`, native source-map and native artifact anchors are absent.
3. Real replacement/native ESP/encoded SIM and saved manifest must be produced
   under the existing source/nonce/custody contracts, then fit actual runtime
   sealed-copy bounds. No synthetic NAS fixture can meet production authority.
4. Root's reviewed c872c7c lazy-bounce kernel fix must be integrated before full
   standalone link. Full real kernel/Win64 builds and actual guest disk install,
   cold boot and Windows-on-ShizukuDOS acceptance remain separate requirements.
   GUI default installer selection is still a subsequent connection task.

Run focused host controls with
`python3 shizukudos/install/tests/test_native_release_admission.py`.
The 8 controls include real GCC/Clang consumer compilation and refusal, real
leased tiny SIM saved-byte readback, forged saved flags/corrupt SIM refusal,
encoded bound checks, stale ingestion, missing custody and actual kbuild profile
selection/receipt ordering. Positive producer and kernel compilation in the
last profile selection control are explicitly **host-only models**. They never
certify real Windows media, generate an actual private release, install a target,
launch a VM or certify boot. The project dependency closure harness separately
checks actual six-profile C selections against the live source inventory.

Read-lease behavior follows the Linux man-pages project's
[F_SETLEASE/F_GETLEASE documentation](https://man7.org/linux/man-pages/man2/F_SETLEASE.2const.html):
leases belong to the held open-file description, conflicting writes notify the
holder, and unsupported filesystems refuse. The tests inspect the actual held
file description rather than opening a new descriptor and treating its lease
state as custody proof. No unsupported-filesystem exemption is provided.
