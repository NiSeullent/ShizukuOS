# source_capsule.py

Explicit pinned public source/license capsule for the candidate ISO. See the module docstring.

- API: `build_capsule(root, *, prefix, commit, project_roots, wineport, receipt_root, max_total) -> (members, manifest)`;
  `write_capsule(members, fresh_dir)`.
- CLI: `--check` (no writes) or `--out FRESH_DIR`; `--strict` exits 2 while requirements remain.
- Member layout matches the builder: `ShizukuDOS10/{LICENSES,SOURCE}/...`, upstream tar stems `<name>-<commit12>.tar.gz`,
  plus `SOURCE/CAPSULE-MANIFEST.json` (SHA-256, provenance, `flags`, `requirements`, `compliance_claim`).
- Project source comes from git blobs of one pinned commit via an allowlist and path/name/content guards (Microsoft media
  names, disk images, keys, secrets, build outputs refused and listed). It never claims source closure: missing
  receipts/trees/pins stay false with the exact requirement recorded.

## Consumed receipts (iso11)

Name the frozen producer receipts explicitly; roles: `kernels`, `guest-result`, `guest-readback`, `setup-build`,
`setup-result`, `dos`.

    source_capsule.py --consumed-only OUT.json --consume kernels=PATH --consume guest-result=PATH ...   # no git/builder
    source_capsule.py --check|--out DIR --commit SHA --consume ROLE=PATH ...                              # in the capsule

API: `consume_receipts(root, {role: path}, capsule_files=None, commit=None)`; `build_capsule(..., consumed={...})`
adds `SOURCE/CONSUMED-RECEIPT.json`. Each receipt is recorded with its SHA-256; its recorded source map
(`sources_sha256`, `pins_before/sources`, ...) is compared with current files and with the shipped capsule bytes.
Entries are current/stale/missing/refused; stale entries are listed and never bound. Unreadable receipts are reported
with the exact requirement. `release_claim` and `acceptance_claim` are always false and the installed UEFI guest FAIL
(stops after `K64 disk: ahci0: 3 partition(s)`, 120 s) is preserved as historical evidence in the receipt.
`compliance_claim` depends on source requirements, separately from OS boot qualification.

## Read-only contract and `--syslinux-cache` (fat12)

`--check` and `--out` never call `ensure_deb_upstream`, any download, build or network helper (the builder's
`syslinux_payload`, `syslinux`, `ensure_*` and `_fetch_pinned` are replaced in memory by recorded raisers,
`FORBIDDEN_CALLS`). The Syslinux upstream is read only from an explicit, already existing cache:

    source_capsule.py --check --syslinux-cache build/upstream/syslinux   # directory holding root/ and downloads/
    API: build_capsule(..., syslinux_cache=Path | (root, downloads))

The cache is validated read-only: every `files` entry in `root/`, every `.deb` and Debian source file in `downloads/`
is re-hashed against `shizukudos/upstream/manifest.json`; each `license_files` entry must be byte-identical to the file
inside its pinned `.deb`. Symlinks, missing/non-regular files or any mismatch leave `source_present` false with the
exact requirement; nothing is created, repaired or unpacked. No cache means the same: upstream false, requirement
recorded, no mutation. Full source closure (`flags.upstream_sources_all_present`, `compliance_claim`) stays false while
anything is missing.

## Consume parser hardening

Strict JSON (duplicate keys, NaN/Infinity, deep nesting refused); the receipt must be a non-empty object, not a JSON
Schema document. The first source-map pointer present decides and must be a non-empty `{path: 64 lowercase hex}` map.
Only named, normalised, allowlisted project-source paths passing the strict guards are opened (no scanning, no
symlinks, one read with stat before/after); compiled outputs are never read, so `compiled_binary_binding_claim` is
false. `recorded_snapshot_sha256` / `read_snapshot_sha256` record the recorded and actually read source snapshots.
`all_roles_consumed_and_current` needs all six roles, valid maps, nothing stale/missing/refused, and the comparison with
shipped capsule bytes (so `--consumed-only` is never true).

`--setup-result PATH` is shorthand for `--consume setup-result=PATH`; the existing receipt is
`build/installer-link-boot05/setup/stage-setup-result.json` (not `setup/result.json`, which is refused).

## Source license data vs OS boot qualification

The installed UEFI guest FAIL stays in the consumed receipt as the historical field `historical_installed_guest`
(`installed_guest_result`), with `os_boot_qualification_claim=false`. It is no longer a GPL corresponding-source
requirement; the manifest carries a separate `os_boot_qualification` block. `compliance_claim` depends only on source
requirements (it also stays false while the toolchain source offer is open).

## Fixtures

`source_capsule.py --self-test` runs offline tmp-dir fixtures (fake builder, poisoned network, tree/cache snapshots)
asserting ensure/download are never called for `--check`, valid/bad-hash/absent cache, and the parser oddities.

Source-map pointers: after the earlier pointers, a producer receipt's top-level `source_before` (K64S `result.json`)
or `before` (`source-pins.json`) map is recognized. `drivers/` is an allowed public-source root (binary, private and
secret names stay refused). A malformed first-present map fails closed; a hash that differs from the current file
stays unbound.
