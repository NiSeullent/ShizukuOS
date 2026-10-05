# installer-media: UNRELEASED installer ISO candidate

Scope: a BIOS+UEFI candidate ISO for the existing project SHZSETUP installer
(loader mode install, `SHZ/SETUP/INSTALL.IMG`, `shz.setup=interactive shz.noapps`).
It is NOT final original-Windows98 / full-OS acceptance. No private Windows
assets are included. Nothing here is released; ISO distribution is exclusively
https://m98.nyase.kr via nginx.

## Files
- `candidate_iso.py` - builder; reuses `tools/build_shizuku_se_iso.py` and
  `tools/shizuku_se_media.py` via isolated module copies (no global monkeypatch).
- `source_capsule.py` - pinned public source/license capsule (see
  `source_capsule.README.md`). Separate output; not yet embedded in the ISO.

## Invocation (root runs this on the NAS, nas-run, into a NEW directory)
    python3 candidate_iso.py --tools <root>/tools --syslinux <pinned syslinux dir> \
        --input-root <frozen build/shizukudos inputs, read-only> \
        --input-pins <pins.json: {schema, files:{relpath:sha256}}> \
        --payload-root <FRESH mkpayload.py --out payload, production answer> \
        --out-dir <NEW dir> [--dry-run]
    python3 candidate_iso.py --check-receipt <NEW dir>/candidate-receipt.json
    python3 source_capsule.py --check [--strict] | --out <empty dir>

## Gates
- Payload must be fresh (default <=24h) and carry the production answer
  (`shizukudos/install/shzsetup.ini`); the QA answer is rejected, and the
  production `setup_payload` guard is not bypassed. Repack once with mkpayload's
  default answer externally.
- Inputs must match `--input-pins` exactly; `--out-dir` must not exist; ISO <=1 GiB;
  17 GiB free reserve; external commands bounded to 180 s.
- Receipt status is `unreleased-candidate` with explicit false gates; schema-only
  or PASS-claiming receipts are rejected by `--check-receipt`.
- `source_capsule.compliance_claim` stays false until every requirement is met
  (missing dos16/csm receipts, upstream trees, clean tree, toolchain offer).

## Known gaps
- Direct-installer menu only; no DOS16 menu entry.
- Capsule not yet wired into the ISO; `shz10_notice` text must be adapted
  (it claims working-tree tarballs).
