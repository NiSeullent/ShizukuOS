# 2026-10-01 portable source checkpoint

This directory contains small, sanitized summaries of actual records, their source-record SHA-256 identifiers, public publisher input pins, and source-only native candidates. It contains no target-app archive, Microsoft redistributable, Windows installation media, key, VM disk or credential.

- `v44-contracts.json`: six real standalone Kernel64 contracts, 252 recorded PASS lines. All application/installed-Windows98 claims remain false.
- `v44-build.json`: ordinary V44 build and independent PE interface checks; changed import closure is static evidence.
- `native-foundation.json`: 37 real Supervisor/native K64 checks; this run configured DOS16/K64 and does not establish Win98 integration.
- `preserved-v43-failure.json`: original freestanding fixture link failure retained separately from the V44 fix.
- `application-status.json`: actual historical application progress/failures, including the corrected Chromium GUI V2 publisher identity and limited older headless provenance.
- `publisher-input-pins.json`: official package identities for private acquisition; historical tested versions are not a moving latest guarantee.
- `native-win98-candidate/`: reviewed 18-file opt-in Supervisor source candidate, pending generic peer-dispatch candidate and host fixture sources. `manifest.json` distinguishes original hashes from the producer/patch copies whose machine-private cold disk path was replaced with a placeholder. These scripts still consume historical ignored build receipts and require a fresh environment adapter; no old runner should be launched as a shortcut.

The source records under `build/` were intentionally not committed as complete machine-dependent outputs. Regenerate build/source/VM records in the new environment and retain them with that environment's real input hashes. See [CONTINUE_MODERN_APPS.md](../../../CONTINUE_MODERN_APPS.md) for build commands and unresolved work.
