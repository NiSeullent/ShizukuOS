# Uncommitted source recovered during branch consolidation

These 27 explicitly selected text sources were missing from or differed from the canonical
`40fd4e6c2d9d80f020bbc5e9bdf9ac5d7ec8b707` tree. `manifest.json` records
their original worktrees, paths, sizes and SHA256 hashes. Files retain their
original relative layout within each cohort and were copied byte-for-byte.
They are preserved source candidates, not enabled production components.

## Adoption map

| Cohort | Intended live destination | Remaining requirement |
| --- | --- | --- |
| storage-authority | `shizukudos/kernel64` and `shizukudos/tests` | Authoring-stage admission policy. Its original runner requires checked entry and an independent preparation review; do not invoke it directly or remove its guard. The original `/dev/shm` source was volatile. |
| fat32-install-bridge | `shizukudos/win64/setup` and `shizukudos/install/tests` | First integrate `c87b5dad` and the actual FADA `native_install.h`/`plat.h` interfaces with the hashes recorded in the original status. Host controls must be rerun against the integrated interfaces before wiring the provider. |
| passive-trace | `shizukudos/supervisor/native_win98` | Passive trace draft. Its original document explicitly reports no compiler/control execution. Guest-memory observations and any generated captures remain private. |
| kernel64-role | `patches/supervisor`, `tests`, and `tools` | Apply-check the original patch against the current candidate builder; preserve producer-role and original-preimage requirements. |
| active-tls | `ntwin32/secure_transport` and `docs/agents/plans` | Snapshot of the active 6970 owner lane; further source changes require owner integration and fresh TLS verification. |
| dos-failure-plan | `docs/superpowers/plans` | Original plan for the live test-harness change described below. |
| owner-review-usb | `tools` and `tools/tests` | Preserve three divergent USB/public-site helper sources; select the current owner-reviewed successor before applying. |
| owner-review-smp | `shizukudos/tests` and `docs` | Preserve uncommitted SMP admission/concurrency fixtures and original status/plan; no AP activation follows from presence. |

## Live adoption in this commit

The original uncommitted DOS10 failure-evidence change is applied to
`shizukudos/dos16/test_user_boot.py`, with its original regression file at
`shizukudos/dos16/test_user_boot_failure.py`. The old harness lost failure
artifacts and could replace the startup exception with a QMP cleanup error.
The successor records bounded registers/VGA/low-memory/serial observations
before owned guest cleanup and retains the original startup error.

Fresh regression execution against the canonical preimage produced three
failures and one error. Applying the captured existing patch passed all four
tests. These tests fake only the external guest/QMP process boundary; no VM
was started. This proves failure handling, not a successful DOS or Windows
boot. The runtime diagnostics can include guest data and must remain in
ignored, private build output.

## Already absorbed work and unresolved differences

All 17 dirty entries in the persistent-AP worktree matched canonical bytes.
16 of 17 native Kernel32 AP entries matched; its remaining `main.c` used an
older boot-policy call and must not overwrite the canonical successor.
All six untracked continuation-publication files matched canonical bytes.

Differences in the apps USB preparation/public verifier, old boot site's
eight tracked files, and SMP memory admission/concurrency changes require
owner review. Their untracked sources are preserved in the two owner-review
cohorts; tracked site/SMP changes are captured in `owner-review-deltas/`
with their original base commits and file hashes. They are not implicitly
resolved by this source snapshot.
Do not sweep-copy generated output, browser captures, collaboration state,
private Zetscape data, Windows media, or guest images into Git.

This recovery does not establish full branch integration, final ISO,
actual Windows 98 on ShizukuDOS, or modern-app acceptance. Branch deletion
must use the final integration owner's preservation and validation report.
