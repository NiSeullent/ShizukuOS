# ShizukuOS 1.0.0 full-goal release preparation

This lane prepares the public installer ISO and official Korean/English
download metadata after the actual integration goal passes. It does not turn
Kernel64 loopback, firmware component tests or a development desktop into
Windows 98 running on ShizukuDOS. Root owns live publication; this tool has no
publish/symlink, nginx, DNS, VM, ISO-copy or remote-configuration operation.

The existing `remaster_continuation_iso.py` retains old boot binaries and the
existing `publish_m98_continuation.py` requires mixed provenance and incomplete
feature/OS flags. Preserve those tools and their original checkpoint scope.
`site/deploy/publish_static.py` admits development ISO/desktop evidence, streams
downloads, and checks origin body/HEAD/range identity; its development acceptance
is insufficient for this full-goal release.

## Actual origin and preservation boundary

Read-only inspection of `/srv/m98/current` resolves to
`/srv/m98/releases/20261001T152940`. Its complete immutable site has 92 regular
files. Never replace it with only a publisher's fixed subset: older evidence,
continuation pages and component downloads must be retained.

The active route configuration is `/srv/m98/nginx/locations.conf`, included by
`/srv/conf.d/nginx/conf.d/m98.nyase.kr.conf`; the nginx installation is under
`/srv/opt/nginx`, with `/srv/conf.d/nginx/nginx.conf`. `/etc/nginx` is unrelated.
The route config is 2,936 bytes with SHA-256
`e5e4cd76b9aad82264bb63101edded8fc95f29251529f89f633951a26dbb86c9`.
It serves `/srv/m98/current/site`, applies `no-store, max-age=0, no-transform`,
redirects `/vnc.html` and `/vnc_lite.html` to `/`, and retains `/legacy-console/`
separately. No route or running service was changed by this lane.

| Preserved body | Bytes | SHA-256 |
| --- | ---: | --- |
| `/index.html` | 11,575 | `e6394476e5d445585528c821fe0671bff1a56efa33f21626d2d0b48115c6653c` |
| `/en/index.html` | 11,693 | `8c3adb4dc59cebe2388ca8deba103a223eafc2d9aa20f8bf2c31fc71f99f23eb` |
| `/continuation/index.html` | 6,440 | `19747185348f7e7675e01bd73cd5752b7aacc54099ba1a29f188d5a7b19e6e3c` |

The optional preservation snapshot binds every inherited route, its size/hash,
the exact current symlink literal and the route configuration. A concurrent
publisher, changed old page or changed route file is rejected before private
staging. These are filesystem preservation checks, not external HTTP evidence.

## Producer receipt contract

`tools/prepare_m98_product_release.py` accepts an approved SHA-256 of an index
with schema `shizukuos.full-release-index.v1` and exact scope
`product-ShizukuOS-1.0.0`. The source checkout must be at the declared full
40-character commit, with no tracked changes. `goal_contract` is exactly
`{path, sha256}`: a tracked project-relative requirements JSON file. The tool
reads its actual bytes and both original specification files; a repeated
`goal_contract_sha256` string cannot substitute for the document.

Index fields are exactly `schema`, `scope`, `release_id`, `source_commit`,
`goal_contract`, `artifacts`, `gates`. Required project artifact roles are
`public_iso`, `boot_loader`, `dos_foundation`, `kernel32`, `kernel64`, `vxd`,
`installer`; each pin is exactly `{path, bytes, sha256}`. Inputs are canonical
absolute regular files with no symlink parents, bounded reads and stable file
identity. Microsoft installation media, installed Windows disks and secrets are
private acceptance inputs; they are never public artifact roles or copied by
this tool. The public ISO's independent inventory/source/licence gate remains
mandatory.

The requirements document has exactly `schema`, `scope`, `source_specs`,
`requirements`, with schema `shizukuos.requirements.v1` and the same full-product
scope. `source_specs` contains exactly the original `win98_architecture` and
`shizukudos10_integration` roles, each `{role, path, sha256}`. Their distinct,
tracked safe paths and actual source bytes are verified. Both originals and
the requirements document must also appear in every producer source closure.

Every requirement has exactly `id`, `category`, `description`, `gate`, `checks`,
`applications`. IDs and check names are unique, descriptions are explicit,
and all eight gates and these twelve categories must be covered:
`distribution`, `windows98_integration`, `vmm_authority`, `pma_scheduling_smp`,
`dos_foundation`, `display_gop`, `installer`, `modern_applications`,
`nt_wrapper_compatibility`, `legacy_win16_win32`, `failure_lifecycle`,
`modern_web_features`. A reviewer remains responsible for verifying that this
inventory actually preserves every source requirement; merely covering these
categories does not prove that semantic audit.

Contract application rows are `{name, version}`. An unspecified required
version is `null`, never an invented version. A draft may omit concrete modern
application names while implementation proceeds, but its affected requirement
IDs are reported in `missing_application_inventory` and release preparation
stays BLOCKED. The inventory must be populated from reviewed actual native
product tests before the final contract/source freeze. Another chat's changed
application scope is not an implicit acceptance requirement.

Required gates: `public_iso`, `windows98_boot`, `windows98_vmm`, `native_smp`,
`iso_bios`, `iso_uefi`, `installation`, `full_goal`. Each index gate has exactly
`receipt` (file pin), `runner` (`{path, sha256}`, tracked project-relative source)
and `sources_sha256` (the reviewed complete transitive producer/build closure).

Each producer receipt uses schema `shizukuos.full-release-gate.v1`, the exact
scope/gate/source/goal, and these required bindings:

- `runner` and `sources_sha256` exactly match the reviewed index and current
  tracked source bytes; the runner is itself in the source closure.
- `artifacts_sha256` exactly identifies all seven final project artifacts.
- `execution` is `actual-guest` or `actual-hardware`; only the independent
  static `public_iso` gate uses `actual-readback`.
- `modeled` and `component_only` are both false. Predecessor source/goal,
  standalone/component schemas, wrong scope and modeled execution are refused.
- `outputs` pins actually readable raw producer receipts/logs with exact size
  and hash (1..64 files; each <=16 MiB, total <=64 MiB). Never export those private
  raw paths through download metadata. Empty output or hashes alone are refused.
- `status` and every uniquely named `checks` row must be PASS. Check rows are
  exactly `{check, status, output_sha256}`; every referenced hash must identify
  one of that producer's actually read, pinned outputs. Each gate includes both
  the tool's mandatory behaviors and the requirements document's checks for
  that gate. Installation requires
  cancellation with zero target writes, an installed Windows 98 on ShizukuDOS
  cold boot, and persistence after restart. Native SMP requires actual work on
  separate CPUs while Windows VMM retains scheduling authority.

The `full_goal` receipt additionally has `requirements`, containing exactly
every contract ID, once each. Each row is exactly `{id, status, checks,
applications}`. Its checks are exactly the contract's check names, with the
same check-row fields as above, and their output hashes must come from the
corresponding producer's **named check**, not another output from the same
gate. A generic "every requested requirement and application passed" string
does not replace these records. Every requirement and linked producer check
must pass; missing or failed producers keep the requirement BLOCKED.

Observed application rows are exactly `{name, version, output_sha256}`. Names
must exactly match that requirement's reviewed contract inventory. Versions
must be explicit nonplaceholder observed values; a pinned contract version
must match exactly. Application evidence hashes must identify that requirement's
behavior outputs. The actual producer must extract the version and validate
the native behavior from those raw outputs; this admission tool binds reviewed
records to preserved bytes and does not interpret arbitrary log text as a
version observation. Unknown versions, missing apps, unpinned outputs and wrong
producer check identities are refused. Failed valid receipts remain BLOCKED;
malformed or misleading identity sets are rejected.

Root's actual producer adapters must validate their original test results and
include those original results/logs in `outputs`. Do not manually stamp these
fields onto a component receipt. The approved index is a review boundary: this
tool verifies record binding and preserved bytes; it cannot authenticate an
untrusted producer or substitute for actual guest execution. Synthetic unit
fixtures test admission behavior only and are never product evidence.

Missing/nonpassing gates produce BLOCKED; malformed, stale or changed inputs
are rejected. All inputs are checked again before/after private preparation.
No component receipt can bypass a missing full-goal gate.

## Source closure, packaging and testing sequence

`build_shizuku_se_iso.py` builds project code, licence/corresponding-source
payloads, BIOS/UEFI hybrid structures and the own SHZSETUP installation payload.
Its `--reuse-builds` still validates consumed source and artifact receipts.
`--win98-media` creates a separately named private ISO, never the public image.
The current default is a development standalone desktop; actual replacement
boot/installation integration must be implemented and tested before a product
ISO is accepted. Do not run this shared-output builder in a peer worktree.

After the final source freeze, rebuild the complete carried runtime/loader/DOS,
wrappers and installer; verify all consumed source closures. Build the public
ISO in owned staging and perform independent `verify_public_iso.py` readback.
Then boot the exact ISO through BIOS and UEFI, execute cancel/install/cold-boot
and persistence checks on owned disposable targets, and retain bounded raw
receipts. Component boot matrix, native desktop and installer checks retain
their scope and cannot replace the Windows/VMM/SMP/full-goal gates.

The new preparation tool produces Korean/English pages, manifest and
`SHA256SUMS` under private `site/downloads/<release-id>/` only after admission
and resource checks. Both languages identify the same exact official ISO URL,
byte size, hash and source commit; neither exposes local paths. It does not
copy the ISO or switch the official site. The deployment owner must preserve
the full prior inventory and add reviewed home navigation separately.

The final external gate requires normal public DNS and valid public TLS,
HTTP 200 and exact body hashes for both languages and metadata; both old VNC
redirects must end at the reviewed homepage. The ISO requires full download
size/SHA, HEAD length and a 206 range with exact `Content-Range` and prefix.
Origin loopback checks, resolver overrides or a proxy challenge do not satisfy
this external gate. Preserve `no-transform`; a rewritten/challenge body fails.

## Resource and ownership status

Initial local available space was 18,932,678,656 bytes. It is below the existing
22,058,516,480-byte publication floor plus artifact bytes and 16 MiB reserve,
and below the remaster's 20 GiB+budget floor. These floors remain intact; no
shared artifacts are deleted. User selected `snowra-f-nas` storage. Root owns
NAS path/permission/transfer coordination; no NAS configuration or transfer has
been performed by this lane. Remote public storage must retain exact closure
and be separate from private acceptance media before it is admitted.

The preceding hash-only schema was reproduced admitting an unpinned contract
and generic full-goal PASS claim. The new source-preparation tests exercise
tracked contracts/original specifications, exact requirement/check/application
identities, version pins, producer output binding, draft inventory blocking,
path/budget constraints and actual CLI staging with small synthetic files.
These tests are admission-logic evidence, not ISO boot, Windows execution,
NAS transfer, external download or product completion. The complete relevant
tools and existing static publisher suites are run again after this change;
the fresh tools run passes 188 tests with one existing skip,
`test_actual_pinned_source_exposes_deceptive_success_stub` (KernelEx submodule
not checked out). This includes all 36 release-preparation tests. The separate
existing static publisher suite passes 35 tests. No guest or public deployment
was executed by these runs.

The final source-epoch regression uses an actual temporary git commit during
private metadata staging. Before the fix it incorrectly wrote predecessor
readiness; the final source check now refuses it before `readiness.json` is
written. The test supplies synthetic capacity so it exercises that boundary
without changing real storage limits or using NAS.

The actual tracked draft was also inspected through the read-only CLI at
source commit `a13fe4aeec6ace52b3388d3ef0a7de7977617b62`, contract SHA-256
`b63e58853a2e65963033bb17e8a4bfb81f3bfa8021b8ba45927b51fd9ab8ae83`.
It has 146 unique requirement IDs after the original capitalization aliases
`NTDWriteWrapper9x`/`NTDWRITEWrapper9x` were represented as one wrapper family.
Its original specification bytes are unchanged. With no fabricated producer
receipts or artifacts, the CLI returns 2/BLOCKED: all 146 requirements remain
unproved, all eight gates and seven artifact roles are missing, and
`apps.requested-applications` has no concrete reviewed inventory. No output
directory, guest, ISO copy or publication was created by this read-only check.

Reserved new files are documented in the shared mailbox
`MESSAGE-fada-163f-PRODUCT-RELEASE-PREP-OWNERSHIP.md`. Existing publishers and
peer trees/indexes are untouched. Runtime/deployment evidence remains pending.

NAS archive helper review is separate from release readiness. In root's native
boot worktree, the existing 10 helper tests pass; three additional temporary
local-boundary controls exercise actual `store()` with real leases and pipes:
healthy stream/readback, bounded helper-output refusal, and concurrent-writer
lease-break refusal. No network or remote NAS was invoked by those controls.
Root verified private storage at
`/volume2/homes/sharhene777/ShizukuOS-private` (0700) and public staging at
`/volume2/iso/ShizukuOS`. Mounted transport is still being established; the
release preparer's canonical local-file and resource-floor requirements remain
unchanged. NAS archive success cannot satisfy Windows/ISO release gates.
