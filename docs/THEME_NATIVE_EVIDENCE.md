# Verifying current native theme evidence

`tools/verify_theme_native.py` reads a stopped owned native trial. It does not
launch a VM, submit keyboard/QMP input, inspect a live disk, or decide what an
image shows. It requires caller-pinned manifest, canonical runner source, and
a separately trusted manual visual review receipt. That review must already
bind the exact native harness result, current frozen manifest, and distinct
direct/static painted screenshots with their hashes and mode-specific review.
PNG filenames and integrity hashes alone never establish visual correctness.

Run it with `--run`, `--manifest`, `--manifest-sha256`, `--runner-sha256`,
`--visual-review`, and `--visual-review-sha256`. It emits JSON on stdout and
returns1 on incomplete or mismatched evidence. It never overwrites receipts.
A caller can retain that output in a new explicitly named review record.

The caller's manifest approval and visual-review trust are external inputs.
The tool binds their bytes; it does not decide that a selected binary is a
production implementation, audit compiler semantics, or grant either approval.
The named production DLL hash in output follows that approved manifest identity.

The required record contains four exact current theme inputs copied to the
private clone, immutable native harness/source evidence, unchanged original
and prepared source flags, cold KVM128MiB/2CPU/no-network hardware and the
unchanged20GiB reserve. The owned VM must have stopped normally. All three
guest logs must be newly created and nonempty, retain actual hashes and byte
counts, and come from the stopped-run readback. The supervisor must identify
Win98 SE4.10/build-low2222 and the frozen nonce. Its two separate actual child
blocks must include successful CreateProcess, real wait and GetExitCodeProcess0,
stdout flush and handle close. Current probes must additionally report their
correct direct/static mode, ACP949 and the complete native API PASS line.

The final supervisor line is explicitly a **requested** exit0. The current
supervisor has no independent outer observer of its own actual exit. The
verifier records `supervisor_actual_exit=not_observed`; it never upgrades that
line to observed supervisor completion. Its passing scope is the two actual
native component child results plus the separately trusted visual comparison.
System-wide themes and modern application behavior remain false.

Evidence reads are bounded regular-file reads with symlink rejection and
before/after file metadata checks. Duplicate JSON/log keys, stale outputs,
source/manifest/image mismatches, a reused single frame for both modes,
missing/full child blocks, failed exits/flushes/closes and different hardware
are rejected with explicit checks that remain active under optimized Python.
The manifest's exact schema/kind and bounded nonce are validated. Its entire
approved manifest/input/two source-receipt hash set must match the native guest
immutable record, and the complete guest output plan must match exactly.
Source receipts are read only from bounded regular files in the same staging
directory; their content remains externally approved provenance. A nonempty
harness error rejects completion even when other fields look successful.
The frozen native harness supplies the protected-source immutability record;
this lightweight verifier does not rehash multi-gigabyte original VM media.

The synthetic unit tests exercise acceptance structure and meaningful failure
cases, including the real v3 failure shape. Their artificial inputs/reviews
are clearly synthetic and never count as guest or pixel evidence. Run
`python3 -m unittest discover -s tests -p test_verify_theme_native.py`.

The unchanged actual v3 result and its trusted manual visual review establish
visible labelled Classic/Modern comparisons. They fail complete-current-probe
acceptance because `THSTA.LOG` is empty and the final static child exit/flush
block is absent. Older v1 original-probe execution remains separate historical
evidence; it is not combined with newer v3 frames to invent a complete fresh
trial. No existing native trial or historical receipt is modified here.
