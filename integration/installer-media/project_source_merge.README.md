# project_source_merge.py

Composes ONE explicitly pinned full git commit of the public project tree (baseline, via the existing guarded
`source_capsule.project_entries`) with an externally pinned `consumed_overlay` TAR + manifest. Overlay paths replace the
same baseline path or are added. Output is a deterministic plain GNU tar `SOURCE/project/<rel>` plus a manifest.
`source_capsule.py` and `consumed_overlay.py` are imported unchanged.

    project_source_merge.py --root REPO --commit FULL_HEX --overlay-tar T --overlay-tar-sha256 H \
        --overlay-manifest M --overlay-manifest-sha256 H (--check | --out DIR) [--project-root ALLOWLISTED ...]
    project_source_merge.py --self-test        # offline, no git, tiny tempfile fixtures

- Both overlay pins are required external lowercase SHA-256 values; digests written inside the manifest are only
  cross-checked. The commit must be a full 40-hex SHA-1 name (SHA-256 repositories are unsupported). It is bound by reading the raw
  `cat-file commit`, requiring `sha1("commit N\0"+body)` to equal the name, and recording the commit's tree id in
  `baseline.tree`. Git runs with `GIT_NO_REPLACE_OBJECTS=1`; an inherited `GIT_DIR`, `GIT_OBJECT_DIRECTORY`,
  `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_REPLACE_REF_BASE`, `GIT_WORK_TREE` or `GIT_COMMON_DIR` is refused. A repository's
  own `objects/info/alternates` file is not inspected.
- Overlay validation: strict JSON, exact key sets, all claims literal false, `snapshot_is_commit` false, exact file
  list/counts/sizes/hashes/roles (`consumed_by`), receipt source-map count + digest cross-check, original
  `producer_status` (absent or a completed-build status) carried over unchanged, bool/negative ints refused, duplicate or
  unsorted entries, malformed digests, NUL/control/surrogate/non-normalised/outside-allowlist/private paths. The TAR is
  parsed in memory (never extracted): only plain regular members with fixed layout/mtime/uid/gid/mode, no
  symlink/hardlink/special/pax/compressed/extra/missing members, and the bytes must equal the exact deterministic archive.
  Member content passes `consumed_overlay.content_refusal` (private key, product key, token, binary).
- Baseline entries are re-checked with `check_path_text`, `_named_source_ok`, `content_refusal`, git blob SHA-1, mode,
  duplicates and file/dir prefix conflicts. Guard-rejected, gitlink/symlink-skipped and stronger-guard-rejected paths are
  listed in the manifest (counts + list digest); an overlay path colliding with one is refused. Closure is never claimed.
- Replacement keeps the baseline git mode (0755 for 100755, else 0644); additions are 0644.
- Provenance: baseline full commit and roots, overlay tar/manifest external pins, original receipt digests/producer
  status, tool digests (merge, source_capsule, consumed_overlay), counts (baseline, additions, replacements,
  overlay_identical_to_baseline, unchanged_baseline, result), per-category path hashes, per-file source/mode/sha256.
  No absolute input paths or raw receipts are shipped.
- Bounds (enforced before any output): file 8 MiB, total 256 MiB, files 20000, manifest/metadata 8 MiB, archive
  total + 1 KiB/file + 1 MiB. Inputs are read once, bounded, regular files, final component opened with `O_NOFOLLOW`
  (intermediate directory symlinks are not rejected).
- `--check` is read-only (`sys.dont_write_bytecode` is set before any sibling import; no `__pycache__`). `--out` DIR
  must be absent or empty; a temp directory beside it is renamed atomically (no rmdir-before-rename); collisions and
  symlinks are refused; inputs and old outputs are never deleted; on failure only the temp directory is removed.
- All fullsource/licence/GPL/upstream/compliance/release/reproducible-binary/compiled-binary/OS/EFI-DOS-install-Win98
  claims are literal false; the result is not a commit.

Memory: `source_capsule.project_entries` reads every allowlisted blob (up to its own 60000-file limit, no total cap) before
this tool's 20000-file/256 MiB bounds apply; the output bounds hold but peak memory is not bounded on a very large tree.

`--project-root` narrows the baseline to a subset of the public allowlist (recorded; `roots_are_default_public_allowlist`
becomes false). It exists for narrow controls only; overlay paths outside the selected roots are refused (they cannot be classified
as additions or replacements).
