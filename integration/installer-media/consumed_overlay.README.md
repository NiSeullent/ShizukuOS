# consumed_overlay

Source-only snapshot exporter for the exact bytes named by producer source maps
(K64S `source_before`/`before`, installer pins `sources`, etc.). Dirty and
untracked files are included because bytes are read from the named working-tree
paths, never from Git.

**Limitation:** this is not a full source capsule and does not by itself close
GPL/LGPL/upstream corresponding source, licence closure, EFI/DOS/install/Win98
proof, release, or a reproducible binary. Every such manifest claim is `false`;
`snapshot_is_commit` is `false` (optional `--git-head` is only a read-only
`git --no-optional-locks rev-parse HEAD` reference).

    consumed_overlay.py --root PROJECT --receipt NAME=PATH [--receipt ...] --check
    consumed_overlay.py --root PROJECT --receipt NAME=PATH [--receipt ...] --out NEWDIR
    consumed_overlay.py --self-test

- NAME: unique, normalised ASCII `[a-z0-9][a-z0-9_-]{0,31}`; exactly one mode flag.
- Reuses `source_capsule.py` (unchanged): guards, `_source_map`, `strict_json`,
  `read_named_source`. Only named paths are opened (union, deduplicated), once each.
- Refused (fail closed, nothing written): duplicate name/receipt/JSON key, schema
  document, receipt `status` present and outside the explicit snapshot status set, `inputs_unchanged` not
  true, `source_after` differing from the recorded maps, no/malformed source map,
  paths with NUL/control characters/lone surrogates, hash conflict across receipts, stale or missing
  file, symlink, FIFO/non-regular, private-key/key-shaped/token-shaped content (heuristic regexes, not a guarantee), binary magic
  (MZ, ELF, zip/gzip/cab, disk images, ISO, GPT, boot sector) or NUL bytes.
- Several known source maps in one receipt (`sources`, `source_before`,
  `pins_before/sources`, ...) are exported as their union; a disagreeing hash or a
  malformed later map refuses. None is silently dropped.
- The tool never writes `__pycache__` (bytecode writing is disabled before import).
- The current K64S producer's `BUILT_PENDING_GUEST_VALIDATION` status names a
  completed build and is accepted for source capture. Its original status is
  retained as `producer_status`; it is not relabelled PASS or used as runtime
  qualification. Failed and unknown states remain refused.
- Bounds: 8 MiB/file, 32 MiB total, 10000 files, 16 receipts, 8 MiB metadata.
- `--check` writes nothing and prints JSON. `--out` must be absent or empty; it is
  built in a sibling temp directory and renamed into place (no overwrite, no symlink
  out, no PASS marker left on failure). Outputs: `overlay-source.tar`
  (`SOURCE/project/<path>`, sorted, epoch, uid/gid 0, mode 0644, plain uncompressed tar, so bytes do not depend on the host zlib) and
  `overlay-manifest.json` (records this tool's and source_capsule.py's SHA-256; per-file sha256 and consuming roles, receipt and
  source-map digests only; raw receipts and paths are not shipped; the manifest is
  independent of the absolute root).
- No traversal, global search, cache, network or Git writes. Intended for later
  NAS-authoritative execution by root; do not export live 440 files from here.
