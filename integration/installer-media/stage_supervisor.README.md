# stage_supervisor.py

Stage-only producer for the Shizuku Supervisor EFI (new producer epoch `stage-supervisor/1`). See the module docstring.

    stage_supervisor.py --help
    stage_supervisor.py --check --root ROOT          # read-only; executes no tool, writes nothing
    stage_supervisor.py --root ROOT --out FRESH_DIR [--reference-efi-sha256 HEX]   # ACTUAL build; needs ROOT approval
    stage_supervisor.py --self-test                  # modeled fixtures with fake shell tools; NOT an EFI compile

## Recipe

`shizukudos/supervisor/build.py` and `shizukudos/tools/shzlib.py` are executed from `--root` in isolated in-memory
namespaces (no bytecode, no permanent `sys.modules` entries). Only `OUT` is relocated and `run` is replaced. Exactly
`build_vbios()`, `build_ap_trampoline()`, `build_payload()`, `build_loader(payload, None)` run, in that order; `main`,
`build_esp`, `guest_kernel_files`, ensure/upstream helpers and the private profile are unreachable. Build flags are
unchanged (including `-Wl,--no-insert-timestamp`); no `-MMD` is added.
`--root` and `--out` are explicit; `--out` must not exist (nothing is reused or deleted) and may not lie inside
`--root` except under `build/`.

## Owned runner

Every call (including refused ones, `nm`/`readelf`/`objcopy` and the pre/post `--version` probes) is recorded:
argv, executable, cwd, env summary, UTC times, return code, stream size and SHA-256, bounded log file. Limits: 180 s per
command, 4 MiB captured text, 1 MiB per stored log, 96 MiB total stream, 32 MiB own output directory, 17 GiB free-disk
reserve. Each command runs in its own process group, which is killed and waited for on every exit; leftover members are
recorded. Only the seven primary tools are permitted; every path argument must be under `--root` (read) or `--out`
(write) and pass the public guards of `source_capsule.py` (media/disk-image/secret names). `capture=True` returns text,
`check=False` is honoured. Anything touching ESP/disk/ISO/main/DOS-image helpers is refused.

## Receipt `OUT/stage-result.json` (atomic; written on failure too)

`status` is `BUILT_PENDING_GUEST_VALIDATION` or `FAILED`. `source_before` / `source_after` (also as `sources_sha256`)
are path -> SHA-256 maps with `source_unchanged`; a mutation or a tool change makes the stage FAILED. Also: tools
(path/realpath/SHA-256/version, pre and post), per-artifact SHA-256 and size (BOOTX64.EFI, payload.elf/.bin, vbios.bin,
ap-trampoline.bin and the generated `images.h`, `vbios_image.h`, `ap_trampoline_image.h`, kept separate from sources),
objects, commands, failure detail, and the optional `reference_efi` comparison (mismatch recorded truthfully; it
never binds history). Old generated headers found in the source tree are listed, never treated as inputs, and one that
would shadow a generated header is a hard refusal.

## Source map and limits

Direct inputs come from the real build module plus the loader source list in this helper, then a conservative literal
local include closure (all `#if` branches, comments included), bounded to 400 files/2 MiB each, project-relative,
symlink-free. Actual loader/payload command file inputs must lie in this map or the stage fails.
This is not the compiler's dependency closure. System headers, compiler/binutils support resources are not captured.
All claims in `claims` (guest acceptance, boot/OS/Win98, release, full source, licence, upstream, historical closure
or byte identity, compiler/system-header closure) are false. `--self-test` is modeled and proves the helper's guards
and receipt logic only.

## Known limits (documented, not fixed)

- m2: tool executables are hashed before/after, but a tool replaced and restored in between is not detected.
- m3: the source map is re-hashed once after the whole stage, not after every command; transient edits can be missed.
- m4: gcc/mingw helper programs (cc1, as, collect2) are not individually recorded; only their group is killed.
- The helper refuses to run under `python -O`/PYTHONOPTIMIZE (build.py's asserts are its artifact checks) and compiles
  build.py with optimize=0. SIGTERM kills the owned process group and still writes a FAILED receipt (`terminated`).

## Postfix (narrow successor)

- Runner limits are evaluated again after the owned group is killed and the pipe is drained, so a command that exits
  before any in-loop poll can no longer slip past the capture, own-output, disk-reserve or total-stream caps. Before
  BUILT is declared, the final own output plus encoded receipt (with a 1 MiB error-receipt budget held back from the
  32 MiB cap) and the free-disk reserve are checked; the FAILED receipt is always written without re-checking limits.
- The bytes actually executed (`build.py`, `shzlib.py`, and the `source_capsule.py` guard; off-root helpers by bare
  name) are hashed at load and must equal the `source_before` snapshot (refusal `hash-binding` before any tool
  command) and the `source_after` snapshot. `hash_binding` in the receipt records both booleans; `source_unchanged`
  also covers the off-root helper hashes.
- Source count: this helper's `--check` reports 95 files versus the 93 project files in the public lineage copy; the
  path sets are identical apart from `integration/installer-media/source_capsule.py` and `stage_supervisor.py`
  (2 helper files not part of the historical list). The lineage's 3 generated headers are separate and excluded here.
  This is a comparison of current conservative lists, not a historical closure.
