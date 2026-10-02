# Decisions — fd5c integration

- Use latest committed `a648e9b`; main checkout `e455f01` is stale. Older audit
  snapshots remain unchanged. Current opt-in native Win98 domain exists.
- Keep Windows VMM scheduling separate from PMA worker scheduling.
- Patch existing channel ABI and Supervisor code; no duplicate scheduler, VGA
  subsystem, wrapper object model or desktop.
- Doorbell injection does not consume pending channel work. Only explicit ACK
  clears its pending state. Narrow WAIT change preserves timer semantics.
- Preserve ABI byte layouts/version and documented generation values. Validate
  physical regions before dereferencing metadata or writing the owner table.
- Reuse the repository's CP437 implementation; no new third-party code copied.
- Preserve NTW64 handle encoding; retain generation history per record and
  retire at8191. Fail before remote creation after65528 successes per loaded
  wrapper instance. DLL reload persistence and concurrent callers are separate.
- Independent peer review found ticket trylock rollover ABA and incomplete
  source receipt closure. c957 acknowledged and fixed both before import.
- PMA service review reproduced finite distinct-identity lifetime budgets
  (8 owners/32 threads), even with only one live identity. The service peer must
  specify or repair those bounds before lifecycle acceptance. The imported
  service now explicitly documents8 distinctPIDs/32TIDs per epoch and returns
  resource errors on further distinct identities; Windows rundown remains open.
- Use isolated worktrees and exclusive file ownership. Local builds/tests write
  build/; no client-global configuration changes are part of this task.
- Treat original-DOS Windows controls, standalone kernels and host fixtures as
  different evidence scopes. The final Windows98 replacement gate is pending.
- Import peer fixes only after exact-source review and evidence reconciliation.
  Require complete source membership in guest receipts, not any nonempty map;
  require QEMU's computed successful termination and fresh bridge outputs.
- Preserve both observed peer native scheduler failures. Passing root focused
  guests do not cancel another source-bound integrated failure. Diagnose useful
  work and interrupted observations without relaxing the40-tick admission bound.
- Build the public project-generated Win64 archive locally for final combined
  component validation, and bind its complete runtime source receipt separately
  before/after the guest. The archive contains no Microsoft installation media.
- Source publication delay is not a reason to stop authorized integration:
  capture the exact independently reviewed peer snapshot with hashes/unchanged
  reads in our own tree, test it, and preserve source authorship. Final capability
  pair matches the subsequently published peer4e6beea;root6938618 records the
  identical frozen unit. No peer working tree or Git index was changed.
