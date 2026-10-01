# Private native disk preparation lineage

`disk_lineage.py` validates immutable byte snapshots of the three existing
preparation records, so a future controller can describe its selected input as
a prepared ShizukuDOS replacement instead of always calling it original DOS.
This module has no CLI, opens no file, runs no producer and changes no current
builder, VM plan or controller. The original-DOS control remains the current
controller behavior until the owner integrates the module prospectively.

`admit(raw, pins, selected_disk, expected_producers)` accepts three snapshots in
this order:

1. The generated `replacement-profile.json` used by the constructor.
2. Its `source-profile.json` launch receipt from
   `shizukudos/install/win98_source_profile.py`.
3. The constructor's completed `preparation.json` receipt.

The caller supplies the exact approved path/byte-count/SHA256 pin for every
snapshot, the selected native builder disk pin and the ordered approved source
pins for the source-profile generator and constructor. The caller must acquire
and retain actual source read leases, read the snapshots from their held file
descriptors and verify the real selected disk's complete extent and SHA. This
pure module verifies these serialized crosslinks; it cannot attest execution
of a producer or establish file ownership, symlink safety or a read lease.

The generated profile, launch record, constructor record and selected disk must
bind each other exactly. The original and replacement paths and hashes must
differ. The profile must contain exactly the five launch payloads, including
the source-built kernel, FreeCOM, XMS and generated CONFIG/AUTOEXEC. The launch
record must name the explicit Windows foundation policy and the four observed
nonempty installed Windows files. The constructor must record the source-built
kernel boot template, preserved source/copy readback and original-member
inventory. Generic PASS, unfinished records, duplicate JSON fields, unbound
outputs and all runtime assertions are refused. Every runtime and publication
assertion in the returned record remains false. Installed-file observations use
the actual FAT regular-file row shape: `bytes`, `sha256`, `metadata_sha256` and
`cluster`, with no directory key. Directory rows and numeric/string lookalikes
are refused. Neither producer duplicates the payload list: the launch record's
complete profile pin and the constructor's exact profile SHA bind the same
five-payload profile transitively. Other producer observations remain permitted
with the same exact regular-file schema and the producer's bounded name/count
limits; this parser does not impose a new optional dependency path allowlist.

The returned `disk_origin` describes preparation, not successful replacement
boot. Future integration must carry these new pins through the new builder,
VM plan and owned controller receipt, check them before and after execution,
freeze this helper with the runtime sources, and preserve the old default when
no replacement lineage is explicitly selected. It must not rewrite historical
records or turn the existing Windows, replacement, persistence or application
acceptance flags true. This module alone is not sufficient to enable that path.

The fourteen host test methods exercise synthetic records, byte/hash mismatch,
crosslink mutation, duplicate keys, exact-false assertions, path/geometry
guards and payload/producer binding. They do not create a real disk, execute
Windows or run QEMU. The retained initial RED is an explicit adapter scaffold
returning the current original-DOS label; it is not a run of the existing
production controller or evidence of a new kernel failure.
