# Borrowed original input descriptors

The task guardian reads and hashes each selected original through its own
immutable Linux read-leased descriptor before admitting the controller. The
controller now receives a duplicate of that same open file description through
the inherited credential-checked Unix seqpacket channel. It does not acquire a
new lease, replace the signal owner, or repeat large original SHA reads.

The `original` request contains exactly one `{path, bytes, sha256}` pin and no
descriptor rights. The guardian admits only entries that passed its initial
full SHA before the server's original snapshot. New paths, conflicting pins,
duplicate transfers, writable owned ESP/VARS and later runtime output entries
are refused. The response contains exactly one SCM_RIGHTS descriptor, the exact
pin, five actual identity fields, actual guardian PID and its initial full-SHA
admission fact. Kernel sender credentials still bind the PID and UID.

Before transfer and at every checkpoint, the guardian checks its SIGIO latch,
readonly regular descriptor, F_GETLEASE, FD and pathname identity, signal
ownership and every canonical ancestor. Ancestors are deduplicated only within
one checkpoint. The controller checks the same actual FD properties and uses
an ordered `original-check` RPC to observe the guardian's current latch and
lease custody. Missing, malformed, foreign or surplus descriptors refuse.

The hidden controller bootstrap carries the exact bounded seven-source pin
map and actual admitted plan extent. This supplies explicit pins before any
original source or metadata content read. The existing four-helper aggregate
SHA must still match. Plan and builder receipt content is read from the actual
borrowed FDs; all later input pins come from that same metadata. Runtime source
snapshots and layout checks keep their existing independent validation.

The controller holds its duplicates through actual owned-child cleanup,
final identity/provenance checks and fsynced controller receipt publication.
The outer CLI then closes only its duplicates; any close/check failure fails
the actual controller return even if the partial receipt was published. Guardian
leases stay held through controller return and its existing late full-SHA
checks and mandatory close. Writable owned ESP/VARS retain independent initial
and final full SHA reads. The non-custody branch keeps its independent hashes
and read leases. Memory, task, space, observation and cleanup limits are
unchanged.

Controller original flags now explicitly mean held identity plus guardian
initial full-SHA admission. They never claim an independent controller final
full read. `guardian_late_full_SHA_closure_pending` and
`guardian_PID1_final_join_required` remain true in its receipt. Admission or a
partial controller receipt cannot establish completed guardian cleanup. The
receipt marks controller FD closure pending, confirms the duplicates were held
at publication and leaves `leases_released_after_reap` false in borrowed mode.
These fields do not claim either controller closure or guardian lease release.
root must join actual native and custody receipts with the guardian's final
late full-SHA/close outcome and exact PID1 terminal.

Host controls use tiny owned RAM files, actual Linux leases, real SCM_RIGHTS,
kernel credentials, SIGIO break requests, same-byte inode replacement and
ancestor aliases. They perform no VM launch, device I/O, media read, compiler
execution, Windows boot, GUI/SMP acceptance or persistence test. Full production
performance and runtime acceptance remain separate actual gates.
