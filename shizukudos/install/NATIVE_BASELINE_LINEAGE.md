# Live original installed-source lineage connector

`native_baseline_lineage.py` connects independently reviewed private root
configuration to the existing fixed launch-owned baseline observer service.
It never modifies release policy or consumes an installer approval JSON field.

The trusted boundary is root's independently source-admitted private bootstrap.
That bootstrap selects the exact reviewed decision pin outside the installer
request and admits the reviewed connector source into the actual ingester Union
before calling `RootLineageOwner.from_admitted_root(decision_pin, union)`.
Arbitrary code with root privileges can replace Python objects or private
configuration: this module is not a sandbox for a hostile root process.
Neither a caller-selected decision nor its hash alone grants authority.

The decision is a root-owned 0400 regular file under a root-owned 0700 parent,
with literal assignments only. It specifies original installed raw source,
archive, exact disk-only snapshot 7, independently reviewed rederivation record,
and three actual review/export/tool producers. These actual inputs and the
connector source remain on the SAME real FD/RDLK/SIGIO Union through compile;
full SHA readbacks run when admitted and when the owner closes. The configured
rederivation record binds full raw equality and producer roles. It is retained
provenance, never a current guest observation or a serialized capability.
Private fingerprints, paths and decision source stay outside public Git.

Use this module's `provider.Client` class, so exact class identity is retained:

1. The private bootstrap admits reviewed code and constructs the lineage owner.
2. Launch `provider.Client(..., control_request=fixed_request,
   borrowed_launcher=union, owner_unit=actual_delegated_unit)`.
3. Root inspects the current guest screenshot and explicitly allows the fixed
   observer. `client.wait_ready()` arrives only after current nonce observation,
   source/clone readback and owned QEMU reap while retained leases remain live.
4. Within the client context, enter the lineage owner context and call
   `owner.bind(client)`. Source-only clients and arbitrary/saved summaries refuse.
5. Policy's future private hook calls `owner.verify(actual_original_source_pin,
   actual_held_union_entry)`. It performs a fresh service challenge and exact
   compiler FD/full SHA binding. Register `owner.check` as a compiler lifetime
   guard while the compile is active; remove that guard before closing the
   owner. Forced verify belongs before/after admission/build phase boundaries.
6. Close lineage owner (final full SHA) BEFORE `client.finish()` (actual service
   reap), and close the Union only after both. Cancellation/deadline/lease break,
   alias replacement, service exit or reused owner revokes this context.

`verify` returns private evidence for an admission evidence digest only. Saving
that dictionary does not retain approval; the production hook must remain bound
to the live owner. The installer request's source origin must equal the private
original pin; a staged clone/profile hash cannot silently replace that binding.
Root owns the release-policy registration and exact source-profile adaptation.

The only permitted grade is `WINDOWS_ORIGINAL_DOS_INSTALLED_SOURCE`. It says
nothing about ShizukuDOS execution, GOP default display, x64 apps, user key,
commercial license or Second Edition licensing. English OEM media is a separate
Setup input and is not asserted to be ancestor of the recovered Korean archive.
A future physical GOP boot still needs its own current-boot resource issuer.

Validation runs actual Linux Union FD/read leases, SIGIO conflicting-writer,
source alias, owner cancellation/expiry, post-exec peer PID and source-only
service refusal controls. Their provenance data is explicitly a Linux fixture;
none is a genuine Windows grade or a QEMU/Windows execution. A source-only
readback of the actual private root decision likewise issues no Windows grade.
The next positive run requires a new fixed service-owned cold guest observation
and root review; historical successful desktop screenshots are not reusable.
