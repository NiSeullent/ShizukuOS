# Existing wrapper capabilities and frontend boundaries

This inventory connects architectural family names to existing source contracts.
It introduces no DLLs, scheduler, object manager, driver stack, hardware owner,
VMM services, or runtime transport. Windows 98 remains the product OS: VMM owns
Windows scheduling and USER/GDI owns the desktop. Shizuku Kernel32/Kernel64 are
backend domains; Shizuku Kernel32 is distinct from Microsoft's KERNEL32.DLL.

`manifest.json` lists all 120 unique requested families. WIC is listed once,
under graphics, although it also serves media. Names denote architectural
boundaries, not installed binary modules. `binary: null` promises no generated
DLL. Architecture fields are requirements, not measurements that PMA or a native
Windows bridge is already online.

Each catalog entry keeps two independent statuses:

- `frontend_status`: `PARTIAL` when one of the six listed providers supplies a
  bounded source contract, otherwise `UNSUPPORTED` for the requested Windows 98
  frontend boundary. This is not a verdict on its existing backend or on the
  whole Windows API family.
- `backend_source_status`: `PARTIAL` for selected, source-bound backend API
  examples; `SOURCE_PRESENT_UNINVENTORIED` for other referenced existing source;
  `NOT_INVENTORIED` when this slice has no backend inventory. The latter two
  states do not mean missing or unsupported implementation.

The six providers inventory 56 source APIs: the existing object/event core,
all 25 named NTW32 exports, the two VxD C dispatch functions, the software
graphics core, and four application-owned Win98 DIB adapter calls. Per-provider
contracts supply minimum ABI, backend, ownership, synchronization, errors and
evidence references. These inherited fields are expanded for every API in the
receipt. NTW32 uses named stdcall exports with verified stack byte counts; no
stable ordinal is invented. The DIB diagnostic `ntwg98_selftest` is excluded
because it is test infrastructure in a separate source, not a compatibility API.

The separate `backend_apis` array supplies 17 existing Kernel64 NT driver API
examples. It binds definitions to the real `ntdrv_prov.c` ntoskrnl/hal tables and
the NTAPI Microsoft x64 attribute. Each row identifies IRQL, ownership, partial
synchronization and concrete limitations. Examples cover Ke events/spin/DPCs/
timers, Io devices/IRPs/work items, Ex pool/work, Mm MMIO, Ps threads, PnP device
properties and HAL PCI configuration. This is a useful slice of the substantial
existing driver fabric, not an exhaustive inventory of its exports. Existing
NTDLL, loader, registry and Win64 DLL sources are separately referenced as reuse
candidates; they are not declared absent.

Current source advertises software graphics mask `0x3f` and W64 process/console
mask `0x1f`. WDDM miniport, D3D and GPU bits remain explicitly unsupported. The
existing W64 frontend requires caller serialization and its custom handles are
not Win32 handles. Its VxD boundary describes bounded single-call serialization;
it makes no SMP or new scheduling claim.

Run from the repository root after approving repository-script execution:

```text
python3 -B -m unittest discover -s ntwrapper/capabilities -p test_validate.py -v
python3 -B ntwrapper/capabilities/validate.py --out build/pma-c957-compat/capabilities.json
```

The test suite uses owned temporary source fixtures and invokes the validator.
It starts no VM, compiler, repository build script, network connection or
service, and changes no client configuration. The second command explicitly
writes its JSON receipt under `build/`; `--out` cannot target repository source
or historical records. Without `--out`, validation is read-only and emits JSON
to stdout. `-B` prevents Python bytecode cache writes. Only the Python standard
library is required.

The validator rejects unknown schema fields, incomplete family coverage,
unbound/duplicate APIs, invented ordinals, calling-convention mismatches, absent
definitions, export/route drift, capability changes, stale evidence anchors,
source traversal, and paths escaping the checkout. It preserves the conservative
owner/synchronization/status policy. A legitimate contract extension requires
reviewing that policy together with source, tests and fresh evidence.

The receipt hashes the exact referenced source, manifest and validator. This
is a narrow lexical source inventory, not compilation, execution, or proof of
API behavior. A definition and matching export cannot prove semantic parity;
each inherited `test_status` is therefore `SOURCE_BOUND`. Source implementations
still require their existing behavioral/native regressions. Do not count these
inventory checks as Windows API compatibility tests or a support percentage.
Historical references are recorded, never rerun or rewritten by this tool.
`RECORDED_BACKEND_COMPONENT` refers to existing component evidence, not a new
Windows 98 frontend test. `RECORDED_NATIVE_NEGATIVE` preserves the accepted native
V9 load/query/reject50/query/close boundary and its explicit absent-Supervisor
scope. Positive Windows-to-Kernel64/PMA execution and replacement-DOS boot flags
remain false. A fresh receipt must match the source hashes of the artifacts being
assessed; an older report's existence establishes no current acceptance.

The next native gates remain an actual Windows domain/channel 2 peer, positive
VxD-to-Supervisor-to-Kernel64 execution, VMM-owned waits/completions and process
exit/restart handling, a native USER/GDI modern-app window/input/audio bridge,
and actual Windows 98 boot on the replacement DOS foundation. Component boot,
loopback and backend tests do not satisfy those gates.

New inventory code and data follow the repository's GPL-2.0-only license; no
external implementation is incorporated.
