# Windows compatibility capability inventory — c957

Completed the assigned source inventory slice on
`codex/pma-c957-compat-20261002` in
`/root/Win98-Modern-pma-c957-compat-20261002`.
Baseline inspected: `a648e9baa1c57289d50e58d3380827bd9239bc52`.
Implementation commit: `8c764e98f53d83ea85a02fc7f8b8109638a0fe7b`.
This status follows that implementation commit; its own commit SHA is available
from Git rather than embedded recursively in its contents.

Owned files:

- `ntwrapper/capabilities/manifest.json`
- `ntwrapper/capabilities/validate.py`
- `ntwrapper/capabilities/test_validate.py`
- `ntwrapper/capabilities/README.md`
- `docs/agents/status/windows-compat-c957.md`

No shared core, display, VxD, scheduler, loader, runtime, frozen report or peer
worktree was edited. No new DLL, object fabric, VMM ordinal or compatibility
success stub was introduced.

The machine manifest catalogs all 120 unique requested architectural families.
Six existing providers describe 56 source APIs, including all 25 named NTW32
exports, the object/event core, custom W64 client, VxD dispatch and software/DIB
graphics. A separate 17-API Kernel64 backend slice binds real Ke/Io/Ex/Mm/Ps/Hal
definitions to the existing NTDRV provider resolver and Microsoft x64 ABI.
Each API has calling convention, source, ownership, synchronization, evidence
and limitations; driver examples also record their partial UP IRQL contracts.
Catalog backend references include existing driver, NTDLL and Win64 DLL source.
This is an exemplar inventory, not the full existing backend export inventory.

`frontend_status` measures the requested Windows 98 boundary independently of
`backend_source_status`. Existing backend code is not described as absent just
because its frontend is unsupported or its exports remain uninventoried.
Windows 98/VMM/USER/GDI retain the product desktop and Windows scheduling;
PMA owns backend work. Shizuku Kernel32 remains distinct from Microsoft
KERNEL32.DLL, and Kernel64 remains a backend. Windows-to-Kernel64/PMA positive
evidence and Windows 98 replacement-DOS boot flags are all false.

Validation requires actual symbols/definitions, named exports/routes and masks
(`NTWG=0x3f`, `W64=0x1f`), stable source bindings, evidence anchors and conservative
ownership/synchronization contracts. Unsupported WDDM/D3D/GPU bits cannot be
promoted by changing manifest values. Definitions alone establish no semantic
parity: every API test status is `SOURCE_BOUND`, referenced historical tests
are not executed, and the JSON receipt records exact source hashes.
The VxD thread contract is bounded synchronous single-call serialization on UP;
it makes no claim about a later peer atomic guard or SMP acceptance.

Executed only the approved repository-script commands:

```text
python3 -B -m unittest discover -s ntwrapper/capabilities -p test_validate.py -v
Ran 56 tests in 11.416s
OK

python3 -B ntwrapper/capabilities/validate.py --out build/pma-c957-compat/capabilities.json
PASS: source capability inventory: 120 families, 56 frontend APIs, 17 backend APIs; receipt build/pma-c957-compat/capabilities.json; behavior/native tests not run
```

Both exited 0. The final suite includes mutations for false native-positive
claims, D3D/WDDM promotion, stale/missing source references, comment/prototype
substitution, export/route drift, wrong ABI/stack sizes, driver resolver removal,
false ownership/SMP synchronization and incomplete catalog coverage. New policy
checks were observed failing before their implementation. `git diff --cached
--check` passed before the implementation commit. The receipt is a generated
local build artifact, not a frozen native receipt or committed acceptance report.
Tests write owned temporary fixtures; the report command writes only its
explicit build output. No compiler/build, VxD script, VM, network, service or
client configuration action was performed.

Dependencies: Python 3.9+ and its standard library, the referenced checkout
sources and existing evidence documents. No dependency installation was needed.
Integration must rerun both approved commands against the final combined source
and retain the resulting hashes; peer core/VxD changes were not cherry-picked
into this isolated compatibility tree.

Remaining native work is outside this slice: an actual Windows domain/channel 2
peer; positive VxD-to-Supervisor-to-Kernel64 execution; VMM-owned wait/completion
integration with process exit/restart handling; native USER/GDI modern-app
window/input/audio routing; and Windows 98 boot on the replacement DOS
foundation. The accepted native V9 load/query/reject50/query/close negative gate
at `2026-10-01 09:28 UTC` is retained as an absent-Supervisor boundary, not a
failure to load and not a positive backend result. Existing NTDRV/component
tests, loopback and backend boot results remain separate evidence. Their native
and behavioral regressions were not rerun here because they were not dispatched
or approved in this lane. Expanding the backend export inventory remains useful
follow-up work after this source gate is integrated.
