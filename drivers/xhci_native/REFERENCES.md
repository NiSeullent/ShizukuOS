# Source provenance

All files in this directory are independently authored project implementation
under GPL-2.0-only. No Linux, BSD, ReactOS, QEMU, OSDev example, vendor driver,
DDK library or other external implementation was copied or linked. The model
and callback API were designed here; implementation code from other projects
was not consulted for this xHCI slice. Builds incorporate no external documents.

Primary interface reference consulted on 2026-09-27:

[Intel xHCI requirements specification revision 1.2b, document 625472](https://cdrdv2-public.intel.com/625472/625472_xHCI_Rev1_2b.pdf).

The public Intel document establishes controller initialization and polling
(4.2), No Op commands (4.6.2), command/event rings (4.9), register access ordering
(5.1), capability and operational registers (5.3–5.4), event-ring registers
(5.5), completion and port-event formats (6.4), and legacy ownership (7.1).
In particular, polling is permitted without interrupts; zero enabled slots is
valid; 32-bit hosts write supported 64-bit address fields low DWORD first;
legacy semaphores permit independent byte accesses. Link TRBs and event rings
use distinct wrap mechanisms. The ERDP contract names the last evaluated event.

The supported policy is deliberately narrower: no scratchpads, USB devices,
endpoints, transfers, interrupt delivery, suspend/resume, virtualization or vendor
commands. Host test success is not hardware conformance or a certification.
Toolchain versions and source/output hashes are generated into
`build/host-tests.json`; any native binding must add its own execution evidence.
