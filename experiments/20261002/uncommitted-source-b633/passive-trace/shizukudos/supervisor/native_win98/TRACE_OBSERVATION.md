# Passive native boot observations

Actual attempt11 remained in real mode without a terminal exception trace.
Its selector0070 is insufficient to establish a reset or boot loop. The
existing device evidence is a fixed prefix printed once and loses later
events after saturation. This diagnostic proposal fills those gaps without
changing guest execution, reset, A20, IRQ, register, device or input policy.

The proposed Win98-only observer keeps fixed reason counters and a recent
32-entry PIO tail, including numeric controller F0..FF, D1 data and port92
values. It emits at most two paused-VMCS snapshots after domain elapsed60s
and240s, with a separate32KiB total serial budget. The existing exceptional
W98TRACE latch is independent. Raw patterns mean observed requests; they do
not mean a reset occurred or Windows started.

Code/stack/IVT and VGA text reads must stay inside owned RAM or the original
SeaBIOS bytes with current A20 and complete32-bit bounds. Optional hardware
VGA overlays and absent-device windows are unavailable to diagnostics.
Paging translations remain unsupported. Hidden CS/SS bases are observed,
never inferred from selectors. ATA fields are already-owned numeric state;
diagnostics do not call ATA/PIC/KBC I/O or acknowledge an interrupt.

Guest memory code, stack and display text belong only in private actual
native serial evidence. They must never enter public captures or source
reports. Host controls use invented tiny RAM/ATA bytes and model privileged
VMCS/time/serial boundaries, while exercising actual observer and device
implementations. They cannot establish Windows VMM/USER/GDI/Explorer, GUI,
SMP, physical authority or persistence.

At this draft stage no compiler or controls have run. The exact source/tool
held finite cohort, original resource floors and explicit RED/GREEN evidence
will be recorded separately. No actual VM or installed-media test is part of
the author controls; root reviews their immutable launch plan first.
