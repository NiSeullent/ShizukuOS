# ShizukuDOS 10 - Kernel64 storage: NVMe and SD/eMMC

Status of the storage track (agent S1). NVMe and eMMC/SD are the core storage of Kernel64; AHCI (agent D1,
`ahci_blk.c`) stays as the legacy path. Everything here runs in the **standalone profile** (`KERNEL64S.BIN`, QEMU
`-kernel` stub, no Supervisor). Under the Supervisor no PCI device is passed through, so the drivers compile to
"no device" and the registry stays empty.

Evidence words as in `BASELINE.md`: `SOURCE`, `BUILT`, `HOST_TESTED`, `GUEST_RUN`. All guest runs below are
**QEMU 8.2.2 TCG** in a KVM-less container shared with other jobs (4 cores). Nothing was run on real hardware or
under KVM; nothing here claims either.

## 1. What exists

| Piece | File | Evidence |
| --- | --- | --- |
| Block registry (D1's API, extended) | `kernel64/blk.h`, `blk.c` | GUEST_RUN |
| MBR/EBR/GPT scanner (header + array CRC, backup header, EBR chains) | `kernel64/blk_part.c` | HOST_TESTED (32 checks, ASan/UBSan), GUEST_RUN |
| PCI capabilities, MSI-X, shared INTx | `kernel64/pci.c`, `pci.h` | GUEST_RUN |
| NVMe driver | `kernel64/nvme.c` | GUEST_RUN |
| SDHCI driver, SD cards | `kernel64/sdhci.c` | GUEST_RUN, HOST_TESTED |
| SDHCI driver, eMMC | `kernel64/sdhci.c` | HOST_TESTED only (see 4.3) |
| Raw block system calls 0xf0-0xf6 | `kernel64/sysblk.c` | GUEST_RUN |
| User-mode tests | `win64/tests/t_blk_raw.c`, `t_blk_perf.c`, `blktest.h` | GUEST_RUN |
| Guest runner with host-side verification | `tests/run_k64_storage.py` | GUEST_RUN |
| Host driver test (register-level SDHCI + SD/eMMC model) | `tests/test_sdhci.c`, `run_sdhci_host.py` | HOST_TESTED (66 checks) |

## 2. Block layer (`blk.h`)

D1's `blk_dev_t` API is kept unchanged (`name, sector_size, sectors, start_lba, parent, flags, mbr_type,
type_guid[16], index, read, write, flush, read_async, priv, counters`; `blk_register/blk_find/blk_first/blk_count`,
`blk_read/blk_write/blk_flush`, `blk_scan_partitions`, drivers started from `disk_init()`). Additions are optional
fields at the end of the struct, so D1's `ahci_blk.c`/`disk.c`/`fat32.c` compile and run as before:

* `write_async` (same contract as `read_async`: queued = 0, `done(ctx, status)` later from a driver thread, never
  from an interrupt handler), `discard` (TRIM), `control` (`BLK_CTL_*`: reset, timeout self-test, completion mode,
  statistics, timeout, SDHCI transfer mode, error self-test);
* metadata: `driver`, `irq_mode` (live), `model`, `serial`, `queue_depth`, `max_sectors`, op/flush/discard/error
  counters, `reg_index`, and for partitions `part_scheme`, `part_name` (GPT), for disks `scan_notes/scan_result`;
* `blk_read_async`/`blk_write_async`/`blk_discard`/`blk_control`: bounds checks and partition offsets are done in the
  layer; without a driver async entry point the call completes synchronously and `done()` runs before it returns;
* `blk_get(index)`, `blk_whole(dev)`, `blk_kva_to_pa(kva)` (walks the kernel page tables, 4 KiB/2 MiB/1 GiB pages);
* flags `BLK_F_MOUNTED` (set by `disk.c` on the device D: lives on), `BLK_F_FLUSH`, `BLK_F_DISCARD`.

`blk_scan_partitions()` now uses the host-tested `blk_part.c` scanner (protective MBR, primary GPT header with header
and entry-array CRC-32, MyLBA and geometry checks, backup header at the last LBA when the primary is bad, MBR primaries,
EBR chain with loop detection) behind D1's superfloppy check, for 512- and 4096-byte sectors. Partitions are named
`<disk>p<n>` with n in scan order (GPT entries, then MBR primaries, then logicals).

Device names: `nvme<c>n<nsid>` (one per active namespace), `mmcblk<n>` (one per SDHCI slot with a card).

## 3. NVMe (`nvme.c`)

Bring-up: PCI class 01:08:02, BAR0 mapped uncached. `CAP` (MQES, DSTRD, TO, CSS, MPSMIN) -> `CC.EN=0`, wait
`CSTS.RDY=0` (CAP.TO) -> 64-entry admin SQ/CQ (`AQA/ASQ/ACQ`) -> `CC` = 4 KiB pages, 64-byte SQE, 16-byte CQE, NVM
command set, `EN` -> wait `CSTS.RDY=1` (or CFS) -> IDENTIFY controller (model, serial, firmware, MDTS, NN, ONCS, VWC) ->
Set Features "number of queues" -> interrupt setup -> Create I/O CQ (IV 1, IEN) and I/O SQ -> IDENTIFY active
namespace list (CNS 2) -> IDENTIFY each namespace: NSZE, FLBAS -> LBA format -> LBADS (512 and 4096 used by the
tests; formats with metadata are skipped).

I/O path: one 64-entry I/O queue pair (one physically contiguous page each), 32 command slots (CID = slot), each slot
with its own PRP-list page (so one command moves up to min(MDTS, 1 MiB); QEMU's MDTS is 512 KiB) and a bounce page.
Requests larger than one command are split and all pieces are submitted before the first is waited for; concurrent
callers and `read_async`/`write_async` share the slots, so **queue depth > 1** (the tests see 32 commands in flight).
PRP1/PRP2/PRP lists are built per page with `blk_kva_to_pa`. A buffer that is not 4-byte aligned (PRP1 cannot
describe it; D1's FAT32 reader reads whole sectors to odd offsets of heap buffers) is bounced, a page per command,
still pipelined - found by running T_DISK.EXE against a FAT32 volume on NVMe.

Interrupts: **QEMU's NVMe function has MSI-X (65 entries) and the driver uses it**: entry 0 (admin CQ) and entry 1
(I/O CQ) are bound to vectors 0x40/0x41 through the new `pci_msix_*` API; the handler reaps both CQs and posts the
waiters' semaphores. Without MSI-X the driver uses INTx on the (possibly shared, level-triggered) legacy line through
`pci_intx_attach()`, armed at the first request made with interrupts on because the 8259 is programmed after
`disk_init()`; without either it polls. `BLK_CTL_IRQ_MODE` switches MSI-X / INTx / polling live; T_BLK_RAW reads the
same 4 MiB in each mode and gets the same data (INTx: 6-8 interrupts, polling: 0, MSI-X again: 7-8). Waiters sleep in
10 ms slices and reap themselves between slices, so a lost interrupt costs latency, not a hang. Before the scheduler
runs (`disk_init()`, interrupts off) everything is polled with TSC deadlines; the TSC rate is measured once against
PIT channel 2 (`blk_tsc_per_ms()`), because under QEMU TCG it runs at the host's rate (2.1 GHz here), not at the
nominal 1 GHz the boot stub reports. Async completions run their callback on the `nvme` worker thread, which sleeps
without a timeout while no async command is outstanding.

Errors and recovery: a non-zero CQE status fails the request and is logged with SCT/SC. A command outstanding longer
than the timeout (5 s default, `BLK_CTL_SET_TIMEOUT_MS`) triggers a **controller reset**: `CC.EN=0`, rebuild admin and
I/O queues, re-enable interrupts, resubmit every outstanding command from its saved SQE; after 2 resets the command is
failed, and a controller that does not come back is marked dead (every request fails fast). The async worker applies
the same timeout to async commands. `BLK_CTL_TIMEOUT_TEST` exercises this for real: it places a READ in the SQ
without writing the doorbell, so the controller never sees it; the driver times out (300 ms in the test), resets,
resubmits and the data must equal a normal read. `BLK_CTL_ERROR_TEST` sends a READ past the namespace end and expects
LBA Out of Range (QEMU returns 0x4080: SC 80h with DNR), then a normal read on the same queue.

FLUSH is sent when VWC reports a volatile write cache (QEMU: yes); DSM deallocate (TRIM) when ONCS has DSM (QEMU: yes;
with `discard=unmap` the backend punches a hole and the guest reads zeros back).

Limits: one I/O queue pair, no metadata/protection-information formats, no SGLs, no namespace management, no
multipath/reservations, no CMB/HMB, no APST/power states, no hot plug.

## 4. SD and eMMC over SDHCI (`sdhci.c`)

### 4.1 Host

PCI class 08:05 (QEMU `sdhci-pci`, 1b36:0007, SDHCI 2.00, one slot). Software reset (all), capabilities (base clock,
voltages, ADMA2, SDMA), bus power at the highest supported voltage, SD clock <= 400 kHz for identification, then at
most 25 MHz (SD) / 26 MHz (eMMC) with the 2.00 power-of-two divider or the 3.00 10-bit divider (QEMU: 52 MHz base,
2.00 divider -> 13 MHz), all normal and error status bits enabled, data timeout at its maximum.

### 4.2 Cards and transfers

SD identification: CMD0 -> CMD8(0x1AA) [R7 echo = SD 2.00+] -> CMD55+ACMD41 (HCS when CMD8 answered) until the OCR
busy bit -> CMD2 (CID) -> CMD3 (card publishes the RCA) -> CMD9 (CSD) -> CMD7 -> ACMD6 (4-bit bus) -> CMD16 512 ->
ACMD51 (SCR). Capacity from CSD 1.0 (SDSC, byte addressed): (C_SIZE+1) * 2^(C_SIZE_MULT+2) * 2^READ_BL_LEN, or CSD
2.0 (SDHC/SDXC, block addressed, OCR.CCS): (C_SIZE+1) * 512 KiB. The guest runner uses a 128 MiB SDSC card and a
4 GiB SDHC card (QEMU makes a card SDHC above 2 GiB and wants power-of-two sizes).

Data: CMD17/CMD18 read, CMD24/CMD25 write, 512-byte blocks, multi-block with Auto CMD12, up to 1 MiB per command.
**Transport: ADMA2 with 32-bit descriptors** (one per physically contiguous run, runs merged up to 32 KiB, table in one
page) whenever the controller has ADMA2 and the buffer is 4-byte aligned below 4 GiB; otherwise **PIO** through the
buffer data port. SDMA is not used. `BLK_CTL_XFER_MODE` forces PIO; T_BLK_RAW reads 512 KiB both ways and writes
through PIO. After every data command the R1 card status error bits are checked (QEMU reports an out-of-range address
there and still runs the data phase with zeros, so this check is what catches it); after a write CMD13 is polled until
the card is ready for data again.

Register traffic per command is kept small (status cleared with one 32-bit write, block size + count and transfer
mode + command written as 32-bit pairs, host control shadowed): every access is a VM exit under a hypervisor.
Completion is **polled** (yielding to other threads when the scheduler runs); the interrupt signal enables stay 0 and
no INTx line is claimed: QEMU completes an SDHCI command inside the register write and an ADMA2 table in steps of
5 descriptors 100 ns apart, so an interrupt would only add latency. The SD queue depth is 1 (the bus is serial);
batches fall back to synchronous calls through the block layer.

Errors: a controller error status (command timeout/CRC/end-bit/index, data timeout/CRC/end-bit, Auto CMD12, ADMA) or
an R1 error bit fails the command; the driver resets the CMD/DAT lines, sends CMD12 when a multi-block transfer was
open, brings the card back to the transfer state with CMD13/CMD12 and retries once (not for address errors).
`BLK_CTL_ERROR_TEST` reads past the end of the card: QEMU answers OUT_OF_RANGE or ADDRESS_ERROR in R1 and the card
must be back in the transfer state afterwards.

### 4.3 eMMC

No answer to CMD55 selects the MMC branch: CMD0 -> CMD1(0x40FF8080, sector mode) until busy=1 -> CMD2 -> CMD3 with a
host-assigned RCA 1 -> CMD9 -> CMD7 -> CMD8 SEND_EXT_CSD (512 bytes) -> SWITCH (BUS_WIDTH = 4 bit, SWITCH_ERROR
checked through CMD13) -> CMD16. Capacity from EXT_CSD SEC_COUNT in sector mode (else the CSD formula).

**QEMU 8.2 has no eMMC model** (`-device help` lists no `emmc`; later QEMU releases add one), so the eMMC branch is not exercised by any
guest run. It is exercised by `tests/run_sdhci_host.py`: `sdhci.c` compiled unchanged against the real kernel headers
with a register-level SDHCI 3.00 model and three card models written from the SD 2.00 and JEDEC eMMC specifications
(SD 1.x SDSC without CMD8, SD 2.00 SDHC, eMMC 8 GiB in sector mode whose CSD claims 1 GiB). 66 checks under ASan/UBSan:
identification paths, capacities, byte vs block addressing, ADMA2 over physically discontiguous pages (the test's page
map is a permutation), PIO both directions, Auto CMD12, one injected data CRC error recovered by the retry, two
failing the request, out-of-range recovery. This checks the driver against my reading of the specs, not against a
real eMMC part.

Limits: one slot per controller, no UHS-I/HS200/HS400 tuning, no CMD23, no SDIO, no card-detect hot plug, no eMMC
boot/RPMB partitions, no write-protect groups; SD high-speed (CMD6 switch function) is not requested.

## 5. PCI interrupt API (`pci.h`)

* `pci_find_cap(dev, id)`: capability list walk.
* `pci_msix_init(dev, &m)`: finds the MSI-X capability, maps table and PBA (uncached), masks every entry.
* `pci_msix_bind(&m, entry, fn, ctx)`: takes a free IDT vector (0x40-0xef), programs the entry (local APIC of the boot
  CPU, fixed delivery, edge), unmasks it; returns the vector. The first bind software-enables the local APIC (SVR,
  spurious vector 0xff) so it accepts MSI writes; LINT0 stays ExtINT, so the 8259 timer and INTx devices are unchanged.
  The trampoline calls `fn(ctx)` with interrupts off and writes the local APIC EOI. (arch.c also sends its 8259 EOI
  for every device vector; no 8259 interrupt is in service while a handler runs, so that non-specific EOI is a no-op.)
* `pci_msix_enable(&m, on)` (also sets/clears the INTx disable bit), `pci_msix_mask`, `pci_intx_disable`.
* `pci_intx_attach/detach(dev, fn, ctx)`: up to four handlers per legacy line behind one trampoline (lines are
  level-triggered and shared: each handler checks its own device); `pci_intx_ready()` tells whether the 8259 is
  programmed yet. `pci_irq_count(vector)` for statistics. Drivers that call `irq_register()` directly (rtl8139) are
  not chained; a line used both ways would lose one handler.

## 6. Raw block system calls (`sysblk.c`, range 0xf0-0xff)

| # | Call | Arguments |
| --- | --- | --- |
| 0xf0 | `NtShzBlkQuery` | index, `struct shz_blk_info *` (264 bytes, `blktest.h`), length, returned length |
| 0xf1 | `NtShzBlkRead` | index, LBA, sectors, user buffer |
| 0xf2 | `NtShzBlkWrite` | index, LBA, sectors, user buffer |
| 0xf3 | `NtShzBlkFlush` | index |
| 0xf4 | `NtShzBlkBatch` | index, `struct shz_blk_io[]` (op, count, LBA, buffer, status), n <= 64, total <= 1 MiB: all issued before the first is waited for |
| 0xf5 | `NtShzBlkControl` | index, `BLK_CTL_*`, argument, `ULONG64 out[4]` |
| 0xf6 | `NtShzBlkDiscard` | index, LBA, sectors |

Data moves through four 1 MiB kernel windows (page-allocator pages mapped once at DIRECT_MAP + 256 GiB, inside the
direct map's PML4 slot so every address space sees them). Raw writes to a device that a file system has mounted (the
device, its disk or one of its partitions) are refused with `STATUS_ACCESS_DENIED`. This is a test and bring-up
interface: any process may read or write unmounted devices. Shared-file hooks: `ntsys.h` (the list and `SYS_MAX`
0x100), `sysext.c` (one routing line and the weak `sys_ext_blk`).

## 7. Tests and results

```
python3 shizukudos/kbuild.py && python3 shizukudos/win64/build.py
python3 shizukudos/tests/run_blk_part_host.py          # partition scanner, host
python3 shizukudos/tests/run_sdhci_host.py             # SD/eMMC driver against the register model, host
python3 shizukudos/tests/run_k64_storage.py            # guest: NVMe + 2 SD cards, host-side verification
python3 shizukudos/tests/run_k64_standalone.py         # guest: no storage devices, T_BLK_* print SKIP
```

`run_k64_storage.py` builds its images from fixed seeds every run and attaches them writable:

| Device | Image | Table |
| --- | --- | --- |
| `nvme0n1` | 256 MiB, 512-byte LBAs, random content | GPT, 3 partitions |
| `nvme0n2` | 64 MiB, **4096-byte LBAs** | MBR: 2 primaries + extended with 2 logicals (EBR chain) |
| `nvme0n3` | 256 MiB FAT32 superfloppy (the volume of `run_k64_disk.py`) | none: mounted as D:\ |
| `mmcblk0` | 128 MiB SDSC card (CSD 1.0) | MBR, 2 partitions |
| `mmcblk1` | 4 GiB SDHC card (CSD 2.0), sparse | GPT, 2 partitions |

The host checks the device and partition list against the tables it wrote; replays the serial log in order on a model
of every image (each guest write `BLK-W` is applied with the same pattern generator after checking the guest's CRC of
it; each guest read `BLK-CRC` - whole-device, partition, random 64 KiB ranges - must equal the model at that moment);
**compares every image file with its model after QEMU exits** (all data extents: every guest write landed exactly
where it should, nothing else changed); checks MSI-X/INTx/poll, queue depth, the timeout -> reset path, both error
paths, TRIM, PIO vs ADMA2, SDSC/SDHC capacities, three threads reading at once, the refused raw write to the mounted
namespace, and runs D1's T_DISK checks against D:\ on NVMe. All checks of `run_k64_standalone.py` must pass too.

### 7.1 Results (commit b0447ff, QEMU 8.2.2 TCG, shared 4-core container, 2026-09-29)

| Run | Result |
| --- | --- |
| `run_blk_part_host.py` | PASS, 32 checks |
| `run_sdhci_host.py` | PASS, 66 checks (SDSC 1.x, SDHC, eMMC models) |
| `run_k64_storage.py` #1 / #2 | **PASS / PASS**, 43 checks each, QEMU 112 s / 130 s; 81 guest writes (97 MiB) and 72 guest CRC ranges replayed per run, 5 image files equal to their models |
| `run_k64_standalone.py` #1 / #2 | **PASS / PASS** (T_BLK_RAW/T_BLK_PERF print SKIP: no NVMe/SDHCI devices) |
| `run_k64_disk.py` (D1's AHCI runner) | PASS (T_BLK_* list `ahci0` and SKIP) |

Flake seen during this work, not caused by storage code: T_NET_LOOP.EXE failed once in an earlier storage run ("a
socket with a full send buffer is not writable", a 20 ms select window on loopback) and once in a D1 disk run ("no
physical page leak across 2 socket rounds: 63381 -> 63372"); in the disk run no storage driver found a device and no
block system call moved data. Both runners passed on the next attempt; the flake is tracked separately.

Driver results reported by the guest in both storage runs: NVMe completion by MSI-X (vectors 0x40/0x41), identical data
with INTx (7-8 interrupts per 4 MiB), polling (0 interrupts) and MSI-X again; 32 commands in flight; the lost-doorbell
READ timed out after 300 ms, one controller reset, the command was resubmitted and returned the right data (302-305 ms
total); READ past the end -> status 0x4080 on both namespaces; TRIM read back zeros (backend `discard=unmap`); SD read
past the end -> R1 0x40000900 (SDSC, ADDRESS_ERROR) / 0x80000900 (SDHC, OUT_OF_RANGE), card back in transfer state;
PIO and ADMA2 reads equal; TSC measured at 2.10 GHz against the PIT.

### 7.2 Throughput (T_BLK_PERF.EXE, user mode through the raw system calls, the two final runs)

Measured with the guest's 1 ms timer ticks; sequential in 1 MiB calls (the NVMe driver splits each into two 512 KiB
commands in flight), random reads uniformly over the first 64 MiB. These are **QEMU TCG numbers on a loaded shared
host**: they measure the emulator and this kernel's software path, not any storage hardware, and vary run to run.

| Device | seq read 64 MiB | seq write | 4 KiB rand read QD1 | 4 KiB rand read QD32 |
| --- | --- | --- | --- | --- |
| `nvme0n1` (NVMe, 512 B LBA) | 184 / 275 MiB/s | 132 / 129 MiB/s (64 MiB) | 2674 / 2960 IOPS | 15876 / 18044 IOPS |
| `nvme0n3` (NVMe, holds D:, read-only here) | 150 / 225 MiB/s | - (mounted) | 1264 / 1399 IOPS | 21333 / 13086 IOPS |
| `mmcblk0` (SDSC over SDHCI, ADMA2) | 151 / 156 MiB/s | 152 / 137 MiB/s (16 MiB) | 1008 / 972 IOPS | 1127 / 1088 IOPS |
| `mmcblk1` (SDHC over SDHCI, ADMA2) | 151 / 146 MiB/s | 142 / 127 MiB/s (16 MiB) | 965 / 959 IOPS | 1136 / 1307 IOPS |

Where the time goes. Measured: TSC probes around `blk_read()` in a scratch build (not committed) put a 4 KiB NVMe
read at about 0.3 ms and a 4 KiB SD read at about 1.2 ms before the SDHCI register-traffic reduction; QD32 SD batches
now take 0.75-0.9 ms per request. Explained from the code: a synchronous NVMe request sleeps on its slot semaphore and
the MSI-X handler posts it, but Kernel64's idle loop (`sti; hlt`) does not yield after an interrupt, so the woken
thread runs at the next 1 ms timer tick unless the completion arrived before it went to sleep - that, not the device,
bounds NVMe QD1 at a few thousand IOPS, while QD32 batches do not wait per command. An SD request is a dozen emulated
register accesses (each takes QEMU's global lock under TCG) plus QEMU's SD card model moving the data a 512-byte block
at a time; the SD bus is serial, so QD32 cannot overlap commands and lands near QD1.

## 8. Known limits and follow-ups

* eMMC is verified only against the host register model; a QEMU with an `emmc` device (or hardware) would be the next
  check. SD high-speed / UHS modes, CMD23 and SDIO are not implemented.
* NVMe: one I/O queue pair and one CPU; no multi-queue, no metadata/PI, no SGLs, no namespace management.
* Interrupt-driven SD completion (INTx) is not used; polling is the design choice for QEMU, and would need revisiting
  on hardware with slow cards.
* Raw block system calls let any process write unmounted devices (test interface). D: is the only mounted file system
  and it is read-only (D1's FAT32 reader).
* Scheduler latency above: a one-line change in `sched.c` (yield after `hlt`) is proposed separately; it is not part
  of this track.
* Nothing here ran under KVM or on hardware; MSI-X under KVM's in-kernel LAPIC and a real 8259/IO-APIC mix is untested.
