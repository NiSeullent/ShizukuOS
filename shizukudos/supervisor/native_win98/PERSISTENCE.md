The optional storage component runs in the Supervisor and presents the existing
PIO ATA device to Win98. An absent `W98PERS.BIN` preserves the RAM baseline.
An explicit configuration that fails admission must abort guest launch; it
cannot silently fall back to successful RAM writes.

`w98_persistence_attach_native()` is the entry before guest/AP launch, after
`w98_ata_init()`. Its object is zeroed, page aligned, exclusively owned and
retained inside the Supervisor region. The separate 192-byte configuration
binds one observed PCI BDF, exact virtio vendor/device IDs, all BAR base/size/type
values, the logical 2304MiB ESP and the 2GiB member. The actual preparation and
custody producer must bind those bytes to the owned QEMU device/resource epoch.
Host fixture values provide no physical-device authorization. The PCI function
stays invisible to the guest; the VGA owner retains guest PCI filtering.

The native boundary uses actual CF8/CFC, uncached MMIO and TSC operations. It
checks the retained handoff and CR3 epoch, mirrors the platform's actual memory
map/2MiB caching rule, and restricts every queue/request DMA pointer to the owned
Supervisor region. BAR probing disables I/O, memory decode and bus mastering on
the selected function, restores BARs, and compares the observed sizes to the
configuration. PCI command readback is mandatory. Only that selected function
is reset and programmed. Reset MMIO requires a complete admitted capability map
and verified enabled memory decode; an unmapped zero cannot acknowledge reset.
The startup path must remain on the BSP before other
PCI users/APs run; broader concurrent PCI arbitration has not been implemented.

The transport requires modern VERSION_1, FLUSH and 512-byte BLK_SIZE features,
rejects read-only storage, and negotiates a single eight-entry split queue.
Indirect descriptors, packed rings, event-index, MSI-X, legacy transport and
guest DMA are unused. One synchronous request is in flight, with bounded poll
and TSC deadlines. Metadata admission has a ten-second absolute bound; each
later sector operation and reset has a two-second bound and a finite poll cap.
These bounds do not extend controller/custody deadlines. Completion and reset
acknowledgments are checked against their absolute end before and after
observation, including the final successful acceptance. See the primary
[VIRTIO 1.2 specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
sections 3.1, 4.1 and 5.2 for initialization, PCI transport and block semantics.

The FAT mapper reads existing metadata only. It validates the exact BPB/backup,
FSInfo, both FAT copies, bounded DOS namespace, chain extents and crosslinks.
Duplicate folded 8.3 names and wrong target types are rejected. There is no FAT
allocation, file growth or metadata write. The mapper identifies only
`SHZDOS/DISK.IMG`; sealing copies its already admitted physical extents into the
transport. Raw writes are denied before sealing and outside those sectors.

Each ATA sector WRITE performs the mapped device WRITE and a real virtio FLUSH
before updating its RAM mirror, counters and successful task-file/IRQ state.
Explicit ATA FLUSH also reaches the device. IDENTIFY advertises no volatile
write cache. Missing FLUSH, malformed completion, timeout or device error latches
failure through guest SRST. An uncertain write may already have changed media;
failure reports no success and makes no rollback claim. QEMU must honor flush
with cache.no-flush disabled and exclusively own the fresh writable ESP.

After the guest stops, `w98_persistence_finish()` flushes and resets the device.
The owner retains object/pages until actual reset acknowledgment; failed reset
forbids recycling DMA storage. A fresh controller/device boot is needed for a
new admission. The caller must not release the ATA callback object or backing
ESP while a guest, request or uncertain device remains alive.

Current evidence is actual compiled C against bounded host callback models.
The linked fixture exercises ATA, the real FAT parser, the real split queue,
WRITE/FLUSH ordering and failure latches, using one 512-byte data slot and a
modeled logical2GiB ATA geometry. It executes no valid native PCI/MMIO path.
Primary project sources, runner and GCC are leased before snapshot/compilation
and checked afterward; external cc1/as/ld, standard includes and library closure
are not completely pinned. Freestanding component compilation/linking is not
a complete Supervisor build or actual hardware proof.

Loader blob loading, the native domain's actual call/teardown and source-list
selection still belong to the canonical owner. They are deliberately absent
from this isolated component patch. Actual optional runtime admission, physical
flush correctness, Windows boot, apps, cold-boot persistence and SMP acceptance
are all false until the exact owned native execution and independent restart
readback establish them. Existing default-source and historical host proofs
retain their original epochs and qualifications.
