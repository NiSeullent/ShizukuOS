# Private FAT32 disk member insertion

The native assembler retains its new 2,304 MiB ESP, formatter, directories,
ordinary boot files and small-member `mcopy` producers. It inserts the private
`SHZDOS/DISK.IMG` last. Both the full ESP preparation budget and the retained
17 GiB filesystem floor remain required; sparse writes promise no particular
filesystem allocation or NAS throughput.

Only a new assembler-owned ESP is supported. The worker parses its real LBA0
superfloppy BPB, true FAT32 cluster count, both mirrored FATs, identical backup
VBR, and primary/backup FSInfo. It inventories the fresh short-name directory
tree, rejects duplicate/deleted/LFN/cyclic/crosslinked/orphan allocations,
requires existing unique `SHZDOS`, absent `DISK.IMG`, enough free clusters and
a zero directory entry with a preserved following terminator. It does not
extend directories or edit arbitrary existing media.

Every source byte is read and hashed from one actual read-leased descriptor.
The worker alone opens the source/request and the exclusive write-leased ESP;
a single SIGIO registry rejects lease breaks and identity/path drift. The
parent passes its held, read-leased helper source FD and one anonymous metadata
pipe write FD. No source, ESP or request data FD is inherited. A small standard
library bootstrap reads and checks those exact bytes before compiling them
with the declared filename. No mutable helper pathname is executed, no data
file description is shared, and importing frozen runtime guards requires no sibling
packer. The worker is a child with the existing 120-second command deadline.

All file clusters are allocated in FAT32, including logically zero data.
Positional writes omit only actually all-zero source chunks, after reading the
corresponding destination region as zero. No hole/extent metadata or
`SEEK_DATA` substitutes for source reads. Nonzero chunks are fully written,
including short-write handling; complete FAT copies preserve their high
reserved bits. Both FSInfo free counts and next-free hints are recomputed.
The exact short directory entry is written last after metadata readback.
Failures preserve private, unaccepted output; it cannot be reused as a fresh
ESP. EOF, I/O, fsync, lease, unlock, close and timeout errors are failures.

Actual consecutive FAT clusters are mapped into source ranges of at most
1 MiB; mixed ranges keep 4 KiB zero-write granularity. Entirely zero ranges
avoid a source syscall per FAT cluster while still reading all source bytes
and checking every omitted destination byte as zero.

The worker verifies the complete member and ESP hashes under its lease. Its
fresh result binds the exact request, executed helper, source identities,
result inode, final ESP identity/hash and byte accounting. After file/directory
fsync and every mandatory lease/unlock/close check, the child sends the exact
saved result-byte SHA/extent through its anonymous pipe, in one packet no larger
than 512 bytes with actual PIPE_BUF capacity checked. Parent admission pins the
result against this producer-returned record. It requires exact successful
child exit/reaping, a bounded packet and EOF under the remaining original
120-second child deadline. Empty/short/extra/flood/unclosed returns fail; result
path self-hashing provides no authority. Parent then independently streams
`mtype` with the unchanged
120-second deadline to check the full member byte count/SHA and rechecks every
earlier boot member. Ordinary full-ESP hashing and source-before/after gates
remain required by the final builder receipt.

Host tests use real `mkfs.vfat`, `mmd`, `mcopy`, `mtype`, Linux leases and tiny
private FAT32 fixtures. Only filesystem capacity is explicitly modeled at
the test boundary so the production 17 GiB policy is unchanged. The authorized
test lane measures allocated bytes (64 MiB maximum), records logical fixture
extents separately, and requires real host/filesystem headroom of 6 GiB plus
the team's pending 160 MiB before execution. Task units retain 1 GiB MemoryHigh,
1280 MiB MemoryMax, 64 tasks, a 120-second runtime and umask 0077.

This is a private packaging optimization. Host fixture success provides no
Windows, replacement DOS, native application, GUI or cold-boot acceptance.
No Microsoft media or private ESP is public source/distribution content.
