This opt-in source candidate observes the SeaBIOS 16-bit read/write bounce path.
Both private profiles use the held corrected completion rules; only the requested
bounce allocation differs (2 KiB or 16 KiB). No current firmware is replaced.

The allocator permanently owns the bounce buffer. The linker places the aligned
224-byte `shz_storage_stats` object in reserved F-segment BIOS data. Its address
comes from each actual `rom.o` symbol table; a reader must use that exact binary
receipt and require full F0000..FFFFF containment, magic `SHZSTAT1`, version1.0,
size224, admitted profile/actual capacity and matching field offsets.

The sole writer is the 16-bit bounce caller. The helper AP never writes these
counters. It publishes an odd sequence before changing observations, then an
even sequence after restoring the caller's pointer/count/LBA. A bounded reader
must read sequence, object, sequence and accept only equal even values also
matching the object's sequence. Sequence uses modulo2^32; a complete sequence
cycle (2^31 requests) during the capture must be excluded. Unexpected reentry
sets flags bit1 and excludes the record from comparisons. Flag bit0 marks any
saturated counter; those counters are lower bounds. Neither flag changes I/O.

Counters distinguish original request blocks/bytes/blocksize, attempted helper
dispatches, full/partial certified completions and normalized errors/rejections.
`chunks` counts calls into the existing helper interface; it does not claim AHCI
issued a hardware command successfully. Completed bytes follow the same
certified counts used for copy/readback, never the stale unchanged error count.
The last LBA is the original request LBA. All numeric counters saturate; the last
request metadata is a value, not a cumulative counter. Histogram buckets are
0,1,2..4,5..8,9..16,17..32,33..64,65+ blocks.
For a zero-block request the original early-return behavior is retained: the
drive is not dereferenced and last blocksize0 means no blocksize observation.

There are no diagnostic prints, clocks, port accesses or additional polling
loops in the statistics helpers. Host controls execute the actual copied
allocation/bounce/statistics functions and compare request/result/copy behavior
with the uninstrumented corrected control. Compiling and host controls do not
prove native memory mapping, lifetime, speed or storage-driver acceleration.
Future native trials must hold source/controller/clock/RAM/disk state equal,
capture both records from separate controlled boots, and retain every failure.

Build only with an explicitly new output under `build/shizukudos`:

```
python3 drivers/shizuku_storage/statistics/build.py --out build/shizukudos/shizuku-storage-statistics-YYYYMMDDTHHMM-v1
```

SeaBIOS source lineage and pinned GNU LGPLv3 terms are retained by the parent
`drivers/shizuku_storage/NOTICE` and each private source copy's COPYING files.
