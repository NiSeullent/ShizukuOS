# Private replacement-DOS disk preparation

`prepare_replacement.py` constructs a new private DOS replacement candidate.
It does not run a VM, modify the original disk, install a public product, or
prove Windows 98 boot, VMM, PMA, SMP, applications or Microsoft DOS replacement
under Windows. Every corresponding acceptance flag remains false.

The input is an independently reviewed, SHA-pinned JSON profile, using schema
`shizukuos.private-replacement-profile.v1`. The example profile contains
deliberately invalid placeholders and cannot be executed as a real preparation.
Root selects real disk/build/kernel/FreeCOM/template inputs and supplies their
actual hashes and byte lengths. Do not generate a generic PASS receipt.

Required fields are `schema`, `disk`, `boot_template`, `freedos_source`,
`build_receipt`, `build_source_root`, `payloads`. File pins are exactly
`{path, bytes, sha256}` with canonical absolute nonsymlink regular files and
literal nonzero SHA-256. `boot_template` is `{kind, file}`; supported kinds are
`fat12com`, `fat16com`, `fat32lba`. Payloads are `{guest, file}` and use unique
uppercase DOS root 8.3 names. `KERNEL.SYS` and `COMMAND.COM` are required;
original Windows system binaries such as `IO.SYS`, `MSDOS.SYS`, `WIN.COM` and
registry files cannot be overwritten by the payload list.

The recognized producer is the existing `dos16-freedos` build-result schema,
with artifact keys `kernel.sys` and `command.com`, pinned FreeDOS ke2046 commit
`5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3` and FreeCOM commit
`04fc21a9f6792abe9048598e8f2d048b4f6cd0e5`. Kernel/shell artifact hashes and
sizes must match. The actual `user_boot.sources_sha256` and every recorded patch
are read and leased against the selected build source root. This verifies those
recorded source/artifact bindings, not an unrecorded complete kernel compiler
closure or a fresh compiler run. The operator must review the actual producer
receipt and its scope; existing historical receipts are not new execution.

Boot construction is based on the actual [ke2046 SYS source](https://github.com/FDOS/kernel/blob/5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3/sys/sys.c).
The pinned local source tree includes the project's existing branding patches.
The constructor verifies fixed hashes for `sys/sys.c`, the selected actual
`boot.asm`/`boot32lb.asm`, and `magic.mac`. It assembles those exact sources with
NASM into a private temporary 512-byte file and compares every byte against the
declared template. Tool argv and actual executable hashes are recorded; no
shell strings or source-script evaluation are used.

FAT12/16 preserve BPB bytes `[11,62)`; FAT32 preserves `[11,90)`. The resulting
OEM is `FRDOS5.1`, kernel name is `KERNEL.SYS`, load segment is 0060, and actual
BIOS DL capture remains enabled. The BIOS drive BPB is 80h. MBR signature,
single active primary partition, overlap, disk/partition/volume extents,
cluster-count-derived FAT type, FAT capacity, root bounds, hidden sectors,
mirroring and FAT32 flags/version/FSInfo/backup indices are checked. Unsupported
extended/GPT partitions and FAT32 backup layouts are refused. Unlike SYS's
fallback to sector 6, an invalid declared backup is never silently corrected.

The FAT32 primary and declared backup boot sectors are updated in the new disk;
both original sectors and the complete original MBR are retained privately.
Each pre-existing payload member is also saved privately before replacement.
The independent bounded FAT12/16/32 reader detects cycles, crosslinks, invalid
chains and differing mirrored FATs. It hashes all original logical files and
their original directory/LFN metadata. After mcopy, every nonpayload original
entry must remain identical, and every installed payload must read back with
the declared size/hash. Source disk bytes are rehashed before acceptance.

All profile, disk, kernel, shell, receipt, selected upstream source and recorded
build-source inputs use actual Linux read leases with one SIGIO handler.
An existing writer, lease-break request, changed inode/extent/bytes, unsupported
lease filesystem or noncanonical path fails closed. No lease fallback exists.
The final lease-close checkpoints pass before a canonical preparation receipt
is atomically linked into place. Failed private staging remains unaccepted and
cannot be resumed under the same output path.

Choose exactly one copy policy. `reflink` requires successful Linux FICLONE and
never falls back. `full` requires an explicit budget at least the complete disk
logical byte length and reads every source byte into a new independent inode.
Only an actually read chunk containing entirely zero bytes omits data writes:
an explicit seek must reach the expected offset. All other chunks use complete
writes, including short-write retries. The final logical extent is established
with `ftruncate` before `fsync` and the independent full destination hash.
The full-copy receipt records `source_bytes_read`, `zero_bytes_omitted` and
`data_bytes_written`; the last two sum to the complete logical size. No
filesystem hole metadata is consulted, and no sparse-allocation guarantee is
made. The complete logical budget and remaining-byte capacity checks still
apply even to an all-zero source. Destination extent/hash are read back in both
modes. Disk sizes above 64 MiB
are confined to the reserved NAS lane
`/mnt/shizukuos-native-workspace-fada-20261001/fada/replacement`; small synthetic
host controls use private temporary directories. Root allocates and coordinates
real NAS jobs. No large NAS copy is launched by the test suite.
An output inside a Git checkout must be under an explicitly ignored `build/`
directory. Visible source paths are refused before an output directory exists;
all real disk jobs remain in the private NAS lane.

The production guard preserves 17 GiB plus the explicit 1 MiB..1 GiB future
capture budget, remaining copy budget, payload/backups and bounded metadata.
Capacity is checked before and during copying, payload operations and receipt
publication. Neither a low local-space state nor unsupported reflink permits
relaxing that guard. Host tests inject synthetic capacity only to test admission
on small temporary disks; this is not proof of real NAS capacity.

After filling and reviewing an actual private profile, first choose a new output
under the allocated lane and perform input-only validation:

```sh
python3 -B shizukudos/win98_boot/prepare_replacement.py \
  --profile /private/replacement-inputs.json --profile-sha256 ACTUAL_PROFILE_SHA256 \
  --out /mnt/shizukuos-native-workspace-fada-20261001/fada/replacement/NEW_EPOCH \
  --copy-mode full --copy-budget-bytes 2147483648 --capture-budget-bytes 1073741824 \
  --validate-only
```

Input-only validation executes the pinned-source template assembly and reads
the private disk inventory, but creates no owned disk/output directory. Remove
`--validate-only` only for the already authorized, resource-coordinated real
constructor job. `preparation.json` says `PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED`.
All disk/receipt paths, inventories, original boot sectors, original member
backups and Microsoft files stay private, outside source/public ISO/site paths.

Run the bounded host controls:

```sh
python3 -B -W error -m unittest shizukudos/win98_boot/tests/test_prepare_replacement.py -v
```

They construct actual tiny FAT12 and 40 MiB FAT32 synthetic images, execute
mcopy/NASM and real Linux lease controls, verify private backups/independent
copies/member hashes, and refuse malformed geometry/source/output/budget inputs.
Full-copy controls include leading/interior/trailing/all-zero regions, nonzero
chunk-edge bytes, short reads/writes, failed or incorrect seeks, failed or
ignored truncation, premature source EOF, capacity loss and actual lease breaks
at zero-skip/truncation boundaries. A failed truncation in an actual tiny FAT
preparation leaves no accepted receipt or copied disk.
These are filesystem/source-preparation checks; no BIOS, DOS, Windows or VM runs.
