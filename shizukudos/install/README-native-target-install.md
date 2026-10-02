# Private native Win98 target installer boundary

`setup_run_native` in `win64/setup/native_install.c` is a separate versioned C entry. It consumes the previously
admitted private `shizukuos.private-native-install-payload.v1` manifest and
`SHZSIMG1` export. Legacy `plat_t`, `setup_run`, answer files and development
media defaults retain their existing ABI. Native success means actual target
partition bytes and GPT were read back. It does not prove a boot.

The native path validates the full held manifest and raw SIM SHA, bounded and
ordered sparse table, expanded FAT32 geometry, primary/backup VBR, the actual
FSInfo pair, all eight pinned native members, Supervisor BOOT.INI, and native
Win98 config. It computes both complete original and relocated image hashes
before the first destructive target operation. Only the hidden-sector DWORD
in each observed VBR may change. Backup and FSInfo offsets come from the BPB;
valid FSInfo copies may differ. Original input bytes remain unchanged. The
producer exports 2304 MiB; core admits 32 MiB through 4 GiB only when exact
manifest extent and true FAT32 geometry pass. The selected pure helper may
apply a tighter bound. No fixture-only production mode exists.

Exactly one reviewed whole target, exact `ERASE`, 512-byte geometry and enough
space for the complete image and both GPT tables are required. The provider
must independently prove source backing wholes, boot/current-system whole
exclusions, generation and exclusive write ownership. Missing or unknown
authority refuses before target writes. Names, serials, JSON/INI flags and
array indices cannot supply that authority. Enumeration failures, duplicate
whole serials, case aliases, partitions and read-only targets refuse.

`native_setup_ops_v1` in `win64/setup/native_install.h` is the provider contract.
It retains checked source handles and checked SHA operations, and supplies
review/claim/check/release with mandatory failure reporting. Matched native
`plat_t` disk callbacks must atomically validate the retained claim in the
actual storage backend at every I/O; a separate check followed by an unrelated
legacy raw-write syscall is insufficient. Core checks the source/target union
and immutable overlay plan before and after every sector call and flush.
The provider must retain unresolved underlying I/O rather than releasing
exclusive authority after a failed wait.

The pure adapter takes four actual 512-byte snapshots: primary VBR, backup
VBR, primary FSInfo and backup FSInfo, plus source extent and exact selected
target interval. Core independently bounds both four-byte overlays and freezes
all plan bytes. The c957 helper is separately owned and has not been adopted
by this branch; host controls explicitly model its callback. Kernel64 source
backing/boot provenance and exclusive target provider are also absent here.

The development command is:

```text
SHZSETUP.EXE /native manifest.json /sim ESP.SIM /manifest-sha256 <64 lowercase hex> /target <name> /serial <serial> /sectors <count> /confirm ERASE
```

Its current guest provider is NULL, so it clearly refuses before opening input
files or enumerating/writing devices. The final runtime importer/UI must
automatically obtain the admitted manifest pin and review the full target;
users should not have to type a hash. A command-line hash is not proof of
previous genuine DOS3/Win98 producer admission.

Installation writes one ESP at LBA 2048, including every logical zero byte,
then flushes and independently reads the entire partition against the
precomputed relocated hash. Original raw inputs are fully rehashed before
GPT publication. Backup table/header and primary table/header precede the
protective MBR; every GPT byte and both CRCs are independently read back.
This native branch provides UEFI Supervisor fallback only. It adds no BIOS
boot code, hybrid MBR, legacy boot attribute or alternate Kernel64 root.
Failures after writes retain partial, unaccepted target contents; no rollback
or clean shutdown is inferred. Checked source close and claim release are
required even after data verification, and their failures reject success.

The host suite uses true 34 MiB FAT32, derived backup sector 9/FSInfo sector 2,
valid unequal FSInfo copies and fresh regular target files. Prior DOS3/native
producer lineage, physical device roles/randomness and the pure peer callback
are explicitly modeled. Linux read/write leases, global SIGIO break refusal,
FD/path/ancestor identity, full SHA, actual FAT contents, sector I/O, fsync and
GPT/partition byte readback are real. This is not production-2304MiB timing,
physical-device authority, guest runtime or actual Windows acceptance.

An official public ISO must boot the project-owned installer and import
user-provided genuine Windows input privately. This branch neither bundles
Microsoft files nor relaxes the public private-SIM refusal boundary. Runtime
user-media import, the real Kernel64 provider, adopted pure helper, actual
native boot, persistence and final installer/ISO acceptance remain separate
required work. All Windows/VM/apps/cold-boot/SMP/ISO result fields stay false.
