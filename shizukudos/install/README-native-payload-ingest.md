# Private native installer input boundary

`native_payload_ingest.py` exports one **private** prepared native Windows 98
ESP as `ESP.SIM` and a typed `manifest.json`. It never runs DOS, Windows, a
compiler, an installer, or a VM, and it never writes an installation target.
The original licensed Windows files remain private. Do not put this output in
Git, a public ISO, an nginx public directory, or a public source archive.

The exact `shizukuos.native-payload-ingest-request.v1` JSON has these fields:
`schema`, `source_profile`, `constructor_profile`, `replacement_receipt`,
`dos_build_receipt`, `native_build_receipt`, `native_esp`, `native_source_root`,
and `readers`. Every file uses `{path, bytes, sha256}` with a canonical absolute
nonsymlink path and a nonzero literal SHA256. `readers` selects the exact
reviewed `constructor` and `fat32` Python sources. `native_source_root` locates
the source paths recorded by the original native builder; it does not change
that builder's producer epoch or claim a fresh build.

Invocation, only after selecting the actual private receipts and adequate space:

```text
python3 shizukudos/install/native_payload_ingest.py \
  --request /private/selected-request.json --request-sha256 <exact-SHA256> \
  --out /private/fresh-owned-leaf --budget-bytes 2420113408
```

The baseline admits the actual DOS3 ke2046/FreeCOM combined patch order,
C/NASM `WIN31SUPPORT`, the source-profile's normal HIMEMX producer/source map,
the independently constructed 2 GiB private FAT32 disk, observed installed
`WIN.COM`/`SYSTEM.INI`/`SYSTEM/VMM32.VXD`/`IFSHLP.SYS`, and its exact
`shz.foundation=win98` CONFIG/AUTOEXEC with one observed `WIN.COM` invocation.
Observed NLS dependencies are preserved; COUNTRY-only startup is refused.
The exact held source-profile policy functions rederive installed paths and
locale rows from original FAT CONFIG/AUTOEXEC contents before those rows can be
replayed; rebound metadata cannot add a second WIN.COM invocation.
Raw receipts, original/config observations, replacement boot template and
primary/backup VBR, actual native input/source pins, ESP FAT geometry and every
recorded member must agree. It admits only the baseline native input set;
optional VGA/persistence device epochs need a separately reviewed importer.
A Supervisor payload linked into `BOOTX64.EFI` is not invented as an additional
`PAYLOAD.BIN` member.

The producer holds actual Linux read leases on all admitted original sources,
receipts and inputs through export and final full SHA checks. It reads every
ESP byte and preserves its exact 2304 MiB LBA0 superfloppy geometry. Each source
hash/FAT read checks its active original FD, canonical ancestors and the union
SIGIO; all union identities are also checked at phase boundaries/finalization.
Every admitted input still receives a final complete SHA pass. ESP export uses
the active original FD per IO and checks the entire input union at export,
scan, copy and saved-readback boundaries. Each partial write checks its actual
owned FD against the named inode and canonical ancestors; completed writer
identity is frozen and checked around every independent saved-file read.
The 17 GiB floor, owner/mode/link count and exact extent checks remain active.
The saved
sparse file is independently expanded and hashed through a bounded streaming
reader. A fresh 0700 leaf and 0600 files use exclusive creation, fsync and
identity checks. Each reopened output must match its actual completed fsynced
writer inode, not merely later identical bytes. Ancestor namespace checks reject
same-inode symlink aliases. The canonical manifest is published only after original input
lease cleanup succeeds; a later mandatory failure invalidates only its owned
manifest inode and retains unaccepted partial data. The explicit full logical
ESP plus 4 MiB metadata budget and 17 GiB reserve remain required. No external
commands are launched by ingestion.

`tools/shizuku_se_media.py:setup_payload()` now refuses typed private native
manifests, embedded relabeling, private native archive entries and actual
private FAT32 directory members inside a renamed sparse image. Recognized
SHZARC01/SHZSIMG1 contents are inspected independently of filenames, including
nested SYSTEM.ARC, with finite aggregate member/byte/depth bounds. Existing public
`desktop`/`self-test` development payloads remain distinct. This is a refusal
boundary, not a general copyright classifier or final product ISO acceptance.

The output schema is `shizukuos.private-native-install-payload.v1`, status
`PRIVATE_NATIVE_ESP_INPUT_EXPORTED_NOT_INSTALLED`; all installer, target-write,
Windows, application, persistence, SMP and ISO flags are false. Receipt/source
crosslinks do not authenticate an independent compiler tool closure, so that
flag is also false. Installed Windows version, actual native boot and real
Windows runtime remain unverified by this producer.

The own installer still needs runtime access to the selected private source,
a fresh source-bound target GPT/partition FAT layout, correct partition BPB
creation rather than relabeling this superfloppy, exact Supervisor BOOT.INI and
DOS disk import, explicit unique target confirmation, actual target readback
and a real cold boot. BIOS-started native Supervisor support remains a separate
capability; this input exporter does not make direct Kernel64 the product body.

Host controls use synthetic producer receipts and sparse 40/64 MiB FAT32
roundtrip fixtures, plus a separate tiny sparse source for short-I/O controls.
Writer/fsync/unlock/lease-break controls isolate that real custody boundary
with explicitly modeled prior lineage; they do not repeat whole FAT validation.
Only test geometry, modeled producer/HIMEMX bytes and fixture capacity are
substituted; Linux descriptors, leases, FAT parsing, hashes and readback are
real. Repository/source bytes are held before evaluation in bounded host units.
An additional scaling control holds 273 actual tiny source read leases while
comparing 1/8 MiB sparse exports. Source provenance is modeled; source FDs,
full SHA, unrelated late path aliases, output substitution and partial IO are
real. These host timings do not establish 2304 MiB NAS performance.
No genuine Windows file, NAS media image or target disk is consumed by tests.
