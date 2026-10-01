# Private installed-Windows launch profile

`win98_source_profile.py` observes a private installed FAT source and produces a
profile consumed by `../win98_boot/prepare_replacement.py`. It creates startup
files and private original-config backups; it does not copy the disk, execute
WIN.COM, install an ESP, configure Supervisor workers, or prove a Windows version.
Every Windows/native/version/VM acceptance flag remains false.

The exact request schema is `shizukuos.win98-source-profile-request.v1` with six
fields:

```json
{
  "schema": "shizukuos.win98-source-profile-request.v1",
  "replacement_profile": {"path": "/private/replacement-base.json", "bytes": 1234, "sha256": "replace-with-actual-file-sha256"},
  "drive": "C",
  "windows_directory": "WINDOWS",
  "boot_policy": "shz.foundation=win98",
  "xms": {
    "file": {"path": "/private/xms/artifacts/HIMEMX.EXE", "bytes": 6100, "sha256": "5e0ed027a150ac1c198e994ca248245c07c1f44796bc0791448afbcf29789211"},
    "build_receipt": {"path": "/private/xms/source-build-receipt.json", "bytes": 12345, "sha256": "replace-with-actual-private-receipt-sha256"},
    "source_root": "/private/xms/source"
  }
}
```

The illustrative sizes and replacement strings are invalid inputs. Use actual
reviewed private files and literal SHA256 values. The base must satisfy the
constructor's seven-field v1 schema and contain only source-built `KERNEL.SYS`
and `COMMAND.COM`. DOS artifact/source/patch pins are checked against its actual
`dos16-freedos` receipt. This producer additionally requires the recorded and
physical `config.mak` with `WIN31SUPPORT` enabled for both C and NASM:

```make
XNASM=nasm
undefine XUPX
ALLCFLAGS=-DWIN31SUPPORT
NASMFLAGS=-DWIN31SUPPORT
```

XMS input must be the normal 6100-byte HIMEMX above, not HIMEMX2/ALTSTRAT, with its
actual `shizukudos-cb43-himemx-source-build-v1` private receipt. All 5 HimemX and
268 JWasm recorded source files must exist unchanged beneath `source_root`.
The upstream identities are HimemX `bbaf6b8951cdac785f1f4e9b67c25439c5bf8e75`
and JWasm `7f6f32e78b79565d40bcce496756aadd1ff66900`. A sanitized documentation
receipt has a different hash and cannot substitute for the selected raw receipt.

The active FAT12/16/32 source is read through the constructor's independent
reader. `MSDOS.SYS` must contain unique `[Paths]` records agreeing on the selected
`C:\WINDOWS` path and host drive C. The selected root directory is an uppercase
short name; nested, reserved-device and case-ambiguous names are refused.
Nonempty WIN.COM, SYSTEM.INI, SYSTEM/VMM32.VXD and IFSHLP.SYS are required.
Cabinet-only media, diagnostic `shz.desktop` policy and ambiguous path selection
are refused. File presence and source pins do not prove installed-version or
native boot compatibility; actual C: drive mapping is still unverified.

Original CONFIG.SYS/AUTOEXEC.BAT files are backed up byte-for-byte in
`original-config/`, including empty originals. They are bounded ASCII inputs
with LF/CRLF physical lines for locale parsing. Other control bytes and lone CR
are refused; arbitrary original drivers and commands are not replayed.
Only an unambiguous observed COUNTRY/NLSFUNC pair with present dependencies is
retained, with dependency hashes and metadata recorded. CONFIG menus/includes,
batch control flow and command operators prevent locale retention. Commands
in retained-locale CONFIG.SYS and AUTOEXEC.BAT are bounded to 250 bytes per
physical line, including CR and comments before comment filtering, to stay
within the pinned FreeDOS and FreeCOM 256-byte readers. CONFIG overflow must
not expose a hidden suffix as another command. Commands
before retained NLS must be plain ECHO ON/OFF, SET, drive selection, CD/CHDIR or
PATH without variable expansion; batch chaining and unproven preceding commands
are refused. No country
or code page is invented when the pair is absent.

The generated CONFIG.SYS uses the existing observed HIGH configuration:
HIMEMX `/VERBOSE`, the selected Windows IFSHLP.SYS, DOS=HIGH, FILES=30,
BUFFERS=20 and FreeCOM `/E:512 /P`. AUTOEXEC sets COMSPEC, windir and PATH,
selects C: and the Windows directory, then invokes its fully qualified WIN.COM
exactly once. It adds no diagnostic probes, banners or `/B` logging switch.

```sh
python3 -B shizukudos/install/win98_source_profile.py \
  --request /private/request.json --request-sha256 ACTUAL_REQUEST_SHA256 \
  --out /private/fresh-profile --capture-budget-bytes 1048576
```

The producer runs pinned-template NASM validation through the existing
constructor, but starts no guest or Windows executable. Its original inputs,
build sources and nonempty staged files have actual Linux read leases and
before/after hash/identity checks. Expected output hashes come from generated
bytes. The canonical constructor profile is published last; publication or
final output lease failure removes both accepted JSON outputs. Later consumers
must use the receipt's exact `constructor_profile` SHA and must verify all its
payload pins. A failed partial private directory is not resumable or accepted.

Outputs are private mode-0700 directories/mode-0600 files. Existing output paths
are refused. The 17 GiB free-space floor plus explicit capture and remaining
write budget is preserved even for small sources. A base disk over 64 MiB
inherits the constructor's reserved NAS replacement-lane restriction for the
profile output. Disk construction remains a separate explicitly budgeted step;
there is no automatic disk-copy or reflink fallback.

Focused verification:

```sh
python3 -B -W error -m unittest shizukudos.install.tests.test_win98_source_profile_fada -v
```

Tests use actual tiny FAT media, pinned upstream assembly and the existing real
source-built XMS input. Windows members and DOS kernel/shell bytes are explicitly
synthetic fixtures and are never executed. Only available-capacity reporting is
modeled for tiny fixtures; production resource guards remain enabled. These
tests are host preparation evidence, not Windows/native/app acceptance.

Public distributions may include this project source and patches. The private
installed source, Microsoft binaries, images, backups and generated private
receipts must remain outside public media and publication paths.
