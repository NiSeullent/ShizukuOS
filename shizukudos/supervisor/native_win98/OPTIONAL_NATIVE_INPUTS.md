# Explicit optional native inputs

`build.py` keeps its existing six original input pins and default BOOT.INI.
Optional inputs require independent path/SHA256 argument pairs:

- `--vga-config` / `--vga-config-sha256`: exact 136-byte `SHZDOS/VGACFG.BIN`.
- `--vga-rom` / `--vga-rom-sha256`: exact 65536-byte `SHZDOS/VGAROM.BIN`.
- `--vga-build-receipt` / `--vga-build-receipt-sha256`: bounded producer receipt,
  retained as provenance and never copied into the ESP.
- `--persistence-config` / `--persistence-config-sha256`: separate exact
  192-byte `SHZDOS/W98PERS.BIN`.

The VGA inputs and producer receipt must be supplied together. The config must
match the loader's version, flags, BDF, reserved fields and aligned 16MiB LFB
geometry. Its three distinct nonzero digests bind the padded ROM, canonical
producer source manifest and generated configuration. ROM admission checks the
x86 signature, original extent, standard VGA PCIR identity/class/code/last-image
fields, checksum and zero-only padding from the same leased original FD.

The separately held receipt must have schema
`shizukuos.actual-source-built-stdvga-rom.v1` and status
`ACTUAL_SOURCE_BOUND_STDVGA_ROM_BUILT_NOT_RUN`. Its ordered source rows reconstruct
the exact UTF-8 JSON manifest with two-space indentation and final newline.
Manifest, generated-config, raw-prefix and padded-ROM pins must agree with the
actual held config/ROM bytes. The producer's original/source custody and empty
descendant-census flags must be true; VM, publication and complete SDK closure
flags must remain false. The builder reads these independent pins from the held
receipt without reopening the receipt's referenced producer artifacts.

Persistence admission checks its separate version/device/geometry wire,
reserved zeros and bounded, aligned, nonoverlapping BAR resources. This is syntax
and resource admission. A config or source producer receipt cannot grant an
actual owned physical PCI-device epoch or prove runtime persistence.

Only admitted blobs enter the ESP. Their presence emits explicit
`win98_vga=yes` and/or `win98_persistence=yes` under `mode=supervisor`.
With no optional inputs, the policy remains exactly
`mode=supervisor\r\nmenu_timeout=0\r\n`.

Builder receipts preserve `input_pins` for the original six. Optional blob pins
use a separate nonempty `optional_native_inputs` map with exact known blob names;
the provenance-only receipt uses a separate nonempty
`optional_native_provenance` map with the single key `vga-build-receipt`.
Each map value is an exact original `{path, bytes, sha256}` pin. Neither optional
map is emitted when absent. All originals use the existing read-lease registry,
same-FD copy/full-hash checks and finalization checks before PASS can escape.

The guardian manifest must explicitly declare exactly matching optional maps.
Custody refuses unknown or incomplete pairs, extra/empty/mismatched maps,
incorrect extents, undeclared optional ESP members and member SHA disagreement.
It leases every optional original and provenance receipt alongside the six
originals, then reruns admission from those held descriptions using the admitted
builder source. Those leases remain in the guardian's union through task return
and cleanup. The provenance receipt is forbidden as an ESP member.

Tiny host controls use synthetic firmware/source metadata and a 4KiB modeled
disk. Compilation and ESP construction are modeled; FD reads, copies, SHA256,
leases, path replacement refusal and custody admission are actual Linux actions.
They prove no actual Windows 98 boot, GUI, SMP, device epoch, persistence or ISO.
