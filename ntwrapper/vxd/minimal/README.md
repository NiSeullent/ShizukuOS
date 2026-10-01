# Isolated VxD loader fixture

This directory is an original, control-only LE/DDB experiment. It does not
modify, replace, install or package the production `NTWRAP9X.VXD`.

The actual Windows 98 SE result in `docs/VXD_V86_LOADER_TRIAL.md` is
`CF=1, AX=0006` (`BAD_DEVICE_FILE`) after checking every input byte and EOF.
Successful host checks cannot turn that result into a successful native load.

The fixture has no C runtime, VMM service, MMIO, DMA, interrupt or hardware
driver operation. Its control procedure accepts lifecycle notifications and
refuses Win32 device I/O with error 50. Use the native V86 loader contract for
future disposable guest trials; do not infer Win32 DIOC/query support.

Interface and format research is recorded in [../REFERENCES.md](../REFERENCES.md).
No DDK implementation or external linker is included. Build the six isolated
object-flag/layout variants and run the independent decoder's host tests with:

```sh
python3 -B ntwrapper/vxd/minimal/build.py
python3 -B ntwrapper/vxd/minimal/test_validate.py
python3 -B ntwrapper/vxd/minimal/validate.py ntwrapper/vxd/minimal/build/shared-data/NTWMIN9X.VXD
```

The host tests cover exported DDB relocation at different load bases, truncated
files, damaged offsets/counts/fixups, overlapping objects and bounded mutations.
They establish neither Windows 98 loader acceptance nor driver operation.
A guest comparison must use a new disposable installed Windows 98 disk for each
variant, verify the exact file and EOF before loading, record raw VXDLDR CF/AX,
and unload only a device whose load succeeded. The existing V86 diagnostic embeds
the production driver and its exact name. `build_loader.py` explicitly selects
one fixture and adapts only its guest paths, name and exact-byte evidence text;
the historical assembly and production diagnostic remain unchanged:

```sh
python3 -B ntwrapper/vxd/minimal/build_loader.py --variant shared-data
python3 -B ntwrapper/vxd/minimal/test_loader.py --variant shared-data --tool-provenance build/minimal-vxd-cpu-tool/tool-provenance.json
```

The COM checks every byte and EOF before load, records raw native flags/AX/DX,
and unloads only its own successful load. A preexisting log is never replaced.
The host CPU test executes the generated COM under the historical bounded
synthetic DOS/VXDLDR model. Its in-memory model adaptations are restricted to
fixture size and identity, recorded with the original/adapted model hashes.
It retains the complete error/cleanup scenario matrix. The externally downloaded
Unicorn 2.1.4 wheel and every extracted tool file are verified before use; this
private host tool is not packaged or needed by the guest. Synthetic successful callbacks establish no native loader acceptance.

Actual Windows 98 SE 4.10.2222 load/unload now passed for the
`shared-nonresident` fixture (code 0x2065, data 0x2063) and the separate
Watcom-linked fixture. Both recorded CF=0 and AX=0 for load and unload,
RESULT_CODE=0 and DOS_EXIT=0 after complete byte and EOF verification.
The shared-both fixture differs only by permanent-resident bit 0x0200 and
retained BAD_DEVICE_FILE; the other rejected layouts remain preserved.

The exact successful VXD hashes are respectively
`351c0d9e1b680c659361db78a231dd4ef1f4b4d93fead6ffd92229558c25a5de`
and `57422c7d6902b238169cc8e59d66e2bf692cf3b72dfc4b488baf7a65f6cecf4d`.
Raw and separately scoped visual reviews are under
`build/shizukudos/csm/run-win98-uefi-q35-kvm-native-vxd-shared-nonresident/`
and `...-native-vxd-watcom-le/`. Their proof applies to these control-only
fixtures. The production NTWRAP9X driver is a separate target.

`build_wlink.py` uses the private actual Open Watcom linker and pinned
MIT-licensed fixlink, without changing the original six byte layouts.
`validate_watcom.py` independently checks that linker output. The original
reader and its six-variant tests retain their narrower format contract.
