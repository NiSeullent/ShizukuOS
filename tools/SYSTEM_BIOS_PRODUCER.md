# Source-built native system BIOS

`build_seabios.py` produces the Supervisor's 256KiB `SEABIOS.BIN` from the
same pinned SeaBIOS commit as the CSMWrap source manifest. The separate
`build_stdvga_rom.py` produces the VGA option ROM. These are distinct images.
The system BIOS enables the QEMU target and disables the boot menu and Xen.
It does not run a VM, install Windows or establish a device epoch.

Run the producer in its own delegated systemd unit with no RuntimeMax, so
failure cleanup can retain original leases until its actual children exit:

```text
systemd-run --wait --collect --unit=shz-seabios-local \
  --property=Delegate=yes --property=TasksMax=128 --property=MemoryMax=1G \
  /usr/bin/python3 /project/tools/build_seabios.py \
  --source /pinned/csmwrap/seabios --private-out /var/tmp/private0700/new-build \
  --unit shz-seabios-local.service
```

Output must be fresh, canonical, owned and outside Git. The producer retains
actual Linux read leases on its sources, Git archive, copied files, generated
configuration and compiler/tool executables through compilation and final
complete hash checks. It uses the reviewed ROM producer's owned-unit cleanup
and source-archive verification. The build-command deadline is fixed; mandatory
cleanup/readback continues after commands finish. Failed cleanup retains leases.

The receipt identifies the BIOS, complete original Git source archive, original
licences, generated configuration/version headers and exact source/tool maps.
Its canonical map digests use sorted JSON with compact separators. Paths in
`sources_sha256` are relative to `source_root` or absolute producer paths.
Source archive and licence bytes come from the same admitted commit. This does
not establish a full compiler shared-library/SDK closure or actual boot support.
The ISO producer requires independent policy anchors and rereads these files;
a saved receipt alone does not issue installation permission.
