# Native theme probe supervisor — chat 5abe

`tools/build_theme_guest_runner.py --nonce theme-5abe-20261001-native-v1`
builds `build/theme-engine/guest-runner/M98THRUN.EXE`. It is a no-CRT native
PE32 GUI 4.10 executable; its 15 imports are original Windows 98 KERNEL32 APIs.
No console, KernelEx installation, system DLL replacement or registry changes
are needed. The build passed 4,504 API/lifecycle assertions across 18 injected
host scenarios normally and under ASan/UBSan. A separate read-only agent reviewed
the native source, failure mocks, PE gate and source/artifact receipt.

Frozen v1 executable SHA-256:
`35e4db62dd5da7f73d97999069d501f28e426545e33672f77a117ee18cfffed9`.
Its receipt SHA-256 is
`5642f151d3948cbf4c9dcce517829ed2fc1adde638a256fdb96929d4c3bf8e5d`.
Neither build/test success nor this review is native guest evidence.

## Runtime scope and evidence

Launch exactly `C:\GOPLAB\M98THRUN.EXE` on a new disposable installed Win98 SE
clone with the frozen DLL and the two probes alongside it. The supervisor
checks platform 1, version 4.10, build low word 2222 and its own absolute path.
It creates `THRUN.LOG`, then independently creates `THPRO.LOG` and `THSTA.LOG`
using `CREATE_NEW`. Existing or inaccessible child logs prevent execution;
no log is overwritten. Its compile-time nonce is
`theme-5abe-20261001-native-v1`.

The two exact child application paths are `C:\GOPLAB\M98THPRO.EXE` and
`C:\GOPLAB\M98THSTA.EXE`. Each receives inheritable native file handles for
stdout/stderr and an inheritable NUL stdin through `STARTF_USESTDHANDLES` and
`CreateProcessA(..., TRUE, ...)`. The DLL is resolved beside the child EXE.
The supervisor closes the thread handle, waits 20 seconds, obtains the full
32-bit process exit and flushes/closes that child's output. A timeout or failed
wait stops only the exclusively owned child, with a further five-second reap
bound. An unreaped child prevents the second launch. The supervisor never
targets a PID discovered outside its own `CreateProcessA` call.

Accept the two probe executions only after fresh host readback proves the
frozen input bytes, nonce and exact OS identity, two normal waits, two successful
exit queries with full exit code zero, successful output flush/close, and both
stdout logs' `WIN98_IDENTIFIED=1` and final native PASS. The updated probes keep
each labelled comparison visible for fifteen seconds; the first native trial
passed both probes but its two-second windows fell between captured frames.
Keep the original trial evidence and bind the updated probe hashes separately.

`supervisor.requested-exit-code` is explicitly the proposed result before final
flush/close/`ExitProcess`. An actual supervisor exit requires an outer observer;
do not treat this field as an observed outer exit. Final flush/close failures
return 14 even if the earlier requested code was zero. A guest batch may use
the guest's verified `START /WAIT` behavior for an outer zero/nonzero observation,
but a shell or console failure cannot substitute for the native child logs.

## Read-only native harness audit

The selected true-color GOP base is:
`/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-latest-npp-cold-v3-20260930T1807`.
The complete 2-GiB raw disk was read-only hashed on 2026-10-01 and matches its
post-run receipt hash
`518d18d5e286cb0eb63065d8d896d0d3ee743289f220fb62083f6176b5925db7`.
The receipt SHA-256 is
`13f76fc4f6870a61d5067b76b7c47a49b7d40ddcd9310f271d5d8cbd1fab8ada`;
the independent native cold keyboard review SHA-256 is
`e945062ad535c5e2b61f7ee39be91c308d1103b29ff3d44d0f5b2e3455d40175`.
This is a source for a new cold sparse copy, not a disk to boot or edit in place.
It retains another owner's installed GOP/application environment; this trial
does not stage or launch that owner's application.

The canonical harness is
`/root/Win98-Modern-boot/shizukudos/csm/test_win98_uefi.py`, audited SHA-256
`5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857`.
Use `--resume-owned-run` for the verified post-run disk: `--prepared-run`
instead expects the original pre-boot preparation hash. It verifies the archive,
checkpoint, CSMWrap receipt and raw source; copies to a newly created run
directory with `cp --reflink=never --sparse=always`; never reuses CPU/RAM/VARS
state; and rechecks immutable sources and the retained raw source afterwards.

Selected source allocation is 248,135,680 bytes. With the unchanged 20-GiB
reserve and 256-MiB dirty budget, the measured prepared-copy minimum is
21,991,407,616 bytes free. Tiny staging copies, VARS, screenshots and logs need
additional space; aim for at least 22 GiB free before starting. No script, VM or
peer disk was executed/mutated by the audit. Shared free space was below the
20-GiB reserve at the last audit; root is coordinating disk reclamation and VM
ownership separately.

The immutable archive is
`/root/Win98-Modern/build/win98-lab/install-packed-z_kei9n1.qcow2.xz`, SHA-256
`0c15c1a7b266599eb1834c9c02f87ee9c1d007a6d2b52e4207b5b89df8ee00d8`.
The checkpoint record is
`/root/Win98-Modern/build/win98-lab/install-packed-current.json`, SHA-256
`d3df8220cde1564ed466567ff28c46dec7e2c9b223c50f8898afd7a28bfd0fd5`.
Selected installed snapshot is `windows98-clean-installed`.
The selected GOP CSMWrap directory is
`/root/Win98-Modern-boot/build/shizukudos/csm-gop-anchor`; audited EFI SHA-256
`17926603f65cb465ea3750d3b5cf51e839ddd3a04c614c989a9b2ab09aa3d0b0`,
Csm16 SHA-256 `039f38c9759add2b192aee7dd80172f975d1c7cbc801d71c37d15634ab653649`,
build receipt SHA-256
`7d8e36d4b7faaa7583ac8b14feb796599928b3814ae8fdfc98ce0a6eeb683ed3`.

Before execution, create a new owned local staging directory such as
`/root/Win98-Modern-boot/build/theme-5abe-native-v1/` with byte-identical copies
of the DLL, two probes, supervisor and both build receipts. Freeze a schema-1
`isolated-guest-file-inputs` manifest there: four inputs mapped to `C:\GOPLAB`
using their uppercase 8.3 names, three absent output log paths listed above,
`backups: []`, and both locally copied receipts in `source_receipts` with hashes.
The ordinary harness accepts 1..8 unique inputs, each 1..1,048,576 bytes under
the manifest's parent, and at most eight unique output paths in GOPLAB/VXDLAB.
Input/output overlap is forbidden. Source receipts must resolve beneath
`/root/Win98-Modern-boot`; copying the receipts is necessary to use that field
for our isolated-worktree build. Bind the original build paths/hashes in an
additional staging-provenance record, and verify every copied byte.

After staging and coordinating the peer VM, run from `/root/Win98-Modern-boot`
with the actual newly frozen manifest digest:

```sh
python3 -u shizukudos/csm/test_win98_uefi.py \
  --archive /root/Win98-Modern/build/win98-lab/install-packed-z_kei9n1.qcow2.xz \
  --checkpoint-record /root/Win98-Modern/build/win98-lab/install-packed-current.json \
  --snapshot windows98-clean-installed \
  --resume-owned-run /root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-latest-npp-cold-v3-20260930T1807 \
  --csm-dir /root/Win98-Modern-boot/build/shizukudos/csm-gop-anchor \
  --replace-csmwrap --firmware-gop \
  --qemu /usr/libexec/qemu-kvm \
  --firmware-code /usr/share/edk2/ovmf/OVMF_CODE.fd \
  --firmware-vars /usr/share/edk2/ovmf/OVMF_VARS.fd \
  --machine q35 --accel kvm --smp 2 --memory 128 \
  --timeout 900 --capture-interval 5 --reserve-gib 20 \
  --manual-gui --manual-purpose diagnostic \
  --guest-files-manifest /root/Win98-Modern-boot/build/theme-5abe-native-v1/manifest.json \
  --guest-files-manifest-sha ACTUAL_FROZEN_MANIFEST_SHA256 \
  --run-name run-win98-gop-theme-5abe-native-v1
```

The named new run is created exclusively below `build/shizukudos/csm/`.
Record host progress in a separate new owned file if desired. The run retains
`runner-source.py`, `OVMF_VARS.fd`, `serial.log`, `qemu.stderr`, screenshot
hashes and `screen-NNN.png`, guest boot logs, `prepared-guest-*` input readbacks,
`guest-output-THRUN.LOG`, `guest-output-THPRO.LOG`, `guest-output-THSTA.LOG`,
the raw post-run hash and `result.json`. QEMU stdout goes to DEVNULL.
Manual requests go only to this new run's `gui-control.json`, with strictly
sequential integers starting at 1 and `name`, QMP chord `keys`, optional ASCII
`text`, `enter`, capture options and `finish`. Every action returns its own
`gui-control-receipt.json`. Launch through the reviewed Run dialog and request
immediate comparison captures; never write another owner's control file.

The diagnostic harness status `NEEDS-VISUAL-REVIEW` is boot/run evidence, not
automatic theme acceptance. Independently review the native logs, exact hashes
and visible comparisons before advancing `native_win98` from `not_tested`.
