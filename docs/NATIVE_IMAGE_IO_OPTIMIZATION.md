# Native Windows 98 image I/O preparation

This change optimizes the private installed-Windows-98 control preparation. It
preserves the source-bound Windows 98 domain and does not validate ShizukuDOS as
an MS-DOS replacement. ShizukuOS 1.0.0 remains the target; the current product is
a development candidate. No Microsoft media or private images are public assets.

The native builder retains its actual Linux read lease and identity/SHA checks.
Its main path attempts FICLONE against that same leased descriptor. A successful
copy has a distinct inode; writes to the owned copy break COW and leave the input
unchanged. Full target size and SHA are read back before accepting the copy.

On unsupported clone operations only (EXDEV, EOPNOTSUPP, ENOTTY, ENOSYS, EINVAL),
the builder first reserves the measured source allocation and then streams from
the same leased descriptor, skipping zero 4 KiB runs. Other errors, including
I/O errors and ENOSPC, remain failures. There is no unannounced dense fallback.
Failed private outputs remain unaccepted; original inputs and evidence are not
removed. Existing files, symlink paths and incompatible source writers remain
refused.

The builder's initial budget is the complete 2,304 MiB ESP capacity, measured
allocated input blocks and 128 MiB for source snapshots, compiler outputs and
filesystem metadata. The full 17 GiB free-space reserve is unchanged. The ESP
capacity is still counted because FAT member copies include the disk's complete
logical extent. COW copies may use fewer physical blocks than this conservative
input estimate. Every copy/package operation retains its space check.

`prepare_vm.py` requires 64 MiB for metadata plus the exact 4 MiB CODE/VARS pair
and explicitly requests COW for its fresh ESP and firmware copies. Unsupported
clone fallback retains the measured-source-allocation space gate before any
bulk data writes. A source ESP is never used as a writable VM disk. The QEMU
recipe, pinned inputs, distinct-inode checks and no-VM-execution receipt gates
remain unchanged.

ESP member verification now reads actual FAT bytes through a bounded `mtype`
pipe into SHA-256 and an exact byte counter. A nonzero exit, timeout, extra or
missing bytes, or a hash difference rejects the build. It materializes no
full-disk readback file. Member names and byte hashes in the receipt retain
their existing format.

Focused host controls cover actual Linux lease refusals/breaks, source identity,
COW write isolation, sparse byte-exact fallback, unsupported-clone and I/O-error
separation, existing-target refusal, actual FAT-member hash/extent verification,
actual injected FAT corruption, 17 GiB reserve preservation, the former upfront
space rejection, CODE/VARS geometry and fresh no-launch VM plans. These tests
use independently created synthetic files. They are not Windows boot results,
modern application results, a final ISO size claim or a general speed benchmark.

Run the native host input and preparation checks from the repository root:

```sh
python3 -B -W error::ResourceWarning -m unittest discover \
  -s shizukudos/supervisor/native_win98/tests -p 'test_*.py'
```

Actual native Windows 98 VMX startup, VMM channels, GUI and modern apps remain
separate required gates after these private images are prepared. Original
MS-DOS control success cannot fulfill ShizukuDOS replacement acceptance. ISO
artifacts remain restricted to m98.nyase.kr; GitHub contains source and patches.
