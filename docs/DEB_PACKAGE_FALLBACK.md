# Pinned Debian packages on build hosts without dpkg-deb

`shizukudos/tools/shzlib.py` still prefers an installed `dpkg-deb -x`.
When it is unavailable, `ensure_deb_upstream` reads the Debian 2.0 ar
container and extracts its data tar archive inside `build/upstream/<name>/root`.
It never installs the package or runs its maintainer scripts.

The fallback supports uncompressed, gzip, xz and bzip2 data archives through
Python's standard library. Zstandard archives use an existing `zstd` executable;
no host package installation or global PATH change is performed. Python must
provide `tarfile.data_filter` (Python 3.12 or a security-backported version).

Package/source SHA-256 checks and manifest member hashes remain mandatory.
An extraction stamp is written only after member hashes pass. Invalid ar
headers, duplicate entries, absolute paths, parent traversal, Windows drive
paths, escaping links and device entries fail. Internal relative symlinks and
hardlinks remain supported, with tar data filtering repeated at every write.

Verification on 2026-09-30:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 shizukudos/tools/tests/test_deb_upstream.py -v
```

All 10 tests passed with no skips. The real cached, SHA-pinned Ubuntu Syslinux
packages were extracted through their `data.tar.zst` members; all 10 listed
binary hashes, three licence paths and the host Syslinux executable mode passed.
Fixtures also exercise malformed archives, pin rejection, path/link containment,
supported compression, and preference for dpkg-deb. Tests do not download files.
The host receipt is under `build/deb-fallback-validation/`; it does not establish
ISO boot, desktop or application acceptance.
