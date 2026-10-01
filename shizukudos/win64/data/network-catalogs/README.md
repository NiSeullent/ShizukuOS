# Public system network catalogs

These are ordinary public operating-system default files. No host `/etc/hosts`,
private VM file, captured Windows installation, or test-specific service is used.

`services.txt` and `protocols.txt` are unmodified Debian netbase 6.4 sources.
Their SHA-512 matches the checksum declarations in Alpine's package recipe at
aports commit `24f4ccc89d6da5b337c32460c5aec8b44146cadf`.
`hosts.txt` is the exact tab-stripped `hosts` heredoc from that recipe, including
its ordinary IPv4/IPv6 localhost names. The recipe is never executed here.
Source URLs, hashes, sizes and collection time are in `manifest.json`.
The upstream copyright notice and complete GPL-2 text are preserved.

`tools/public_network_catalogs.py` validates the pinned recipe and source files,
then packages the three catalogs and two license notices under
`\SHZ\SYS64\DRIVERS\ETC`. The normal Win64 and driver archives carry the same
bytes. Production desktop/install selection already retains this system path.
All files are included in the full runtime source hash and membership guard.
The helper is offline and changes no host resolver, TLS or Winsock settings.

Winsock opens these real files read-only. Missing catalogs remain actual errors;
the runtime does not invent successful entries. Host tests compile the exact
production parser/TLS/heap/thread bodies with copied public catalogs and strict
GCC/Clang sanitizers. Native fixtures still need a fresh coherent runtime and
whole GOP VM run. Catalog packaging does not prove DNS/PTR, IPv6 reverse lookup,
Windows 98 MS-DOS replacement, or real Chromium/Steam application acceptance.

Primary sources: [Debian services](https://salsa.debian.org/md/netbase/-/blob/v6.4/etc/services),
[Debian protocols](https://salsa.debian.org/md/netbase/-/blob/v6.4/etc/protocols),
[Debian copyright](https://salsa.debian.org/md/netbase/-/blob/v6.4/debian/copyright),
and [pinned Alpine recipe](https://github.com/alpinelinux/aports/blob/24f4ccc89d6da5b337c32460c5aec8b44146cadf/main/alpine-baselayout/APKBUILD).
