# Corrected native TLS evidence

`tools/verify_tls13_i486_native.py` accepts only the reviewed corrected stage at
`/root/Win98-Modern-boot/build/tls13-i486-native-5abe-20261001-v1` and fresh
`run-win98-gop-tls13-i486-5abe-native-vN` results directly under the owned boot
lab directory. It starts no guest, controls no process, writes no file and imports
no historical verifier, builder or scanner. Its approved own stage helper is
loaded from pinned bytes in memory, then called before and after native evidence.
All old builds, original verifier and the four stage sources remain unchanged.

Required caller approvals are the run SHA, manifest, stage authority, provenance,
five corrective-build authorities, harness source, stage helper and a fresh
host-control authority. The fixed stage pins are `e0c7af02378c03edd1e6a21d00787964ee9b6b20cb8d28d2f646f7191fed9632`,
`ad368edb18594c5b9a12823655eb9d8ebd13a28c814519996af6e1b14687c852`,
`3776c62a6bcb80548263e664508aa38df08eea1892a5f7c8dc7253e99557f634`.
The stage helper is `ba9eb7542b099b81a43f75c474602a27a14d6ee9b2f14f9c526a8da2c6d1ef92`
and harness is `5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857`.

The caller-pinned host-control authority is explicitly synthetic tests only. It
binds all three current/frozen new sources, normal and Python `-O` commands/logs,
their exact source-derived method count, the actual interpreter binary and every
tested dependency's current/frozen bytes. It is never a native acceptance receipt.
Production uses explicit requirements rather than `assert` and is unchanged by
optimization. JSON duplicate fields, boolean/integer aliases, partial/nonfinite
records, excessive files, symlinks and noncanonical/outside paths fail closed.

The native catalog is the unchanged original verifier's pinned 24 checks, joined
to the exact original probe and observer source bytes. Full CRLF ASCII key order
is required, including positive metadata between pair creation and handshake.
Successful evidence includes native CryptoAPI entropy and UTC, actual TLSv1.3,
client certificate-chain/hostname verification, exact source-defined 3,072/1,021
byte payload comparisons, bounded retries, authenticated close, rejected writes,
bad host/CA/ciphertext/entropy controls and backend/provider/DLL teardown. No
client certificate is requested; server peer-verification flags are informational
and cannot prove mutual authentication.

The original observer must report Win98 SE 4.10/build-low 2222/platform 1, a
nonzero full DWORD child PID, actual child DWORD exit 0, successful output flush
and handle closure. Its requested supervisor exit 0 precedes its own last close;
the actual outer supervisor exit remains unobserved. Neither original program
calls GetACP: ACP is reported as unavailable and unverified, never invented.

The pinned harness must record a normally finished preserved private cold GOP
run with offline networking, q35/KVM, 128 MiB, two CPUs and the unchanged 20 GiB
reserve. Actual serial GOP markers, manual action sequence/command records,
initial private file plan, exact eight prepared readbacks and all three fresh
captured outputs are bound to the approved root stage authority. The root manifest
has sorted outputs; the original old build-manifest order is not reused here.
GUI dispatch records do not prove physical input or painted pixels.

After the second slow full stage check, every consumed regular stage/native/run/
source/input/log/receipt byte is rehashed. Stage members are processed first,
small native logs and run receipt last, then all inode/size/time/mode snapshots
are compared. Exact aliases/directories and target types are checked again;
sources and small native/run files are reread after that walk, then every
consumed metadata snapshot is compared again. Any late mutation rejects acceptance.
Ordinary proof is bounded to 16 MiB per file, native output to 64 KiB, guest
prepared input to 1 MiB, run/control receipts to 2 MiB and provenance to 4 MiB.

Large original OS media and cold source-disk preservation are recorded by the
pinned harness; this bounded verifier does not claim an independent multi-GiB
media/subtool/system-header closure. A genuine pass proves only native DLL TLS
interoperability through offline memory queues. WinSock, OS TLS integration,
network transport, applications, rendering and all full modern web standards
remain unverified. Root owns native admission and requires independent source
review before this helper is used against any real run.

The read-only invocation supplies all approvals explicitly:

```text
python3 -B tools/verify_tls13_i486_native.py --run-result /root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-tls13-i486-5abe-native-v1/result.json --run-result-sha256 <approved-run-sha> --manifest /root/Win98-Modern-boot/build/tls13-i486-native-5abe-20261001-v1/guest-files.json --manifest-sha256 e0c7af02378c03edd1e6a21d00787964ee9b6b20cb8d28d2f646f7191fed9632 --stage-authority-sha256 ad368edb18594c5b9a12823655eb9d8ebd13a28c814519996af6e1b14687c852 --stage-provenance-sha256 3776c62a6bcb80548263e664508aa38df08eea1892a5f7c8dc7253e99557f634 --harness-sha256 5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857 --stage-helper-sha256 ba9eb7542b099b81a43f75c474602a27a14d6ee9b2f14f9c526a8da2c6d1ef92 --verifier-authority /root/Win98-Modern-theme-tls-5abe/build/tls13-i486-native-verifier-v1/result.json --verifier-authority-sha256 <approved-control-authority-sha> --tls-sha256 98c526151545be95fe5f6cd58140ae2dfdc52d21038fe1de893387290dea1819 --root-review-sha256 d2eaf7896235fedb8246bb7197ac24297f4a265d6dda21295b7f76bcdb8892cf --independent-review-sha256 9ef72856e5dfddb357e9e89211dcf0f01d18babe437cec30649e52fe04ebb9e3 --client-sha256 7e5d48151b4754adfcdf6cf5c9e5ef4747c3b61ed37a1e84eb1991847c1496f9 --server-sha256 6ad287ce7b43ed45af43f2b8b62f4ea678f876ec2341a4bc87cb72c8a913ad97
```

Replace both placeholders with independently approved receipt pins. The full
command does not authorize or perform native admission.
