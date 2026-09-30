# Source provenance

The new transport adapter, native clock/runtime/startup, probes, builders and
staging code are original project code, SPDX GPL-2.0-only. Protocol, public-key
cryptography and X.509 implementations are linked from the unmodified official
Mbed TLS 3.6.7 source archive:

- [Official release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7)
- Archive: `mbedtls-3.6.7.tar.bz2`, 5,473,689 bytes.
- Publisher SHA-256: `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.
- [Publisher checksum](https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7-sha256sum.txt)
- Upstream's license is Apache-2.0 OR GPL-2.0-or-later; select the GPL-2.0
  option for the project combination. Keep the full upstream LICENSE,
  LICENSES and each third-party notice with any later binary distribution.
- The 3.6 branch is maintained with bug/security fixes until at least March 2027
  according to the publisher; this pin is a maintained LTS choice, not a claim
  that 3.6.7 is the newest major branch. The peer's 4.2.0 client foundation is
  separately owned and can be compared through an adapter after its own checks.

Every final build extracts a newly verified archive and freezes adapter inputs
before compiling. Its receipt includes the command list, source SHA-256s,
archive identity, artifact digests and exact original OEM export baseline.
The OEM manifest is metadata; Windows DLLs, installation media, private guest
disks, official app archives and test keys are not added to source control.

The native toolchain here is mingw32-gcc 15.1.1-1.el10, mingw32-crt
12.0.0-4.el10 and mingw32-headers 12.0.0-3.el10. Installed MinGW formatting and
GCC arithmetic helpers retain their own runtime licenses/exceptions. A binary
release must include the matching notices and satisfy applicable source duties;
this development checkpoint has not published a binary release.

The native adapter uses the measured ANSI CryptoAPI path rather than the
Win98 Unicode function that returned ERROR_CALL_NOT_IMPLEMENTED in earlier
peer guest experiments. Import existence, these earlier experiments and this
new build do not establish behavior of the new artifacts. Fresh guest execution
remains mandatory.

No Wine/ReactOS Schannel code is copied here. Their system-facing SSPI families
and dependencies remain a future integration concern. This engine's API is not
a replacement export table for secur32.dll or winhttp.dll.
