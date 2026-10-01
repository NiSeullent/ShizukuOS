# Theme, graphics, DirectWrite, TLS and apps: continuation checkpoint

This is a development checkpoint from 2026-10-01. Publication of the source
and a bootable development ISO is separate from completing Windows 98 Modern.
The required system themes, full DirectX/Direct2D/DirectWrite, modern Office,
Legcord/Discord, Signal and OS-wide TLS 1.3 remain active goals.

Use the repository-wide [new machine guide](CONTINUE_ON_ANOTHER_MACHINE.md)
after the integrated `main` is published. Record the actual main commit and
start a new `codex/` branch. Old `/root/.../build/` paths in receipts identify
historical private artifacts; they are not files supplied by cloning GitHub.
Rebuild public sources and generate fresh source-bound receipts on the new host.
Never edit old hashes or weaken a verifier to reuse a relocated trial.

## Component entry points

| Component | Source and evidence guide | Current boundary |
| --- | --- | --- |
| Native Win98 theme | [checkpoint](THEME_NATIVE_CHECKPOINT_6970.md), `ntwddm/win98/theme_composition` | Native v13 pixels/text/lifecycle observed, strict metadata gate FAIL; corrected v14 stopped at disk floor before desktop/child proof |
| AMD64 theme | `ntwddm/win64/theme_provider`, `ntwddm/win64/theme_probe` | Actual isolated Windows ABI and visible pixels verified; global Win98/app themes pending |
| Real Mesa resources | [graphics checkpoint](DIRECTX_GRAPHICS_CONTINUATION_6970.md), `ntwddm/graphics_backend` | Actual private resources/pixels and guest lifecycle verified; full DirectX COM/device APIs pending |
| Wine graphics/compiler | [port guide](DIRECTX_WINE_PORT_6970.md), `ntwddm/win64/directx_wine_port` | 107 genuine AMD64 objects and normal shader tests verified; memory-leak repair and linked/runtime API libraries pending |
| DirectWrite | [probe guide](DIRECTWRITE_PROBE_6970.md), `ntwddm/win64/dwrite_probe` | Real glyph analysis/Latin framebuffer progress; Korean layout/raster and normal exit FAIL/unverified |
| TLS/SSPI | [integration](TLS_SSPI_INTEGRATION_6970.md), `ntwin32/secure_transport` | Real host protocol/lifetime and i486/OEM PE checks; native communication and OS integration pending |
| Required modern apps | [runtime gaps](REQUIRED_APPS_RUNTIME_GAPS_6970.md), [loader comparison](MEMORY_RUNTIME_LOADER_AUDIT_6970.md) | Office requires genuine D3D11/DXGI; Signal has unresolved application startup failure |

Python 3, GCC and Clang with sanitizers, both MinGW toolchains, binutils,
Bison/Flex, FAT utilities, QEMU and matching firmware are component-specific
prerequisites. Follow each guide's explicit upstream commit/archive hash,
licenses and actual command arguments. The private runtime/font/native-media
prerequisites are different for each test. A checkout alone does not supply
licensed Windows installation files or app payloads.

A small source-only verifier can run immediately:

```sh
python3 -B -m unittest discover -s ntwddm/win98/theme_composition -p 'test_*.py'
```

The publication recheck passed all 14 of these builder/verifier tests. Host
and parser checks do not constitute a new Windows 98 trial. Read skip counts
in other suites: historical fixture or compiler-dependent cases may skip on
a fresh host, as documented in the DirectWrite guide.

## Private evidence and resource handling

Keep original VM/media and failed/successful receipts intact. Use a private COW
per native trial, a fresh output directory/nonce, no uncontrolled parallel VM
writes, and independently check KVM descriptors, final pixels, source hashes,
normal child exit and reaping. Keep the unchanged 20 GiB free-space floor,
256 MiB private write limit and 16 MiB host output limit. Budget additional
room for source closures, compiler outputs and ISO staging before allocation.

A separate disk optimizer recovered exact allocated blocks without deleting
originals, source/license trees or VM evidence. The latest bounded cache pass
reclaimed 50,470,912 bytes; it is not credited with unrelated global free-space
changes. Its historical checkpoint SHA-256 is
`9010e7368d7cec9fedaacb8a06c69288001340a24f1fc1db7dc35d9f396e1925`.
The separate four-pair 889,573,376-byte sharing plan was a potential estimate,
not an executed/reclaimed result at this checkpoint. It must not be claimed
as completed cleanup.

Before reporting a release, verify the exact remote main SHA, ISO source
receipt/member/license hashes, real boot results, published download checksum
and outside-host HTTPS homepage. Loopback success does not prove the public
edge. On 2026-10-01 public-DNS HTTPS requests with a normal browser User-Agent
returned the Korean/English homepages and redirected old VNC URLs to `/`,
but the actual automated Chrome browser and independent web fetch remained
Cloudflare-blocked. Outside-host browser and new ISO publication acceptance
remain pending. Preserve both results rather than calling the whole deployment
PASS.
