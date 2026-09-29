# Windows 98 native V86 loader diagnosis

On 2026-09-27, a fresh copy of the installed Korean Windows 98 SE guest,
without KernelEx, executed the original `NTWLDR.COM` diagnostic. The actual
VXDLDR load call returned **CF=1, AX=0006**; the DOS program exited **5**.
The archived Win98 declaration names error 6
[`VXDLDR_ERR_BAD_DEVICE_FILE`](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/VXDLDR.INC).
This narrows the earlier Win32 error 2, but does not identify the rejected field.

The candidate was the same isolated data-SHARABLE-bit experiment from
[the prior trial](VXD_LOADER_TRIAGE.md): 9,390 bytes, SHA-256
`83952d5c220272d4dbd724e309e29fcc431d2eefa0e59253d3283a116fc0801e`.
The diagnostic compared every byte against its embedded expectation, required
EOF, and successfully closed the read handle before calling the loader.
Only file offset 356 differs from the original VxD: `43` to `63` hex.
The production VxD remains unchanged.

The V86 entry was `FDA9:2087`; the version call returned CF=0, AX=0000,
DX=040A. These are recorded register values. Loading used AX=1 and the fixed
path `C:\NTWLAB\NTWRAP9X.VXD`. The returned FLAGS/AX/DX were saved before
flag-changing instructions. The failed load did not authorize an unload call.
The log ends before final close, so a separate DOS batch captured the actual
exit code. No kernel initialization, VMM service call or Win32 DIOC pass follows.

The 22,176-byte COM SHA-256 is
`d203ba8fb79658f633c5647ed8790795ca55e9f5ff9a8365f04fbb642db4d1ff`.
Before the guest trial, its actual instructions passed 731 synthetic Unicorn
scenarios and 72,827 checks, including raw register preservation, every log-write
position, short writes and ownership cleanup. Those host tests model the external
interfaces; this guest failure is the separate native result. See
[the diagnostic source and contract](../ntwrapper/vxd/v86diag/README.md).

The private QA guest ran with KVM, 128 MiB RAM, no network device and a read-only
diagnostic CD. The supervisor stopped it after 110.409 seconds. A disk-reserve
guard retained the stopped RAM image when its initial stop receipt could not be
published; explicit recovery later verified it and recorded the stopped state.
The baseline pointer and archived installation remained unchanged. Six extracted
guest files match the media where applicable; 27 evidence files totaling 682,077
bytes were sealed with manifest SHA-256
`d9f02a2cb7d115a2a89a71ac528a5651609559da124293b4fe5e3d2adfb65992`.

[The machine-readable receipt](VXD_V86_LOADER_TRIAL.json) contains exact logs,
file hashes, source disk identity and QA disposition. The next kernel experiment
should isolate LE container/DDB acceptance with a minimal driver before adding
more VMM service behavior. This result does not validate NTWrapper9x installation
or Chromium execution.
