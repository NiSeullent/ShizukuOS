# Pre-Beta 01 site preparation

The Korean and English home, download and setup pages distinguish the pending
Pre-Beta 01 installer from the available component ZIPs. The main download
button links directly to the existing combined component package.
The development pages describe the current Core hierarchy; the app pages keep
their historical observations while updating the next integration target.

This change supplies release-page copy. It does not create an ISO, run a VM,
change nginx or publish the site. Original component downloads, application
statuses, screenshots and their original Microsoft DOS control-test scope are
preserved. The full 1.0.0 goals remain active.

Pre-Beta 01 publication requires actual results for a stated supported subset:

1. Actual Windows 98 userland boots and performs window, input and file work,
   with real ShizukuCore service requests and results in the same system.
2. The project installer writes and verifies a UEFI target disk.
3. The installed system cold boots with the installation ISO detached.
4. The installed GOP basic display driver produces output, and installed core
   drivers are identified.

The first validation target is an x86_64 UEFI virtual machine. These draft
pages mark all four checks as pending. They offer no ISO download and claim no
modern application functionality in this release. Those application targets
remain part of the full project goal.

The user's 2026-10-03 hierarchy places ShizukuDOS (SZRm), Shizuku32 (SZPrtm),
Shizuku64 (SZLm) and ShizukuOS (Windows 98) below ShizukuCore Kernel. This is the
transition target, not a claim that the common core is already implemented.
The [phase contract](SHIZUKU_HYBRID_TRANSITION.md) describes gradual ownership
transfer. The tested release must identify its stage, actual API/service owners
and any remaining original DOS/VMM dependencies. The earlier requirement to
replace DOS does not impose a permanent ceiling on the final kernel. Historical
control results keep their original scope.

Windows installation files, product keys and personal installed disks stay
private. Publishing a private Windows-bearing installer as a project-only ISO
is prohibited. The actual public installer and local user-owned media procedure
need their own matching execution evidence. Carrying an untouched Windows ISO
on USB does not establish installation or hybrid service integration.

At publication, the publisher must use the accepted public artifact's actual
size, SHA-256, source revision and supported conditions. Update the home status,
primary download button and component ZIP caption as well as the existing
`M98:DEVELOPMENT-ISO` slots and `prebeta-checks` sections. Leave the strict
full-product and standalone development acceptance rules intact.

Fresh validation exercised the existing static publisher's actual
`prepare_assets` path without publication. All 100 assets matched the reviewed
preparation: ten changed HTML pages and 90 unchanged files. Independent review
confirmed the same download bytes/checksums, 48 recorded frames per language,
app observations, valid new local links and unchanged strict validation code.
Historical screenshots keep their original control-test scope. Static
preparation evidence does not establish a browser render, external network or
guest installation result.
