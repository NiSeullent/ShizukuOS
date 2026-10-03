# Pre-Beta 01 site preparation

The Korean and English home, download and setup pages distinguish the pending
Pre-Beta 01 installer from the available component ZIPs. The main download
button links directly to the existing combined component package.

This change supplies release-page copy. It does not create an ISO, run a VM,
change nginx or publish the site. Original component downloads, application
statuses, screenshots and their original Microsoft DOS control-test scope are
preserved. The full 1.0.0 goals remain active.

Pre-Beta 01 publication requires actual results for a stated supported subset:

1. Actual Windows 98 boots on source-built ShizukuDOS.
2. The project installer writes and verifies a UEFI target disk.
3. The installed system cold boots with the installation ISO detached.
4. The installed GOP basic display driver produces output, and installed core
   drivers are identified.

The first validation target is an x86_64 UEFI virtual machine. These draft
pages mark all four checks as pending. They offer no ISO download and claim no
modern application functionality in this release. Those application targets
remain part of the full project goal.

Windows installation files, product keys and personal installed disks stay
private. Publishing a private Windows-bearing installer as a project-only ISO
is prohibited. The actual public installer and local user-owned media procedure
need their own matching execution evidence. Carrying an untouched Windows ISO
on USB does not establish installation or ShizukuDOS integration.

At publication, the publisher must use the accepted public artifact's actual
size, SHA-256, source revision and supported conditions. Update the home status,
primary download button and component ZIP caption as well as the existing
`M98:DEVELOPMENT-ISO` slots and `prebeta-checks` sections. Leave the strict
full-product and standalone development acceptance rules intact.

Preparation validation exercised the existing static publisher's actual
`prepare_assets` path without publication. All 100 assets matched the reviewed
preparation, with six changed HTML pages and 94 unchanged files. Independent
review confirmed localized download cards, checksums and 48 recorded frames per
language. This is static preparation evidence, not a browser render, external
network or guest installation result.
