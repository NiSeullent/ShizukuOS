/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 consumer of the boot route's installed-target identity
 * (shz_bootinfo_t.install, routing02 contract C2/C3).  The writer verified
 * \SHZDOS\SHZBOOT.MAN against the loaded bytes; this file only accepts a
 * well-formed record, keeps a private copy and reports it.  Install ids are
 * opaque target identities, not secrets or credentials.
 */
#include "k64.h"
#include "install_identity.h"

static shz_install_identity_t g_install;
static int g_install_attested;

static int instid_zero(const uint8_t *p, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i)
        if (p[i]) return 0;
    return 1;
}

static const char *instid_route(uint32_t flags)
{
    return flags == SHZ_INSTID_SUPERVISOR ? "ShizukuCore manifest admission" :
           flags == SHZ_INSTID_UEFI_DIRECT ? "UEFI boot manager mode=kernel64" :
           flags == SHZ_INSTID_MULTIBOOT ? "BIOS Multiboot stub" : "unknown";
}

int k64_install_identity_init(const shz_bootinfo_t *bi)
{
    shz_install_identity_t copy;
    const uint32_t routes = SHZ_INSTID_SUPERVISOR | SHZ_INSTID_UEFI_DIRECT | SHZ_INSTID_MULTIBOOT;

    memset(&g_install, 0, sizeof g_install);
    g_install_attested = 0;
    if (!bi || !SHZ_BOOTINFO_HAS(bi, install)) {
        kprintf("K64 install identity: unattested (boot info has no install identity; historical route)\n");
        return 1;
    }
    memcpy(&copy, &bi->install, sizeof copy);       /* single read of the writer's record */
    if (instid_zero((const uint8_t *)&copy, sizeof copy)) {
        kprintf("K64 install identity: unattested (no SHZBOOT.MAN verified by the boot route; historical route)\n");
        return 1;
    }
    if (copy.magic != SHZ_INSTID_MAGIC || !copy.flags || (copy.flags & ~routes) || (copy.flags & (copy.flags - 1)) ||
        !copy.install_generation || instid_zero(copy.install_id, sizeof copy.install_id) ||
        instid_zero(copy.entries_sha256, sizeof copy.entries_sha256)) {
        kprintf("K64 install identity: MALFORMED record (magic %x flags %x generation %llu); not attested\n",
                copy.magic, copy.flags, (unsigned long long)copy.install_generation);
        return -1;
    }
    memcpy(&g_install, &copy, sizeof g_install);
    g_install_attested = 1;
    kprintf("K64 install identity: attested generation %llu via %s, manifest table %02x%02x%02x%02x%02x%02x%02x%02x\n",
            (unsigned long long)g_install.install_generation, instid_route(g_install.flags),
            g_install.entries_sha256[0], g_install.entries_sha256[1], g_install.entries_sha256[2],
            g_install.entries_sha256[3], g_install.entries_sha256[4], g_install.entries_sha256[5],
            g_install.entries_sha256[6], g_install.entries_sha256[7]);
    return 0;
}

uint64_t k64_install_generation(void)
{
    return g_install_attested ? g_install.install_generation : 0;
}

const shz_install_identity_t *k64_install_identity(void)
{
    return g_install_attested ? &g_install : 0;
}
