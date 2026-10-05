/* SPDX-License-Identifier: GPL-2.0-only
 * Binds the account realm store (auth_policy.h shz_auth_store_ops) to the ShizukuFS atomic record store on the
 * installed system volume (sfs_mount.h). Without a read/write installed volume nothing is attached and the realm
 * stays volatile; a present-but-unreadable record seals the realm inside sysk32_auth.c (fail closed).
 */
#include "k64.h"
#include "auth_policy.h"
#include "sfs_mount.h"
#include "../../shizukufs/v1/libsfs/sfs.h"

#define K64_AUTH_RECORD "REALM"

/* One protected store directory: the auth deny-list constant is the record wall. */
_Static_assert(sizeof(SHZ_AUTH_STORE_DIR) == sizeof(SFSK_ACCOUNT_DIR), "auth store dir != SFS account wall");
static char store_dir[3 + sizeof(SHZ_AUTH_STORE_DIR)];   /* "X:" + SHZ_AUTH_STORE_DIR */

static int store_load(void *ctx, void *buf, size_t cap, size_t *len)
{
    uint32_t got = 0;
    uint64_t seq = 0;
    int rc;
    (void)ctx;
    if (!buf || !len || cap > SFSK_RECORD_MAX || !store_dir[0]) return -1;
    rc = sfsk_record_get(store_dir, K64_AUTH_RECORD, buf, (uint32_t)cap, &got, &seq);
    if (rc == SFS_ENOENT) return SHZ_AUTH_STORE_ABSENT;
    if (rc) return rc < 0 ? rc : -1;
    *len = got;
    return 0;
}

static int store_commit(void *ctx, const void *buf, size_t len)
{
    uint64_t seq = 0;
    (void)ctx;
    if (!buf || !len || len > SFSK_RECORD_MAX || !store_dir[0]) return -1;
    return sfsk_record_put(store_dir, K64_AUTH_RECORD, buf, (uint32_t)len, &seq) ? -1 : 0;
}

/* Once after volumes mount and before any user process. */
void k64_auth_store_bind(void)
{
    static const shz_auth_store_ops ops = { store_load, store_commit, 0 };
    int writable = 0;
    uint32_t accounts = 0;
    const char vol = sfsk_system_volume(&writable);
    int32_t rc;
    int state;
    if (!vol || !writable) {
        kprintf("K64 auth: no read/write installed ShizukuFS system volume; realm store volatile\n");
        return;
    }
    if (strcmp(SHZ_AUTH_STORE_DIR, SFSK_ACCOUNT_DIR)) {
        kprintf("K64 auth: store directory differs from the SFS account wall; realm store not attached\n");
        return;
    }
    store_dir[0] = vol;
    store_dir[1] = ':';
    memcpy(store_dir + 2, SHZ_AUTH_STORE_DIR, sizeof(SHZ_AUTH_STORE_DIR));
    rc = shz_auth_store_attach(&ops);
    state = shz_auth_store_state(&accounts);
    kprintf("K64 auth: realm store %s attach=%d state=%s accounts=%u\n", store_dir, (int)rc,
            state == SHZ_AUTH_STORE_PERSISTENT ? "persistent" : state == SHZ_AUTH_STORE_SEALED ? "SEALED" : "volatile",
            accounts);
}
