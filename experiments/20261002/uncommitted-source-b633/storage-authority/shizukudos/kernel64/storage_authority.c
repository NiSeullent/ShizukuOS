/* SPDX-License-Identifier: GPL-2.0-only */
#include "storage_authority.h"
#include "../kcommon/pma_sync.h"

#define IO_SLOTS 64u
#define CLAIM_SLOTS BLK_MAX_DEVICES
enum { CLAIM_ACTIVE = 1, CLAIM_REVOKING, CLAIM_TAINTED, CLAIM_CLOSED };
enum { MOUNT_RESERVED = 1, MOUNT_COMMITTED };
struct device_record {
    blk_dev_t *dev, *parent;
    uint64_t identity, generation, sectors, start;
    uint32_t sector_size;
    unsigned uncertain;
};
struct storage_claim {
    const void *owner;
    blk_dev_t *whole;
    uint64_t identity, generation;
    unsigned state, inflight;
};
struct io_record {
    uint64_t token;
    blk_dev_t *chain[BLK_MAX_DEVICES];
    unsigned depth, operation, mutating_control;
    storage_claim_t *claim;
};
struct mount_record {
    uint64_t token, generation;
    fsnode_t *root;
    fsvol_t *volume;
    blk_dev_t *dev, *whole;
    unsigned state;
};
static struct device_record devices[BLK_MAX_DEVICES];
static struct io_record ios[IO_SLOTS];
static struct storage_claim claims[CLAIM_SLOTS];
static struct mount_record mounts[VFS_MAX_MOUNTS];
static unsigned device_count, claim_count, mutating_controls;
static uint64_t next_token = 1;
static pma_ticketlock_t admission;

static uint64_t enter(uint32_t *ticket)
{
    uint64_t flags = irq_save();
    *ticket = pma_ticket_lock(&admission);
    return flags;
}
static void leave(uint32_t ticket, uint64_t flags)
{
    (void)pma_ticket_unlock(&admission, ticket);
    irq_restore(flags);
}
static struct device_record *record(blk_dev_t *dev)
{
    for (unsigned i = 0; i < device_count; ++i)
        if (devices[i].dev == dev) return &devices[i];
    return 0;
}
static int stable(const struct device_record *r)
{
    return r && r->generation && r->dev->parent == r->parent &&
           r->dev->sector_size == r->sector_size && r->dev->sectors == r->sectors &&
           r->dev->start_lba == r->start && r->dev->reg_index + 1ull == r->identity;
}
/* Every link is registered, extent-checked and visited at most once. */
static int normalize(blk_dev_t *dev, uint64_t lba, unsigned count,
                     int ranged, int writing, struct io_record *out,
                     uint64_t *absolute)
{
    unsigned depth = 0;
    for (;;) {
        struct device_record *r = record(dev);
        if (!stable(r) || depth == BLK_MAX_DEVICES || !dev->sector_size ||
            dev->sectors > UINT64_MAX / dev->sector_size ||
            (writing && (dev->flags & BLK_F_READONLY))) return -1;
        for (unsigned i = 0; i < depth; ++i) if (out->chain[i] == dev) return -1;
        if (ranged && (!count || lba >= dev->sectors || count > dev->sectors - lba)) return -1;
        out->chain[depth++] = dev;
        if (!dev->parent) break;
        struct device_record *parent = record(dev->parent);
        if (!stable(parent) || parent->sector_size != dev->sector_size ||
            dev->start_lba > parent->sectors || dev->sectors > parent->sectors - dev->start_lba ||
            lba > UINT64_MAX - dev->start_lba) return -1;
        lba += dev->start_lba;
        dev = dev->parent;
    }
    out->depth = depth;
    *absolute = lba;
    return 0;
}
static int protected_whole(blk_dev_t *whole)
{
    for (unsigned i = 0; i < device_count; ++i) {
        struct io_record path = {0}; uint64_t ignored;
        if ((devices[i].dev->flags & BLK_F_MOUNTED) &&
            (normalize(devices[i].dev, 0, 0, 0, 0, &path, &ignored) ||
             path.chain[path.depth - 1] == whole)) return 1;
    }
    for (unsigned i = 0; i < VFS_MAX_MOUNTS; ++i)
        if (mounts[i].state && mounts[i].whole == whole) return 1;
    for (unsigned i = 0; i < claim_count; ++i)
        if (claims[i].state != CLAIM_CLOSED && claims[i].whole == whole) return 1;
    return 0;
}
static int globally_protected(void)
{
    for (unsigned i = 0; i < device_count; ++i)
        if ((devices[i].dev->flags & BLK_F_MOUNTED) || devices[i].uncertain) return 1;
    for (unsigned i = 0; i < VFS_MAX_MOUNTS; ++i) if (mounts[i].state) return 1;
    for (unsigned i = 0; i < claim_count; ++i)
        if (claims[i].state != CLAIM_CLOSED) return 1;
    return 0;
}
static int inflight(blk_dev_t *whole)
{
    for (unsigned i = 0; i < IO_SLOTS; ++i)
        if (ios[i].token && (!whole || ios[i].chain[ios[i].depth - 1] == whole)) return 1;
    return 0;
}
static uint64_t issue_token(void)
{
    /* No wrapping token can ever re-authorize a retired lease or callback. */
    if (!next_token || next_token == UINT64_MAX) return 0;
    return next_token++;
}
static int valid_claim(storage_claim_t *claim)
{
    for (unsigned i = 0; i < claim_count; ++i) if (claim == &claims[i]) return 1;
    return 0;
}
int storage_device_register(blk_dev_t *dev, blk_dev_t **head,
                            blk_dev_t **tail, unsigned *count)
{
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1;
    if (!dev || !head || !tail || !count || device_count == BLK_MAX_DEVICES ||
        *count != device_count || !dev->sector_size || !dev->sectors || !dev->read ||
        dev->sectors > UINT64_MAX / dev->sector_size || !dev->name[0]) goto done;
    unsigned length = 0;
    while (length < BLK_NAME_MAX && dev->name[length]) ++length;
    if (length == BLK_NAME_MAX) goto done;
    for (unsigned i = 0; i < device_count; ++i)
        if (devices[i].dev == dev || !strcmp(devices[i].dev->name, dev->name)) goto done;
    if (dev->parent) {
        struct device_record *p = record(dev->parent);
        if (!stable(p) || dev->sector_size != p->sector_size ||
            dev->start_lba > p->sectors || dev->sectors > p->sectors - dev->start_lba) goto done;
    } else if (dev->start_lba || (dev->flags & BLK_F_PARTITION)) goto done;
    struct device_record *r = &devices[device_count];
    *r = (struct device_record){dev, dev->parent, device_count + 1ull, 1,
                               dev->sectors, dev->start_lba, dev->sector_size, 0};
    dev->reg_index = device_count; dev->next = 0;
    if (*tail) (*tail)->next = dev; else *head = dev;
    *tail = dev; ++device_count; *count = device_count;
    rc = 0;
done:
    leave(ticket, flags); return rc;
}
int storage_device_identity(blk_dev_t *dev, storage_identity_t *out)
{
    if (!out) return -1;
    uint32_t ticket; uint64_t flags = enter(&ticket); struct io_record path = {0}; uint64_t ignored;
    int rc = normalize(dev, 0, 0, 0, 0, &path, &ignored);
    if (!rc) {
        struct device_record *r = record(path.chain[path.depth - 1]);
        if (r->uncertain) rc = -1;
        else *out = (storage_identity_t){r->dev, r->identity, r->generation};
    }
    leave(ticket, flags); return rc;
}
int storage_user_write_busy(blk_dev_t *dev)
{
    uint32_t ticket; uint64_t flags = enter(&ticket); struct io_record path = {0}; uint64_t ignored;
    int busy = normalize(dev, 0, 0, 0, 1, &path, &ignored) != 0;
    if (!busy) {
        blk_dev_t *whole = path.chain[path.depth - 1];
        busy = record(whole)->uncertain || mutating_controls || protected_whole(whole) || inflight(whole);
    }
    leave(ticket, flags); return busy;
}
int storage_io_begin(blk_dev_t *dev, unsigned operation, uint64_t lba,
                     unsigned count, unsigned control,
                     storage_claim_t *claim, const void *actual_owner,
                     storage_io_lease_t *out)
{
    if (!out) return -1;
    *out = (storage_io_lease_t){0};
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1; struct io_record path = {0}; uint64_t absolute;
    int mutation = operation == STORAGE_CONTROL && control != BLK_CTL_STATS;
    int stats = operation == STORAGE_CONTROL && control == BLK_CTL_STATS;
    if (operation > STORAGE_CONTROL || (operation == STORAGE_CONTROL &&
        (control < BLK_CTL_RESET || control > BLK_CTL_ERROR_TEST)) ||
        normalize(dev, lba, count, operation == STORAGE_READ || operation == STORAGE_WRITE || operation == STORAGE_DISCARD,
                  operation == STORAGE_WRITE || operation == STORAGE_DISCARD, &path, &absolute)) goto done;
    blk_dev_t *whole = path.chain[path.depth - 1]; struct device_record *r = record(whole);
    if ((!stats && (r->uncertain || mutating_controls)) ||
        (mutation && (globally_protected() || inflight(0)))) goto done;
    for (unsigned i = 0; i < claim_count; ++i)
        if (claims[i].state != CLAIM_CLOSED && claims[i].whole == whole && &claims[i] != claim) goto done;
    if (claim && (!valid_claim(claim) || claim->state != CLAIM_ACTIVE ||
        claim->owner != actual_owner || claim->whole != whole ||
        claim->identity != r->identity || claim->generation != r->generation ||
        operation == STORAGE_CONTROL || operation == STORAGE_DISCARD)) goto done;
    unsigned slot = 0;
    while (slot < IO_SLOTS && ios[slot].token) ++slot;
    if (slot == IO_SLOTS) goto done;
    path.token = issue_token(); if (!path.token) goto done;
    path.operation = operation; path.mutating_control = mutation; path.claim = claim;
    ios[slot] = path; if (claim) ++claim->inflight;
    if (mutation) ++mutating_controls;
    *out = (storage_io_lease_t){path.token, whole, absolute}; rc = 0;
done:
    leave(ticket, flags); return rc;
}
void storage_io_uncertain(const storage_io_lease_t *lease)
{
    if (!lease || !lease->opaque) return;
    uint32_t ticket; uint64_t flags = enter(&ticket);
    for (unsigned i = 0; i < IO_SLOTS; ++i) if (ios[i].token == lease->opaque) {
        record(ios[i].chain[ios[i].depth - 1])->uncertain = 1;
        if (ios[i].claim) ios[i].claim->state = CLAIM_TAINTED;
        break;
    }
    leave(ticket, flags);
}
int storage_io_end(storage_io_lease_t *lease, int status, unsigned accounting)
{
    if (!lease || !lease->opaque) return -1;
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1;
    for (unsigned i = 0; i < IO_SLOTS; ++i) if (ios[i].token == lease->opaque) {
        struct io_record *io = &ios[i];
        unsigned depth = accounting == STORAGE_ACCOUNT_REQUEST ? 1 : io->depth;
        for (unsigned j = 0; j < depth; ++j) {
            blk_dev_t *dev = io->chain[j];
            if (status) ++dev->errors;
            else if (io->operation == STORAGE_FLUSH) ++dev->flushes;
            else if (io->operation == STORAGE_DISCARD && !j) ++dev->discards;
        }
        if (io->claim) {
            --io->claim->inflight;
            if (status && io->operation != STORAGE_READ) io->claim->state = CLAIM_TAINTED;
        }
        if (io->mutating_control) {
            --mutating_controls;
            /* Driver generation/recovery notification is deliberately absent.
             * Any mutating-control return makes this generation unsuitable for
             * subsequent authority, including a seemingly successful RESET.
             */
            record(io->chain[io->depth - 1])->uncertain = 1;
        }
        io->token = 0; *lease = (storage_io_lease_t){0}; rc = 0; break;
    }
    leave(ticket, flags); return rc;
}
int storage_mount_reserve(fsnode_t *root, fsvol_t *volume, blk_dev_t *dev,
                          storage_mount_token_t *out)
{
    if (!out) return -1;
    *out = (storage_mount_token_t){0};
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1; struct io_record path = {0}; uint64_t ignored;
    if (!root || !volume || root->vol != volume || mutating_controls ||
        normalize(dev, 0, 0, 0, 0, &path, &ignored)) goto done;
    blk_dev_t *whole = path.chain[path.depth - 1]; struct device_record *r = record(whole);
    if (r->uncertain || inflight(whole)) goto done;
    for (unsigned i = 0; i < claim_count; ++i)
        if (claims[i].whole == whole && claims[i].state != CLAIM_CLOSED) goto done;
    for (unsigned i = 0; i < VFS_MAX_MOUNTS; ++i)
        if (mounts[i].state && (mounts[i].volume == volume || mounts[i].dev == dev)) goto done;
    unsigned slot = 0; while (slot < VFS_MAX_MOUNTS && mounts[slot].state) ++slot;
    if (slot == VFS_MAX_MOUNTS) goto done;
    uint64_t token = issue_token(); if (!token) goto done;
    mounts[slot] = (struct mount_record){token, r->generation, root, volume, dev, whole, MOUNT_RESERVED};
    out->opaque = token; rc = 0;
done:
    leave(ticket, flags); return rc;
}
int storage_mount_commit(storage_mount_token_t *token)
{
    if (!token || !token->opaque) return -1;
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1;
    for (unsigned i = 0; i < VFS_MAX_MOUNTS; ++i) if (mounts[i].token == token->opaque && mounts[i].state == MOUNT_RESERVED) {
        struct mount_record *m = &mounts[i]; struct device_record *r = record(m->whole);
        /* A published namespace is never rolled back as if it were absent.
         * If its binding changed, retain the protected reservation.
         */
        if (stable(r) && !r->uncertain && r->generation == m->generation && m->root->vol == m->volume) {
            m->state = MOUNT_COMMITTED; m->dev->flags |= BLK_F_MOUNTED; token->opaque = 0; rc = 0;
        }
        break;
    }
    leave(ticket, flags); return rc;
}
int storage_mount_abort(storage_mount_token_t *token)
{
    if (!token || !token->opaque) return -1;
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1;
    for (unsigned i = 0; i < VFS_MAX_MOUNTS; ++i) if (mounts[i].token == token->opaque && mounts[i].state == MOUNT_RESERVED) {
        mounts[i] = (struct mount_record){0}; token->opaque = 0; rc = 0; break;
    }
    leave(ticket, flags); return rc;
}
int storage_backing_snapshot(const fsnode_t *node, storage_identity_t *out)
{
    if (!node || !out || node->backing != FSB_DISK || !node->vol) return -1;
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1;
    for (unsigned i = 0; i < VFS_MAX_MOUNTS; ++i) {
        struct mount_record *m = &mounts[i]; struct device_record *r = record(m->whole);
        if (m->state == MOUNT_COMMITTED && m->volume == node->vol &&
            m->root->vol == m->volume && stable(r) && !r->uncertain && r->generation == m->generation) {
            *out = (storage_identity_t){r->dev, r->identity, r->generation}; rc = 0; break;
        }
    }
    leave(ticket, flags); return rc;
}

#ifdef SHZ_STORAGE_AUTHORITY_HOST_TEST
struct storage_source_set { const void *owner; unsigned count; blk_dev_t *excluded[BLK_MAX_DEVICES]; };
static struct storage_source_set modeled_sources;
const storage_source_set_t *storage_test_provenance(const void *owner, blk_dev_t *const *excluded, unsigned count)
{
    if (!owner || count > BLK_MAX_DEVICES || (count && !excluded)) return 0;
    uint32_t ticket; uint64_t flags = enter(&ticket);
    modeled_sources.owner = owner; modeled_sources.count = count;
    for (unsigned i = 0; i < count; ++i) modeled_sources.excluded[i] = excluded[i];
    leave(ticket, flags); return &modeled_sources;
}
static int proof_known(const void *owner, blk_dev_t *whole, const storage_source_set_t *sources)
{
    if (sources != &modeled_sources || sources->owner != owner) return 0;
    for (unsigned i = 0; i < sources->count; ++i) {
        struct io_record path = {0}; uint64_t ignored;
        if (normalize(sources->excluded[i], 0, 0, 0, 0, &path, &ignored) || path.chain[path.depth - 1] == whole) return 0;
    }
    return 1;
}
#else
static int proof_known(const void *owner, blk_dev_t *whole, const storage_source_set_t *sources)
{ (void)owner; (void)whole; (void)sources; return 0; }
#endif
int storage_claim_acquire(const void *owner, blk_dev_t *whole,
                          const storage_source_set_t *sources, storage_claim_t **out)
{
    if (!out) return -1;
    *out = 0;
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1;
    struct device_record *r = record(whole);
    if (!owner || !stable(r) || whole->parent || r->uncertain ||
        !proof_known(owner, whole, sources) || mutating_controls ||
        protected_whole(whole) || inflight(whole) || claim_count == CLAIM_SLOTS) goto done;
    storage_claim_t *claim = &claims[claim_count++];
    *claim = (storage_claim_t){owner, whole, r->identity, r->generation, CLAIM_ACTIVE, 0};
    *out = claim; rc = 0;
done:
    leave(ticket, flags); return rc;
}
static int claim_io(storage_claim_t *claim, const void *owner, unsigned operation,
                    uint64_t lba, unsigned count, void *buffer)
{
    /* Never dereference an unvalidated opaque claim pointer. */
    uint32_t ticket; uint64_t flags = enter(&ticket);
    blk_dev_t *dev = valid_claim(claim) ? claim->whole : 0;
    leave(ticket, flags);
    storage_io_lease_t lease;
    if (!dev || ((operation == STORAGE_READ || operation == STORAGE_WRITE) && !buffer) ||
        storage_io_begin(dev, operation, lba, count, 0, claim, owner, &lease)) return -1;
    int rc;
    if (operation == STORAGE_READ) rc = dev->read ? dev->read(dev, lease.lba, count, buffer) : -1;
    else if (operation == STORAGE_WRITE) rc = dev->write ? dev->write(dev, lease.lba, count, buffer) : -1;
    else rc = dev->flush ? dev->flush(dev) : 0;
    (void)storage_io_end(&lease, rc, STORAGE_ACCOUNT_CHAIN); return rc;
}
int storage_claim_read(storage_claim_t *claim, const void *owner, uint64_t lba, unsigned count, void *buffer)
{ return claim_io(claim, owner, STORAGE_READ, lba, count, buffer); }
int storage_claim_write(storage_claim_t *claim, const void *owner, uint64_t lba, unsigned count, const void *buffer)
{ return claim_io(claim, owner, STORAGE_WRITE, lba, count, (void *)buffer); }
int storage_claim_flush(storage_claim_t *claim, const void *owner)
{ return claim_io(claim, owner, STORAGE_FLUSH, 0, 0, 0); }
int storage_claim_release(storage_claim_t *claim, const void *owner)
{
    uint32_t ticket; uint64_t flags = enter(&ticket); int rc = -1;
    if (valid_claim(claim) && claim->owner == owner && claim->state != CLAIM_CLOSED) {
        if (claim->state != CLAIM_TAINTED) {
            claim->state = CLAIM_REVOKING;
            if (!claim->inflight) { claim->state = CLAIM_CLOSED; rc = 0; }
        }
    }
    leave(ticket, flags); return rc;
}
void storage_claim_revoke_owner(const void *owner)
{
    uint32_t ticket; uint64_t flags = enter(&ticket);
    for (unsigned i = 0; i < claim_count; ++i) if (claims[i].owner == owner && claims[i].state == CLAIM_ACTIVE)
        claims[i].state = claims[i].inflight ? CLAIM_REVOKING : CLAIM_CLOSED;
    leave(ticket, flags);
}
