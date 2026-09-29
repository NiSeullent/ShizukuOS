/* SPDX-License-Identifier: GPL-2.0-only */
#include "adapter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(x) do { ++assertions; if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
typedef struct backend {
    unsigned allocations, live, create_calls, releases, syncs, paints;
    unsigned fail_allocation;
    int fail_create, partial_create, fail_sync, fail_paint, fail_release, bad_pitch;
    unsigned char *allocation;
    size_t bytes;
} backend;
static void *allocate(void *user, size_t bytes)
{
    backend *b = user;
    void *p;
    if (++b->allocations == b->fail_allocation) return NULL;
    p = malloc(bytes); if (p) ++b->live;
    return p;
}
static void deallocate(void *user, void *p, size_t bytes)
{
    backend *b = user; (void)bytes;
    CHECK(b->live > 0); --b->live; free(p);
}
static int create(void *user, uint32_t width, uint32_t height, ntwg98_dib *dib)
{
    backend *b = user;
    ++b->create_calls;
    if (b->fail_create && !b->partial_create) return 0;
    dib->pitch = width * 4u + 12u;
    b->bytes = (size_t)dib->pitch * height;
    b->allocation = malloc(b->bytes + 32u);
    CHECK(b->allocation != NULL);
    memset(b->allocation, 0xa7, b->bytes + 32u);
    dib->handle = b; dib->pixels = b->allocation + 16; dib->bytes = b->bytes;
    if (b->bad_pitch) dib->pitch = width * 4u - 1u;
    return !b->fail_create;
}
static int synchronize(void *user)
{
    backend *b = user; ++b->syncs; return !b->fail_sync;
}
static int paint(void *user, const ntwg98_dib *dib, uint32_t width, uint32_t height)
{
    backend *b = user;
    CHECK(dib->handle == b && width >= 16 && height >= 16);
    ++b->paints; return !b->fail_paint;
}
static int release(void *user, ntwg98_dib *dib)
{
    backend *b = user; unsigned i;
    ++b->releases;
    if (b->fail_release) return 0;
    CHECK(dib->handle == b);
    for (i = 0; i < 16; ++i) {
        CHECK(b->allocation[i] == 0xa7);
        CHECK(b->allocation[b->bytes + 16u + i] == 0xa7);
    }
    free(b->allocation); b->allocation = NULL; dib->handle = NULL; dib->pixels = NULL;
    return 1;
}
static const ntwg98_ops ops = { allocate, deallocate, create, synchronize, paint, release };

static void success_cases(void)
{
    const uint32_t sizes[][2] = {{16,16},{37,29},{320,200}};
    unsigned i;
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        backend b = {0}; ntwg98_view v = {0}; uint32_t checks;
        CHECK(ntwg98_open(&v, &ops, &b, sizes[i][0], sizes[i][1]) == NTWG_OK);
        {
            size_t n;
            for (n = 0; n < v.dib.bytes; ++n) CHECK(((const unsigned char *)v.dib.pixels)[n] == 0);
        }
        CHECK(ntwg98_paint(&v) == NTWG_E_INVALID && b.paints == 0);
        CHECK(ntwg98_open(&v, &ops, &b, 16,16) == NTWG_E_BUSY);
        CHECK(ntwg98_selftest(&v, &checks) == NTWG_OK);
        CHECK(checks > sizes[i][0] * sizes[i][1] * 2u);
        assertions += checks;
        CHECK(ntwg98_paint(&v) == NTWG_OK && b.paints == 1);
        CHECK(ntwg98_close(&v) == NTWG_OK && b.live == 0 && !b.allocation);
        CHECK(ntwg98_close(&v) == NTWG_OK && b.releases == 1);
        CHECK(ntwg98_paint(&v) == NTWG_E_INVALID);
    }
}
static void creation_failures(void)
{
    unsigned i;
    for (i = 1; i <= 2; ++i) {
        backend b = {0}; ntwg98_view v = {0}; b.fail_allocation = i;
        CHECK(ntwg98_open(&v, &ops, &b, 16,16) == NTWG_E_NOMEM);
        CHECK(!b.live && !b.allocation && !v.ops && !v.core);
    }
    for (i = 0; i < 2; ++i) {
        backend b = {0}; ntwg98_view v = {0}; b.fail_create = 1; b.partial_create = (int)i;
        CHECK(ntwg98_open(&v, &ops, &b, 16,16) == NTWG98_E_PLATFORM);
        CHECK(!b.live && !b.allocation && !v.ops && b.releases == i);
    }
    {
        backend b = {0}; ntwg98_view v = {0}; b.bad_pitch = 1;
        CHECK(ntwg98_open(&v, &ops, &b, 16,16) == NTWG_E_BOUNDS);
        CHECK(!b.live && !b.allocation && !v.ops);
    }
    {
        backend b = {0}; ntwg98_view v = {0}; b.fail_sync = 1;
        CHECK(ntwg98_open(&v, &ops, &b, 16,16) == NTWG98_E_PLATFORM);
        CHECK(v.ops && v.core && b.live == 1 && b.allocation);
        b.fail_sync = 0;
        CHECK(ntwg98_close(&v) == NTWG_OK && !b.live && !b.allocation);
    }
    {
        backend b = {0}; ntwg98_view v = {0}; b.fail_create = b.partial_create = b.fail_release = 1;
        CHECK(ntwg98_open(&v, &ops, &b, 16,16) == NTWG98_E_PLATFORM);
        CHECK(v.ops && v.dib.handle && !v.core && !b.live && b.allocation);
        b.fail_release = 0;
        CHECK(ntwg98_close(&v) == NTWG_OK && !b.allocation);
    }
}
static void operation_failures(void)
{
    backend b = {0}; ntwg98_view v = {0}; uint32_t checks, complete;
    ntwg_rect rect = {0,0,16,16}; ntwg_fence fence = {1,1,1};
    unsigned char snapshot[16 * (16 * 4 + 12)];
    ntwg_mapping mapping;
    CHECK(ntwg98_open(&v, &ops, &b, 16,16) == NTWG_OK);
    memcpy(snapshot, v.dib.pixels, sizeof(snapshot));
    b.fail_sync = 1;
    CHECK(ntwg98_present(&v, &rect, 0,0,&fence) == NTWG98_E_PLATFORM);
    CHECK(!fence.owner && !fence.epoch && !fence.sequence && !v.image_ready);
    CHECK(memcmp(snapshot, v.dib.pixels, sizeof(snapshot)) == 0);
    CHECK(ntwg98_close(&v) == NTWG98_E_PLATFORM && b.live == 2 && b.allocation);
    b.fail_sync = 0;
    CHECK(ntwg98_selftest(&v, &checks) == NTWG_OK);
    CHECK(ntwg98_present(&v, &rect, 0,0,&fence) == NTWG_OK);
    b.fail_paint = 1;
    CHECK(ntwg98_paint(&v) == NTWG98_E_PLATFORM);
    CHECK(ntwg_fence_query(v.core, &fence, &complete) == NTWG_OK && complete == 1);
    b.fail_paint = 0;
    CHECK(ntwg98_paint(&v) == NTWG_OK);
    memcpy(snapshot, v.dib.pixels, sizeof(snapshot));
    CHECK(ntwg98_present(&v, &rect, 1,0,&fence) == NTWG_E_BOUNDS);
    CHECK(!fence.sequence && memcmp(snapshot, v.dib.pixels, sizeof(snapshot)) == 0);
    CHECK(ntwg_surface_map(v.core, v.surface, &mapping) == NTWG_OK);
    CHECK(ntwg98_close(&v) == NTWG_E_BUSY && b.live == 2 && b.allocation);
    CHECK(ntwg_surface_unmap(v.core, v.surface) == NTWG_OK);
    b.fail_release = 1;
    CHECK(ntwg98_close(&v) == NTWG98_E_PLATFORM && !b.live && b.allocation && !v.image_ready);
    CHECK(ntwg98_paint(&v) == NTWG_E_INVALID);
    b.fail_release = 0;
    CHECK(ntwg98_close(&v) == NTWG_OK && !b.allocation);
}
int main(void)
{
    ntwg98_view v = {0}; backend b = {0};
    CHECK(ntwg98_open(NULL, &ops, &b, 16,16) == NTWG_E_INVALID);
    CHECK(ntwg98_open(&v, NULL, &b, 16,16) == NTWG_E_INVALID);
    CHECK(ntwg98_open(&v, &ops, &b, UINT32_MAX,16) == NTWG_E_BOUNDS);
    CHECK(ntwg98_open(&v, &ops, &b, 16,0) == NTWG_E_INVALID);
    CHECK(b.allocations == 0 && !v.ops);
    success_cases(); creation_failures(); operation_failures();
    printf("PASS: %u adapter/pixel/lifetime checks; host only\n", assertions);
    return 0;
}
