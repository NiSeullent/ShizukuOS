/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWG98_ADAPTER_H
#define NTWG98_ADAPTER_H
#include "../include/ntwddm.h"

#define NTWG98_E_PLATFORM (-100)
typedef struct ntwg98_dib {
    void *handle;
    void *pixels;
    size_t bytes;
    uint32_t pitch;
} ntwg98_dib;
typedef struct ntwg98_ops {
    ntwg_allocate_fn allocate;
    ntwg_deallocate_fn deallocate;
    /* A failed create must retain any partial resources in dib.handle. */
    int (*create)(void *, uint32_t, uint32_t, ntwg98_dib *);
    int (*sync)(void *);
    int (*paint)(void *, const ntwg98_dib *, uint32_t, uint32_t);
    /* On failure retain owned resources in dib for a later close retry. */
    int (*release)(void *, ntwg98_dib *);
} ntwg98_ops;
typedef struct ntwg98_view {
    const ntwg98_ops *ops;
    void *user;
    ntwg_context *core;
    ntwg_surface surface;
    ntwg98_dib dib;
    uint32_t width, height;
    int image_ready;
} ntwg98_view;

/* Caller supplies a zero-initialized view and serializes all calls. Ops/user
 * remain valid until close succeeds. Call close even after an open failure. */
int ntwg98_open(ntwg98_view *, const ntwg98_ops *, void *, uint32_t, uint32_t);
int ntwg98_present(ntwg98_view *, const ntwg_rect *, uint32_t, uint32_t, ntwg_fence *);
int ntwg98_paint(ntwg98_view *);
int ntwg98_close(ntwg98_view *);
/* Deterministic native/host pixel and lifetime probe; dimensions >= 16. */
int ntwg98_selftest(ntwg98_view *, uint32_t *checks);
#endif
