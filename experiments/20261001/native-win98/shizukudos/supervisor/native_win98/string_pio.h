/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_STRING_PIO_H
#define SHZ_WIN98_STRING_PIO_H
#include <stdint.h>
/* Only actual domain-owned guest physical memory is returned by this callback. */
typedef struct {
    void *opaque;
    uint8_t *(*physical)(void *, uint32_t gpa, unsigned bytes, int write);
    uint32_t cr0, cr3, cr4;
    unsigned cpl;
} w98_memory_t;
typedef struct {
    uint64_t index, count;
    uint32_t segment_base, segment_limit, segment_ar;
    unsigned address_bits, width, input, repeat, direction_down, alignment_check, segment_is_ss;
    uint16_t port;
} w98_string_io_t;
typedef struct {
    unsigned vector, error;
    uint32_t linear;
    unsigned completed;
} w98_io_fault_t;
typedef struct {
    void *opaque;
    int (*input)(void *, uint16_t, unsigned, uint32_t *);
    int (*output)(void *, uint16_t, unsigned, uint32_t);
} w98_ports_t;
/* 0 complete, 1 bounded progress/re-enter, -1 architectural fault,
 * -2 unsupported addressing/physical mapping, -3 unsupported port.
 * A failing transfer performs no port operation for that element. */
int w98_string_pio(w98_memory_t *, w98_string_io_t *, const w98_ports_t *, w98_io_fault_t *, unsigned budget);
#endif
