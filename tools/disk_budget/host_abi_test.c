/* SPDX-License-Identifier: GPL-2.0-only */
/* Check the installed Linux UAPI. This program never invokes an ioctl. */
#include <linux/fs.h>
#include <stddef.h>
#include <stdio.h>

_Static_assert(sizeof(struct file_dedupe_range) == 24, "header");
_Static_assert(offsetof(struct file_dedupe_range, info) == 24, "array offset");
_Static_assert(sizeof(struct file_dedupe_range_info) == 32, "destination info");
_Static_assert(offsetof(struct file_dedupe_range_info, bytes_deduped) == 16, "result bytes");
_Static_assert(offsetof(struct file_dedupe_range_info, status) == 24, "status");
_Static_assert(FIDEDUPERANGE == 0xC0189436UL, "host ioctl number");

int main(void)
{
    printf("PASS installed Linux UAPI: header=%zu, destination=%zu, one-request=%zu, "
           "ioctl=0x%lx; no ioctl invoked\n", sizeof(struct file_dedupe_range),
           sizeof(struct file_dedupe_range_info),
           sizeof(struct file_dedupe_range) + sizeof(struct file_dedupe_range_info),
           (unsigned long)FIDEDUPERANGE);
    return 0;
}
