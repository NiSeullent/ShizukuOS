/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/csmwrap_abi.h"

static char text[192];
static unsigned used;

void csmwrap_diag_reset(void)
{
    unsigned i;
    used = 0;
    for (i = 0; i < sizeof text; ++i)
        text[i] = 0;
}

void csmwrap_diag_note(const char *message)
{
    unsigned i;
    if (!message)
        return;
    for (i = 0; message[i] && used + 1 < sizeof text; ++i)
        text[used++] = message[i];
    text[used] = 0;
}

const char *csmwrap_diag_text(void)
{
    return text;
}
