/* SPDX-License-Identifier: GPL-2.0-only */
#include "../broker.h"
#include <stddef.h>
_Static_assert(sizeof(struct ntwp_submit) == 40, "broker input layout");
_Static_assert(sizeof(struct ntwp_open_info) == 32, "broker open layout");
_Static_assert(sizeof(struct ntwp_reply) == 80, "broker reply layout");
_Static_assert(offsetof(struct ntwp_reply, payload) == 16,
               "reply payload offset");
_Static_assert(offsetof(struct ntwp_submit, deadline_ns) == 16,
               "deadline offset");
