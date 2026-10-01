/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of libpsl (libpsl-5.dll, built-in list compiled from the pinned publicsuffix-list): public suffixes and
 * registrable domains as WebKit's cookie code asks for them. */
#include <string.h>
#include <libpsl.h>
#include "deptest.h"

int main(void)
{
    const psl_ctx_t *psl = psl_builtin();
    printf("libpsl %s, built-in list: %d rules\n", psl_get_version(), psl ? psl_suffix_count(psl) : -1);
    CHECK(psl != NULL && psl_suffix_count(psl) > 5000);
    CHECK(psl_is_public_suffix(psl, "com") && psl_is_public_suffix(psl, "co.uk") && !psl_is_public_suffix(psl, "example.com"));
    const char *reg = psl_registrable_domain(psl, "www.shop.example.co.uk");
    CHECK(reg && !strcmp(reg, "example.co.uk"));
    CHECK(psl_is_cookie_domain_acceptable(psl, "www.example.com", "example.com"));
    CHECK(!psl_is_cookie_domain_acceptable(psl, "www.example.com", "com"));
    return DONE("t_dep_libpsl");
}
