/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32test.h"
typedef int (__cdecl *random_fn)(unsigned *);
typedef void (__cdecl *seed_fn)(unsigned);
typedef int (__cdecl *rand_fn)(void);
typedef int *(__cdecl *errno_fn)(void);
typedef void (__cdecl *invalid_fn)(const unsigned short *, const unsigned short *, const unsigned short *, unsigned, uintptr_t);
typedef invalid_fn (__cdecl *set_invalid_fn)(invalid_fn);
static int invalid_calls;
static void __cdecl invalid_handler(const unsigned short *a, const unsigned short *b, const unsigned short *c, unsigned d, uintptr_t e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; ++invalid_calls; }
int main(void)
{
    HMODULE module = LoadLibraryW(L"api-ms-win-crt-utility-l1-1-0.dll");
    random_fn secure = module ? (random_fn)GetProcAddress(module, "rand_s") : 0;
    seed_fn seed = module ? (seed_fn)GetProcAddress(module, "srand") : 0;
    rand_fn plain = module ? (rand_fn)GetProcAddress(module, "rand") : 0;
    errno_fn error = module ? (errno_fn)GetProcAddress(module, "_errno") : 0;
    set_invalid_fn handler = module ? (set_invalid_fn)GetProcAddress(module, "_set_invalid_parameter_handler") : 0;
    invalid_fn previous;
    unsigned value, first, changed = 0, i;
    int plain_first, plain_second, result, saved_errno;
    CHECK(secure && seed && plain && error && handler, "real CRT utility API-set exposes secure randomness and state contracts");
    if (!secure || !seed || !plain || !error || !handler) return 1;
    previous = handler(invalid_handler);
    *error() = 0; result = secure(NULL); saved_errno = *error();
    CHECK(result == 22 && saved_errno == 22 && invalid_calls == 1, "null rand_s invokes actual invalid handler and returns EINVAL");
    handler(previous);
    seed(123); plain_first = plain(); plain_second = plain(); seed(123);
    CHECK(plain() == plain_first, "repeatable rand seed before entropy calls");
    *error() = 123; result = secure(&first); saved_errno = *error();
    CHECK(result == 0 && saved_errno == 123, "real entropy syscall succeeds without changing errno");
    for (i = 0; i < 64; ++i) {
        result = secure(&value);
        CHECK(result == 0, "actual entropy backend fills an unsigned integer");
        if (result) return 1;
        if (value != first) changed = 1;
    }
    CHECK(changed, "real entropy stream changes across sampled requests");
    CHECK(plain() == plain_second, "secure randomness leaves rand sequence unchanged");
    CHECK(FreeLibrary(module), "release utility API-set reference");
    return k32t_finish("T_U_OFFICE_RANDOM");
}
