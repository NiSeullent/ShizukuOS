/* SPDX-License-Identifier: GPL-2.0-only
 * Host contract for the routing policy: parser strictness, mode precedence,
 * provider order, stub demotion, KernelEx attribution and diagnostics.
 * Mocked lookups only; no Windows loader, no DLL and no guest. */
#include "../resolve.h"
#include "../routing.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "FAIL routing_test.c:%d: %s\n", __LINE__, #expression); exit(1); } } while (0)

/* ---- log capture ------------------------------------------------------ */
static char captured[64][NTW_ROUTE_MESSAGE_MAX + 1];
static unsigned captured_count;
static void capture(void *context, const char *message) {
    CHECK(context == (void *)0x51);
    CHECK(strlen(message) < NTW_ROUTE_MESSAGE_MAX);
    if (captured_count < 64) strcpy(captured[captured_count], message);
    ++captured_count;
}
static void reset_log(void) { captured_count = 0; }
static int logged(const char *needle) {
    unsigned i;
    for (i = 0; i < captured_count && i < 64; ++i)
        if (strstr(captured[i], needle)) return 1;
    return 0;
}
static int logged_exactly(const char *text) {
    unsigned i;
    for (i = 0; i < captured_count && i < 64; ++i)
        if (!strcmp(captured[i], text)) return 1;
    return 0;
}

/* ---- text builder ------------------------------------------------------ */
static void text_builder(void) {
    char small[8];
    struct ntw_text t;
    ntw_text_start(&t, small, sizeof small);
    CHECK(small[0] == 0 && t.length == 0);
    ntw_text_add(&t, "abc");
    ntw_text_add_uint(&t, 4096);
    CHECK(!strcmp(small, "abc4096"));
    ntw_text_add(&t, "overflow");
    CHECK(!strcmp(small, "abc4096") && strlen(small) == 7);   /* never exceeds capacity-1 */
    ntw_text_start(&t, small, sizeof small);
    ntw_text_add_uint(&t, 0);
    ntw_text_add(&t, NULL);
    CHECK(!strcmp(small, "0(null)"));
    ntw_text_start(&t, small, sizeof small);
    ntw_text_add_bounded(&t, "AB\x01" "C", 2);
    CHECK(!strcmp(small, "AB..."));
    ntw_text_start(&t, small, sizeof small);
    ntw_text_add_bounded(&t, "A\x7f" "B", 10);
    CHECK(!strcmp(small, "A?B"));
    ntw_text_start(&t, small, sizeof small);
    ntw_text_add_slice(&t, "key=value", 3);   /* an exact slice is never marked as cut */
    CHECK(!strcmp(small, "key"));
    ntw_text_add_slice(&t, "a\0b", 3);
    CHECK(!strcmp(small, "keya"));
    ntw_text_add_slice(&t, NULL, 3);
    CHECK(!strcmp(small, "keya(nu"));
    ntw_text_start(&t, small, 0);   /* zero capacity: nothing is written */
    ntw_text_add(&t, "x");
    CHECK(t.length == 0);
    ntw_text_start(&t, small, 1);
    ntw_text_add(&t, "x");
    CHECK(small[0] == 0);
}

/* ---- names and modes --------------------------------------------------- */
static void names_and_modes(void) {
    unsigned mode = 99;
    CHECK(ntw_route_parse_mode("auto", 4, &mode) && mode == NTW_MODE_AUTO);
    CHECK(ntw_route_parse_mode("OWN", 3, &mode) && mode == NTW_MODE_OWN);
    CHECK(ntw_route_parse_mode("KernelEx", 8, &mode) && mode == NTW_MODE_KERNELEX);
    CHECK(ntw_route_parse_mode("native", 6, &mode) && mode == NTW_MODE_NATIVE);
    CHECK(!ntw_route_parse_mode("nativ", 5, &mode) && !ntw_route_parse_mode("natives", 7, &mode));
    CHECK(!ntw_route_parse_mode("auto ", 5, &mode) && !ntw_route_parse_mode("", 0, &mode));
    CHECK(!ntw_route_parse_mode("kernelexx", 9, &mode) && !ntw_route_parse_mode(NULL, 4, &mode));
    CHECK(!ntw_route_parse_mode("auto", 4, NULL));
    CHECK(!strcmp(ntw_route_mode_name(NTW_MODE_AUTO), "auto") && !strcmp(ntw_route_mode_name(7), "invalid"));
    CHECK(!strcmp(ntw_route_provider_name(NTW_PROVIDER_KERNELEX), "kernelex"));
    CHECK(!strcmp(ntw_route_provider_name(NTW_PROVIDER_NONE), "none"));
    CHECK(!strcmp(ntw_route_kernelex_name(NTW_KERNELEX_ACTIVE), "active"));
    CHECK(!strcmp(ntw_route_kernelex_name(NTW_KERNELEX_CORE_ONLY), "core-only"));
    CHECK(!strcmp(ntw_route_kernelex_name(9), "not-detected"));
    CHECK(ntw_route_name_equal("Same", "Same") && !ntw_route_name_equal("Same", "same"));
    CHECK(ntw_route_name_iequal("Kernel32.dll", "KERNEL32.DLL") && !ntw_route_name_iequal("a", "ab"));
    CHECK(!ntw_route_name_equal(NULL, "x") && !ntw_route_name_iequal("x", NULL));
    CHECK(NTW_ORDER_AT(NTW_ORDER3(NTW_PROVIDER_NATIVE, NTW_PROVIDER_OWN, NTW_PROVIDER_KERNELEX), 0) == NTW_PROVIDER_NATIVE);
    CHECK(NTW_ORDER_AT(NTW_ORDER3(NTW_PROVIDER_NATIVE, NTW_PROVIDER_OWN, NTW_PROVIDER_KERNELEX), 2) == NTW_PROVIDER_KERNELEX);
    CHECK(NTW_ORDER_AT(NTW_ORDER1(NTW_PROVIDER_NATIVE), 1) == NTW_PROVIDER_NONE);
}

/* ---- parser ------------------------------------------------------------ */
static const char *const module_name = "KERNEL32.DLL";
static void parser_accepts(void) {
    struct ntw_route_policy policy;
    static const char text[] =
        "; comment\r\n"
        "# another comment\r\n"
        "\r\n"
        "  [ Routing ]  \r\n"
        "\tMODE = KernelEx\r\n"
        "log=1\r\n"
        "[modules]\r\n"
        "kernel32.dll=own\r\n"
        "user32.dll = native\r\n"
        "[functions]\r\n"
        "GetTickCount64 = native\r\n"
        "_private9=auto\r\n";
    unsigned warnings;
    ntw_route_policy_init(&policy);
    CHECK(policy.mode == NTW_MODE_AUTO && policy.log == 0 && policy.override_count == 0 && policy.warnings == 0);
    reset_log();
    warnings = ntw_route_parse(&policy, text, sizeof text - 1, '\n', capture, (void *)0x51);
    CHECK(warnings == 0 && policy.warnings == 0 && captured_count == 0);
    CHECK(policy.mode == NTW_MODE_KERNELEX && policy.log == 1 && policy.override_count == 4);
    CHECK(policy.overrides[0].kind == NTW_OVERRIDE_MODULE && policy.overrides[0].mode == NTW_MODE_OWN);
    CHECK(!strcmp(policy.overrides[0].name, "KERNEL32.DLL"));   /* modules are stored upper-case */
    CHECK(!strcmp(policy.overrides[1].name, "USER32.DLL") && policy.overrides[1].mode == NTW_MODE_NATIVE);
    CHECK(policy.overrides[2].kind == NTW_OVERRIDE_FUNCTION && !strcmp(policy.overrides[2].name, "GetTickCount64"));
    CHECK(policy.overrides[2].mode == NTW_MODE_NATIVE);
    CHECK(!strcmp(policy.overrides[3].name, "_private9") && policy.overrides[3].mode == NTW_MODE_AUTO);
    /* Precedence: function, then module (case-insensitive), then process. */
    CHECK(ntw_route_effective_mode(&policy, module_name, "GetTickCount64") == NTW_MODE_NATIVE);
    CHECK(ntw_route_effective_mode(&policy, "kernel32.DLL", "Sleep") == NTW_MODE_OWN);
    CHECK(ntw_route_effective_mode(&policy, "USER32.DLL", "GetTickCount64") == NTW_MODE_NATIVE);
    CHECK(ntw_route_effective_mode(&policy, "USER32.DLL", "MessageBoxA") == NTW_MODE_NATIVE);
    CHECK(ntw_route_effective_mode(&policy, "GDI32.DLL", "BitBlt") == NTW_MODE_KERNELEX);
    CHECK(ntw_route_effective_mode(&policy, module_name, "gettickcount64") == NTW_MODE_OWN);  /* exact names */
    CHECK(ntw_route_effective_mode(NULL, module_name, "GetTickCount64") == NTW_MODE_OWN);     /* no policy: Own */
    /* The environment form: '|' ends a line, as does '\n'. */
    {
        static const char env[] = "[routing]|mode=native|log=0\n[functions]|Sleep=own";
        ntw_route_policy_init(&policy);
        warnings = ntw_route_parse(&policy, env, sizeof env - 1, '|', capture, (void *)0x51);
    }
    CHECK(warnings == 0 && policy.mode == NTW_MODE_NATIVE && policy.log == 0 && policy.override_count == 1);
    CHECK(!strcmp(policy.overrides[0].name, "Sleep") && policy.overrides[0].mode == NTW_MODE_OWN);
    /* Empty text is a valid, default configuration. */
    ntw_route_policy_init(&policy);
    CHECK(ntw_route_parse(&policy, "", 0, '\n', capture, (void *)0x51) == 0 && policy.mode == NTW_MODE_AUTO);
    /* Exactly the limits: 4096 bytes and a 127-byte line are accepted. */
    {
        char *big = malloc(NTW_ROUTE_TEXT_MAX + 1);
        size_t i;
        CHECK(big != NULL);
        memset(big, ';', NTW_ROUTE_TEXT_MAX);
        for (i = 63; i < NTW_ROUTE_TEXT_MAX; i += 64) big[i] = '\n';
        ntw_route_policy_init(&policy);
        CHECK(ntw_route_parse(&policy, big, NTW_ROUTE_TEXT_MAX, '\n', capture, (void *)0x51) == 0);
        memcpy(big, "[functions]\n", 12);
        memset(big + 12, 'F', NTW_ROUTE_LINE_MAX - 4);
        memcpy(big + 12 + NTW_ROUTE_LINE_MAX - 4, "=own", 4);   /* 127-byte line, 123-char name */
        ntw_route_policy_init(&policy);
        reset_log();
        CHECK(ntw_route_parse(&policy, big, 12 + NTW_ROUTE_LINE_MAX, '\n', capture, (void *)0x51) == 1);
        CHECK(logged("line 2: invalid function name"));   /* name too long for storage, not the line */
        memset(big + 12, 'F', NTW_ROUTE_NAME_MAX - 1);
        memcpy(big + 12 + NTW_ROUTE_NAME_MAX - 1, "=own", 4);   /* 63-char name: the longest stored */
        ntw_route_policy_init(&policy);
        CHECK(ntw_route_parse(&policy, big, 12 + NTW_ROUTE_NAME_MAX - 1 + 4, '\n', capture, (void *)0x51) == 0);
        CHECK(policy.override_count == 1 && strlen(policy.overrides[0].name) == NTW_ROUTE_NAME_MAX - 1);
        free(big);
    }
}

static void parser_rejects(void) {
    struct ntw_route_policy policy;
    static const char text[] =
        "mode=own\n"                 /* 1: outside any section */
        "[routing]\n"                /* 2 */
        "mode=turbo\n"               /* 3 */
        "mode=own\n"                 /* 4: duplicate, first (rejected) kept the default */
        "log=2\n"                    /* 5 */
        "log=1\n"                    /* 6: duplicate */
        "speed=fast\n"               /* 7: unknown key */
        "novalue\n"                  /* 8 */
        "=own\n"                     /* 9: empty key */
        "log=\n"                     /* 10: empty value */
        "[functions\n"               /* 11: unterminated */
        "[FUNCTIONS]\n"              /* 12 */
        "1abc=own\n"                 /* 13 */
        "Get-Tick=own\n"             /* 14 */
        "Sleep=fast\n"               /* 15 */
        "Sleep=own\n"                /* 16 */
        "Sleep=native\n"             /* 17: duplicate */
        "[modules]\n"                /* 18 */
        "C:\\KERNEL32.DLL=own\n"     /* 19: path separator */
        "KERNEL32.DLL=own\n"         /* 20 */
        "Kernel32.dll=auto\n"        /* 21: duplicate (case-insensitive) */
        "[other]\n"                  /* 22 */
        "x=y\n";                     /* 23 */
    unsigned warnings;
    ntw_route_policy_init(&policy);
    reset_log();
    warnings = ntw_route_parse(&policy, text, sizeof text - 1, '\n', capture, (void *)0x51);
    CHECK(warnings == 18 && policy.warnings == 18 && captured_count == 18);
    CHECK(logged_exactly("NTW32: routing config line 1: key outside any section 'mode'"));
    CHECK(logged_exactly("NTW32: routing config line 3: unknown mode; Auto retained 'turbo'"));
    CHECK(logged_exactly("NTW32: routing config line 4: duplicate mode ignored 'own'"));
    CHECK(logged_exactly("NTW32: routing config line 5: log must be 0 or 1 '2'"));
    CHECK(logged_exactly("NTW32: routing config line 6: duplicate log ignored '1'"));
    CHECK(logged_exactly("NTW32: routing config line 7: unknown key 'speed'"));
    CHECK(logged_exactly("NTW32: routing config line 8: expected key=value 'novalue'"));
    CHECK(logged_exactly("NTW32: routing config line 9: empty key '=own'"));
    CHECK(logged_exactly("NTW32: routing config line 10: empty value 'log'"));
    CHECK(logged_exactly("NTW32: routing config line 11: unterminated section header '[functions'"));
    CHECK(logged_exactly("NTW32: routing config line 13: invalid function name '1abc'"));
    CHECK(logged_exactly("NTW32: routing config line 14: invalid function name 'Get-Tick'"));
    CHECK(logged_exactly("NTW32: routing config line 15: unknown mode 'fast'"));
    CHECK(logged_exactly("NTW32: routing config line 17: duplicate override ignored 'Sleep'"));
    CHECK(logged_exactly("NTW32: routing config line 19: invalid module name 'C:\\KERNEL32.DLL'"));
    CHECK(logged_exactly("NTW32: routing config line 21: duplicate override ignored 'Kernel32.dll'"));
    CHECK(logged_exactly("NTW32: routing config line 22: unknown section 'other'"));
    CHECK(logged_exactly("NTW32: routing config line 23: key under unknown section ignored 'x'"));
    /* Wrong values fell back: Auto, log 0, two overrides retained. */
    CHECK(policy.mode == NTW_MODE_AUTO && policy.log == 0 && policy.override_count == 2);
    CHECK(!strcmp(policy.overrides[0].name, "Sleep") && policy.overrides[0].mode == NTW_MODE_OWN);
    CHECK(!strcmp(policy.overrides[1].name, "KERNEL32.DLL") && policy.overrides[1].mode == NTW_MODE_OWN);
    /* Whole-configuration rejections leave every default untouched. */
    ntw_route_policy_init(&policy);
    reset_log();
    CHECK(ntw_route_parse(&policy, "[routing]\nmode=own\n\x01", 20, '\n', capture, (void *)0x51) == 1);
    CHECK(logged_exactly("NTW32: routing config: control or non-ASCII byte; configuration ignored"));
    CHECK(policy.mode == NTW_MODE_AUTO && policy.override_count == 0 && policy.warnings == 1);
    reset_log();
    CHECK(ntw_route_parse(&policy, "[routing]\nmode=own\n\xc3\xa9", 21, '\n', capture, (void *)0x51) == 1);
    CHECK(policy.mode == NTW_MODE_AUTO);
    reset_log();
    CHECK(ntw_route_parse(&policy, NULL, 0, '\n', capture, (void *)0x51) == 1);
    CHECK(logged_exactly("NTW32: routing config: configuration missing or longer than 4096 bytes; ignored"));
    {
        char *big = malloc(NTW_ROUTE_TEXT_MAX + 1);
        CHECK(big != NULL);
        memset(big, ';', NTW_ROUTE_TEXT_MAX + 1);
        reset_log();
        CHECK(ntw_route_parse(&policy, big, NTW_ROUTE_TEXT_MAX + 1, '\n', capture, (void *)0x51) == 1);
        CHECK(logged("longer than 4096 bytes"));
        /* A single 128-byte line is too long and is skipped, the rest parses. */
        memcpy(big, "[routing]\n", 10);
        memset(big + 10, 'x', NTW_ROUTE_LINE_MAX + 1);
        memcpy(big + 10 + NTW_ROUTE_LINE_MAX + 1, "\nmode=own\n", 10);
        ntw_route_policy_init(&policy);
        reset_log();
        CHECK(ntw_route_parse(&policy, big, 20 + NTW_ROUTE_LINE_MAX + 1, '\n', capture, (void *)0x51) == 1);
        CHECK(logged_exactly("NTW32: routing config line 2: line too long; ignored"));
        CHECK(policy.mode == NTW_MODE_OWN);
        free(big);
    }
    /* Override storage is bounded: the 33rd entry is refused with a warning. */
    {
        char text33[33 * 8 + 16];
        size_t at = 0;
        unsigned i;
        memcpy(text33, "[functions]\n", 12);
        at = 12;
        for (i = 0; i < 33; ++i) at += (size_t)sprintf(text33 + at, "F%02u=own\n", i);
        ntw_route_policy_init(&policy);
        reset_log();
        CHECK(ntw_route_parse(&policy, text33, at, '\n', capture, (void *)0x51) == 1);
        CHECK(policy.override_count == NTW_ROUTE_MAX_OVERRIDES);
        CHECK(logged_exactly("NTW32: routing config line 34: override limit reached; entry ignored 'F32'"));
        CHECK(ntw_route_effective_mode(&policy, module_name, "F31") == NTW_MODE_OWN);
        CHECK(ntw_route_effective_mode(&policy, module_name, "F32") == NTW_MODE_AUTO);
    }
    /* A NULL log callback and a NULL policy are tolerated. */
    ntw_route_policy_init(&policy);
    CHECK(ntw_route_parse(&policy, "garbage", 7, '\n', NULL, NULL) == 1 && policy.warnings == 1);
    CHECK(ntw_route_parse(NULL, "garbage", 7, '\n', capture, (void *)0x51) == 0);
}

/* ---- order and stubs --------------------------------------------------- */
static const struct ntw_route_entry entries[] = {
    { "GetTickCount64", NTW_ORDER3(NTW_PROVIDER_NATIVE, NTW_PROVIDER_OWN, NTW_PROVIDER_KERNELEX) },
    { "MultiByteToWideChar", NTW_ORDER3(NTW_PROVIDER_OWN, NTW_PROVIDER_NATIVE, NTW_PROVIDER_KERNELEX) },
    { "OnlyOwn", NTW_ORDER1(NTW_PROVIDER_OWN) },
};
static const struct ntw_stub_entry stubs[] = {
    { "KERNEL32.DLL", "CompareStringW", NTW_PROVIDER_NATIVE },
    { "KERNEL32.DLL", "ReplaceFileW", NTW_PROVIDER_KERNELEX },
    { "KERNEL32.DLL", "GetTickCount64", NTW_PROVIDER_KERNELEX },
    { "USER32.DLL", "Other", NTW_PROVIDER_NATIVE },
};
static const struct ntw_route_table table = { entries, 3, stubs, 4, 0 };

static void order_and_stubs(void) {
    const struct ntw_route_table custom = { entries, 3, stubs, 4,
        NTW_ORDER2(NTW_PROVIDER_KERNELEX, NTW_PROVIDER_NATIVE) };
    CHECK(ntw_route_order(NTW_MODE_OWN, &table, "GetTickCount64") == NTW_ORDER2(NTW_PROVIDER_OWN, NTW_PROVIDER_NATIVE));
    CHECK(ntw_route_order(NTW_MODE_KERNELEX, NULL, "x") == NTW_ORDER3(NTW_PROVIDER_KERNELEX, NTW_PROVIDER_NATIVE, NTW_PROVIDER_OWN));
    CHECK(ntw_route_order(NTW_MODE_NATIVE, &table, "MultiByteToWideChar") == NTW_ORDER1(NTW_PROVIDER_NATIVE));
    CHECK(ntw_route_order(NTW_MODE_AUTO, &table, "MultiByteToWideChar") == entries[1].order);
    CHECK(ntw_route_order(NTW_MODE_AUTO, &table, "Sleep") == NTW_ORDER_DEFAULT);
    CHECK(ntw_route_order(NTW_MODE_AUTO, NULL, "Sleep") == NTW_ORDER_DEFAULT);
    CHECK(ntw_route_order(NTW_MODE_AUTO, &custom, "Sleep") == custom.default_order);
    CHECK(ntw_route_order(NTW_MODE_AUTO, &custom, "GetTickCount64") == entries[0].order);
    CHECK(ntw_route_order(77, &table, "x") == NTW_ORDER_DEFAULT);   /* unknown mode behaves as Auto */
    CHECK(ntw_route_is_stub(&table, "kernel32.dll", "CompareStringW", NTW_PROVIDER_NATIVE));
    CHECK(!ntw_route_is_stub(&table, "KERNEL32.DLL", "CompareStringW", NTW_PROVIDER_KERNELEX));
    CHECK(!ntw_route_is_stub(&table, "KERNEL32.DLL", "comparestringw", NTW_PROVIDER_NATIVE));
    CHECK(ntw_route_is_stub(&table, "USER32.DLL", "Other", NTW_PROVIDER_NATIVE));
    CHECK(!ntw_route_is_stub(&table, "KERNEL32.DLL", "Other", NTW_PROVIDER_NATIVE));
    CHECK(!ntw_route_is_stub(NULL, "KERNEL32.DLL", "CompareStringW", NTW_PROVIDER_NATIVE));
}

/* ---- PE header reading -------------------------------------------------- */
static void put32(unsigned char *at, uint32_t v) { at[0] = (unsigned char)v; at[1] = (unsigned char)(v >> 8); at[2] = (unsigned char)(v >> 16); at[3] = (unsigned char)(v >> 24); }
static void put16(unsigned char *at, uint16_t v) { at[0] = (unsigned char)v; at[1] = (unsigned char)(v >> 8); }
static void image_size(void) {
    unsigned char h[4096];
    uint32_t size = 0;
    memset(h, 0, sizeof h);
    h[0] = 'M'; h[1] = 'Z';
    put32(h + 60, 0x100);
    put32(h + 0x100, UINT32_C(0x00004550));
    put16(h + 0x104, 0x14c);
    put16(h + 0x118, 0x10b);
    put32(h + 0x118 + 56, 0x9000);
    CHECK(ntw_route_image_size(h, sizeof h, &size) && size == 0x9000);
    CHECK(ntw_route_image_size(h, 0x100 + 84, &size));      /* exactly enough bytes */
    CHECK(!ntw_route_image_size(h, 0x100 + 83, &size));     /* one byte short */
    CHECK(!ntw_route_image_size(h, 63, &size) && !ntw_route_image_size(NULL, sizeof h, &size));
    CHECK(!ntw_route_image_size(h, sizeof h, NULL));
    h[1] = 'X'; CHECK(!ntw_route_image_size(h, sizeof h, &size)); h[1] = 'Z';
    put32(h + 60, 63); CHECK(!ntw_route_image_size(h, sizeof h, &size));
    put32(h + 60, 0xffffff00); CHECK(!ntw_route_image_size(h, sizeof h, &size));
    put32(h + 60, 0x100);
    put32(h + 0x100, UINT32_C(0x00004551)); CHECK(!ntw_route_image_size(h, sizeof h, &size));
    put32(h + 0x100, UINT32_C(0x00004550));
    put16(h + 0x104, 0x8664); CHECK(!ntw_route_image_size(h, sizeof h, &size));
    put16(h + 0x104, 0x14c);
    put16(h + 0x118, 0x20b); CHECK(!ntw_route_image_size(h, sizeof h, &size));
    put16(h + 0x118, 0x10b);
    put32(h + 0x118 + 56, 0xfff); CHECK(!ntw_route_image_size(h, sizeof h, &size));
    put32(h + 0x118 + 56, UINT32_C(0x10000001)); CHECK(!ntw_route_image_size(h, sizeof h, &size));
    put32(h + 0x118 + 56, UINT32_C(0x10000000)); CHECK(ntw_route_image_size(h, sizeof h, &size) && size == UINT32_C(0x10000000));
}

/* ---- resolution -------------------------------------------------------- */
struct mocks {
    int own_present, native_present, kernelex_present;
    unsigned own_calls, native_calls, owner_calls;
    uintptr_t last_module;
    const char *last_name;
};
static void own_code(void) {}
static void native_code(void) {}
static void kernelex_code(void) {}
static ntw_proc mock_owned(void *context, const char *name) {
    struct mocks *m = context;
    ++m->own_calls;
    return m->own_present && (!strcmp(name, "GetTickCount64") || !strcmp(name, "MultiByteToWideChar") ||
                              !strcmp(name, "OnlyOwn") || !strcmp(name, "Owned")) ? own_code : (ntw_proc)0;
}
static ntw_proc mock_native(void *context, uintptr_t module, const char *name) {
    struct mocks *m = context;
    ++m->native_calls;
    m->last_module = module;
    m->last_name = name;
    if (module != 0x8000) return native_code;
    if (m->kernelex_present) return kernelex_code;   /* a hooked loader answers with KernelEx code */
    return m->native_present ? native_code : (ntw_proc)0;
}
static int mock_owner(void *context, ntw_proc address) {
    struct mocks *m = context;
    ++m->owner_calls;
    return address == kernelex_code;
}
static void log_to_capture(void *context, const char *message) {
    (void)context;
    capture((void *)0x51, message);
}

static struct ntw_route_policy policies[4];
static struct ntw_resolver make(struct mocks *m, unsigned mode, const struct ntw_route_table *t, int with_owner) {
    struct ntw_resolver r;
    ntw_route_policy_init(&policies[mode]);
    policies[mode].mode = (unsigned char)mode;
    r.kernel32_module = 0x8000;
    r.owned = mock_owned;
    r.native = mock_native;
    r.context = m;
    r.table = t;
    r.policy = &policies[mode];
    r.kernelex_owns = with_owner ? mock_owner : NULL;
    r.kernelex_state = with_owner ? NTW_KERNELEX_ACTIVE : NTW_KERNELEX_NOT_DETECTED;
    r.log = log_to_capture;
    return r;
}
static ntw_proc resolve(struct ntw_resolver *r, struct mocks *m, int own, int native, int kex,
                        const char *name, unsigned *provider) {
    m->own_present = own; m->native_present = native; m->kernelex_present = kex;
    reset_log();
    return ntw_resolve_named(r, name, provider);
}

static void resolution_matrix(void) {
    struct mocks m = {0, 0, 0, 0, 0, 0, 0, 0};
    struct ntw_resolver r;
    unsigned p;
    /* Auto, native-first entry: native, own, kernelex, unresolved. */
    r = make(&m, NTW_MODE_AUTO, &table, 1);
    CHECK(resolve(&r, &m, 1, 1, 0, "GetTickCount64", &p) == native_code && p == NTW_PROVIDER_NATIVE);
    CHECK(captured_count == 0);
    CHECK(resolve(&r, &m, 1, 0, 0, "GetTickCount64", &p) == own_code && p == NTW_PROVIDER_OWN);
    CHECK(resolve(&r, &m, 0, 0, 1, "GetTickCount64", &p) == kernelex_code && p == NTW_PROVIDER_KERNELEX);
    /* ...and a KernelEx stub for the name is the last resort, announced. */
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!GetTickCount64 -> known-stub provider used as last resort: kernelex (mode auto)"));
    CHECK(resolve(&r, &m, 1, 0, 1, "GetTickCount64", &p) == own_code && p == NTW_PROVIDER_OWN);
    CHECK(captured_count == 0);
    CHECK(resolve(&r, &m, 0, 0, 0, "GetTickCount64", &p) == NULL && p == NTW_PROVIDER_NONE);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!GetTickCount64 unresolved (mode auto; native absent; own absent; kernelex active)"));
    /* Auto, own-first entry: own beats a present native. */
    CHECK(resolve(&r, &m, 1, 1, 0, "MultiByteToWideChar", &p) == own_code && p == NTW_PROVIDER_OWN);
    m.native_calls = 0;
    CHECK(resolve(&r, &m, 1, 1, 0, "MultiByteToWideChar", &p) == own_code && m.native_calls == 0);
    CHECK(resolve(&r, &m, 0, 1, 0, "MultiByteToWideChar", &p) == native_code && p == NTW_PROVIDER_NATIVE);
    /* Auto, name without an entry: the default order and no own answer. */
    CHECK(resolve(&r, &m, 1, 1, 0, "Sleep", &p) == native_code);
    CHECK(resolve(&r, &m, 1, 0, 1, "Sleep", &p) == kernelex_code && p == NTW_PROVIDER_KERNELEX);
    CHECK(resolve(&r, &m, 1, 0, 0, "Sleep", &p) == NULL);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!Sleep unresolved (mode auto; native absent; own absent; kernelex active)"));
    /* Auto, a known native stub: own first, then KernelEx, then the stub. */
    CHECK(resolve(&r, &m, 0, 1, 0, "CompareStringW", &p) == native_code && p == NTW_PROVIDER_NATIVE);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!CompareStringW -> known-stub provider used as last resort: native (mode auto)"));
    CHECK(resolve(&r, &m, 0, 0, 1, "CompareStringW", &p) == kernelex_code && captured_count == 0);
    /* Auto, a known KernelEx stub: native wins, and without native it is unresolved
     * before the stub is offered... no: the stub is the last resort. */
    CHECK(resolve(&r, &m, 0, 0, 1, "ReplaceFileW", &p) == kernelex_code && p == NTW_PROVIDER_KERNELEX);
    CHECK(logged("ReplaceFileW -> known-stub provider used as last resort: kernelex"));
    /* Entry restricted to own only. */
    CHECK(resolve(&r, &m, 0, 1, 0, "OnlyOwn", &p) == NULL && p == NTW_PROVIDER_NONE);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!OnlyOwn unresolved (mode auto; native not consulted; own absent; kernelex active)"));
    CHECK(resolve(&r, &m, 1, 1, 0, "OnlyOwn", &p) == own_code);
    /* Tracing: log=1 reports every successful route. */
    policies[NTW_MODE_AUTO].log = 1;
    CHECK(resolve(&r, &m, 1, 1, 0, "GetTickCount64", &p) == native_code);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!GetTickCount64 -> native (mode auto)"));
    CHECK(resolve(&r, &m, 1, 0, 0, "MultiByteToWideChar", &p) == own_code);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!MultiByteToWideChar -> own (mode auto)"));
    policies[NTW_MODE_AUTO].log = 0;
    /* Without an owner callback KernelEx code is indistinguishable from native. */
    r = make(&m, NTW_MODE_AUTO, &table, 0);
    CHECK(resolve(&r, &m, 1, 0, 1, "GetTickCount64", &p) == kernelex_code && p == NTW_PROVIDER_NATIVE);
    CHECK(resolve(&r, &m, 0, 0, 0, "Sleep", &p) == NULL);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!Sleep unresolved (mode auto; native absent; own absent; kernelex not-detected)"));
    r.kernelex_state = NTW_KERNELEX_CORE_ONLY;
    CHECK(resolve(&r, &m, 0, 0, 0, "Sleep", &p) == NULL && logged("kernelex core-only)"));

    /* Own: own, then native; a KernelEx-attributed answer is rejected. */
    r = make(&m, NTW_MODE_OWN, &table, 1);
    m.native_calls = 0;
    CHECK(resolve(&r, &m, 1, 1, 1, "GetTickCount64", &p) == own_code && p == NTW_PROVIDER_OWN);
    CHECK(m.native_calls == 0);   /* lazy: the loader was never asked */
    CHECK(resolve(&r, &m, 0, 1, 0, "GetTickCount64", &p) == native_code && p == NTW_PROVIDER_NATIVE);
    CHECK(resolve(&r, &m, 0, 0, 1, "GetTickCount64", &p) == NULL && p == NTW_PROVIDER_NONE);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!GetTickCount64 unresolved (mode own; native result attributed to KernelEx and rejected; own absent; kernelex active)"));
    CHECK(resolve(&r, &m, 0, 1, 0, "CompareStringW", &p) == native_code);   /* the stub is all there is */
    CHECK(logged("CompareStringW -> known-stub provider used as last resort: native (mode own)"));
    CHECK(resolve(&r, &m, 0, 0, 0, "Sleep", &p) == NULL);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!Sleep unresolved (mode own; native absent; own absent; kernelex active)"));

    /* KernelEx: kernelex, then native, then own; a KernelEx stub still loses
     * to a real own implementation and is only the last resort. */
    r = make(&m, NTW_MODE_KERNELEX, &table, 1);
    CHECK(resolve(&r, &m, 1, 1, 1, "GetTickCount64", &p) == own_code && p == NTW_PROVIDER_OWN);
    CHECK(captured_count == 0);
    CHECK(resolve(&r, &m, 0, 0, 1, "GetTickCount64", &p) == kernelex_code && p == NTW_PROVIDER_KERNELEX);
    CHECK(logged("GetTickCount64 -> known-stub provider used as last resort: kernelex (mode kernelex)"));
    CHECK(resolve(&r, &m, 1, 1, 1, "MultiByteToWideChar", &p) == kernelex_code && captured_count == 0);
    CHECK(resolve(&r, &m, 1, 1, 0, "MultiByteToWideChar", &p) == native_code && p == NTW_PROVIDER_NATIVE);
    CHECK(resolve(&r, &m, 1, 0, 0, "MultiByteToWideChar", &p) == own_code && p == NTW_PROVIDER_OWN);
    CHECK(resolve(&r, &m, 0, 0, 0, "MultiByteToWideChar", &p) == NULL);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!MultiByteToWideChar unresolved (mode kernelex; native absent; own absent; kernelex active)"));
    CHECK(resolve(&r, &m, 0, 0, 1, "ReplaceFileW", &p) == kernelex_code);   /* stub, last resort */
    CHECK(logged("ReplaceFileW -> known-stub provider used as last resort: kernelex (mode kernelex)"));

    /* Native: the loader's own answer, whatever it is, and silence. */
    r = make(&m, NTW_MODE_NATIVE, &table, 1);
    m.own_calls = 0;
    CHECK(resolve(&r, &m, 1, 1, 0, "GetTickCount64", &p) == native_code && p == NTW_PROVIDER_NATIVE);
    CHECK(resolve(&r, &m, 1, 0, 0, "GetTickCount64", &p) == NULL && p == NTW_PROVIDER_NONE && captured_count == 0);
    CHECK(resolve(&r, &m, 1, 0, 1, "GetTickCount64", &p) == kernelex_code && p == NTW_PROVIDER_NATIVE);
    CHECK(resolve(&r, &m, 1, 1, 0, "CompareStringW", &p) == native_code && captured_count == 0);
    CHECK(m.own_calls == 0);

    /* Overrides steer individual names and modules through the resolver. */
    r = make(&m, NTW_MODE_OWN, &table, 1);
    reset_log();
    CHECK(ntw_route_parse(&policies[NTW_MODE_OWN], "[functions]|GetTickCount64=native|[modules]|kernel32.dll=kernelex",
                          65, '|', capture, (void *)0x51) == 0);
    CHECK(resolve(&r, &m, 1, 0, 0, "GetTickCount64", &p) == NULL && captured_count == 0);   /* native passthrough */
    CHECK(resolve(&r, &m, 1, 1, 1, "MultiByteToWideChar", &p) == kernelex_code);            /* module: kernelex */
    CHECK(resolve(&r, &m, 1, 0, 0, "MultiByteToWideChar", &p) == own_code);

    /* Legacy: no policy and no table behave as Own without diagnostics. */
    r.policy = NULL; r.table = NULL; r.log = NULL; r.kernelex_owns = NULL;
    m.native_calls = 0;
    CHECK(resolve(&r, &m, 1, 1, 0, "GetTickCount64", &p) == own_code && m.native_calls == 0);
    CHECK(resolve(&r, &m, 0, 1, 0, "GetTickCount64", &p) == native_code);
    CHECK(resolve(&r, &m, 0, 0, 0, "GetTickCount64", &p) == NULL && captured_count == 0);
    CHECK(resolve(&r, &m, 0, 0, 0, "GetTickCount64", NULL) == NULL);   /* provider out is optional */

    /* Module identity and ordinals pass through in every mode. */
    {
        unsigned mode;
        for (mode = 0; mode < 4; ++mode) {
            uintptr_t ordinal;
            r = make(&m, mode, &table, 1);
            m.own_present = 1; m.native_present = 0; m.kernelex_present = 1;
            m.own_calls = 0;
            CHECK(ntw_resolve(&r, 0x8001, "GetTickCount64") == native_code && m.last_module == 0x8001);
            for (ordinal = 0; ordinal <= UINT16_MAX; ordinal += 257)
                CHECK(ntw_resolve(&r, 0x8000, (const char *)ordinal) == kernelex_code &&
                      (uintptr_t)m.last_name == ordinal);
            CHECK(ntw_resolve(&r, 0x8000, (const char *)(uintptr_t)UINT16_MAX) == kernelex_code);
            CHECK(m.own_calls == 0);
            r.kernel32_module = 0;
            CHECK(ntw_resolve(&r, 0, "GetTickCount64") == native_code);
        }
    }
    CHECK(ntw_resolve(NULL, 0x8000, "GetTickCount64") == NULL);
    r = make(&m, NTW_MODE_AUTO, &table, 1);
    r.native = NULL;
    CHECK(ntw_resolve(&r, 0x8000, "GetTickCount64") == NULL);
    CHECK(ntw_resolve_named(&r, "GetTickCount64", &p) == NULL && p == NTW_PROVIDER_NONE);
    r.native = mock_native;
    CHECK(ntw_resolve_named(&r, NULL, &p) == NULL);

    /* Diagnostics are bounded: a long or odd name is truncated, not overflowed. */
    {
        char long_name[300];
        memset(long_name, 'N', sizeof long_name - 1);
        long_name[1] = '\n';
        long_name[sizeof long_name - 1] = 0;
        r = make(&m, NTW_MODE_AUTO, &table, 1);
        CHECK(resolve(&r, &m, 0, 0, 0, long_name, &p) == NULL);
        CHECK(captured_count == 1 && strlen(captured[0]) < NTW_ROUTE_MESSAGE_MAX);
        CHECK(strstr(captured[0], "N?NNNN") && strstr(captured[0], "... unresolved (mode auto"));
    }
}

/* ---- configurable provider order --------------------------------------- */
static void order_text(unsigned order, const char *expected) {
    char buffer[40];
    struct ntw_text t;
    ntw_text_start(&t, buffer, sizeof buffer);
    ntw_text_add_order(&t, order);
    CHECK(!strcmp(buffer, expected));
}
static int order_is(const char *text, unsigned expected) {
    unsigned order = 0xdead;
    return ntw_route_parse_order(text, strlen(text), &order) && order == expected;
}
static int order_rejected(const char *text) {
    unsigned order = 0xdead;
    return !ntw_route_parse_order(text, strlen(text), &order) && order == 0xdead;
}
static unsigned parse_env(struct ntw_route_policy *policy, const char *text) {
    return ntw_route_parse(policy, text, strlen(text), '|', capture, (void *)0x51);
}
static void configured_order(void) {
    const unsigned N = NTW_PROVIDER_NATIVE, O = NTW_PROVIDER_OWN, K = NTW_PROVIDER_KERNELEX;
    struct ntw_route_policy policy;
    struct mocks m = {0, 0, 0, 0, 0, 0, 0, 0};
    struct ntw_resolver r;
    unsigned p, order = 0;
    char long_value[NTW_ROUTE_LINE_MAX + 2];

    /* Grammar of a provider list. */
    CHECK(order_is("native,own,kernelex", NTW_ORDER3(N, O, K)));
    CHECK(order_is("KernelEx , OWN,\tnative", NTW_ORDER3(K, O, N)));
    CHECK(order_is("own, kernelex", NTW_ORDER2(O, K)));
    CHECK(order_is(" kernelex ", NTW_ORDER1(K)));
    CHECK(order_rejected("") && order_rejected(",") && order_rejected("own,") && order_rejected(",own"));
    CHECK(order_rejected("own,,native") && order_rejected("own,own") && order_rejected("own,OWN"));
    CHECK(order_rejected("own;native") && order_rejected("own native") && order_rejected("nativ"));
    CHECK(order_rejected("natives") && order_rejected("own,native,kernelex,own") && order_rejected("auto"));
    CHECK(order_rejected("none") && order_rejected("own,native,kernelex,"));
    CHECK(!ntw_route_parse_order(NULL, 3, &order) && !ntw_route_parse_order("own", 3, NULL));
    memset(long_value, ' ', sizeof long_value);
    memcpy(long_value, "own", 3);
    CHECK(ntw_route_parse_order(long_value, NTW_ROUTE_LINE_MAX, &order) && order == NTW_ORDER1(O));
    CHECK(!ntw_route_parse_order(long_value, NTW_ROUTE_LINE_MAX + 1, &order));   /* bounded */
    order_text(NTW_ORDER3(N, O, K), "native,own,kernelex");
    order_text(NTW_ORDER2(K, N), "kernelex,native");
    order_text(0, "none");

    /* [routing] order= and [order] entries are parsed, one per key. */
    {
        static const char text[] =
            "[routing]\n"
            "order = kernelex, own, native\n"   /* 2 */
            "[order]\n"
            "MultiByteToWideChar=native\n"      /* 4 */
            "Sleep = own ,kernelex\n";          /* 5 */
        ntw_route_policy_init(&policy);
        CHECK(policy.order == 0);
        reset_log();
        CHECK(ntw_route_parse(&policy, text, sizeof text - 1, '\n', capture, (void *)0x51) == 0);
        CHECK(policy.order == NTW_ORDER3(K, O, N) && policy.mode == NTW_MODE_AUTO && policy.override_count == 2);
        CHECK(policy.overrides[0].kind == NTW_OVERRIDE_ORDER && policy.overrides[0].order == NTW_ORDER1(N));
        CHECK(!strcmp(policy.overrides[1].name, "Sleep") && policy.overrides[1].order == NTW_ORDER2(O, K));
        /* Order entries never change a mode. */
        CHECK(ntw_route_effective_mode(&policy, module_name, "MultiByteToWideChar") == NTW_MODE_AUTO);
    }
    /* Precedence in Auto: [order] entry, then [routing] order, then the table. */
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_AUTO, "MultiByteToWideChar") == NTW_ORDER1(N));
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_AUTO, "GetTickCount64") == NTW_ORDER3(K, O, N));
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_AUTO, "sleep") == NTW_ORDER3(K, O, N));
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_AUTO, "Sleep") == NTW_ORDER2(O, K));
    /* The fixed modes ignore every configured order. */
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_OWN, "Sleep") == NTW_ORDER2(O, N));
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_KERNELEX, "Sleep") == NTW_ORDER3(K, N, O));
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_NATIVE, "Sleep") == NTW_ORDER1(N));
    CHECK(ntw_route_effective_order(NULL, &table, NTW_MODE_AUTO, "MultiByteToWideChar") == entries[1].order);
    policy.order = 0;
    CHECK(ntw_route_effective_order(&policy, &table, NTW_MODE_AUTO, "GetTickCount64") == entries[0].order);
    CHECK(ntw_route_effective_order(&policy, NULL, NTW_MODE_AUTO, "Other") == NTW_ORDER_DEFAULT);
    policy.order = (unsigned char)NTW_ORDER3(K, O, N);

    /* Through the resolver: the configured order is what is tried. */
    r = make(&m, NTW_MODE_AUTO, &table, 1);
    policies[NTW_MODE_AUTO] = policy;
    CHECK(resolve(&r, &m, 1, 0, 1, "Owned", &p) == kernelex_code && p == NTW_PROVIDER_KERNELEX);
    CHECK(resolve(&r, &m, 1, 1, 0, "Owned", &p) == own_code && p == NTW_PROVIDER_OWN);
    m.native_calls = 0;
    CHECK(resolve(&r, &m, 1, 1, 0, "MultiByteToWideChar", &p) == native_code && p == NTW_PROVIDER_NATIVE);
    CHECK(m.native_calls == 1);
    /* An order that omits a provider never falls back to it. */
    CHECK(resolve(&r, &m, 1, 0, 0, "MultiByteToWideChar", &p) == NULL && p == NTW_PROVIDER_NONE);
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!MultiByteToWideChar unresolved (mode auto; native absent; own not consulted; kernelex active)"));
    CHECK(resolve(&r, &m, 0, 1, 0, "Sleep", &p) == NULL);
    /* The KernelEx probe asked the loader, so the diagnostic shows that
     * native had the name but the configured order excluded it. */
    CHECK(logged_exactly("NTW32: KERNEL32.DLL!Sleep unresolved (mode auto; native present but not selected; own absent; kernelex active)"));
    /* Stub demotion still applies: GetTickCount64 is a KernelEx stub in this
     * table, so a KernelEx-first order still prefers own and native. */
    CHECK(resolve(&r, &m, 1, 1, 1, "GetTickCount64", &p) == own_code && p == NTW_PROVIDER_OWN);
    CHECK(resolve(&r, &m, 0, 0, 1, "GetTickCount64", &p) == kernelex_code);
    CHECK(logged("GetTickCount64 -> known-stub provider used as last resort: kernelex (mode auto)"));
    /* A [functions] override to a fixed mode wins over any order. */
    reset_log();
    CHECK(parse_env(&policies[NTW_MODE_AUTO], "[functions]|Owned=own") == 0);
    m.native_calls = 0;
    CHECK(resolve(&r, &m, 1, 1, 1, "Owned", &p) == own_code && m.native_calls == 0);

    /* Rejections keep the defaults, each with a warning. */
    {
        static const char text[] =
            "[routing]\n"
            "order=own,own\n"              /* 2: duplicate provider */
            "order=native\n"               /* 3: duplicate key (first, rejected, counts) */
            "[order]\n"
            "Sleep=auto\n"                 /* 5: a mode is not an order */
            "Get.Tick=own\n"               /* 6 */
            "Sleep=own,native,kernelex\n"  /* 7 */
            "Sleep=own\n"                  /* 8: duplicate */
            "KERNEL32.DLL=own\n";          /* 9: module names are not function names */
        ntw_route_policy_init(&policy);
        reset_log();
        CHECK(ntw_route_parse(&policy, text, sizeof text - 1, '\n', capture, (void *)0x51) == 6);
        CHECK(logged_exactly("NTW32: routing config line 2: invalid provider order; routes.json order retained 'own,own'"));
        CHECK(logged_exactly("NTW32: routing config line 3: duplicate order ignored 'native'"));
        CHECK(logged_exactly("NTW32: routing config line 5: invalid provider order 'auto'"));
        CHECK(logged_exactly("NTW32: routing config line 6: invalid function name 'Get.Tick'"));
        CHECK(logged_exactly("NTW32: routing config line 8: duplicate override ignored 'Sleep'"));
        CHECK(logged_exactly("NTW32: routing config line 9: invalid function name 'KERNEL32.DLL'"));
        CHECK(policy.order == 0 && policy.override_count == 1 && policy.overrides[0].order == NTW_ORDER3(O, N, K));
    }

    /* Post-parse check: entries that cannot take effect are reported. */
    {
        static const char text[] =
            "[routing]|mode=own|order=kernelex|[modules]|user32.dll=native|KERNEL32.DLL=own|"
            "[functions]|Sleep=kernelex|[order]|Sleep=own|GetTickCount64=native";
        ntw_route_policy_init(&policy);
        reset_log();
        CHECK(ntw_route_parse(&policy, text, sizeof text - 1, '|', capture, (void *)0x51) == 0);
        CHECK(ntw_route_check(&policy, module_name, capture, (void *)0x51) == 4 && policy.warnings == 4);
        CHECK(captured_count == 4);
        CHECK(logged_exactly("NTW32: routing config: [modules] USER32.DLL is not routed by this provider; entry has no effect"));
        CHECK(logged_exactly("NTW32: routing config: [order] Sleep has no effect: the effective mode is kernelex"));
        CHECK(logged_exactly("NTW32: routing config: [order] GetTickCount64 has no effect: the effective mode is own"));
        CHECK(logged_exactly("NTW32: routing config: [routing] order has no effect: no name is routed in mode auto; the mode is own"));
        /* A single function in Auto makes both kinds of order meaningful. */
        CHECK(parse_env(&policy, "[functions]|GetTickCount64=auto") == 0);
        reset_log();
        CHECK(ntw_route_check(&policy, module_name, capture, (void *)0x51) == 2 && captured_count == 2);
        CHECK(!logged("[routing] order") && !logged("[order] GetTickCount64"));
        /* A module override to Auto under another process mode, too. */
        ntw_route_policy_init(&policy);
        CHECK(parse_env(&policy, "[routing]|mode=native|order=own|[modules]|kernel32.dll=auto|[order]|Sleep=own") == 0);
        reset_log();
        CHECK(ntw_route_check(&policy, module_name, capture, (void *)0x51) == 0 && captured_count == 0);
        /* Defaults and tolerated NULLs. */
        ntw_route_policy_init(&policy);
        CHECK(ntw_route_check(&policy, module_name, capture, (void *)0x51) == 0);
        CHECK(ntw_route_check(NULL, module_name, capture, (void *)0x51) == 0);
        CHECK(ntw_route_check(&policy, NULL, capture, (void *)0x51) == 0);
        CHECK(ntw_route_parse(&policy, "[modules]|GDI32.DLL=own", 23, '|', NULL, NULL) == 0);
        CHECK(ntw_route_check(&policy, module_name, NULL, NULL) == 1 && policy.warnings == 1);
    }
}

int main(void) {
    text_builder();
    names_and_modes();
    parser_accepts();
    parser_rejects();
    order_and_stubs();
    image_size();
    resolution_matrix();
    configured_order();
    printf("PASS: routing policy modes, overrides, configured order, stub demotion, KernelEx "
           "attribution, bounded INI parsing; %u checks; host mocks only, no Windows 98 guest\n", checks);
    return 0;
}
