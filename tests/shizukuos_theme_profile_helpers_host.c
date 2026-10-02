/* SPDX-License-Identifier: GPL-2.0-only
 * Pure production helper tests: no Windows APIs, registry/GDI mocks or native
 * probe entrypoint are executed. Native profile/pixel acceptance stays pending.
 */
#define M98_PROFILE_HELPERS_ONLY
#include "shizukuos_theme_profile_guest.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

int main(void)
{
    static const char *names[] = { "default-shizukuos", "save-classic", "check-classic",
                                 "save-shizukuos", "check-shizukuos" };
    static const enum m98p_mode values[] = { M98P_DEFAULT, M98P_SAVE_CLASSIC,
        M98P_CHECK_CLASSIC, M98P_SAVE_SHIZUKUOS, M98P_CHECK_SHIZUKUOS };
    static const char *bad[] = { "", "SHZTPRO.EXE", "SHZTPRO.EXE unknown",
        "SHZTPRO.EXE save-classi", "SHZTPRO.EXE save-classic extra",
        "SHZTPRO.EXE --mode save-classic", "SHZTPRO.EXE SAVE-CLASSIC",
        "\"\" save-classic", "\"C:\\A B\\SHZTPRO.EXE save-classic",
        "\"C:\\SHZTPRO.EXE\"save-classic", "SHZT\"PRO.EXE save-classic",
        "SHZTPRO.EXE \"save-classic\"", "SHZTPRO.EXE save-classic\n" };
    static const char *bad_paths[] = { "", "SHZTPRO.EXE", "C:SHZTPRO.EXE",
        "\\\\server\\share\\SHZTPRO.EXE", "C:\\..\\SHZTPRO.EXE", "C:\\.\\SHZTPRO.EXE",
        "C:/GOPLAB/SHZTPRO.EXE", "C:\\GOPLAB\\", "C:\\GOPLAB\\bad\".EXE",
        "C:\\GOPLAB\\bad:EXE", "C:\\\\SHZTPRO.EXE" };
    char command[512], long_input[512];
    struct { unsigned char before[8]; char text[260]; unsigned char after[8]; } guarded;
    unsigned i, j, platform, major, minor, mode;

    /* Literal first oracle must fail at runtime before helper implementation. */
    CHECK(m98p_parse_mode("SHZTPRO.EXE default-shizukuos") == M98P_DEFAULT);
    for (i = 0; i < 5; ++i) {
        snprintf(command, sizeof(command), "C:\\GOPLAB\\SHZTPRO.EXE %s", names[i]);
        CHECK(m98p_parse_mode(command) == values[i]);
        snprintf(command, sizeof(command), " \t\"C:\\A B\\SHZTPRO.EXE\"\t%s \t", names[i]);
        CHECK(m98p_parse_mode(command) == values[i]);
    }
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        CHECK(m98p_parse_mode(bad[i]) == M98P_INVALID);
    memset(long_input, 'x', sizeof(long_input));
    CHECK(m98p_parse_mode(long_input) == M98P_INVALID);
    CHECK(m98p_parse_mode(NULL) == M98P_INVALID);
    for (platform = 0; platform < 4; ++platform)
        for (major = 3; major <= 5; ++major)
            for (minor = 0; minor <= 90; ++minor) {
                int win98 = platform == 1 && major == 4 && minor == 10;
                CHECK(m98p_win98(platform, major, minor) == win98);
                for (mode = 0; mode <= 5; ++mode)
                    CHECK(m98p_save_allowed((enum m98p_mode)mode, platform, major, minor) ==
                          (win98 && (mode == 2 || mode == 4)));
            }
    CHECK(!m98p_win98(UINT32_MAX, 4, 10));
    CHECK(!m98p_win98(1, UINT32_MAX, 10));
    CHECK(!m98p_win98(1, 4, UINT32_MAX));
    CHECK(!m98p_save_allowed((enum m98p_mode)99, 1, 4, 10));
    memset(&guarded, 0x5a, sizeof(guarded));
    CHECK(m98p_adjacent("C:\\GOPLAB\\SHZTPRO.EXE", guarded.text, 23));
    CHECK(!strcmp(guarded.text, "C:\\GOPLAB\\M98THEME.DLL"));
    CHECK(guarded.text[22] == 0 && (unsigned char)guarded.text[23] == 0x5a);
    for (j = 0; j < 8; ++j) CHECK(guarded.before[j] == 0x5a && guarded.after[j] == 0x5a);
    memset(&guarded, 0x5a, sizeof(guarded));
    CHECK(!m98p_adjacent("C:\\GOPLAB\\SHZTPRO.EXE", guarded.text, 22));
    for (j = 0; j < sizeof(guarded); ++j) CHECK(((unsigned char *)&guarded)[j] == 0x5a);
    CHECK(m98p_adjacent("c:\\A B\\SHZTPRO.EXE", guarded.text, sizeof(guarded.text)));
    CHECK(!strcmp(guarded.text, "c:\\A B\\M98THEME.DLL"));
    CHECK(m98p_adjacent("C:\\SHZTPRO.EXE", guarded.text, sizeof(guarded.text)));
    CHECK(!strcmp(guarded.text, "C:\\M98THEME.DLL"));
    for (i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); ++i) {
        memset(&guarded, 0x5a, sizeof(guarded));
        CHECK(!m98p_adjacent(bad_paths[i], guarded.text, sizeof(guarded.text)));
        for (j = 0; j < sizeof(guarded); ++j) CHECK(((unsigned char *)&guarded)[j] == 0x5a);
    }
    memset(long_input, 'x', 260); long_input[260] = 0;
    CHECK(!m98p_adjacent(long_input, guarded.text, sizeof(guarded.text)));
    CHECK(!m98p_adjacent(NULL, guarded.text, sizeof(guarded.text)));
    CHECK(!m98p_adjacent("C:\\SHZTPRO.EXE", NULL, 260));
    CHECK(!m98p_adjacent("C:\\SHZTPRO.EXE", guarded.text, 0));
    CHECK(m98p_same_path("C:\\GOPLAB\\M98THEME.DLL", "c:/goplab/m98theme.dll"));
    CHECK(!m98p_same_path("C:\\GOPLAB\\M98THEME.DLL", "C:\\OTHER\\M98THEME.DLL"));
    CHECK(!m98p_same_path("C:\\GOPLAB\\M98THEME.DLL", "C:\\GOPLAB\\M98THEME.DLLx"));
    CHECK(!m98p_same_path(NULL, "C:\\M98THEME.DLL"));
    printf("PASS_HOST_HELPERS_ONLY: %u literal CLI/OS/path assertions; no native API execution\n", checks);
    return 0;
}
