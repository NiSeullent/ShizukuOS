/* SPDX-License-Identifier: GPL-2.0-only */
#include "shell.h"
#define CSIDL_CREATE 0x8000u
#define CSIDL_NO_VERIFY 0x4000u
#define KF_CREATE 0x8000u
#define KF_NO_VERIFY 0x400u

static int copy_rel(char *out, uint32_t cap, const char *root, const char *rel) {
    uint32_t i = 0, j = 0;
    if (!root || !root[0] || !out || cap < 4) return 0;
    while (root[i] && j + 1 < cap) out[j++] = root[i++];
    if (j && out[j - 1] != '/') out[j++] = '/';
    i = 0;
    while (rel[i] && j + 1 < cap) out[j++] = rel[i++];
    out[j] = 0;
    return 1;
}
static int windows_path(const char *rel, uint16_t *out, uint32_t chars) {
    uint32_t i = 0, n = 3;
    if (chars < 8) return 0;
    out[0] = 'C'; out[1] = ':'; out[2] = '\\';
    while (rel[i] && n + 1 < chars) {
        char ch = rel[i++];
        out[n++] = (uint16_t)(ch == '/' ? '\\' : ch);
    }
    out[n] = 0;
    return rel[i] == 0;
}
static int path_ready(const char *path, int create, ntw_shell_exists exists, ntw_shell_mkdir mkdir, void *user, uint32_t *hr) {
    char partial[260];
    uint32_t n = 0, i;
    if (exists && exists(user, path) == 1) return 1;
    if (!create) { *hr = NTW_SHELL_MISSING; return 0; }
    if (!mkdir) { *hr = NTW_SHELL_MISSING; return 0; }
    while (path[n]) n++;
    for (i = 1; i < n; ++i) {
        uint32_t k;
        if (path[i] != '/') continue;
        for (k = 0; k < i && k + 1 < sizeof partial; ++k) partial[k] = path[k];
        partial[k] = 0;
        if (exists && exists(user, partial) == 1) continue;
        {
            int made = mkdir(user, partial);
            if (made < 0 && !(exists && exists(user, partial) == 1)) {
                *hr = made == -13 ? 0x80070005u : NTW_SHELL_MISSING;
                return 0;
            }
        }
    }
    {
        int made = mkdir(user, path);
        if (made < 0 && !(exists && exists(user, path) == 1)) {
            *hr = made == -13 ? 0x80070005u : NTW_SHELL_MISSING;
            return 0;
        }
    }
    return 1;
}
static const char *csidl_rel(uint32_t id) {
    if (id == 0x1a) return "AppData/Roaming";
    if (id == 0x1c) return "AppData/Local";
    if (id == 0x23) return "ProgramData";
    if (id == 0x28) return "Profile";
    if (id == 0x10) return "Profile/Desktop";
    if (id == 0x05) return "Profile/Documents";
    if (id == 0x26) return "Program Files";
    if (id == 0x24) return "Windows";
    if (id == 0x25) return "Windows/System32";
    if (id == 0x20) return "AppData/Local/INetCache";
    if (id == 0x14) return "Windows/Fonts";
    return 0;
}
static int same_guid(const uint8_t *guid, const uint8_t *want) {
    uint32_t i;
    for (i = 0; i < 16; ++i) if (guid[i] != want[i]) return 0;
    return 1;
}
static const char *guid_rel(const uint8_t guid[16]) {
    static const uint8_t roam[] = {0xDB,0x85,0xB6,0x3E,0xF9,0x65,0xF6,0x4C,0xA0,0x3A,0xE3,0xEF,0x65,0x72,0x9F,0x3D};
    static const uint8_t local[] = {0x85,0x27,0xB3,0xF1,0xBA,0x6F,0xCF,0x4F,0x9D,0x55,0x7B,0x8E,0x7F,0x15,0x70,0x91};
    static const uint8_t program[] = {0x82,0x5D,0xAB,0x62,0xC1,0xFD,0xC3,0x4D,0xA9,0xDD,0x07,0x0D,0x1D,0x49,0x5D,0x97};
    static const uint8_t profile[] = {0x8F,0x85,0x6C,0x5E,0x22,0x0E,0x60,0x47,0x9A,0xFE,0xEA,0x33,0x17,0xB6,0x71,0x73};
    static const uint8_t desktop[] = {0x3A,0xFC,0xBF,0xB4,0x2C,0xDB,0x4C,0x42,0xB0,0x29,0x7F,0xE9,0x9A,0x87,0xC6,0x41};
    static const uint8_t docs[] = {0xD0,0x9A,0xD3,0xFD,0x8F,0x23,0xAF,0x46,0xAD,0xB4,0x6C,0x85,0x48,0x03,0x69,0xC7};
    if (same_guid(guid, roam)) return "AppData/Roaming";
    if (same_guid(guid, local)) return "AppData/Local";
    if (same_guid(guid, program)) return "ProgramData";
    if (same_guid(guid, profile)) return "Profile";
    if (same_guid(guid, desktop)) return "Profile/Desktop";
    if (same_guid(guid, docs)) return "Profile/Documents";
    return 0;
}
static int finish_folder(const char *root, const char *rel, int create, int allow_missing,
                         ntw_shell_exists exists, ntw_shell_mkdir mkdir, void *user,
                         uint16_t *out, uint32_t chars, uint32_t *hr) {
    char path[260];
    if (!out || chars < 8) { *hr = NTW_SHELL_INVALID; return 0; }
    if (!copy_rel(path, sizeof path, root, rel)) { *hr = NTW_SHELL_INVALID; return 0; }
    if (!path_ready(path, 1, exists, mkdir, user, hr)) return 0;
    if (!windows_path(rel, out, chars)) { *hr = NTW_SHELL_INVALID; return 0; }
    (void)create; (void)allow_missing;
    *hr = NTW_SHELL_OK;
    return 1;
}
int ntw_shell_folder(uint32_t csidl, const char *root, ntw_shell_exists exists, ntw_shell_mkdir mkdir,
                     void *user, uint16_t *out, uint32_t chars, uint32_t *hr) {
    uint32_t id = csidl & 0xffu;
    const char *rel;
    if (!hr) return 0;
    rel = csidl_rel(id);
    if (!rel) { *hr = NTW_SHELL_INVALID; return 0; }
    return finish_folder(root, rel, (csidl & CSIDL_CREATE) != 0, (csidl & CSIDL_NO_VERIFY) != 0,
                         exists, mkdir, user, out, chars, hr);
}
int ntw_shell_known(const uint8_t guid[16], uint32_t flags, const char *root, ntw_shell_exists exists,
                    ntw_shell_mkdir mkdir, void *user, uint16_t *out, uint32_t chars, uint32_t *hr) {
    const char *rel;
    if (!hr) return 0;
    if (!guid) { *hr = NTW_SHELL_INVALID; return 0; }
    rel = guid_rel(guid);
    if (!rel) { *hr = NTW_SHELL_INVALID; return 0; }
    return finish_folder(root, rel, (flags & KF_CREATE) != 0, (flags & KF_NO_VERIFY) != 0,
                         exists, mkdir, user, out, chars, hr);
}
int ntw_shell_argv(const uint16_t *cmd, uint16_t *words, uint32_t word_cap, uint32_t *offsets,
                   int max_args, int *argc, uint32_t *error) {
    uint32_t used = 0;
    int count = 0;
    if (!error || !argc) return 0;
    *argc = 0;
    if (!cmd || !words || !offsets || max_args < 1 || word_cap < 2) { *error = 87; return 0; }
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (!*cmd) { *error = 87; return 0; }
    while (*cmd) {
        int quote = 0;
        if (count >= max_args || used + 1 >= word_cap) { *error = 122; return 0; }
        offsets[count] = used;
        while (*cmd && (quote || (*cmd != ' ' && *cmd != '\t'))) {
            uint16_t ch = *cmd++;
            if (ch == '"') { quote = !quote; continue; }
            if (used + 1 >= word_cap) { *error = 122; return 0; }
            words[used++] = ch;
        }
        words[used++] = 0;
        count++;
        while (*cmd == ' ' || *cmd == '\t') cmd++;
    }
    *argc = count;
    *error = 0;
    return 1;
}
