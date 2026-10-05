/* SPDX-License-Identifier: GPL-2.0-only
 * Private append-only NtShzToken operations; existing auth/SAW ABI unchanged. */
#ifndef SHZ_FIRSTBOOT_ABI_H
#define SHZ_FIRSTBOOT_ABI_H
#include <stdint.h>
#define SHZ_FIRSTBOOT_VERSION 1u
#define SHZ_FIRSTBOOT_QUERY 0x205u
#define SHZ_FIRSTBOOT_COMPLETE 0x206u
#define SHZ_FIRSTBOOT_NEW 0u
#define SHZ_FIRSTBOOT_RESUME 1u
#define SHZ_FIRSTBOOT_DONE 2u
#define SHZ_FIRSTBOOT_EXISTING 3u
#define SHZ_FIRSTBOOT_STORE_PERSISTENT 1u
#define SHZ_FIRSTBOOT_STORE_SEALED 2u
#define SHZ_FIRSTBOOT_LANG_KO 1u
#define SHZ_FIRSTBOOT_LANG_EN 2u
#define SHZ_FIRSTBOOT_KEYBOARD_US 1u /* Layout identity; no Korean IME claim. */
#define SHZ_FIRSTBOOT_PREFS_MAGIC 0x46505a53u /* SZPF */
typedef struct {
    uint32_t magic,version,language,keyboard;
} shz_firstboot_preferences; /* Installed SHZ\SETUP\FIRSTBOOT.CFG, exact LE16B. */
typedef struct {
    uint32_t version,size,uid,language,keyboard,flags,reserved[2];
} shz_firstboot_request;
typedef struct {
    uint32_t version,size,phase,store_flags,accounts,uid,language,keyboard;
    char user[32],home[48];
} shz_firstboot_reply;
_Static_assert(sizeof(shz_firstboot_preferences)==16,"firstboot prefs ABI");
_Static_assert(sizeof(shz_firstboot_request)==32,"firstboot request ABI");
_Static_assert(sizeof(shz_firstboot_reply)==112,"firstboot reply ABI");
#endif
