/* SPDX-License-Identifier: GPL-2.0-only */
#include "user32.h"
#include <stdio.h>
static int failures;
static uint32_t last_error;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
typedef uint32_t __attribute__((stdcall)) (*wndfn)(uint32_t, const uint16_t *, const uint16_t *, uint32_t,
                                                  int32_t, int32_t, int32_t, int32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t __attribute__((stdcall)) (*stationfn)(void);
int main(void) {
    uint16_t name[8];
    wndfn create;
    stationfn station;
    ntw_user_bind(&last_error);
    name[0] = 'M'; name[1] = 'a'; name[2] = 'i'; name[3] = 'n'; name[4] = 0;
    create = (wndfn)(unsigned long)ntw_user_export("CreateWindowExW");
    station = (stationfn)(unsigned long)ntw_user_export("GetProcessWindowStation");
    C(create && station && ntw_user_export("RegisterClassW"));
    C(create(0, name, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) == 0 && last_error == 1407);
    C(station() == 0x5100u);
    C(ntw_user_owns(0x5100u) && ntw_user_owns(0x5200u) && !ntw_user_owns(1));
    {
        typedef uint32_t __attribute__((stdcall)) (*cstafn)(uint32_t, uint32_t, uint32_t, uint32_t);
        typedef uint32_t __attribute__((stdcall)) (*setfn)(uint32_t);
        typedef uint32_t __attribute__((stdcall)) (*infofn)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t *);
        cstafn make_station = (cstafn)(unsigned long)ntw_user_export("CreateWindowStationW");
        setfn set_station = (setfn)(unsigned long)ntw_user_export("SetProcessWindowStation");
        infofn info = (infofn)(unsigned long)ntw_user_export("GetUserObjectInformationW");
        uint32_t alt, needed = 0;
        C(make_station && set_station && info);
        alt = make_station(0, 0, 0x37f, 0);
        C(alt != 0 && alt != 0x5100u);
        C(info(alt, 2, 0, 0, &needed) == 0 && last_error == 122 && needed > 2);
        C(info(0x1111u, 2, 0, 0, &needed) == 0 && last_error == 6);
        C(set_station(1) == 0 && last_error == 6);
        C(set_station(alt) == 1 && station() == alt);
        C(set_station(0x5100u) == 1 && station() == 0x5100u);
    }
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"user32\":true}\n");
    return 0;
}
