/* SPDX-License-Identifier: GPL-2.0-only */
#include "clock.h"
#include "regs.h"

void csm_ticks_init(csm_ticks *t)
{
    if (!t)
        return;
    t->ticks = 0;
    t->midnight = 0;
}

int csm_ticks_set(csm_ticks *t, uint32_t ticks)
{
    if (!t || ticks >= CSM_TICKS_PER_DAY)
        return CSM_ERR_RANGE;
    t->ticks = ticks;
    t->midnight = 0;
    return CSM_OK;
}

void csm_ticks_advance(csm_ticks *t, uint32_t count)
{
    uint64_t sum, days;
    if (!t)
        return;
    sum = (uint64_t)t->ticks + count;
    days = sum / CSM_TICKS_PER_DAY;
    t->ticks = (uint32_t)(sum % CSM_TICKS_PER_DAY);
    if (days) {
        unsigned add = days > 255ull ? 255u : (unsigned)days;
        if ((unsigned)t->midnight + add > 255u)
            t->midnight = 255;
        else
            t->midnight = (uint8_t)(t->midnight + add);
    }
}

uint32_t csm_ticks_read(csm_ticks *t, uint8_t *midnight)
{
    uint8_t flag;
    if (!t)
        return 0;
    flag = t->midnight;
    t->midnight = 0;
    if (midnight)
        *midnight = flag;
    return t->ticks;
}

int csm_civil_valid(const csm_civil *time)
{
    static const uint8_t mdays[13] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int leap, dim;
    if (!time || time->year < 0 || time->year > 9999)
        return 0;
    if (time->month < 1 || time->month > 12 || time->day < 1)
        return 0;
    if (time->hour < 0 || time->hour > 23 || time->minute < 0 || time->minute > 59 ||
        time->second < 0 || time->second > 59)
        return 0;
    leap = ((time->year % 4) == 0 && (time->year % 100) != 0) || (time->year % 400) == 0;
    dim = mdays[time->month];
    if (time->month == 2 && leap)
        dim = 29;
    return time->day <= dim;
}

uint8_t csm_to_bcd(int value)
{
    if (value < 0 || value > 99)
        return 0xff;
    return (uint8_t)(((value / 10) << 4) | (value % 10));
}

int csm_read_clock(csm_time_source source, void *context, csm_civil *out)
{
    csm_civil raw;
    if (!source || !out)
        return CSM_ERR_ARG;
    raw.year = raw.month = raw.day = raw.hour = raw.minute = raw.second = -1;
    if (source(context, &raw) != 0 || !csm_civil_valid(&raw))
        return CSM_ERR_MALFORMED;
    *out = raw;
    return CSM_OK;
}
