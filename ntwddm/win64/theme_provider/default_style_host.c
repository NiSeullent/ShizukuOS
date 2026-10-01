/* SPDX-License-Identifier: GPL-2.0-only
 * Real core default initialization, style transitions and allocation failures.
 * No Windows locking/ABI execution or guest rendering is claimed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "default_style.h"

static unsigned checks, allocations, live, failure_at;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)
typedef struct allocation { size_t bytes; } allocation;
static void *allocate(void *user, size_t bytes)
{
    allocation *memory;
    CHECK(user == &checks); ++allocations;
    if (allocations == failure_at) return NULL;
    memory = calloc(1,sizeof(*memory)+bytes); CHECK(memory != NULL);
    memory->bytes = bytes; ++live; return memory+1;
}
static void deallocate(void *user, void *value, size_t bytes)
{
    allocation *memory = (allocation *)value - 1;
    CHECK(user == &checks && value && live && memory->bytes == bytes);
    --live; free(memory);
}
static void drawing(m98_theme_engine *engine, uint32_t style)
{
    m98_theme_handle handle = 0;
    ntth_part_properties props;
    uint8_t pixels[64];
    ntwg_rect area = {0,0,4,4};
    CHECK(m98_theme_engine_open(engine,"BUTTON",&handle) == NTTH_OK);
    CHECK(handle != 0 && m98_theme_engine_query(engine,handle,1,1,&props) == NTTH_OK);
    CHECK(props.fillcolor == (style == M98_THEME_CLASSIC ? 0xc0c0c0u : 0xf0f0f0u));
    memset(pixels,0,sizeof(pixels));
    CHECK(m98_theme_engine_draw(engine,handle,1,1,pixels,4,4,16,&area,NULL) == NTTH_OK);
    CHECK(pixels[20] == (style == M98_THEME_CLASSIC ? 0xc0 : 0xf0));
    CHECK(pixels[21] == pixels[20] && pixels[22] == pixels[20]);
    CHECK(m98_theme_engine_style(engine,style == M98_THEME_CLASSIC ? M98_THEME_MODERN : M98_THEME_CLASSIC) == NTTH_OK);
    CHECK(m98_theme_engine_query(engine,handle,1,1,&props) != NTTH_OK);
    CHECK(m98_theme_engine_close(engine,handle) == NTTH_OK);
}
int main(void)
{
    ntth_create_desc descriptor = {sizeof(descriptor),allocate,deallocate,&checks};
    m98_theme_engine *engine;
    for (uint32_t style=M98_THEME_OFF; style<=M98_THEME_MODERN; ++style) {
        unsigned successful_allocations;
        allocations=live=failure_at=0;
        CHECK(m98w_create_default(&descriptor,style,&engine) == NTTH_OK && engine);
        successful_allocations=allocations;
        CHECK(m98_theme_engine_get_style(engine) == style);
        CHECK(m98_theme_engine_get_flags(engine) == 7u);
        CHECK(m98_theme_engine_active(engine) == (style != M98_THEME_OFF));
        if (style == M98_THEME_OFF) {
            m98_theme_handle handle=77;
            CHECK(m98_theme_engine_open(engine,"BUTTON",&handle) == NTTH_E_NO_THEME && handle == 0);
            CHECK(m98_theme_engine_style(engine,M98_THEME_MODERN) == NTTH_OK);
            drawing(engine,M98_THEME_MODERN);
        } else drawing(engine,style);
        /* Selection following lazy creation directly uses the core while the
         * caller owns its lock, including selecting OFF immediately afterwards. */
        for (unsigned i=0;i<16;++i) {
            CHECK(m98_theme_engine_style(engine,i % 3) == NTTH_OK);
            CHECK(m98_theme_engine_get_style(engine) == i % 3);
        }
        CHECK(m98_theme_engine_destroy(engine) == NTTH_OK); CHECK(live==0);
        for (unsigned fail=1; fail<=successful_allocations; ++fail) {
            allocations=live=0; failure_at=fail; engine=(m98_theme_engine *)1;
            CHECK(m98w_create_default(&descriptor,style,&engine) != NTTH_OK);
            CHECK(engine==NULL && live==0);
        }
    }
    allocations=live=failure_at=0; engine=(m98_theme_engine *)1;
    CHECK(m98w_create_default(&descriptor,3,&engine) == NTTH_E_INVALID);
    CHECK(engine==NULL && allocations==0 && live==0);
    CHECK(m98w_create_default(&descriptor,0,NULL) == NTTH_E_INVALID);
    CHECK(m98w_create_default(NULL,2,&engine) == NTTH_E_INVALID && engine==NULL);
    printf("PASS: %u default-style initialization, pixel, transition and allocation assertions\n",checks);
    return 0;
}
