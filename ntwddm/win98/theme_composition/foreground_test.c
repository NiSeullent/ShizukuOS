/* SPDX-License-Identifier: GPL-2.0-only; ownership/refusal tests, not native ABI proof. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef void *HWND;
typedef uint32_t DWORD;
static HWND own = (HWND)(uintptr_t)1, foreign = (HWND)(uintptr_t)2, current;
static DWORD owner, thread;
static int visible, api, sets, reads, ownership_queries, checks;
static DWORD GetWindowThreadProcessId(HWND w, DWORD *p)
{ assert(w == own || w == foreign); ++ownership_queries; *p = owner; return thread; }
static DWORD GetCurrentProcessId(void) { return 42; }
static int IsWindowVisible(HWND w) { assert(w == own); return visible; }
static int SetForegroundWindow(HWND w) { assert(w == own); ++sets; return api; }
static HWND GetForegroundWindow(void) { ++reads; return current; }
#include "foreground.h"
#define CHECK(v) do { ++checks; assert(v); } while (0)
static void reset(void)
{ owner=42; thread=7; visible=1; api=1; current=own; sets=reads=ownership_queries=0; }
int main(void)
{
    foreground_report r;
    reset(); r=acquire_own_foreground(NULL);
    CHECK(!r.owned && !r.requested && !sets && !reads && !ownership_queries);
    reset(); owner=99; r=acquire_own_foreground(foreign);
    CHECK(!r.owned && !r.requested && !sets && !reads);
    reset(); thread=0; r=acquire_own_foreground(own);
    CHECK(!r.owned && !r.requested && !sets && !reads);
    reset(); owner=0; r=acquire_own_foreground(own);
    CHECK(!r.owned && !r.requested && !sets && !reads);
    reset(); visible=0; r=acquire_own_foreground(own);
    CHECK(r.owned && !r.visible && !r.requested && !sets && !reads);
    reset(); r=acquire_own_foreground(own);
    CHECK(r.owned && r.visible && r.requested && r.api_return && r.matches);
    CHECK(sets==1 && reads==1 && ownership_queries==1);
    reset(); api=0; current=foreign; r=acquire_own_foreground(own);
    CHECK(r.requested && !r.api_return && !r.matches && sets==1 && reads==1);
    reset(); current=foreign; r=acquire_own_foreground(own);
    CHECK(r.api_return && !r.matches && sets==1 && reads==1);
    reset(); api=0; r=acquire_own_foreground(own);
    CHECK(!r.api_return && r.matches && sets==1 && reads==1);
    reset(); current=NULL; r=acquire_own_foreground(own);
    CHECK(r.requested && !r.matches && sets==1 && reads==1);
    printf("PASS: %d foreground ownership, refusal and independent handle assertions\n",checks);
    return 0;
}
