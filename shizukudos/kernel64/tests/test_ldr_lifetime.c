/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ldr_lifetime.h"
#define N 24
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static unsigned rng = 0x152acd9u;
static unsigned random_word(void) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }

int main(void)
{
    shz_ldr_life_t n[N];
    shz_ldr_edge_t edges[N][N];
    unsigned round, i, j;
    for (round = 0; round < 12000; ++round) {
        unsigned expected[N] = {0}, stack[N], used = 0;
        memset(n,0,sizeof n); memset(edges,0,sizeof edges);
        for (i = 0; i < N; ++i) {
            n[i].next = i+1 < N ? &n[i+1] : NULL;
            n[i].refs = random_word()%13 == 0;
            n[i].root = random_word()%17 == 0;
            n[i].pinned = random_word()%29 == 0;
            n[i].retiring = random_word()%23 == 0;
            for (j = 0; j < N; ++j) if (random_word()%19 == 0) {
                edges[i][j].to = &n[j]; edges[i][j].next = n[i].edges; n[i].edges = &edges[i][j];
            }
            if (!n[i].retiring && (n[i].refs || n[i].root || n[i].pinned)) { expected[i]=1; stack[used++]=i; }
        }
        /* Independent bounded DFS oracle, including strongly connected cycles. */
        while (used) {
            unsigned from = stack[--used];
            for (j=0;j<N;++j) if (edges[from][j].to && !n[j].retiring && !expected[j]) {
                expected[j]=1; stack[used++]=j;
            }
        }
        shz_ldr_life_mark(n);
        for (i=0;i<N;++i) CHECK(n[i].reachable == expected[i]);
        shz_ldr_life_mark(n);
        for (i=0;i<N;++i) CHECK(n[i].reachable == expected[i]);
    }
    memset(n,0,sizeof n); memset(edges,0,sizeof edges);
    n[0].next=&n[1]; n[1].next=&n[2]; n[2].next=&n[3];
    edges[0][1].to=&n[1]; n[0].edges=&edges[0][1];
    edges[1][2].to=&n[2]; n[1].edges=&edges[1][2];
    edges[2][1].to=&n[1]; n[2].edges=&edges[2][1];
    n[0].refs=2; n[3].root=1;
    shz_ldr_life_mark(n); CHECK(n[0].reachable&&n[1].reachable&&n[2].reachable&&n[3].reachable);
    --n[0].refs; shz_ldr_life_mark(n); CHECK(n[1].reachable&&n[2].reachable);
    --n[0].refs; shz_ldr_life_mark(n); CHECK(!n[0].reachable&&!n[1].reachable&&!n[2].reachable&&n[3].reachable);
    CHECK(shz_ldr_life_addref(&n[2],1)==0); shz_ldr_life_mark(n); CHECK(n[1].reachable&&n[2].reachable&&!n[0].reachable);
    CHECK(shz_ldr_life_has_edge(&n[0],&n[1])); CHECK(!shz_ldr_life_has_edge(&n[0],&n[2]));
    n[0].refs=UINT32_MAX; CHECK(shz_ldr_life_addref(&n[0],0)==-1); CHECK(n[0].refs==UINT32_MAX);
    CHECK(shz_ldr_life_addref(&n[0],1)==0&&n[0].pinned);
    n[0].retiring=1; CHECK(shz_ldr_life_addref(&n[0],0)==-1); CHECK(shz_ldr_life_addref(&n[0],1)==-1);
    {
        shz_ldr_image_life_t im={1,0};
        CHECK(shz_ldr_image_acquire(&im)==0&&im.refs==2);
        CHECK(shz_ldr_image_acquire(&im)==0&&im.refs==3);
        /* Two real page-ins are blocked when the module owner retires. */
        CHECK(!shz_ldr_image_retire(&im)&&im.retired&&im.refs==2);
        CHECK(shz_ldr_image_acquire(&im)==-1&&im.refs==2);
        CHECK(!shz_ldr_image_retire(&im)&&im.refs==2);
        CHECK(!shz_ldr_image_release(&im)&&im.refs==1);
        CHECK(shz_ldr_image_release(&im)&&im.refs==0);
        CHECK(!shz_ldr_image_release(&im)); CHECK(shz_ldr_image_acquire(&im)==-1);
        im=(shz_ldr_image_life_t){UINT32_MAX,0}; CHECK(shz_ldr_image_acquire(&im)==-1&&im.refs==UINT32_MAX);
        im=(shz_ldr_image_life_t){1,0}; CHECK(shz_ldr_image_retire(&im)&&im.refs==0);
    }
    printf("LDR-LIFETIME-HOST: %u checks passed; graph roots/cycles/pins/ref overflow and blocked page-in ownership\n",checks);
    return 0;
}
