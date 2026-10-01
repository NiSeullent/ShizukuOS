/* SPDX-License-Identifier: GPL-2.0-only
 * Static fatal-state core. The interrupted OS never resumes. Games touch only
 * this owned state; neither game uses heap, scheduler, FS, GPU commands or IPC.
 */
#include "dead_screen.h"

static void zero(void *p, size_t n) { uint8_t *b = p; while (n--) *b++ = 0; }
static uint32_t random_next(ds_state *s)
{
    uint32_t x = s->rng;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    s->rng = x ? x : 0x53485a31u;
    return s->rng;
}
static unsigned sat_add(unsigned a, unsigned b) { return a > UINT32_MAX - b ? UINT32_MAX : a + b; }

/* Clockwise rotations, four rows of four bits. All seven tetrominoes are real
 * collision objects. Rotation uses a small bounded wall-kick search. */
static const uint16_t shape[7][4] = {
    {0x00f0,0x4444,0x0f00,0x2222}, {0x0660,0x0660,0x0660,0x0660},
    {0x0072,0x0262,0x0270,0x0232}, {0x0036,0x0462,0x0360,0x0231},
    {0x0063,0x0264,0x0630,0x0132}, {0x0071,0x0226,0x0470,0x0322},
    {0x0074,0x0622,0x0170,0x0223}
};
static int occupied(unsigned p, unsigned r, unsigned x, unsigned y)
{ return (shape[p][r] >> (y * 4 + x)) & 1; }
int ds_tetris_fits(const ds_tetris *t, unsigned p, unsigned r, int x, int y)
{
    unsigned xx, yy;
    if (!t || p >= 7 || r >= 4 || x < -4 || x > 10 || y < -4 || y > 20) return 0;
    for (yy = 0; yy < 4; ++yy) for (xx = 0; xx < 4; ++xx) if (occupied(p,r,xx,yy)) {
        const int bx = x + (int)xx, by = y + (int)yy;
        if (bx < 0 || bx >= 10 || by >= 20) return 0;
        if (by >= 0 && t->board[by][bx]) return 0;
    }
    return 1;
}
unsigned ds_tetris_clear(ds_tetris *t)
{
    int y, out = 19;
    unsigned n = 0, x;
    for (y = 19; y >= 0; --y) {
        int full = 1;
        for (x = 0; x < 10; ++x) if (!t->board[y][x]) full = 0;
        if (full) { ++n; continue; }
        for (x = 0; x < 10; ++x) t->board[out][x] = t->board[y][x];
        --out;
    }
    while (out >= 0) { for (x = 0; x < 10; ++x) t->board[out][x] = 0; --out; }
    t->lines = sat_add(t->lines, n);
    t->score = sat_add(t->score, n * n * 100u);
    return n;
}
static void spawn(ds_state *s)
{
    ds_tetris *t = &s->tetris;
    t->piece = random_next(s) % 7; t->rotation = 0; t->x = 3; t->y = 0; t->fall = 0;
    if (!ds_tetris_fits(t,t->piece,0,t->x,t->y)) t->over = 1;
}
static void lock_piece(ds_state *s)
{
    ds_tetris *t = &s->tetris;
    unsigned x,y;
    for (y = 0; y < 4; ++y) for (x = 0; x < 4; ++x) if (occupied(t->piece,t->rotation,x,y)) {
        const int bx = t->x + (int)x, by = t->y + (int)y;
        if (by < 0) { t->over = 1; return; }
        t->board[by][bx] = (uint8_t)(1 + t->piece % 6);
    }
    (void)ds_tetris_clear(t);
    spawn(s);
}
static void down(ds_state *s)
{
    ds_tetris *t = &s->tetris;
    if (ds_tetris_fits(t,t->piece,t->rotation,t->x,t->y+1)) ++t->y; else lock_piece(s);
}

static const int radius[6] = { 10,15,21,28,36,45 };
static int32_t clamp(int32_t v, int32_t lo, int32_t hi) { return v < lo ? lo : v > hi ? hi : v; }
static uint32_t root64(uint64_t v)
{
    uint64_t bit = (uint64_t)1 << 62, out = 0;
    while (bit > v) bit >>= 2;
    while (bit) { if (v >= out + bit) { v -= out + bit; out = (out >> 1) + bit; } else out >>= 1; bit >>= 2; }
    return (uint32_t)out;
}
static void ball_bounds(ds_ball *b)
{
    const int32_t r = radius[b->level] * 256;
    b->vx = clamp(b->vx,-2048,2048); b->vy = clamp(b->vy,-3072,3072);
    if (b->x < r) { b->x = r; if (b->vx < 0) b->vx = -b->vx/2; }
    if (b->x > 240*256-r) { b->x = 240*256-r; if (b->vx > 0) b->vx = -b->vx/2; }
    b->y = clamp(b->y,-64*256,288*256);
    if (b->y > 288*256-r) { b->y = 288*256-r; if (b->vy > 0) b->vy = -b->vy/4; }
}
void ds_suika_step(ds_suika *u)
{
    unsigned i,j;
    if (u->over) return;
    if (u->cooldown) --u->cooldown;
    for (i=0;i<DS_BALLS;++i) if (u->ball[i].used) {
        ds_ball *b=&u->ball[i];
        /* Corrupted owned game state cannot index radius or overflow arithmetic. */
        if (b->level >= 6) { u->over=1; return; }
        ball_bounds(b);
        b->vy=clamp(b->vy+48,-3072,3072);
        b->x+=b->vx; b->y+=b->vy; b->vx=b->vx*250/256;
        ball_bounds(b);
    }
    /* Two fixed solver passes; at most 992 pairs, never an unbounded relaxation. */
    for (unsigned pass=0;pass<2;++pass) for(i=0;i<DS_BALLS;++i) if(u->ball[i].used)
        for(j=i+1;j<DS_BALLS;++j) if(u->ball[j].used) {
            ds_ball *a=&u->ball[i], *b=&u->ball[j];
            int32_t dx=b->x-a->x, dy=b->y-a->y;
            const int32_t sum=(radius[a->level]+radius[b->level])*256;
            uint32_t d=root64((uint64_t)((int64_t)dx*dx+(int64_t)dy*dy));
            if(d >= (uint32_t)sum) continue;
            if(a->level==b->level && a->level<5) {
                a->x=(a->x+b->x)/2; a->y=(a->y+b->y)/2;
                a->vx=(a->vx+b->vx)/2; a->vy=(a->vy+b->vy)/2;
                ++a->level; a->ceiling_ticks=0; b->used=0;
                u->score=sat_add(u->score,1u<<a->level); ball_bounds(a); continue;
            }
            if(!d) { dx=256; dy=0; d=256; }
            const int32_t push=(sum-(int32_t)d+1)/2;
            const int32_t px=(int32_t)((int64_t)dx*push/d), py=(int32_t)((int64_t)dy*push/d);
            a->x-=px; a->y-=py; b->x+=px; b->y+=py;
            /* Dissipative collision, stable bounded gameplay rather than floating point. */
            a->vx=a->vx/2-px/8; b->vx=b->vx/2+px/8;
            a->vy=a->vy/2-py/8; b->vy=b->vy/2+py/8;
            ball_bounds(a); ball_bounds(b);
        }
    for(i=0;i<DS_BALLS;++i) if(u->ball[i].used) {
        ds_ball *b=&u->ball[i];
        if (b->y-radius[b->level]*256 < 24*256) {
            if(b->ceiling_ticks < 120) ++b->ceiling_ticks;
            if(b->ceiling_ticks == 120) u->over=1;
        } else b->ceiling_ticks=0;
    }
}
static void reset_game(ds_state *s)
{
    if(s->mode==DS_TETRIS) { zero(&s->tetris,sizeof s->tetris); spawn(s); }
    if(s->mode==DS_SUIKA) { zero(&s->suika,sizeof s->suika); s->suika.aim=120; s->suika.next=random_next(s)%3; }
}
void ds_init(ds_state *s) { zero(s,sizeof *s); s->rng=0x53485a31u; s->korean=1; s->show_trace=1; }
int ds_latch(ds_state *s, enum ds_severity severity, const ds_fault *r)
{
    size_t i;
    if(!s || severity!=DS_KERNEL_FATAL) return 0;
    if(s->latched) return -1;
    if(!r) return 0;
    s->fault=*r;
    s->fault.reason[DS_REASON-1]=0;
    if(s->fault.frame_count>DS_FRAMES) s->fault.frame_count=DS_FRAMES;
    for(i=s->fault.frame_count;i<DS_FRAMES;++i) s->fault.frames[i]=0;
    s->fault.registers_valid=!!r->registers_valid;
    s->latched=1; s->mode=DS_MENU;
    return 1;
}
void ds_key_event(ds_state *s, enum ds_key key)
{
    if(!s || !s->latched || s->graphics_failed) return;
    if(key==DS_LANGUAGE) { s->korean^=1; return; }
    if(key==DS_TRACE) { s->show_trace^=1; return; }
    if(key==DS_ESCAPE) { s->mode=DS_MENU; return; }
    if(key==DS_ONE || key==DS_TWO) { s->mode=key==DS_ONE?DS_TETRIS:DS_SUIKA; reset_game(s); return; }
    if(key==DS_RESTART) { reset_game(s); return; }
    if(s->mode==DS_TETRIS && !s->tetris.over) {
        ds_tetris *t=&s->tetris;
        if(t->piece>=7 || t->rotation>=4 || t->x < -4 || t->x>10 || t->y < -4 || t->y>20 ||
           !ds_tetris_fits(t,t->piece,t->rotation,t->x,t->y)) {s->graphics_failed=1;return;}
        const int shift=key==DS_LEFT?-1:key==DS_RIGHT?1:0;
        if(shift && ds_tetris_fits(t,t->piece,t->rotation,t->x+shift,t->y)) t->x+=shift;
        if(key==DS_UP) {
            static const int kick[5]={0,-1,1,-2,2};
            const unsigned r=(t->rotation+1)%4;
            for(unsigned i=0;i<5;++i) if(ds_tetris_fits(t,t->piece,r,t->x+kick[i],t->y)) { t->x+=kick[i]; t->rotation=r; break; }
        }
        if(key==DS_DOWN) down(s);
        if(key==DS_DROP) { for(unsigned i=0;i<24 && ds_tetris_fits(t,t->piece,t->rotation,t->x,t->y+1);++i) ++t->y; lock_piece(s); }
    } else if(s->mode==DS_SUIKA && !s->suika.over) {
        ds_suika *u=&s->suika;
        if(u->next>=3 || u->aim<24 || u->aim>216) {s->graphics_failed=1;return;}
        if(key==DS_LEFT) u->aim=clamp(u->aim-8,24,216);
        if(key==DS_RIGHT) u->aim=clamp(u->aim+8,24,216);
        if((key==DS_DROP || key==DS_DOWN) && !u->cooldown) {
            unsigned i;
            for(i=0;i<DS_BALLS && u->ball[i].used;++i) {}
            if(i==DS_BALLS) { u->over=1; return; }
            ds_ball *b=&u->ball[i]; zero(b,sizeof *b);
            b->used=1; b->level=(uint8_t)u->next; b->x=u->aim*256; b->y=16*256;
            u->next=random_next(s)%3; u->cooldown=30;
        }
    }
}
void ds_tick(ds_state *s)
{
    if(!s || !s->latched || s->graphics_failed) return;
    ++s->ticks;
    if(s->mode==DS_TETRIS && !s->tetris.over) {
        if(s->tetris.piece>=7 || s->tetris.rotation>=4 ||
           !ds_tetris_fits(&s->tetris,s->tetris.piece,s->tetris.rotation,s->tetris.x,s->tetris.y)) {
            s->graphics_failed=1;return;
        }
        unsigned interval=30-(s->tetris.lines<25?s->tetris.lines:25);
        if(++s->tetris.fall>=interval) { s->tetris.fall=0; down(s); }
    }
    if(s->mode==DS_SUIKA) ds_suika_step(&s->suika);
}
enum ds_key ds_scan1(ds_state *s, uint8_t b)
{
    if(s->pause_bytes) { --s->pause_bytes; return DS_NONE; }
    if(b==0xe1) { s->pause_bytes=5; s->prefix=0; return DS_NONE; }
    if(b==0xe0) { s->prefix=1; return DS_NONE; }
    const unsigned ext=s->prefix;s->prefix=0;
    if(b&0x80) return DS_NONE;
    if(ext && b!=0x4b && b!=0x4d && b!=0x48 && b!=0x50 && b!=0x1c) return DS_NONE;
    switch(b) {
    case 0x02:return DS_ONE; case 0x03:return DS_TWO; case 0x4b:case 0x1e:return DS_LEFT;
    case 0x4d:case 0x20:return DS_RIGHT; case 0x48:case 0x11:return DS_UP;
    case 0x50:case 0x1f:return DS_DOWN; case 0x39:case 0x1c:return DS_DROP;
    case 0x01:return DS_ESCAPE; case 0x13:return DS_RESTART; case 0x26:return DS_LANGUAGE;
    case 0x14:return DS_TRACE; default:return DS_NONE;
    }
}
enum ds_key ds_serial_key(uint8_t b)
{
    switch(b) { case '1':return DS_ONE; case '2':return DS_TWO;
    case 'a':return DS_LEFT; case 'd':return DS_RIGHT; case 'w':return DS_UP; case 's':return DS_DOWN;
    case ' ':case '\r':return DS_DROP; case 27:return DS_ESCAPE; case 'r':return DS_RESTART;
    case 'l':return DS_LANGUAGE; case 't':return DS_TRACE; default:return DS_NONE; }
}
