/* SPDX-License-Identifier: GPL-2.0-only */
#include "dead_screen.h"
#include "../supervisor/src/font8x8_basic.h"

typedef struct { const ds_surface *fb; int scale, ox, oy, width, height; } canvas;
static const uint32_t color[6]={0xffffff,0x253bb6,0x1764a9,0x0075b8,0x146cd4,0x146cd4};
static const char *const short_label[6]={"","2K","XP","8.1","10","11"};
static const int radius[6]={10,15,21,28,36,45};
static const char *const regname[DS_REGS]={"AX","BX","CX","DX","SI","DI","BP","R8","R9","R10","R11","R12","R13","R14","R15","CS"};

int ds_surface_storage_valid(const ds_surface *f)
{
    size_t need;
    uintptr_t base;
    if(!f || !f->pixels || f->width<8 || f->height<8 || f->width>4096 || f->height>4096 ||
       f->pitch_words<f->width || f->pitch_words>16384 || f->rgbx>1) return 0;
    /* Last visible pixel, not an assumed tightly packed allocation. */
    if((size_t)(f->height-1) > (SIZE_MAX-f->width)/f->pitch_words) return 0;
    need=(size_t)(f->height-1)*f->pitch_words+f->width;
    if(need>f->span_words || f->span_words>SIZE_MAX/4) return 0;
    base=(uintptr_t)f->pixels;
    if(base%4 || base>UINTPTR_MAX-f->span_words*4) return 0;
    return 1;
}
int ds_surface_valid(const ds_surface *f)
{return ds_surface_storage_valid(f) && f->width>=640 && f->height>=480;}
static uint32_t native_color(const ds_surface *f,uint32_t rgb)
{ return f->rgbx?((rgb&0xff)<<16)|(rgb&0xff00)|((rgb>>16)&0xff):rgb; }
static void pixel(canvas *c,int x,int y,uint32_t rgb)
{
    if(x<0 || y<0 || x>=c->width || y>=c->height) return;
    const unsigned xx=(unsigned)(c->ox+x*c->scale), yy=(unsigned)(c->oy+y*c->scale);
    const uint32_t v=native_color(c->fb,rgb);
    for(int i=0;i<c->scale;++i) for(int j=0;j<c->scale;++j)
        if(yy+(unsigned)i<c->fb->height && xx+(unsigned)j<c->fb->width)c->fb->pixels[(size_t)(yy+(unsigned)i)*c->fb->pitch_words+xx+(unsigned)j]=v;
}
static void rect(canvas *c,int x,int y,int w,int h,uint32_t rgb)
{
    if(w<=0 || h<=0) return;
    /* All private primitives accept bounded internal coordinates. Clipping here
     * makes even the large Suika circles harmless at canvas edges. */
    int x0=x<0?0:x, y0=y<0?0:y, x1=x+w>c->width?c->width:x+w, y1=y+h>c->height?c->height:y+h;
    for(int yy=y0;yy<y1;++yy) for(int xx=x0;xx<x1;++xx) pixel(c,xx,yy,rgb);
}
static void line(canvas *c,int x0,int y0,int x1,int y1,uint32_t rgb)
{
    int dx=x1-x0; if(dx<0) dx=-dx;
    int dy=y1-y0; if(dy<0) dy=-dy;
    const int sx=x0<x1?1:-1,sy=y0<y1?1:-1;
    int err=dx-dy;
    for(unsigned n=0;n<128;++n) {
        pixel(c,x0,y0,rgb); if(x0==x1 && y0==y1) return;
        const int e=2*err;
        if(e>-dy) {err-=dy;x0+=sx;}
        if(e<dx) {err+=dx;y0+=sy;}
    }
}
static void ascii(canvas *c,int x,int y,const char *s,unsigned max,uint32_t rgb,int scale)
{
    for(unsigned n=0;n<max && s[n];++n) {
        const unsigned ch=(unsigned char)s[n]<128?(unsigned char)s[n]:'?';
        for(unsigned r=0;r<8;++r) for(unsigned b=0;b<8;++b) if(font8x8_basic[ch][r]&(1u<<b))
            rect(c,x+(int)n*8*scale+(int)b*scale,y+(int)r*scale,scale,scale,rgb);
    }
}
static void box(canvas *c,int x,int y,int w,int h,uint32_t rgb)
{ rect(c,x,y,w,1,rgb);rect(c,x,y+h-1,w,1,rgb);rect(c,x,y,1,h,rgb);rect(c,x+w-1,y,1,h,rgb); }

/* Original stroke font for the 13 Hangul syllables in the requested title/menu.
 * No borrowed raster asset, missing-glyph substitution or runtime font load.
 * Component indices: g=ㄱ,r=ㄹ,m=ㅁ,b=ㅂ,s=ㅅ,o=ㅇ,t=ㅌ,h=ㅎ. */
static void consonant(canvas *c,char v,int x,int y,int w,int h,uint32_t rgb)
{
    const int m=x+w/2;
    switch(v) {
    case 'g':line(c,x,y,x+w,y,rgb);line(c,x+w,y,x+w,y+h,rgb);break;
    case 'r':line(c,x,y,x+w,y,rgb);line(c,x+w,y,x+w,y+h/2,rgb);line(c,x,y+h/2,x+w,y+h/2,rgb);
             line(c,x,y+h/2,x,y+h,rgb);line(c,x,y+h,x+w,y+h,rgb);break;
    case 'm':box(c,x,y,w+1,h+1,rgb);break;
    case 'b':box(c,x,y,w+1,h+1,rgb);line(c,x,y+h/2,x+w,y+h/2,rgb);break;
    case 's':line(c,m,y,x,y+h,rgb);line(c,m,y,x+w,y+h,rgb);break;
    case 'o':line(c,x+1,y,x+w-1,y,rgb);line(c,x+1,y+h,x+w-1,y+h,rgb);
             line(c,x,y+1,x,y+h-1,rgb);line(c,x+w,y+1,x+w,y+h-1,rgb);break;
    case 't':line(c,x,y,x+w,y,rgb);line(c,x,y+h/2,x+w,y+h/2,rgb);line(c,x,y+h,x+w,y+h,rgb);
             line(c,x,y,x,y+h,rgb);break;
    case 'h':line(c,m-1,y,m+1,y,rgb);line(c,x,y+2,x+w,y+2,rgb);consonant(c,'o',x,y+4,w,h-4,rgb);break;
    default:break;
    }
}
static void vowel(canvas *c,char v,int x,int y,int w,int h,uint32_t rgb)
{
    if(v=='a' || v=='e' || v=='i') {
        line(c,x+1,y,x+1,y+h,rgb);
        if(v!='i') line(c,x+1,y+h/2,x+w-1,y+h/2,rgb);
        if(v=='e') line(c,x+w,y,x+w,y+h,rgb);
    } else if(v=='E') {
        line(c,x+w-2,y,x+w-2,y+h,rgb);line(c,x,y+h/2,x+w-2,y+h/2,rgb);line(c,x+w,y,x+w,y+h,rgb);
    } else {
        const int yy=v=='o'?y+h:y;
        line(c,x,yy,x+w,yy,rgb);
        if(v=='o') line(c,x+w/2,y,x+w/2,yy,rgb);
        if(v=='u') line(c,x+w/2,y,x+w/2,y+h,rgb);
        if(v=='U') {line(c,x+w/3,y,x+w/3,y+h,rgb);line(c,x+2*w/3,y,x+2*w/3,y+h,rgb);}
    }
}
typedef struct {uint16_t cp;char c,v,t;} syllable;
static const syllable hangul[]={
    {0xc624,'o','o',0},{0xb958,'r','U',0},{0xd14c,'t','E',0},{0xd2b8,'t','-',0},
    {0xb9ac,'r','i',0},{0xc2a4,'s','-',0},{0xac8c,'g','E',0},{0xc784,'o','i','m'},
    {0xc744,'o','-','r'},{0xd560,'h','a','r'},{0xb798,'r','e',0},
    {0xc218,'s','u',0},{0xbc15,'b','a','g'}
};
static void korean(canvas *c,int x,int y,const uint16_t *s,unsigned n,uint32_t rgb)
{
    for(unsigned i=0;i<n;++i,x+=18) {
        if(s[i]<128) {char a[2]={(char)s[i],0};ascii(c,x,y+4,a,1,rgb,1);continue;}
        const syllable *g=0;
        for(unsigned k=0;k<sizeof hangul/sizeof hangul[0];++k) if(hangul[k].cp==s[i]) g=&hangul[k];
        if(!g) {ascii(c,x,y+4,"?",1,rgb,1);continue;}
        const int vertical=g->v=='a'||g->v=='e'||g->v=='E'||g->v=='i';
        const int h=g->t?10:15;
        if(vertical) {consonant(c,g->c,x+1,y+1,7,h-2,rgb);vowel(c,g->v,x+10,y+1,5,h-2,rgb);}
        else {consonant(c,g->c,x+3,y+1,9,h/2-1,rgb);vowel(c,g->v,x+1,y+h/2+1,14,h/2-2,rgb);}
        if(g->t) consonant(c,g->t,x+3,y+12,10,4,rgb);
    }
}
static void sadmac(canvas *c,int x,int y,int size)
{
    box(c,x,y,size,size,0xffffff);box(c,x+2,y+2,size-4,size-7,0xffffff);
    const int a=size/4,b=size/2;
    line(c,x+a,y+a,x+a+2,y+a+2,0xffffff);line(c,x+a+2,y+a,x+a,y+a+2,0xffffff);
    line(c,x+b+1,y+a,x+b+3,y+a+2,0xffffff);line(c,x+b+3,y+a,x+b+1,y+a+2,0xffffff);
    line(c,x+a,y+b+2,x+b+3,y+b+2,0xffffff);
    rect(c,x+size-6,y+size-4,3,1,0xffffff);
}
static void bsod_art(canvas *c,int x,int y,int size,unsigned level)
{
    if(level<3) {
        /* Original miniature classic STOP/text lines. No modern sad face. */
        rect(c,x+2,y+2,size-4,1,0xffffff);
        rect(c,x+2,y+4,size-(level==1?6:4),1,0xffffff);
        if(size>=18)rect(c,x+2,y+7,size-7,1,0xffffff);
    } else {
        /* Original modern face glyph; Win11 has a distinct inner frame. */
        if(level==5)box(c,x+1,y+1,size-2,size-2,0xffffff);
        if(size>=18)ascii(c,x+3,y+3,":(",2,0xffffff,1);
        else {pixel(c,x+2,y+2,0xffffff);pixel(c,x+2,y+4,0xffffff);
            line(c,x+5,y+2,x+4,y+3,0xffffff);line(c,x+4,y+3,x+5,y+5,0xffffff);}
        if(level==4) {
            /* Decorative checker, not a scannable code or copied OS asset. */
            const int cell=size>=24?2:1,side=cell*4;
            for(unsigned yy=0;yy<4;++yy)for(unsigned xx=0;xx<4;++xx)if((xx+yy)%2==0)
                rect(c,x+size-side-2+(int)xx*cell,y+size-side-3+(int)yy*cell,cell,cell,0xffffff);
        }
    }
    if(size>=24)ascii(c,x+2,y+size-10,short_label[level],3,0xffffff,1);
    else if(size>=18 && level<3)ascii(c,x+2,y+size-9,short_label[level],2,0xffffff,1);
    else {char tag[2]={(char)('0'+level),0};ascii(c,x+size-8,y+size-8,tag,1,0xffffff,1);}
}
static void item(canvas *c,int x,int y,int size,unsigned level)
{
    if(!level) {sadmac(c,x,y,size);return;}
    rect(c,x,y,size,size,color[level]);box(c,x,y,size,size,0xffffff);
    bsod_art(c,x,y,size,level);
}
static void hex(char out[17],uint64_t n)
{ for(unsigned i=0;i<16;++i) {unsigned b=(unsigned)(n>>((15-i)*4))&15;out[i]="0123456789abcdef"[b];}out[16]=0; }
static void number(canvas *c,int x,int y,unsigned n)
{
    char out[11]; unsigned len=0;
    do {out[len++]=(char)('0'+n%10);n/=10;}while(n);
    for(unsigned i=0;i<len/2;++i) {char b=out[i];out[i]=out[len-i-1];out[len-i-1]=b;}
    out[len]=0;ascii(c,x,y,out,len,0xffffff,1);
}
static void field(canvas *c,int x,int y,const char *name,uint64_t v)
{char h[17];hex(h,v);ascii(c,x,y,name,12,0xaaaaaa,1);ascii(c,x+80,y,h,16,0xffffff,1);}
static void trace(canvas *c,const ds_state *s)
{
    const ds_fault *f=&s->fault;
    ascii(c,304,76,"REAL CAPTURED TRACEBACK",25,0xffffff,1);
    field(c,304,88,"IP",f->ip);field(c,304,100,"SP",f->sp);field(c,304,112,"BP",f->bp);
    field(c,304,124,"FLAGS",f->flags);
    if(f->registers_valid) {field(c,304,136,"VECTOR",f->vector);field(c,304,148,"ERROR",f->error);}
    else ascii(c,304,140,"Software panic: no exception vector",36,0xaaaaaa,1);
    field(c,304,160,"CR2",f->cr2);field(c,304,172,"CR3",f->cr3);
    if(f->registers_valid) for(unsigned i=0;i<DS_REGS;++i) field(c,304,190+(int)i*11,regname[i],f->reg[i]);
    else ascii(c,304,194,"Full interrupt registers unavailable",37,0xaaaaaa,1);
    ascii(c,304,378,"Frames: captured addresses only",32,0xaaaaaa,1);
    for(unsigned i=0;i<f->frame_count && i<3;++i) field(c,304,390+(int)i*11,"FRAME",f->frames[i]);
    ascii(c,304,426,"No unsafe stack walk; no OS recovery",37,0xaaaaaa,1);
    if(f->context_valid) {
        field(c,304,438,"CPU",f->cpu);
        field(c,304,366,"PID/TID",((uint64_t)f->pid<<32)|f->tid);
    }
}
static void game(canvas *c,const ds_state *s)
{
    if(s->mode==DS_MENU) {
        const uint16_t menu1[]={0xd14c,0xd2b8,0xb9ac,0xc2a4,' ',0xac8c,0xc784,0xc744,' ',0xd560,0xb798,'?'};
        const uint16_t menu2[]={0xc218,0xbc15,' ',0xac8c,0xc784,0xc744,' ',0xd560,0xb798,'?'};
        ascii(c,24,92,"1",1,0xffffff,2);ascii(c,24,126,"2",1,0xffffff,2);
        if(s->korean) {korean(c,50,90,menu1,12,0xffffff);korean(c,50,124,menu2,10,0xffffff);}
        else {ascii(c,50,96,"Play Tetris?",16,0xffffff,1);ascii(c,50,130,"Play Suika?",16,0xffffff,1);}
        /* A deliberate monochrome pile of original Sad Mac silhouettes. */
        for(unsigned row=0;row<5;++row) for(unsigned j=0;j<=row;++j)
            sadmac(c,138-(int)row*22+(int)j*44,198+(int)row*39,38);
    } else if(s->mode==DS_TETRIS) {
        const ds_tetris *t=&s->tetris;
        ascii(c,30,80,"TETRIS",6,0xffffff,2);number(c,160,84,t->score);
        box(c,48,119,142,282,0x777777);
        for(unsigned y=0;y<20;++y) for(unsigned x=0;x<10;++x) if(t->board[y][x])
            item(c,49+(int)x*14,120+(int)y*14,13,(t->board[y][x]-1)%6);
        if(!t->over) { for(unsigned y=0;y<4;++y) for(unsigned x=0;x<4;++x) {
            /* The same actual collision routine identifies occupied cells by a
             * one-cell blocker; no independent shape table to drift from core. */
            ds_tetris test=*t;
            const int bx=t->x+(int)x,by=t->y+(int)y;
            if(bx<0 || bx>=10 || by<0 || by>=20) continue;
            test.board[by][bx]=1;
            if(!ds_tetris_fits(&test,t->piece,t->rotation,t->x,t->y))
                item(c,49+bx*14,120+by*14,13,t->piece%6);
        } }
        else ascii(c,38,414,"GAME OVER - R restarts",23,0xffffff,1);
    } else if(s->mode==DS_SUIKA) {
        const ds_suika *u=&s->suika;
        ascii(c,30,80,"SUIKA",5,0xffffff,2);number(c,160,84,u->score);
        box(c,25,111,242,290,0x777777);
        rect(c,25,135,242,1,0x777777);
        item(c,25+u->aim-radius[u->next],108-radius[u->next]*2,radius[u->next]*2,u->next);
        for(unsigned i=0;i<DS_BALLS;++i) if(u->ball[i].used && u->ball[i].level<6) {
            const ds_ball *b=&u->ball[i];const int r=radius[b->level],x=25+b->x/256,y=111+b->y/256;
            for(int yy=-r;yy<=r;++yy) for(int xx=-r;xx<=r;++xx) if(xx*xx+yy*yy<=r*r)
                pixel(c,x+xx,y+yy,b->level?color[b->level]:xx*xx+yy*yy>=(r-1)*(r-1)?0xffffff:0);
            if(b->level==0) sadmac(c,x-6,y-6,13);
            else {const int size=r*4/3;bsod_art(c,x-size/2,y-size/2,size,b->level);}
        }
        if(u->over) ascii(c,38,414,"GAME OVER - R restarts",23,0xffffff,1);
    }
}
int ds_render(ds_state *s,const ds_surface *f)
{
    if(!s || !s->latched || s->graphics_failed) return -1;
    if(s->mode>DS_SUIKA || (s->mode==DS_TETRIS &&
       (s->tetris.piece>=7 || s->tetris.rotation>=4 || s->tetris.x < -4 ||
        s->tetris.x>10 || s->tetris.y < -4 || s->tetris.y>20)) ||
       (s->mode==DS_SUIKA && (s->suika.next>=3 || s->suika.aim<24 || s->suika.aim>216))) {
        s->graphics_failed=1;return -1;
    }
    if(!ds_surface_valid(f)) {s->graphics_failed=1;return -1;}
    canvas c={f,1,0,0,640,480};
    c.scale=(int)(f->width/640); if(c.scale>(int)(f->height/480)) c.scale=(int)(f->height/480);
    c.ox=((int)f->width-640*c.scale)/2;c.oy=((int)f->height-480*c.scale)/2;
    for(unsigned y=0;y<f->height;++y) for(unsigned x=0;x<f->width;++x) f->pixels[(size_t)y*f->pitch_words+x]=0;
    if(s->korean) {
        const uint16_t title[]={0xc624,0xb958,'!','!','!','!'};korean(&c,24,20,title,6,0xffffff);
    } else ascii(&c,24,18,"Halted!!!!",10,0xffffff,2);
    ascii(&c,220,24,"K64 PANIC / DEAD SCREEN CONTROL",31,0xffffff,1);
    ascii(&c,220,35,"Kernel64 built " __DATE__ " " __TIME__,40,0xaaaaaa,1);
    for(unsigned row=0;row<3;++row) {
        char fragment[75];unsigned n=0;
        const unsigned offset=row*74;
        while(n<74 && offset+n<DS_REASON-1 && s->fault.reason[offset+n]) {
            char b=s->fault.reason[offset+n];fragment[n++]=b=='\n'?' ':b;
        }
        fragment[n]=0;ascii(&c,24,45+(int)row*10,fragment,n,0xaaaaaa,1);
        if(n<74)break;
    }
    game(&c,s);
    if(s->show_trace) trace(&c,s);
    else {
        ascii(&c,304,92,"MERGE / BLOCK ITEMS",20,0xffffff,1);
        const char *const full[6]={"Sad Mac","Windows 2000 BSOD","Windows XP BSOD","Windows 8.1 BSOD","Windows 10 BSOD","Windows 11 BSOD"};
        for(unsigned i=0;i<6;++i) {item(&c,304,116+(int)i*43,32,i);ascii(&c,350,128+(int)i*43,full[i],22,0xffffff,1);}
        ascii(&c,304,396,"T shows actual traceback",25,0xaaaaaa,1);
    }
    ascii(&c,24,450,"1 Tetris  2 Suika | A/D move W rotate S down Space drop",56,0xffffff,1);
    ascii(&c,24,466,"Esc menu  R restart  L KO/EN  T trace/items | kernel halted",60,0xaaaaaa,1);
    return 0;
}
static int write(ds_write_fn w,void *p,const char *s,size_t n) {return w(p,s,n)?-1:0;}
static int write_field(ds_write_fn w,void *p,const char *name,uint64_t v)
{
    char h[17];hex(h,v);
    size_t n=0;while(name[n])++n;
    return write(w,p,name,n)||write(w,p,"=0x",3)||write(w,p,h,16)||write(w,p,"\n",1)?-1:0;
}
int ds_fallback(const ds_state *s,ds_write_fn w,void *p)
{
    if(!s || !s->latched || !w) return -1;
    const char title[]="Your computer was trashed.\n";
    if(write(w,p,title,sizeof title-1) || write(w,p,"English traceback: Shizuku Kernel halted\n",41)) return -1;
    size_t n=0;while(n<DS_REASON-1 && s->fault.reason[n])++n;
    if(write(w,p,"Reason: ",8)||write(w,p,s->fault.reason,n)||write(w,p,"\n",1))return -1;
    const ds_fault *f=&s->fault;
    const char build[]="Build: Kernel64 " __DATE__ " " __TIME__ "\n";
    if(write(w,p,build,sizeof build-1))return -1;
    if(write_field(w,p,"IP",f->ip)||write_field(w,p,"SP",f->sp)||write_field(w,p,"BP",f->bp)||
       write_field(w,p,"FLAGS",f->flags)||
       write_field(w,p,"CR2",f->cr2)||write_field(w,p,"CR3",f->cr3)) return -1;
    if(f->registers_valid && (write_field(w,p,"VECTOR",f->vector)||write_field(w,p,"ERROR",f->error))) return -1;
    if(f->context_valid && (write_field(w,p,"CPU",f->cpu)||write_field(w,p,"PID",f->pid)||write_field(w,p,"TID",f->tid)))return -1;
    if(f->registers_valid) { for(unsigned i=0;i<DS_REGS;++i) if(write_field(w,p,regname[i],f->reg[i]))return -1; }
    else if(write(w,p,"Full interrupt registers unavailable\n",37)) return -1;
    for(unsigned i=0;i<f->frame_count;++i) if(write_field(w,p,"FRAME",f->frames[i]))return -1;
    const char tail[]="Further unwind unavailable; no arbitrary stack memory was read.\n";
    return write(w,p,tail,sizeof tail-1);
}

/* Minimal fatal renderer shares only retained pixel storage and the ASCII font.
 * No windows, heap, filesystem, game-state parsing, GUI calls or stack walking. */
enum ds_fatal_audio ds_nyan_audio_select(unsigned pcm,unsigned pitched,unsigned fixed)
{ return pcm ? DS_AUDIO_PCM : pitched ? DS_AUDIO_PITCHED : fixed ? DS_AUDIO_FIXED : DS_AUDIO_SILENT; }
const char *ds_nyan_audio_name(enum ds_fatal_audio a)
{
    return a==DS_AUDIO_PCM ? "PCM DMA progressing" : a==DS_AUDIO_PITCHED ? "PIT pitched beep" :
           a==DS_AUDIO_FIXED ? "Fixed tone gate only" : "No verified audio output";
}
int ds_nyan_framebuffer(const ds_state *s,const ds_surface *f,enum ds_fatal_audio audio)
{
    if(!s || !s->latched || !ds_surface_storage_valid(f))return -1;
    canvas c={f,1,0,0,(int)f->width,(int)f->height};
    for(unsigned y=0;y<f->height;++y)for(unsigned x=0;x<f->width;++x)
        f->pixels[(size_t)y*f->pitch_words+x]=native_color(f,0x10203b);
    const uint32_t rainbow[6]={0xff5555,0xffaa44,0xffee55,0x55cc66,0x5599ee,0xaa77ee};
    const int x=(int)f->width/2-36,y=(int)f->height/2-18;
    for(unsigned i=0;i<6;i++)rect(&c,x-92,y+(int)i*6,94,6,rainbow[i]);
    rect(&c,x,y,64,40,0xe6ba81);rect(&c,x+5,y+5,54,30,0xf4a5c2);
    rect(&c,x+48,y+5,40,28,0xbfc4ce);rect(&c,x+49,y-2,9,12,0xbfc4ce);
    rect(&c,x+76,y-2,9,12,0xbfc4ce);rect(&c,x+56,y+13,4,4,0x101010);
    rect(&c,x+77,y+13,4,4,0x101010);rect(&c,x+64,y+23,10,2,0x101010);
    rect(&c,x+8,y+38,12,7,0xbfc4ce);rect(&c,x+51,y+38,12,7,0xbfc4ce);
    ascii(&c,8,8,"Your computer was trashed.",26,0xffffff,1);
    ascii(&c,8,24,"NYAN CAT SCREEN | kernel halted",31,0xffffff,1);
    ascii(&c,8,40,ds_nyan_audio_name(audio),40,0xffffff,1);
    if(f->height>=200) {
        field(&c,8,(int)f->height-52,"IP",s->fault.ip);
        field(&c,8,(int)f->height-40,"CR3",s->fault.cr3);
        ascii(&c,8,(int)f->height-24,"Output level is evidence, not a hardware diagnosis.",51,0xffffff,1);
        ascii(&c,8,(int)f->height-12,"No output cannot establish a specific CPU failure.",50,0xffffff,1);
    }
    return 0;
}

typedef struct {const ds_surface *fb;unsigned col,row,truncated;} text_canvas;
static int framebuffer_writer(void *context,const char *bytes,size_t n)
{
    text_canvas *t=context;
    const unsigned cols=t->fb->width/8,rows=t->fb->height/8;
    for(size_t i=0;i<n;++i) {
        const unsigned ch=(unsigned char)bytes[i]<128?(unsigned char)bytes[i]:'?';
        if(ch=='\n') {t->col=0;++t->row;continue;}
        if(t->col==cols) {t->col=0;++t->row;}
        if(t->row>=rows) {t->truncated=1;continue;}
        for(unsigned y=0;y<8;++y)for(unsigned x=0;x<8;++x)if(font8x8_basic[ch][y]&(1u<<x))
            t->fb->pixels[(size_t)(t->row*8+y)*t->fb->pitch_words+t->col*8+x]=0xffffff;
        ++t->col;
    }
    return 0;
}
int ds_fallback_framebuffer(const ds_state *s,const ds_surface *f)
{
    if(!s || !s->latched || !ds_surface_storage_valid(f))return -1;
    for(unsigned y=0;y<f->height;++y)for(unsigned x=0;x<f->width;++x)f->pixels[(size_t)y*f->pitch_words+x]=0;
    text_canvas t={f,0,0,0};
    if(ds_fallback(s,framebuffer_writer,&t))return -1;
    return t.truncated?-1:0;
}
