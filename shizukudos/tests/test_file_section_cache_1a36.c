/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual section/page/view bodies are supplied by the runner. Only hardware,
 * VFS, allocator, object-reference and page-table boundaries are modeled. */
#define _POSIX_C_SOURCE 200112L
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#define PAGE_SIZE 4096u
#define PAGE_NOACCESS 1u
#define PAGE_READONLY 2u
#define PAGE_READWRITE 4u
#define PAGE_WRITECOPY 8u
#define PAGE_EXECUTE 16u
#define PAGE_EXECUTE_READ 32u
#define PAGE_EXECUTE_READWRITE 64u
#define PAGE_EXECUTE_WRITECOPY 128u
#define PT_W 2u
#define STATUS_ACCESS_VIOLATION ((int)0xc0000005)
#define STATUS_GUARD_PAGE_VIOLATION ((int)0x80000001)
#define STATUS_NO_MEMORY ((int)0xc0000017)
typedef struct fsnode { uint64_t size,open_count; int delete_pending; uint8_t bytes[PAGE_SIZE*3]; } fsnode_t;
typedef struct object { struct { struct { void *file; } file; } u; unsigned refs; } kobject_t;
typedef struct view view_t;
typedef struct ipc_proc { view_t *views; } ipc_proc_t;
typedef struct process { ipc_proc_t *ipc; uint64_t pml4; int teardown; } process_t;
typedef struct vad { uint32_t prot; } vad_t;
static unsigned checks,failures,removed,reads,writes;
static unsigned ipc_stat_sections,ipc_stat_views;
static long heap_live,page_live,heap_fail=-1,page_fail=-1;
static int read_fail;
static pthread_barrier_t *read_gate;
static pthread_mutex_t snapshot_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t snapshot_changed=PTHREAD_COND_INITIALIZER;
static pthread_t snapshot_thread;
static int snapshot_enabled,snapshot_captured,snapshot_continue;
static pthread_mutex_t pages_lock=PTHREAD_MUTEX_INITIALIZER;
static uint64_t pages[1024];
static uint64_t irq_save(void){return 0;}
static void irq_restore(uint64_t f){(void)f;}
static void check(int ok,const char *what){++checks;if(!ok){++failures;fprintf(stderr,"FAIL: %s\n",what);}}
#define CHECK(x) check(!!(x),#x)
static void *kzalloc(size_t n){size_t *p;if(heap_fail==0)return 0;if(heap_fail>0)--heap_fail;p=calloc(1,n+sizeof(size_t));if(!p)return 0;*p=n;__atomic_add_fetch(&heap_live,1,__ATOMIC_RELAXED);return p+1;}
static void kfree(void *v){if(v){__atomic_sub_fetch(&heap_live,1,__ATOMIC_RELAXED);free((size_t *)v-1);}}
static uint64_t pmm_alloc(void){void *p;unsigned i;if(page_fail==0)return 0;if(page_fail>0)--page_fail;if(posix_memalign(&p,PAGE_SIZE,PAGE_SIZE))return 0;memset(p,0,PAGE_SIZE);pthread_mutex_lock(&pages_lock);for(i=0;i<1024&&pages[i];i++){}if(i==1024)abort();pages[i]=(uint64_t)(uintptr_t)p;++page_live;pthread_mutex_unlock(&pages_lock);return (uint64_t)(uintptr_t)p;}
static int page_valid(uint64_t pa){unsigned i;int found=0;pthread_mutex_lock(&pages_lock);for(i=0;i<1024;i++)if(pages[i]==pa){found=1;break;}pthread_mutex_unlock(&pages_lock);return found;}
static void pmm_free(uint64_t pa){unsigned i;pthread_mutex_lock(&pages_lock);for(i=0;i<1024&&pages[i]!=pa;i++){}if(i==1024)abort();pages[i]=0;--page_live;pthread_mutex_unlock(&pages_lock);free((void *)(uintptr_t)pa);}
static void *p2v(uint64_t p){return (void *)(uintptr_t)p;}
static int fs_read(fsnode_t *n,uint64_t off,void *p,uint64_t len,uint64_t *done){__atomic_add_fetch(&reads,1,__ATOMIC_RELAXED);if(read_gate)pthread_barrier_wait(read_gate);*done=0;if(read_fail)return -1;if(off>=n->size)return 0;if(len>n->size-off)len=n->size-off;memcpy(p,n->bytes+off,(size_t)len);*done=len;
 pthread_mutex_lock(&snapshot_lock);if(snapshot_enabled&&pthread_equal(pthread_self(),snapshot_thread)){++snapshot_captured;pthread_cond_broadcast(&snapshot_changed);while(snapshot_captured==1&&!snapshot_continue)pthread_cond_wait(&snapshot_changed,&snapshot_lock);}pthread_mutex_unlock(&snapshot_lock);return 0;}
static int fs_write(fsnode_t *n,uint64_t off,const void *p,uint64_t len){++writes;if(off>n->size||len>n->size-off)return -1;memcpy(n->bytes+off,p,(size_t)len);return 0;}
static void fs_remove(fsnode_t *n){(void)n;++removed;}
struct mapping { uint64_t root,va,pa,flags; };
static struct mapping mappings[64];
static uint64_t vm_lookup(uint64_t r,uint64_t va,uint64_t *flags){unsigned i;for(i=0;i<64;i++)if(mappings[i].root==r&&mappings[i].va==va){*flags=mappings[i].flags;return mappings[i].pa;}return 0;}
static int vm_map(uint64_t r,uint64_t va,uint64_t pa,uint64_t flags){unsigned i;for(i=0;i<64;i++)if(!mappings[i].root){mappings[i]=(struct mapping){r,va,pa,flags};return 0;}return -1;}
static void vm_unmap(uint64_t r,uint64_t va,int release){unsigned i;(void)release;for(i=0;i<64;i++)if(mappings[i].root==r&&mappings[i].va==va)mappings[i]=(struct mapping){0};}
static uint64_t kernel_pml4(void){return 999;}
static uint64_t prot_to_ptflags(uint32_t p){return (p==PAGE_READWRITE||p==PAGE_WRITECOPY||p==PAGE_EXECUTE_READWRITE||p==PAGE_EXECUTE_WRITECOPY)?PT_W:0;}
static void vad_remove_view(process_t *p,uint64_t v){(void)p;(void)v;}
static void ob_deref(kobject_t *o);

/* PRODUCTION_BODIES */

static void ob_deref(kobject_t *o){if(!--o->refs)section_free(o);}
static void node_init(fsnode_t *n,uint8_t value){memset(n,0,sizeof *n);n->size=sizeof n->bytes;memset(n->bytes,value,sizeof n->bytes);}
static section_t *make_section(fsnode_t *n,kobject_t *o,uint64_t size){section_t *s=kzalloc(sizeof *s);if(!s)abort();s->size=size;s->npages=(size+PAGE_SIZE-1)/PAGE_SIZE;s->node=n;s->prot=PAGE_READWRITE;s->file_writable=n!=0;s->dir=kzalloc(((s->npages+511)/512)*sizeof(uint64_t));if(!s->dir)abort();if(n)++n->open_count;o->u.file.file=s;o->refs=1;++ipc_stat_sections;return s;}
static uint8_t *data(uint64_t pa){return p2v(pa);}
static void close_section(kobject_t *o){ob_deref(o);}
static void same_file(void){fsnode_t n; kobject_t a={0},b={0};uint64_t pa,pb;node_init(&n,0x11);section_t *sa=make_section(&n,&a,n.size),*sb=make_section(&n,&b,n.size);pa=section_page(sa,0,1);pb=section_page(sb,0,1);CHECK(pa&&pb);CHECK(pa==pb);data(pa)[57]=0x72;CHECK(data(pb)[57]==0x72);data(pb)[58]=0x93;CHECK(data(pa)[58]==0x93);CHECK(sa->resident==1&&sb->resident==1);CHECK(section_page(sa,0,1)==pa&&sa->resident==1);close_section(&a);CHECK(page_valid(pb)&&data(pb)[58]==0x93);CHECK(n.open_count==1);close_section(&b);CHECK(n.open_count==0);CHECK(n.bytes[57]==0x72&&n.bytes[58]==0x93);CHECK(heap_live==0&&page_live==0);}
static void separation(void){fsnode_t n,m;kobject_t a={0},b={0},c={0},d={0};node_init(&n,0x31);node_init(&m,0x52);section_t *sa=make_section(&n,&a,n.size),*sb=make_section(&m,&b,m.size),*sc=make_section(0,&c,PAGE_SIZE),*sd=make_section(0,&d,PAGE_SIZE);uint64_t p=section_page(sa,0,1),q=section_page(sa,1,1),r=section_page(sb,0,1),x=section_page(sc,0,1),y=section_page(sd,0,1);CHECK(p!=q&&p!=r&&x!=y);CHECK(data(p)[0]==0x31&&data(r)[0]==0x52&&data(x)[0]==0);data(x)[0]=0xaa;CHECK(data(y)[0]==0);CHECK(section_page(sa,sa->npages,1)==0);close_section(&a);close_section(&b);close_section(&c);close_section(&d);CHECK(heap_live==0&&page_live==0);}
static void recreate(void){fsnode_t n;kobject_t a={0};node_init(&n,0x21);section_t *s=make_section(&n,&a,n.size);uint64_t p=section_page(s,0,1);data(p)[0]=0x80;close_section(&a);CHECK(heap_live==0&&page_live==0);memset(n.bytes,0x44,sizeof n.bytes);s=make_section(&n,&a,n.size);p=section_page(s,0,1);CHECK(data(p)[0]==0x44);n.delete_pending=1;unsigned before=removed;close_section(&a);CHECK(removed==before+1&&n.open_count==0);CHECK(heap_live==0&&page_live==0);}
static void views_and_cow(void){fsnode_t n;kobject_t a={0},b={0};ipc_proc_t ip={0};process_t p={&ip,1,0};vad_t ro={PAGE_READONLY},cow={PAGE_WRITECOPY};node_init(&n,0x67);make_section(&n,&a,n.size);make_section(&n,&b,n.size);view_t *va=kzalloc(sizeof *va),*vb=kzalloc(sizeof *vb);va->base=0x100000;va->size=PAGE_SIZE;va->sec=&a;vb->base=0x200000;vb->size=PAGE_SIZE;vb->sec=&b;va->next=vb;ip.views=va;a.refs++;b.refs++;ipc_stat_views+=2;CHECK(view_fault(&p,&ro,va->base,0,0)==0);CHECK(view_fault(&p,&cow,vb->base,0,0)==0);uint64_t f=0,pa=vm_lookup(p.pml4,va->base,&f),pb=vm_lookup(p.pml4,vb->base,&f);CHECK(pa&&pb&&pa==pb);CHECK(view_fault(&p,&ro,va->base,1,0)==STATUS_ACCESS_VIOLATION);CHECK(view_fault(&p,&ro,va->base,0,1)==STATUS_ACCESS_VIOLATION);CHECK(view_fault(&p,&cow,vb->base,1,0)==0);pb=vm_lookup(p.pml4,vb->base,&f);CHECK(pb!=pa&&(f&PT_W));data(pb)[0]=0xc2;CHECK(data(pa)[0]==0x67);close_section(&a);close_section(&b);CHECK(page_valid(pa)&&page_valid(pb));view_detach(&p,va);view_release(&p,va,1);CHECK(page_valid(pb)&&data(pb)[0]==0xc2);view_detach(&p,vb);view_release(&p,vb,1);CHECK(ip.views==0&&ipc_stat_views==0);CHECK(heap_live==0&&page_live==0);CHECK(n.bytes[0]==0x67);}
static void failures_and_growth(void){fsnode_t n;kobject_t a={0},b={0};node_init(&n,0x19);section_t *sa=make_section(&n,&a,PAGE_SIZE),*sb=make_section(&n,&b,n.size);page_fail=0;CHECK(section_page(sa,0,1)==0);page_fail=-1;uint64_t p=section_page(sa,0,1),q=section_page(sb,0,1),r=section_page(sb,2,1);CHECK(p&&q&&r&&p==q&&r!=p);CHECK(section_page(sa,2,1)==0);close_section(&a);close_section(&b);CHECK(heap_live==0&&page_live==0);
 sa=make_section(&n,&a,n.size);CHECK(leaf_of(sa,0,1)!=0);page_fail=0;CHECK(section_page(sa,0,1)==0);page_fail=-1;CHECK(section_page(sa,0,1)!=0);close_section(&a);CHECK(heap_live==0&&page_live==0);
 sa=make_section(&n,&a,n.size);read_fail=1;CHECK(section_page(sa,0,1)==0);read_fail=0;CHECK(section_page(sa,0,1)!=0);close_section(&a);CHECK(heap_live==0&&page_live==0);
 sa=make_section(&n,&a,n.size);heap_fail=0;CHECK(section_page(sa,0,1)==0);heap_fail=-1;CHECK(section_page(sa,0,1)!=0);close_section(&a);CHECK(heap_live==0&&page_live==0);
}
static void process_views_and_permissions(void)
{
    fsnode_t n;
    kobject_t writable={0},readonly={0};
    ipc_proc_t wa={0},ra={0};
    process_t wp={&wa,11,0},rp={&ra,12,0};
    vad_t wd={PAGE_READWRITE},rd={PAGE_READONLY};
    uint64_t flags=0;
    node_init(&n,0x35);
    section_t *ws=make_section(&n,&writable,n.size);
    section_t *rs=make_section(&n,&readonly,n.size);
    rs->prot=PAGE_READONLY;rs->file_writable=0;
    view_t *wv=kzalloc(sizeof *wv),*rv=kzalloc(sizeof *rv);
    wv->base=0x300000;wv->size=PAGE_SIZE;wv->sec=&writable;wa.views=wv;
    rv->base=0x400000;rv->size=PAGE_SIZE;rv->sec=&readonly;ra.views=rv;
    ++writable.refs;++readonly.refs;ipc_stat_views+=2;
    CHECK(view_fault(&wp,&wd,wv->base,1,0)==0);
    CHECK(view_fault(&rp,&rd,rv->base,0,0)==0);
    uint64_t wpa=vm_lookup(wp.pml4,wv->base,&flags);
    CHECK(flags&PT_W);
    uint64_t rpa=vm_lookup(rp.pml4,rv->base,&flags);
    CHECK(rpa==wpa&&!(flags&PT_W));
    data(wpa)[17]=0xa7;
    CHECK(data(rpa)[17]==0xa7);
    CHECK(view_fault(&rp,&rd,rv->base,1,0)==STATUS_ACCESS_VIOLATION);
    unsigned before=writes;
    section_write_back(rs,0,1);CHECK(writes==before);
    section_write_back(ws,0,1);CHECK(n.bytes[17]==0xa7);
    data(wpa)[18]=0xb8;
    close_section(&writable);close_section(&readonly);
    CHECK(page_valid(rpa)&&n.open_count==2);
    view_detach(&wp,wv);view_release(&wp,wv,1);
    CHECK(page_valid(rpa)&&data(rpa)[18]==0xb8&&n.open_count==1);
    view_detach(&rp,rv);view_release(&rp,rv,1);
    CHECK(n.open_count==0&&heap_live==0&&page_live==0);
}
static void file_size_boundaries(void)
{
    fsnode_t n;
    kobject_t a={0},b={0};
    node_init(&n,0x48);n.size=PAGE_SIZE+23;
    section_t *sa=make_section(&n,&a,n.size);
    uint64_t pa=section_page(sa,1,1);
    CHECK(data(pa)[22]==0x48&&data(pa)[23]==0);
    data(pa)[22]=0x91;data(pa)[23]=0x92;
    /* Extend the backing file with zeroes, then independently map its new page.
     * Direct WriteFile cache coherence is outside this mapping-only contract. */
    memset(n.bytes+n.size,0,sizeof n.bytes-(size_t)n.size);n.size=sizeof n.bytes;
    section_t *sb=make_section(&n,&b,n.size);
    uint64_t pb=section_page(sb,1,1),pc=section_page(sb,2,1);
    CHECK(pb==pa&&data(pb)[22]==0x91&&data(pb)[23]==0x92);
    CHECK(pc&&pc!=pa&&data(pc)[0]==0);
    CHECK(section_page(sa,2,1)==0);
    data(pc)[0]=0x93;
    n.size=PAGE_SIZE+19;
    unsigned before=writes;
    section_write_back(sb,1,2);
    CHECK(n.size==PAGE_SIZE+19&&writes==before+1);
    CHECK(n.bytes[PAGE_SIZE+18]==0x48&&n.bytes[PAGE_SIZE+19]==0x48);
    close_section(&a);close_section(&b);
    CHECK(heap_live==0&&page_live==0);
}
struct snapshot_case { section_t *section; uint64_t pa; };
static void *snapshot_acquire(void *arg)
{
    struct snapshot_case *c=arg;
    pthread_mutex_lock(&snapshot_lock);snapshot_thread=pthread_self();pthread_mutex_unlock(&snapshot_lock);
    c->pa=section_page(c->section,0,1);
    return 0;
}
static void intervening_publication_and_release(void)
{
    fsnode_t n;kobject_t a={0},b={0};pthread_t thread;
    node_init(&n,0x37);
    section_t *sa=make_section(&n,&a,n.size);
    struct snapshot_case c={sa,0};
    snapshot_enabled=1;snapshot_captured=0;snapshot_continue=0;
    if(pthread_create(&thread,0,snapshot_acquire,&c))abort();
    pthread_mutex_lock(&snapshot_lock);
    while(!snapshot_captured)pthread_cond_wait(&snapshot_changed,&snapshot_lock);
    pthread_mutex_unlock(&snapshot_lock);
    /* A holds an old read snapshot; B publishes, writes back, then removes the
     * same cache key before A's second lookup. No direct file writer is used. */
    section_t *sb=make_section(&n,&b,n.size);
    uint64_t pb=section_page(sb,0,1);data(pb)[0]=0xad;
    close_section(&b);CHECK(n.bytes[0]==0xad&&n.open_count==1);
    pthread_mutex_lock(&snapshot_lock);snapshot_continue=1;pthread_cond_broadcast(&snapshot_changed);pthread_mutex_unlock(&snapshot_lock);
    pthread_join(thread,0);snapshot_enabled=0;
    CHECK(c.pa&&data(c.pa)[0]==0xad);
    close_section(&a);
    CHECK(n.bytes[0]==0xad&&heap_live==0&&page_live==0);
}
struct parallel { section_t *section; pthread_barrier_t *ready,*release; uint64_t pa; };
static void *parallel_acquire(void *arg){struct parallel *c=arg;c->pa=section_page(c->section,0,1);pthread_barrier_wait(c->ready);pthread_barrier_wait(c->release);return 0;}
/* Only cache acquisition runs in parallel: existing object/node counters have
 * interrupt-serialized lifetimes and are created/released serially here. */
static void concurrent_acquire(void){fsnode_t n;kobject_t objects[8];pthread_t threads[8];struct parallel contexts[8];pthread_barrier_t ready,release,reading;memset(objects,0,sizeof objects);node_init(&n,0x56);pthread_barrier_init(&ready,0,9);pthread_barrier_init(&release,0,9);pthread_barrier_init(&reading,0,8);read_gate=&reading;unsigned before=reads;for(unsigned i=0;i<8;i++){contexts[i]=(struct parallel){make_section(&n,&objects[i],PAGE_SIZE),&ready,&release,0};if(pthread_create(&threads[i],0,parallel_acquire,&contexts[i]))abort();}pthread_barrier_wait(&ready);CHECK(reads==before+8);for(unsigned i=0;i<8;i++)CHECK(contexts[i].pa&&contexts[i].pa==contexts[0].pa);pthread_barrier_wait(&release);for(unsigned i=0;i<8;i++){pthread_join(threads[i],0);close_section(&objects[i]);}read_gate=0;pthread_barrier_destroy(&ready);pthread_barrier_destroy(&release);pthread_barrier_destroy(&reading);CHECK(heap_live==0&&page_live==0);}
int main(void){same_file();separation();recreate();views_and_cow();failures_and_growth();process_views_and_permissions();file_size_boundaries();intervening_publication_and_release();concurrent_acquire();CHECK(ipc_stat_sections==0);printf("file-section production: checks=%u failures=%u reads=%u writes=%u live_pages=%ld live_heap=%ld\n",checks,failures,reads,writes,page_live,heap_live);return failures?1:0;}
