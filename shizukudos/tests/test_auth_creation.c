/* SPDX-License-Identifier: GPL-2.0-only
 * Actual process construction bodies; allocation/IRQ/preemption boundaries only.
 */
#include "../kernel64/proc_internal.h"
#include "../kernel64/auth_policy.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t host_irq_flags=0x202;
static uint64_t host_irq_save(void){uint64_t f=host_irq_flags;host_irq_flags&=~0x200ull;return f;}
static void host_irq_restore(uint64_t f){host_irq_flags=f;}
#define irq_save host_irq_save
#define irq_restore host_irq_restore
/* @PRODUCTION_PROCESS_DECLARATIONS@ */
/* @PRODUCTION_PROCESS_CREATE@ */

static unsigned checks,failures,vm_live,alloc_live,heap_failures;
static int vm_failure,object_failure,pending_failure,inject_creation;
static process_t *nested;
static uint64_t next_vm=0x1000;
static void *allocations[256];
static process_t *pending_subjects[65];
static void check(const char *what,int okay){checks++;failures+=!okay;printf("%s: %s\n",okay?"PASS":"FAIL",what);}
void kprintf(const char *f,...){(void)f;}
void thread_reap_exited(void){}
uint64_t ticks_now(void){return 47;}
uint64_t vm_new_space(void){
    if(inject_creation){inject_creation=0;nested=process_create_empty("inner");}
    if(vm_failure)return 0;
    vm_live++;next_vm+=0x1000;return next_vm;
}
void vm_free_space(uint64_t p){assert(p&&vm_live);vm_live--;}
void *kzalloc(uint64_t n){
    if(heap_failures){heap_failures--;return 0;}
    void *p=calloc(1,(size_t)n);assert(p);
    for(unsigned i=0;i<256;i++)if(!allocations[i]){allocations[i]=p;alloc_live++;return p;}
    abort();
}
void kfree(void *p){if(!p)return;for(unsigned i=0;i<256;i++)if(allocations[i]==p){allocations[i]=0;alloc_live--;free(p);return;}abort();}
void vad_init(process_t *p){(void)p;}
void sem_init(ksem_t *s,int n){memset(s,0,sizeof *s);s->count=n;}
kobject_t *ob_create(uint32_t type,const char *name){(void)name;if(object_failure)return 0;kobject_t *o=kzalloc(sizeof *o);o->type=type;o->refs=1;return o;}
void ob_deref(kobject_t *o){assert(o&&o->refs);if(!--o->refs)kfree(o);}
int32_t shz_auth_process_pending(process_t *p){
    assert(p&&!p->used&&p->object&&p->object->u.proc.p==p&&p->pid);
    if(pending_failure)return STATUS_NO_MEMORY;
    assert(p>=procs&&p<=procs+MAX_PROCS);pending_subjects[p-procs]=p;return 0;
}
void shz_auth_process_gone(process_t *p){if(p>=procs&&p<=procs+MAX_PROCS)pending_subjects[p-procs]=0;}
static void reset(void){
    for(unsigned i=0;i<256;i++)if(allocations[i]){free(allocations[i]);allocations[i]=0;}
    memset(procs,0,sizeof procs);memset(pending_subjects,0,sizeof pending_subjects);
    vm_live=alloc_live=heap_failures=0;vm_failure=object_failure=pending_failure=inject_creation=0;
    nested=0;host_irq_flags=0x202;
}
static void recursive_creation(void){
    reset();inject_creation=1;process_t *outer=process_create_empty("outer");
    check("preempting constructor gets a different reserved slot",outer&&nested&&outer!=nested);
    check("preempting constructors retain distinct CIDs and names",outer&&nested&&outer->pid!=nested->pid&&!strcmp(outer->name,"outer")&&!strcmp(nested->name,"inner"));
    check("both published processes already own pending admission",outer&&nested&&pending_subjects[outer-procs]==outer&&pending_subjects[nested-procs]==nested);
    check("IRQ state restored after recursive allocation",host_irq_flags==0x202);
    reset();
}
static void failed_creation(void){
    const char *labels[]={"VM failure releases slot","heap failure releases slot","object failure releases slot","pending authority failure releases slot"};
    for(unsigned which=0;which<4;which++){
        reset();vm_failure=which==0;heap_failures=which==1?2:0;object_failure=which==2;pending_failure=which==3;
        process_t *p=process_create_empty("fail");check(labels[which],!p&&!procs[1].used&&!vm_live&&!alloc_live&&!pending_subjects[1]);
        vm_failure=object_failure=pending_failure=0;heap_failures=0;
        p=process_create_empty("retry");check("failed reservation is immediately reusable",p==&procs[1]&&p->used&&pending_subjects[1]==p);
    }
    reset();
}
int main(int argc,char **argv){
    recursive_creation();if(argc<2||strcmp(argv[1],"recursive"))failed_creation();
    printf("process creation: checks=%u failures=%u scope=actual-production-construction-host-boundaries\n",checks,failures);
    return failures?1:0;
}
