/* SPDX-License-Identifier: GPL-2.0-only
 * Standard exception classes defined from C for vcruntime140 (std::bad_cast, std::bad_typeid) and msvcp140
 * (std::logic_error family, std::bad_alloc, ...): the object layout, virtual function table, RTTI (complete object
 * locator, class hierarchy) and throw information of Microsoft's x64 C++ ABI, so that code compiled by MSVC or clang
 * catches them by type, calls what() and runs typeid / dynamic_cast on them.
 *
 * Object layout (std::exception and every class here): { vfptr; __std_exception_data { const char *what; bool free; } }.
 * vftable: [-1] complete object locator, [0] scalar deleting destructor, [1] what().
 * The includer provides vcr_exc_copy_data / vcr_exc_free_data (the __std_exception_copy / __std_exception_destroy
 * semantics) and _CxxThrowException.
 */
#ifndef SHZ_CXXCLASS_H
#define SHZ_CXXCLASS_H
#include "vcrint.h"

extern IMAGE_DOS_HEADER __ImageBase;
#define CXX_RVA(p) ((int32_t)((uintptr_t)(p) - (uintptr_t)&__ImageBase))

typedef struct { uint32_t signature, offset, cd_offset; int32_t type, hierarchy, self; } rtti_col;
typedef struct { uint32_t signature, attributes, nbases; int32_t bases; } rtti_chd;
typedef struct { int32_t type; uint32_t ncontained; eh_pmd where; uint32_t attributes; int32_t hierarchy; } rtti_bcd;
#define BCD_NOTVISIBLE 0x01u
#define BCD_AMBIGUOUS 0x02u
#define BCD_HASPCHD 0x40u
#define CHD_MULTINH 0x01u
#define CHD_VIRTINH 0x02u

typedef struct { const char *what; char do_free; } vcr_exc_data;
typedef struct { const void *const *vfptr; vcr_exc_data data; } vcr_exc;

#define CXX_MAX_DEPTH 5
typedef struct cxx_class {
    struct { const void *vftable; void *spare; char name[48]; } td;       /* TypeDescriptor */
    rtti_col col;
    rtti_chd chd;
    rtti_bcd bcd;
    int32_t bases[CXX_MAX_DEPTH];                   /* base class array: this class, then its ancestors */
    eh_catchable ct;
    struct { int32_t count; int32_t types[CXX_MAX_DEPTH]; } cta;
    eh_throwinfo ti;
    const void *vtbl[3];                             /* COL, scalar deleting destructor, what */
    const struct cxx_class *parent;
    unsigned depth;
} cxx_class;

static void vcr_exc_copy_data(const vcr_exc_data *from, vcr_exc_data *to);
static void vcr_exc_free_data(vcr_exc_data *d);

static const char *cxx_exc_what(const vcr_exc *e) { return e->data.what ? e->data.what : "Unknown exception"; }
static void cxx_exc_dtor(vcr_exc *e) { vcr_exc_free_data(&e->data); }
static void *cxx_exc_sdtor(vcr_exc *e, unsigned flags)
{
    vcr_exc_free_data(&e->data);
    if (flags & 1) free(e);
    return e;
}
/* type_info's own vftable: TypeDescriptors point at it; slot 0 is its (never called) scalar deleting destructor */
static void *cxx_type_info_sdtor(void *self, unsigned flags) { (void)flags; return self; }
static const void *cxx_type_info_vtbl[2] = { 0, (const void *)cxx_type_info_sdtor };

/* Fill in a class. `copy` is its copy constructor (dst, src), which must set dst's vfptr to this class's table. */
static void cxx_class_init(cxx_class *c, const char *name, const cxx_class *parent, void (*copy)(vcr_exc *, const vcr_exc *))
{
    unsigned i = 0, k;
    const cxx_class *a;
    while (name[i] && i < sizeof c->td.name - 1) { c->td.name[i] = name[i]; ++i; }
    c->td.name[i] = 0;
    c->td.vftable = &cxx_type_info_vtbl[1];
    c->parent = parent;
    c->depth = parent ? parent->depth + 1 : 1;
    c->bcd.type = CXX_RVA(&c->td);
    c->bcd.ncontained = c->depth - 1;
    c->bcd.where.mdisp = 0; c->bcd.where.pdisp = -1; c->bcd.where.vdisp = 0;
    c->bcd.attributes = BCD_HASPCHD;
    c->bcd.hierarchy = CXX_RVA(&c->chd);
    for (a = c, k = 0; a && k < CXX_MAX_DEPTH; a = a->parent, ++k) {
        c->bases[k] = CXX_RVA(&a->bcd);
        c->cta.types[k] = CXX_RVA(&a->ct);
    }
    c->chd.signature = 0; c->chd.attributes = 0; c->chd.nbases = k; c->chd.bases = CXX_RVA(c->bases);
    c->col.signature = 1; c->col.offset = 0; c->col.cd_offset = 0;
    c->col.type = CXX_RVA(&c->td); c->col.hierarchy = CXX_RVA(&c->chd); c->col.self = CXX_RVA(&c->col);
    c->ct.properties = 0; c->ct.type = CXX_RVA(&c->td);
    c->ct.this_disp.mdisp = 0; c->ct.this_disp.pdisp = -1; c->ct.this_disp.vdisp = 0;
    c->ct.size = (int32_t)sizeof(vcr_exc); c->ct.copy_ctor = CXX_RVA(copy);
    c->cta.count = (int32_t)k;
    c->ti.attributes = 0; c->ti.destructor = CXX_RVA(cxx_exc_dtor); c->ti.forward_compat = 0; c->ti.catchables = CXX_RVA(&c->cta);
    c->vtbl[0] = &c->col;
    c->vtbl[1] = (const void *)cxx_exc_sdtor;
    c->vtbl[2] = (const void *)cxx_exc_what;
}

/* A copy constructor per class (it installs the class's own vftable). */
#define CXX_COPY_CTOR(cls)                                                   \
    static void cxx_copy_##cls(vcr_exc *dst, const vcr_exc *src)             \
    {                                                                        \
        dst->vfptr = &g_##cls.vtbl[1];                                       \
        dst->data.what = 0;                                                  \
        dst->data.do_free = 0;                                               \
        vcr_exc_copy_data(&src->data, &dst->data);                           \
    }

#ifndef VCR_LOCAL_THROW
__declspec(dllimport) VCR_NORETURN void __stdcall _CxxThrowException(void *obj, const eh_throwinfo *ti);
#endif

/* throw cls(what): the message is copied (the object owns it), as the standard classes' constructors do */
static VCR_NORETURN void cxx_throw(const cxx_class *c, const char *what)
{
    vcr_exc e;
    vcr_exc_data src;
    e.vfptr = &c->vtbl[1];
    e.data.what = 0;
    e.data.do_free = 0;
    src.what = what;
    src.do_free = 1;
    if (what) vcr_exc_copy_data(&src, &e.data);
    _CxxThrowException(&e, &c->ti);
}

#endif
