// SPDX-License-Identifier: GPL-2.0-only
// C++ exception handling through vcruntime140.dll, compiled the way MSVC compiles: clang++ -target
// x86_64-pc-windows-msvc emits Microsoft x64 FH3 tables (__CxxFrameHandler3, catch/cleanup funclets, ip-to-state maps)
// and _CxxThrowException calls; lld-link imports them from the Shizuku DLLs. Covered: catch by reference / value /
// pointer with base-class conversion and multiple-inheritance adjustment, catch(...), nested try blocks, rethrow in and
// outside the catch, exceptions leaving a catch, try inside catch, destructor order during unwinding,
// std::uncaught_exceptions, SEH __try/__except/__finally (software and hardware exceptions, a C++ exception through a
// __finally), setjmp/longjmp unwinding, typeid/dynamic_cast (bad_cast), per-thread exception state under two threads,
// and std::terminate for noexcept violations and throwing destructors (in child processes).
// No C++ standard library is used: the few declarations needed are written out below, matching MSVC's layouts.

extern "C" {
__declspec(dllimport) void *__stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int __stdcall WriteFile(void *, const void *, unsigned long, unsigned long *, void *);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) void __stdcall RaiseException(unsigned long, unsigned long, unsigned long, const unsigned long long *);
__declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void *, char *, unsigned long);
__declspec(dllimport) char *__stdcall GetCommandLineA(void);
__declspec(dllimport) int __stdcall CreateProcessA(const char *, char *, void *, void *, int, unsigned long, void *, const char *, void *, void *);
__declspec(dllimport) unsigned long __stdcall WaitForSingleObject(void *, unsigned long);
__declspec(dllimport) int __stdcall GetExitCodeProcess(void *, unsigned long *);
__declspec(dllimport) int __stdcall CloseHandle(void *);
__declspec(dllimport) void *__stdcall CreateThread(void *, unsigned long long, unsigned long(__stdcall *)(void *), void *, unsigned long, unsigned long *);
__declspec(dllimport) int __uncaught_exceptions(void);
__declspec(dllimport) void **__current_exception(void);
__declspec(dllimport) const char *__std_type_info_name(void *data, void *root);
__declspec(dllimport) int __std_type_info_compare(const void *a, const void *b);
__declspec(dllimport) __attribute__((returns_twice)) int __intrinsic_setjmpex(void *buf, void *frame);
__declspec(dllimport) __declspec(noreturn) void longjmp(void *buf, int value);
__declspec(dllimport) void free(void *);
unsigned long _exception_code(void);
int _fltused = 0;
}
// operator delete comes from the static part of MSVC's CRT (the scalar deleting destructors reference it)
void operator delete(void *p) noexcept { free(p); }
void operator delete(void *p, unsigned long long) noexcept { free(p); }
#define GetExceptionCode _exception_code

// type_info's vftable: MSVC's static vcruntime.lib provides it to every image; here it is defined in the test.
asm(".section .rdata,\"dr\"\n.p2align 3\n.quad 0\n.globl \"??_7type_info@@6B@\"\n\"??_7type_info@@6B@\":\n.quad 0\n.text\n");

class type_info {
public:
    virtual ~type_info();
    const char *name() const { return __std_type_info_name(&data_, &root_); }
    bool operator==(const type_info &o) const { return __std_type_info_compare(&data_, &o.data_) == 0; }
private:
    mutable struct { const char *undecorated; char decorated[1]; } data_;
    static struct node { void *head[2]; } root_;
};
type_info::node type_info::root_;
namespace std {
using ::type_info;
class exception {
public:
    virtual ~exception();
    virtual const char *what() const;
private:
    const char *what_;
    bool free_;
};
class bad_cast : public exception {};
// msvcp140.dll
class logic_error : public exception {};
class length_error : public logic_error {};
class out_of_range : public logic_error {};
class runtime_error : public exception {};
class overflow_error : public runtime_error {};
class bad_alloc : public exception {};
[[noreturn]] __declspec(dllimport) void __cdecl _Xlength_error(const char *);
[[noreturn]] __declspec(dllimport) void __cdecl _Xout_of_range(const char *);
[[noreturn]] __declspec(dllimport) void __cdecl _Xoverflow_error(const char *);
[[noreturn]] __declspec(dllimport) void __cdecl _Xbad_alloc();
}
extern "C" {
struct Thrd { void *handle; unsigned id; };
__declspec(dllimport) void _Mtx_init_in_situ(void *mtx, int flags);
__declspec(dllimport) int _Mtx_lock(void *mtx);
__declspec(dllimport) int _Mtx_trylock(void *mtx);
__declspec(dllimport) int _Mtx_unlock(void *mtx);
__declspec(dllimport) int _Mtx_current_owns(void *mtx);
__declspec(dllimport) void _Cnd_init_in_situ(void *cnd);
__declspec(dllimport) int _Cnd_wait(void *cnd, void *mtx);
__declspec(dllimport) int _Cnd_broadcast(void *cnd);
__declspec(dllimport) int _Thrd_start(Thrd *t, unsigned(__stdcall *fn)(void *), void *arg);
__declspec(dllimport) int _Thrd_join(Thrd t, int *result);
__declspec(dllimport) unsigned _Thrd_id(void);
}

// ---------------------------------------------------------------- reporting
static int g_checks, g_failed;
static void out(const char *s)
{
    unsigned long n = 0, w;
    while (s[n]) ++n;
    WriteFile(GetStdHandle((unsigned long)-11), s, n, &w, 0);
}
static void out_int(long long v)
{
    char b[24];
    int i = 23;
    bool neg = v < 0;
    unsigned long long u = neg ? 0 - (unsigned long long)v : (unsigned long long)v;
    b[i] = 0;
    do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (neg) b[--i] = '-';
    out(b + i);
}
static void check(const char *what, bool ok, long long got = 0)
{
    ++g_checks;
    if (!ok) ++g_failed;
    out(ok ? "PASS: " : "FAIL: ");
    out(what);
    if (!ok) { out(" (got "); out_int(got); out(")"); }
    out("\n");
}
#define EXPECT(desc, expr, want)                        \
    do {                                                \
        const long long v_ = (expr);                    \
        check(desc, v_ == (want), v_);                  \
    } while (0)
static bool streq(const char *a, const char *b)
{
    while (*a && *a == *b) ++a, ++b;
    return *a == *b;
}

// ---------------------------------------------------------------- types
static int g_log[32], g_nlog;
struct Guard {
    int id;
    explicit Guard(int i) : id(i) {}
    ~Guard() { if (g_nlog < 32) g_log[g_nlog++] = id; }
};
struct Base { virtual ~Base() {} int v = 0; };
struct Derived : Base { explicit Derived(int x) { v = x; } };
struct Counted {
    static int live, copies;
    int v;
    explicit Counted(int x) : v(x) { ++live; }
    Counted(const Counted &o) : v(o.v) { ++live; ++copies; }
    ~Counted() { --live; }
};
int Counted::live, Counted::copies;
struct A { int a = 1; virtual ~A() {} };
struct B { int b = 2; virtual ~B() {} };
struct C : A, B { int c = 3; };

__declspec(noinline) static void thrower(int x)
{
    Guard g1(1);
    Guard g2(2);
    if (x) throw Derived(x);
}
__declspec(noinline) static void rethrow_now() { throw; }

// ---------------------------------------------------------------- C++ cases
static int t_basic()
{
    try { thrower(5); } catch (Base &b) { return b.v; }
    return -1;
}
static int t_by_value()
{
    int r = -1;
    Counted::live = Counted::copies = 0;
    try { throw Counted(7); } catch (Counted c) { r = c.v + 100 * Counted::copies; }
    return r;
}
static int t_int_and_all()
{
    int r = 0;
    try { throw 42; } catch (long) { r = 1; } catch (int i) { r = i; } catch (...) { r = 2; }
    try { throw 3.5; } catch (int) { r += 1000; } catch (...) { r += 100; }
    return r;
}
static int t_nested_outer()
{
    try {
        try { thrower(3); } catch (int) { return -5; }
    } catch (...) { return 7; }
    return 0;
}
static int t_rethrow_same_function()
{
    try {
        try { thrower(4); } catch (Base &) { throw; }
    } catch (Derived &d) { return d.v; }
    return 0;
}
static int t_rethrow_callee()
{
    try {
        try { thrower(8); } catch (Base &) { rethrow_now(); }
    } catch (Derived &d) { return d.v; }
    return 0;
}
static int t_new_exception_in_catch()
{
    Counted::live = 0;
    try {
        try { throw Counted(1); } catch (Counted &) { throw 5; }
    } catch (int x) { return x * 10 + Counted::live; }
    return -1;
}
static int t_try_in_catch()
{
    int r = 0;
    try { throw 1; } catch (int a) {
        try { throw 2; } catch (int b) { r = a * 10 + b; }
        r += 100;
    }
    return r;
}
static int t_pointer_mi()
{
    C obj;
    try { throw &obj; } catch (B *p) { return p == static_cast<B *>(&obj) ? p->b : -1; }
    return -2;
}
static int t_reference_mi()
{
    try { throw C(); } catch (B &b) { return b.b * 10 + (dynamic_cast<C *>(&b) ? dynamic_cast<C *>(&b)->c : 0); }
    return -1;
}
struct Probe { int *out; ~Probe() { *out = __uncaught_exceptions(); } };
static int t_uncaught()
{
    int during = -1, in_catch = -1;
    try { Probe p{&during}; throw 1; } catch (int) { in_catch = __uncaught_exceptions(); }
    return during * 10 + in_catch;
}
static int t_current_exception()
{
    int r = 0;
    try { throw 9; } catch (int) { r = *__current_exception() != 0; }
    return r * 10 + (*__current_exception() == 0);
}
static int t_deep(int depth)
{
    Guard g(depth);
    if (!depth) throw Counted(depth);
    return t_deep(depth - 1) + 1;
}
static int t_deep_unwind()
{
    g_nlog = 0;
    Counted::live = 0;
    try { t_deep(10); } catch (const Counted &c) { return c.v * 1000 + g_nlog * 10 + (g_log[0] == 0 && g_log[10] == 10); }
    return -1;
}

// ---------------------------------------------------------------- SEH
__declspec(noinline) static int deref(volatile int *p) { return *p; }
static int t_seh_raise()
{
    int r = 0;
    __try { RaiseException(0xE0001234u, 0, 0, 0); } __except (GetExceptionCode() == 0xE0001234u ? 1 : 0) { r = 1; }
    return r;
}
static int t_seh_access_violation()
{
    int r = 0;
    __try { r = deref((volatile int *)16); } __except (GetExceptionCode() == 0xC0000005u ? 1 : 0) { r = 55; }
    return r;
}
static int g_fin;
__declspec(noinline) static void seh_finally_thrower()
{
    __try { throw 9; } __finally { g_fin = 1; }
}
static int t_cxx_through_finally()
{
    g_fin = 0;
    try { seh_finally_thrower(); } catch (int x) { return x + 100 * g_fin; }
    return -1;
}
alignas(16) static unsigned char g_jb[256];
static int g_lj;
__declspec(noinline) static void lj_inner()
{
    __try { longjmp(g_jb, 3); } __finally { g_lj += 10; }
}
static int t_longjmp()
{
    g_lj = 0;
    const int r = __intrinsic_setjmpex(g_jb, __builtin_frame_address(0));
    if (r == 0) { lj_inner(); return -1; }
    return r + g_lj;
}

// ---------------------------------------------------------------- RTTI
static int t_rtti()
{
    C c;
    A a;
    A *pa = &c;
    int r = 0;
    B *pb = dynamic_cast<B *>(pa);
    if (pb == static_cast<B *>(&c) && dynamic_cast<C *>(pb) == &c) r += 1;
    if (dynamic_cast<C *>(&a) == nullptr) r += 10;
    try { (void)dynamic_cast<C &>(a); } catch (std::bad_cast &e) { r += streq(e.what(), "Bad dynamic_cast!") ? 100 : 0; }
    if (typeid(*pa) == typeid(C) && streq(typeid(*pa).name(), "struct C")) r += 1000;
    return r;
}

// ---------------------------------------------------------------- msvcp140
static int t_msvcp_exceptions()
{
    int r = 0;
    try { std::_Xlength_error("vector too long"); } catch (std::logic_error &e) { r += streq(e.what(), "vector too long"); }
    try { std::_Xout_of_range("invalid index"); } catch (std::length_error &) { r += 5; } catch (std::exception &e) { r += 10 * streq(e.what(), "invalid index"); }
    try { std::_Xoverflow_error("ovf"); } catch (std::runtime_error &e) { r += 100 * streq(e.what(), "ovf"); }
    try { std::_Xbad_alloc(); } catch (std::bad_alloc &e) { r += 1000 * streq(e.what(), "bad allocation"); }
    return r;
}
alignas(8) static unsigned char g_mtx[80], g_cnd[72], g_rmtx[80];
static int g_counter, g_done;
static unsigned __stdcall mtx_worker(void *arg)
{
    for (int i = 0; i < 2000; ++i) {
        _Mtx_lock(g_mtx);
        ++g_counter;
        _Mtx_unlock(g_mtx);
    }
    _Mtx_lock(g_mtx);
    ++g_done;
    _Cnd_broadcast(g_cnd);
    _Mtx_unlock(g_mtx);
    return (unsigned)(unsigned long long)arg;
}
static int t_msvcp_threads()
{
    Thrd t1, t2;
    int r1 = 0, r2 = 0, ok = 1;
    _Mtx_init_in_situ(g_mtx, 1);                          // _Mtx_plain
    _Cnd_init_in_situ(g_cnd);
    _Mtx_init_in_situ(g_rmtx, 0x101);                     // _Mtx_plain | _Mtx_recursive
    ok &= _Mtx_lock(g_rmtx) == 0 && _Mtx_trylock(g_rmtx) == 0 && _Mtx_current_owns(g_rmtx);
    _Mtx_unlock(g_rmtx);
    ok &= _Mtx_current_owns(g_rmtx) != 0;
    _Mtx_unlock(g_rmtx);
    ok &= !_Mtx_current_owns(g_rmtx);
    if (_Thrd_start(&t1, mtx_worker, (void *)11) || _Thrd_start(&t2, mtx_worker, (void *)22)) return -1;
    ok &= t1.id != t2.id && t1.id != _Thrd_id();
    _Mtx_lock(g_mtx);
    while (g_done < 2) _Cnd_wait(g_cnd, g_mtx);
    ok &= _Mtx_current_owns(g_mtx) != 0;
    _Mtx_unlock(g_mtx);
    ok &= _Thrd_join(t1, &r1) == 0 && _Thrd_join(t2, &r2) == 0 && r1 == 11 && r2 == 22;
    return ok ? g_counter : -2;
}

// ---------------------------------------------------------------- threads
static unsigned long __stdcall thread_body(void *arg)
{
    int *result = static_cast<int *>(arg), sum = 0, i;
    for (i = 0; i < 300; ++i) {
        try {
            try { thrower(i + 1); } catch (int) { sum -= 1000000; }
        } catch (Base &b) { sum += b.v; }
    }
    *result = sum;
    return 0;
}
static int t_threads()
{
    int r1 = 0, r2 = 0;
    void *h1 = CreateThread(0, 0, thread_body, &r1, 0, 0), *h2 = CreateThread(0, 0, thread_body, &r2, 0, 0);
    if (!h1 || !h2) return -1;
    WaitForSingleObject(h1, 60000);
    WaitForSingleObject(h2, 60000);
    CloseHandle(h1);
    CloseHandle(h2);
    return r1 == 45150 && r2 == 45150;
}

// ---------------------------------------------------------------- std::terminate (child processes)
// The callees are reached through plain function pointers so the compiler keeps the handlers: clang implements noexcept
// with a cleanup funclet calling __std_terminate, which runs when the unwind (phase 2) reaches the noexcept frame.
static volatile int g_dtor_throws = 1;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexceptions"
__declspec(noinline) static void noexcept_violation() noexcept { throw 1; }
#pragma clang diagnostic pop
struct ThrowingDtor { ~ThrowingDtor() noexcept(false) { if (g_dtor_throws) throw 2; } };
__declspec(noinline) static void throw_with_throwing_dtor() { ThrowingDtor d; throw 1; }
static void (*volatile g_child_fn[2])() = { noexcept_violation, throw_with_throwing_dtor };
__declspec(noinline) static void child(int mode)
{
    if (mode == 1 || mode == 2) {
        try { g_child_fn[mode - 1](); } catch (...) {}
    }
    ExitProcess(0);
}
static unsigned long run_child(int mode)
{
    char path[300], cmd[400];
    unsigned long code = 0xffffffffu;
    struct { unsigned cb; char pad[100]; } si = {};
    struct { void *process, *thread; unsigned long pid, tid; } pi = {};
    unsigned long n = GetModuleFileNameA(0, path, sizeof path), i, k = 0;
    if (!n || n >= sizeof path) return code;
    cmd[k++] = '"';
    for (i = 0; i < n; ++i) cmd[k++] = path[i];
    cmd[k++] = '"';
    for (const char *s = " child:"; *s; ++s) cmd[k++] = *s;
    cmd[k++] = (char)('0' + mode);
    cmd[k] = 0;
    si.cb = 104;
    if (!CreateProcessA(path, cmd, 0, 0, 0, 0, 0, 0, &si, &pi)) return code;
    WaitForSingleObject(pi.process, 60000);
    GetExitCodeProcess(pi.process, &code);
    CloseHandle(pi.thread);
    CloseHandle(pi.process);
    return code;
}

extern "C" void ShzCxxStart()
{
    const char *cl = GetCommandLineA();
    for (const char *p = cl; *p; ++p)
        if (p[0] == 'c' && p[1] == 'h' && p[2] == 'i' && p[3] == 'l' && p[4] == 'd' && p[5] == ':') child(p[6] - '0');

    int r;
    g_nlog = 0;
    r = t_basic();
    check("throw Derived, catch (Base &): value and both locals destroyed in order", r == 5 && g_nlog == 2 && g_log[0] == 2 && g_log[1] == 1, r);
    r = t_by_value();
    check("catch by value copy-constructs once; catch object and exception object destroyed", r == 107 && Counted::live == 0, r);
    EXPECT("catch (int) after a non-matching catch (long); catch (...) takes a double", t_int_and_all(), 142);
    EXPECT("an inner try that does not match passes the exception to the outer catch (...)", t_nested_outer(), 7);
    EXPECT("throw; inside a catch is caught by the enclosing try of the same function", t_rethrow_same_function(), 4);
    EXPECT("throw; in a function called from the catch rethrows the handled exception", t_rethrow_callee(), 8);
    EXPECT("a new exception leaving a catch destroys the handled exception object", t_new_exception_in_catch(), 50);
    EXPECT("try/catch inside a catch block", t_try_in_catch(), 112);
    EXPECT("catch (B *) of a thrown C * adjusts to the B subobject", t_pointer_mi(), 2);
    EXPECT("catch (B &) of a thrown C binds the B subobject; dynamic_cast back to C", t_reference_mi(), 23);
    EXPECT("std::uncaught_exceptions: 1 during unwinding, 0 in the handler", t_uncaught(), 10);
    EXPECT("__current_exception is set inside the catch and cleared after it", t_current_exception(), 11);
    EXPECT("unwinding eleven recursive frames runs every destructor innermost first", t_deep_unwind(), 111);
    EXPECT("__try/__except catches RaiseException, filter sees GetExceptionCode()", t_seh_raise(), 1);
    EXPECT("__try/__except catches an access violation raised in a callee", t_seh_access_violation(), 55);
    EXPECT("a C++ exception passing a __finally runs it", t_cxx_through_finally(), 109);
    EXPECT("longjmp from __setjmpex state unwinds through a __finally", t_longjmp(), 13);
    EXPECT("dynamic_cast (cross, down, failing, reference -> bad_cast) and typeid", t_rtti(), 1111);
    EXPECT("two threads throwing and catching concurrently keep separate exception state", t_threads(), 1);
    EXPECT("msvcp140 std::_X* helpers throw length_error / out_of_range / overflow_error / bad_alloc with their messages", t_msvcp_exceptions(), 1111);
    EXPECT("msvcp140 _Mtx_* / _Cnd_* / _Thrd_*: recursive mutex, two workers counting under a mutex, condition wait, join", t_msvcp_threads(), 4000);
    unsigned long code = run_child(1);
    check("an exception leaving a noexcept function calls std::terminate (abort: exit code 3)", code == 3, (long long)code);
    code = run_child(2);
    check("an exception leaving a destructor during unwinding calls std::terminate", code == 3, (long long)code);

    out("t_crt_eh: ");
    out_int(g_checks);
    out(" checks, ");
    out_int(g_failed);
    out(" failed\n");
    ExitProcess(g_failed ? 1 : 0);
}
