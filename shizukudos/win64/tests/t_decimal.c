/* SPDX-License-Identifier: GPL-2.0-only
 * Actual provider fixture: arithmetic, fixed ordinals, NLS, real BSTR heap and
 * two kernel threads. No target application or synthetic locale is involved. */
#include "k32test.h"
#include <oleauto.h>

static DECIMAL number(ULONGLONG low, ULONG high, BYTE scale, BYTE sign)
{
    DECIMAL d={0}; d.Lo64=low; d.Hi32=high; d.scale=scale; d.sign=sign; return d;
}
static int text_equal(const WCHAR *a,const WCHAR *b)
{
    if(!a || !b) return 0;
    while(*a && *a==*b) {++a;++b;}
    return *a==*b;
}
struct decimal_thread_context { ULONGLONG base; HANDLE start; };
static DWORD WINAPI decimal_worker(void *arg)
{
    struct decimal_thread_context *context=arg;
    unsigned i; ULONGLONG base=context->base;
    if (WaitForSingleObject(context->start,30000)!=WAIT_OBJECT_0) return 4;
    for(i=0;i<100;i++) {
        DECIMAL a=number(base+i,0,2,0),b=number(2,0,0,0),out;
        DECIMAL scaled=number(base+i+1000,0,2,0);
        BSTR value=NULL;
        if (VarDecAdd(&scaled,&b,&out)!=S_OK || out.Lo64!=base+i+1200 || out.Hi32 || out.scale!=2 || out.sign) return 5;
        if (VarDecAdd(&b,&scaled,&out)!=S_OK || out.Lo64!=base+i+1200 || out.Hi32 || out.scale!=2 || out.sign) return 6;
        if (VarDecSub(&scaled,&b,&out)!=S_OK || out.Lo64!=base+i+800 || out.Hi32 || out.scale!=2 || out.sign) return 7;
        if (VarDecSub(&b,&scaled,&out)!=S_OK || out.Lo64!=base+i+800 || out.Hi32 || out.scale!=2 || out.sign!=0x80) return 8;
        HRESULT hr=VarDecMul(&a,&b,&out);
        if(hr!=S_OK || out.Lo64!=2*(base+i) || out.Hi32 || out.scale!=2 || out.sign) return 1;
        hr=VarBstrFromDec(&a,0x409,0,&value);
        if(hr!=S_OK || !value) return 2;
        if(!SysStringLen(value)) {SysFreeString(value);return 3;}
        SysFreeString(value);
    }
    return 0;
}
int main(void)
{
    static const struct {const char *name; WORD ordinal;} exports[]={
        {"VarDecAdd",177},{"VarDecDiv",178},{"VarDecMul",179},{"VarDecSub",181},{"VarDecNeg",189},
        {"VarDecFromUI1",190},{"VarDecFromI2",191},{"VarDecFromI4",192},{"VarDecFromR4",193},{"VarDecFromR8",194},
        {"VarDecFromStr",197},{"VarDecCmp",204},{"VarI2FromDec",208},{"VarI4FromDec",212},{"VarR4FromDec",216},
        {"VarR8FromDec",220},{"VarBstrFromDec",232},{"VarUI1FromDec",240},{"VarDecFromUI2",242},{"VarDecFromUI4",243},
        {"VarUI2FromDec",269},{"VarUI4FromStr",277},{"VarUI4FromDec",282},{"VarI8FromDec",345},
        {"VarDecFromI8",374},{"VarDecFromUI8",375},{"VarUI8FromDec",441}};
    HMODULE module=GetModuleHandleW(L"oleaut32.dll");
    DECIMAL a=number(12345,0,2,0),b=number(200,0,2,0),out,zero=number(0,0,0,0),max=number(~0ULL,~0u,0,0);
    LONGLONG signed_value; ULONGLONG unsigned_value; BYTE byte; SHORT small; LONG integer;
    USHORT ushort; ULONG uint; FLOAT single; DOUBLE real; BSTR str=NULL; WCHAR formatted[256];
    HANDLE threads[2]={NULL,NULL}; DWORD code=1; unsigned i; BOOL bindings=module!=NULL;
    HANDLE start=NULL;
    struct decimal_thread_context contexts[2]={{100,NULL},{7000,NULL}};
    union {ULONGLONG bits; DOUBLE real;} fp;
    for(i=0;i<sizeof(exports)/sizeof(exports[0]);i++) {
        FARPROC named=module?GetProcAddress(module,exports[i].name):NULL;
        FARPROC ordinal=module?GetProcAddress(module,(LPCSTR)(ULONG_PTR)exports[i].ordinal):NULL;
        bindings &= named!=NULL && named==ordinal;
    }
    CHECK(bindings,"all 27 actual named exports match their canonical ordinal addresses");
    CHECK(VarDecAdd(&a,&b,&out)==S_OK && out.Lo64==12545 && out.scale==2 && !out.Hi32 && !out.sign,"real decimal addition retains exact cents");
    CHECK(VarDecSub(&a,&b,&out)==S_OK && out.Lo64==12145 && out.scale==2 && !out.sign,"real decimal subtraction retains exact cents");
    CHECK(VarDecMul(&a,&b,&out)==S_OK && out.Lo64==2469000 && out.scale==4,"real decimal multiplication uses 96-bit limbs");
    b=number(2,0,0,0);
    CHECK(VarDecDiv(&a,&b,&out)==S_OK && out.Lo64==61725 && out.scale==3,"real decimal division preserves an exact fractional result");
    CHECK(VarDecDiv(&a,&zero,&out)==DISP_E_DIVBYZERO,"division by zero is an honest arithmetic failure");
    CHECK(VarDecAdd(&max,&b,&out)==DISP_E_OVERFLOW,"96-bit overflow is rejected");
    CHECK(VarDecNeg(&a,&a)==S_OK && a.sign==0x80 && a.Lo64==12345,"negation supports an aliased output");
    CHECK(VarDecCmp(&a,&zero)==VARCMP_LT && VarDecCmp(&zero,&zero)==VARCMP_EQ && VarDecCmp(&b,&zero)==VARCMP_GT,"decimal comparisons return all three outcomes");
    CHECK(VarDecFromUI1(255,&out)==S_OK && out.Lo64==255 && !out.scale && !out.sign,"byte input uses exact unsigned magnitude");
    CHECK(VarDecFromI2(-32768,&out)==S_OK && out.Lo64==32768 && out.sign==0x80,"signed short minimum is representable");
    CHECK(VarDecFromI4((LONG)0x80000000u,&out)==S_OK && out.Lo64==0x80000000ULL && out.sign==0x80,"signed long minimum avoids signed-negation overflow");
    CHECK(VarDecFromUI2(65535,&out)==S_OK && out.Lo64==65535,"unsigned short maximum is representable");
    CHECK(VarDecFromUI4(~0u,&out)==S_OK && out.Lo64==0xffffffffULL,"unsigned long maximum is representable");
    CHECK(VarDecFromI8((LONGLONG)0x8000000000000000ULL,&out)==S_OK && out.Lo64==0x8000000000000000ULL && out.sign==0x80
          && VarI8FromDec(&out,&signed_value)==S_OK && signed_value==(LONGLONG)0x8000000000000000ULL,"signed 64-bit minimum round-trips exactly");
    CHECK(VarDecFromUI8(~0ULL,&out)==S_OK && VarUI8FromDec(&out,&unsigned_value)==S_OK && unsigned_value==~0ULL,"unsigned 64-bit maximum round-trips exactly");
    out=number(0xfffffffffffffff6ULL,4,1,0);
    CHECK(VarI8FromDec(&out,&signed_value)==S_OK && signed_value==0x7fffffffffffffffLL,"scaled signed maximum is not rounded through double");
    out=number(25,0,1,0);
    CHECK(VarI2FromDec(&out,&small)==S_OK && small==2 && VarI4FromDec(&out,&integer)==S_OK && integer==2,"signed narrowing rounds halfway to even");
    out.Lo64=35;
    CHECK(VarUI1FromDec(&out,&byte)==S_OK && byte==4 && VarUI2FromDec(&out,&ushort)==S_OK && ushort==4 && VarUI4FromDec(&out,&uint)==S_OK && uint==4,"unsigned narrowing rounds halfway to even");
    out=number(4,0,1,0x80);
    CHECK(VarUI8FromDec(&out,&unsigned_value)==S_OK && !unsigned_value,"negative fraction rounds to unsigned zero before range checking");
    out.Lo64=6; CHECK(VarUI8FromDec(&out,&unsigned_value)==DISP_E_OVERFLOW,"negative rounded unsigned magnitude is rejected");
    CHECK(VarDecFromR4(-0.5f,&out)==S_OK && out.Lo64==5 && out.scale==1 && out.sign==0x80,"real float conversion preserves sign and decimal scale");
    CHECK(VarDecFromR8(0.5,&out)==S_OK && VarR8FromDec(&out,&real)==S_OK && real==0.5 && VarR4FromDec(&out,&single)==S_OK && single==0.5f,"double and float conversions round-trip an exact binary fraction");
    fp.bits=0x7ff0000000000000ULL; CHECK(VarDecFromR8(fp.real,&out)==DISP_E_OVERFLOW,"infinity does not become a fabricated decimal");
    fp.bits=0x7ff8000000000000ULL; CHECK(VarDecFromR8(fp.real,&out)==DISP_E_BADVARTYPE,"NaN preserves the real Wine invalid numeric-type failure");
    CHECK(VarDecFromStr(L"18446744073709551616",0x409,0,&out)==S_OK && out.Hi32==1 && !out.Lo64 && !out.wReserved,"actual parser accepts a value beyond 64 bits");
    CHECK(VarDecFromStr(L"($1,234.5)",0x409,0,&out)==S_OK && out.Lo64==12345 && out.scale==1 && out.sign==0x80,"actual locale metadata supplies currency and grouping syntax");
    CHECK(VarUI4FromStr(L"4294967295",0x409,0,&uint)==S_OK && uint==~0u && VarUI4FromStr(L"4294967296",0x409,0,&uint)==DISP_E_OVERFLOW,"actual unsigned string conversion respects its 32-bit bound");
    CHECK(VarDecFromStr(L"1e-256",0x409,0,&out)==S_OK && !out.Lo64 && !out.Hi32 && out.scale<=28,"tiny decimal strings never wrap the byte scale into a false value");
    CHECK(VarDecFromStr(L"1e214748364800000",0x409,0,&out)==DISP_E_OVERFLOW,"very long exponent syntax is consumed without signed overflow");
    CHECK(VarDecFromStr(NULL,0x409,0,&out)==DISP_E_TYPEMISMATCH && VarDecFromStr(L"abc",0x409,0,&out)==DISP_E_TYPEMISMATCH,"invalid string syntax preserves a type mismatch");
    CHECK(VarDecFromStr(L"1",0x412,0,&out)==HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER),"absent Korean locale metadata returns the actual provider failure");
    out=number(12345,0,2,0);
    CHECK(VarBstrFromDec(&out,0x409,0,&str)==S_OK && text_equal(str,L"123.45") && SysStringLen(str)==6 && SysStringByteLen(str)==12,"actual BSTR allocation contains the exact decimal text and byte length");
    SysFreeString(str);str=NULL;
    CHECK(GetNumberFormatW(0x409,0,L"123.45",NULL,formatted,256)>0 && VarBstrFromDec(&out,0x409,LOCALE_USE_NLS,&str)==S_OK && text_equal(str,formatted),"decimal NLS formatting agrees with the actual independent provider");
    SysFreeString(str);str=NULL;
    CHECK(VarBstrFromDec(&out,0x412,0,&str)==HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER) && !str,"missing formatter locale does not allocate success-shaped text");
    out.scale=29;
    CHECK(VarR8FromDec(&out,&real)==E_INVALIDARG && VarDecNeg(&out,&out)==E_INVALIDARG,"invalid decimal scale is rejected across the coherent family");
    CHECK(VarDecFromUI8(1,NULL)==E_INVALIDARG && VarI8FromDec(NULL,&signed_value)==E_INVALIDARG,"NULL input/output parameters are rejected before computation");
    start=CreateEventW(NULL,TRUE,FALSE,NULL);
    CHECK(start!=NULL,"real manual-reset event gates concurrent mismatched-scale arithmetic");
    contexts[0].start=contexts[1].start=start;
    if(start) {
        threads[0]=CreateThread(NULL,0,decimal_worker,&contexts[0],0,NULL);
        threads[1]=CreateThread(NULL,0,decimal_worker,&contexts[1],0,NULL);
        CHECK(SetEvent(start),"both arithmetic workers receive the same real start signal");
    }
    CHECK(threads[0] && threads[1],"two real kernel threads start independent decimal and BSTR work");
    for(i=0;i<2;i++) if(threads[i]) {
        DWORD waited=WaitForSingleObject(threads[i],30000);
        if (waited!=WAIT_OBJECT_0) {
            CHECK(FALSE,"worker exit is unproved; terminate before borrowed context lifetime ends");
            ExitProcess(2);
        }
        CHECK(waited==WAIT_OBJECT_0 && GetExitCodeThread(threads[i],&code) && code==0,"real worker completes arithmetic and releases its owned BSTRs");
        CHECK(CloseHandle(threads[i]),"joined kernel thread handle is released");
    }
    if(start) CHECK(CloseHandle(start),"the joined workers' start event is released");
    return k32t_finish("T_DECIMAL");
}
