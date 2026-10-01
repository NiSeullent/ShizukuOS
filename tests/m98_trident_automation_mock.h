/* SPDX-License-Identifier: GPL-2.0-only
 * Original COM/OS doubles; not a native ABI or DOM implementation. */
#ifndef M98_AUTOMATION_MOCK_H
#define M98_AUTOMATION_MOCK_H
#include <stdint.h>
#include <stddef.h>
#define STDMETHODCALLTYPE
typedef int32_t HRESULT,LONG,DISPID;
typedef uint32_t ULONG,DWORD,UINT,LCID;
typedef uint16_t WORD,OLECHAR,VARTYPE;
typedef int16_t VARIANT_BOOL;
typedef OLECHAR *BSTR,*LPOLESTR;
struct GUID {uint32_t Data1;uint16_t Data2,Data3;uint8_t Data4[8];};
typedef const GUID &REFIID;
struct ITypeInfo;struct IDispatch;struct IServiceProvider;
struct IUnknown {virtual HRESULT QueryInterface(REFIID,void **)=0;virtual ULONG AddRef()=0;virtual ULONG Release()=0;};
struct VARIANT {
    VARTYPE vt;WORD wReserved1,wReserved2,wReserved3;
    union {int8_t cVal;uint8_t bVal;int16_t iVal;uint16_t uiVal;int32_t lVal;uint32_t ulVal;float fltVal;double dblVal;VARIANT_BOOL boolVal;BSTR bstrVal;IDispatch *pdispVal;IUnknown *punkVal;void *byref;};
};
struct DISPPARAMS {VARIANT *rgvarg;DISPID *rgdispidNamedArgs;UINT cArgs,cNamedArgs;};
struct EXCEPINFO {WORD wCode,wReserved;BSTR bstrSource,bstrDescription,bstrHelpFile;DWORD dwHelpContext;void *pvReserved;HRESULT (*pfnDeferredFillIn)(EXCEPINFO *);HRESULT scode;};
struct TYPEATTR {uint16_t cFuncs;};struct FUNCDESC {DISPID memid;uint32_t invkind;};
struct ITypeInfo: IUnknown {virtual HRESULT GetTypeAttr(TYPEATTR **)=0;virtual HRESULT GetFuncDesc(UINT,FUNCDESC **)=0;virtual void ReleaseTypeAttr(TYPEATTR *)=0;virtual void ReleaseFuncDesc(FUNCDESC *)=0;};
struct IDispatch: IUnknown {
    virtual HRESULT GetTypeInfoCount(UINT *)=0;virtual HRESULT GetTypeInfo(UINT,LCID,ITypeInfo **)=0;
    virtual HRESULT GetIDsOfNames(REFIID,LPOLESTR *,UINT,LCID,DISPID *)=0;
    virtual HRESULT Invoke(DISPID,REFIID,LCID,WORD,DISPPARAMS *,VARIANT *,EXCEPINFO *,UINT *)=0;
};
struct IDispatchEx: IDispatch {
    virtual HRESULT GetDispID(BSTR,DWORD,DISPID *)=0;
    virtual HRESULT InvokeEx(DISPID,LCID,WORD,DISPPARAMS *,VARIANT *,EXCEPINFO *,IServiceProvider *)=0;
    virtual HRESULT DeleteMemberByName(BSTR,DWORD)=0;virtual HRESULT DeleteMemberByDispID(DISPID)=0;
    virtual HRESULT GetMemberProperties(DISPID,DWORD,DWORD *)=0;virtual HRESULT GetMemberName(DISPID,BSTR *)=0;
    virtual HRESULT GetNextDispID(DWORD,DISPID,DISPID *)=0;virtual HRESULT GetNameSpaceParent(IUnknown **)=0;
};
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_NOTIMPL ((HRESULT)0x80004001u)
#define E_NOINTERFACE ((HRESULT)0x80004002u)
#define E_POINTER ((HRESULT)0x80004003u)
#define E_FAIL ((HRESULT)0x80004005u)
#define E_OUTOFMEMORY ((HRESULT)0x8007000eu)
#define E_INVALIDARG ((HRESULT)0x80070057u)
#define RPC_E_DISCONNECTED ((HRESULT)0x80010108u)
#define DISP_E_UNKNOWNINTERFACE ((HRESULT)0x80020001u)
#define DISP_E_MEMBERNOTFOUND ((HRESULT)0x80020003u)
#define DISP_E_UNKNOWNNAME ((HRESULT)0x80020006u)
#define DISP_E_EXCEPTION ((HRESULT)0x80020009u)
#define DISP_E_TYPEMISMATCH ((HRESULT)0x80020005u)
#define DISP_E_BADPARAMCOUNT ((HRESULT)0x8002000eu)
#define DISPID_VALUE 0
#define DISPID_UNKNOWN (-1)
#define DISPID_PROPERTYPUT (-3)
#define DISPID_THIS (-613)
#define DISPID_STARTENUM (-1)
#define DISPATCH_METHOD 1
#define DISPATCH_PROPERTYGET 2
#define DISPATCH_PROPERTYPUT 4
#define DISPATCH_PROPERTYPUTREF 8
#define LOCALE_USER_DEFAULT 0x400
#define fdexNameCaseSensitive 1
#define fdexNameCaseInsensitive 8
#define fdexPropCanCall 0x100
#define fdexPropCanPut 4
#define fdexPropCanPutRef 16
#define INVOKE_FUNC 1
#define INVOKE_PROPERTYPUT 4
#define INVOKE_PROPERTYPUTREF 8
#define VT_EMPTY 0
#define VT_NULL 1
#define VT_I2 2
#define VT_I4 3
#define VT_R4 4
#define VT_R8 5
#define VT_CY 6
#define VT_DATE 7
#define VT_BSTR 8
#define VT_DISPATCH 9
#define VT_ERROR 10
#define VT_BOOL 11
#define VT_UNKNOWN 13
#define VT_I1 16
#define VT_UI1 17
#define VT_UI2 18
#define VT_UI4 19
#define VT_INT 22
#define VT_UINT 23
#define VT_ARRAY 0x2000
#define VT_BYREF 0x4000
#define VARIANT_TRUE (-1)
#define VARIANT_FALSE 0
DWORD GetCurrentThreadId();void *GetProcessHeap();void *HeapAlloc(void *,DWORD,size_t);int HeapFree(void *,DWORD,void *);
LONG InterlockedIncrement(volatile LONG *);LONG InterlockedDecrement(volatile LONG *);LONG InterlockedCompareExchange(volatile LONG *,LONG,LONG);
BSTR SysAllocStringLen(const OLECHAR *,UINT);void SysFreeString(BSTR);UINT SysStringLen(BSTR);HRESULT VariantClear(VARIANT *);
#endif
