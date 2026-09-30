/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of the Shizuku ole32.dll implementation.
 *
 * What ole32.dll is here: apartment bookkeeping (CoInitializeEx & friends, initialize spies, server-process counting),
 * the task allocator (CoTaskMem*, IMalloc), GUID text conversion, CoCreateGuid, PROPVARIANT clear/copy, the
 * OleInitialize reference count, an in-process class table (classes.c: CoRegisterClassObject / CoGetClassObject /
 * CoCreateInstance; every CLSID nobody registered is REGDB_E_CLASSNOTREG - there is no class store), IStream/ILockBytes
 * over global memory and STGMEDIUM release (stream.c), and in-process interface transfer, the free-threaded marshaler,
 * agile references and the drop-target table (marshal.c). There is NO RPC, no proxy/stub layer, no clipboard, no
 * compound-file storage and no drag loop (DoDragDrop is not exported).
 */
#ifndef SHZ_OLE32_INT_H
#define SHZ_OLE32_INT_H
#include "nt.h"
#include <string.h>
#define _OLE32_
#define COBJMACROS
#include <objbase.h>
#include <ole2.h>
#include <oleauto.h>
#include <propidl.h>

extern const GUID shz_iid_unknown, shz_iid_malloc, shz_iid_initializespy;
#endif
