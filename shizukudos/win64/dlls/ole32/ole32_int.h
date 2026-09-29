/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of the Shizuku ole32.dll implementation.
 *
 * What ole32.dll is here: apartment bookkeeping (CoInitializeEx & friends, initialize spies, server-process counting),
 * the task allocator (CoTaskMem*, IMalloc), GUID text conversion, CoCreateGuid, PROPVARIANT clear/copy, and the
 * OleInitialize reference count. There is NO class registry, marshaling, RPC, clipboard, drag and drop, storage or
 * stream implementation: CoCreateInstance, CoGetClassObject, CoRegisterClassObject, CoMarshal*, CreateStreamOnHGlobal,
 * RegisterDragDrop, ProgID lookups ... are not exported at all.
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
