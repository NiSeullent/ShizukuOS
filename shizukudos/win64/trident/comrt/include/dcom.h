/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: stand-in for dcom.h, which Wine generates from dlls/ole32/dcom.idl (the DCOM wire types) and which
 * dlls/ole32/compobj_private.h includes. tridentrt compiles dlls/ole32/oleobj.c (the OLE/data advise holders) through
 * that header; nothing oleobj.c or compobj_private.h uses comes from dcom.idl, so the generated header is not needed.
 */
#ifndef SHZ_TRIDENTRT_DCOM_STANDIN_H
#define SHZ_TRIDENTRT_DCOM_STANDIN_H
#endif
