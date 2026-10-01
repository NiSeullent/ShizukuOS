/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Rtl string functions
 *
 * Copyright (C) 1996-1998 Marcus Meissner
 * Copyright (C) 2000      Alexandre Julliard
 * Copyright (C) 2003      Thomas Mertes
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Adapted descriptor and ordinal comparison contracts from pinned Wine
 * db11d0fe6a169c457e23d007e20404643d067aa8 rtlstr.c and locale.c.
 * Additional locale copyright: 2019, 2022 Alexandre Julliard.
 * Local bounds, descriptor alias snapshots and actual fixed UTF-8 ACP port. */
#ifdef SHZ_RTL_BOOTSTRAP_HOST
#include "../tests/rtl_bootstrap_host_contract.h"
#else
#include "nt.h"
#endif
#include "rtl_bootstrap_utf8.h"

#ifndef SHZ_RTL_BOOTSTRAP_HOST
typedef struct {USHORT Length,MaximumLength;char *Buffer;} SHZ_BOOTSTRAP_ANSI_STRING;
#endif
extern WCHAR ShzBootstrapUpcase(WCHAR);

SHZ_EXPORT SIZE_T NTAPI RtlCompareMemory(const VOID *left,const VOID *right,SIZE_T length)
{
    const unsigned char *a=left,*b=right;
    SIZE_T i=0;
    while(i<length && a[i]==b[i])++i;
    return i;
}

SHZ_EXPORT LONG NTAPI RtlCompareUnicodeString(const SHZ_UNICODE_STRING *left,const SHZ_UNICODE_STRING *right,BOOLEAN insensitive)
{
    SIZE_T a=left->Length/sizeof(WCHAR),b=right->Length/sizeof(WCHAR),count=a<b?a:b;
    for(SIZE_T i=0;i<count;++i) {
        WCHAR x=left->Buffer[i],y=right->Buffer[i];
        if(insensitive){x=ShzBootstrapUpcase(x);y=ShzBootstrapUpcase(y);}
        if(x!=y)return (LONG)x-(LONG)y;
    }
    return (LONG)a-(LONG)b;
}

SHZ_EXPORT BOOLEAN NTAPI RtlEqualUnicodeString(const SHZ_UNICODE_STRING *left,const SHZ_UNICODE_STRING *right,BOOLEAN insensitive)
{
    if(left->Length!=right->Length)return FALSE;
    return RtlCompareUnicodeString(left,right,insensitive)==0;
}

SHZ_EXPORT NTSTATUS NTAPI RtlDuplicateUnicodeString(ULONG flags,const SHZ_UNICODE_STRING *source,SHZ_UNICODE_STRING *destination)
{
    SHZ_UNICODE_STRING saved;
    unsigned capacity;
    WCHAR *buffer;
    if(!source || !destination || flags==2 || flags>=4)return STATUS_INVALID_PARAMETER;
    saved=*source;
    if(saved.Length>saved.MaximumLength || (saved.Length&1) || (!saved.Buffer && (saved.Length || saved.MaximumLength)))return STATUS_INVALID_PARAMETER;
    if(!saved.Length && flags!=3){destination->Length=destination->MaximumLength=0;destination->Buffer=0;return STATUS_SUCCESS;}
    capacity=(unsigned)saved.Length+(flags?sizeof(WCHAR):0);
    if(capacity>0xffff)return STATUS_INVALID_PARAMETER;
    buffer=RtlAllocateHeap(ShzProcessHeap(),0,capacity);
    destination->Buffer=buffer;
    if(!buffer)return STATUS_NO_MEMORY;
    for(unsigned i=0;i<saved.Length/sizeof(WCHAR);++i)buffer[i]=saved.Buffer[i];
    if(flags)buffer[saved.Length/sizeof(WCHAR)]=0;
    destination->Length=saved.Length;destination->MaximumLength=(USHORT)capacity;
    return STATUS_SUCCESS;
}

SHZ_EXPORT NTSTATUS NTAPI RtlAnsiStringToUnicodeString(SHZ_UNICODE_STRING *destination,const SHZ_BOOTSTRAP_ANSI_STRING *source,BOOLEAN allocate)
{
    SHZ_BOOTSTRAP_ANSI_STRING saved;
    unsigned units,total,written;
    char *snapshot=0;
    const char empty=0,*input;
    if(!destination || !source)return STATUS_INVALID_PARAMETER;
    saved=*source;
    if(saved.Length>saved.MaximumLength || (!saved.Buffer && saved.Length))return STATUS_INVALID_PARAMETER_2;
    input=saved.Length?saved.Buffer:&empty;
    utf8_mbstowcs_size(input,saved.Length,&units);
    total=(units+1)*sizeof(WCHAR);
    if(total>0xffff)return STATUS_INVALID_PARAMETER_2;
    destination->Length=(USHORT)(total-sizeof(WCHAR));
    if(allocate) {
        destination->MaximumLength=(USHORT)total;
        destination->Buffer=RtlAllocateHeap(ShzProcessHeap(),0,total);
        if(!destination->Buffer)return STATUS_NO_MEMORY;
    } else {
        uintptr_t from=(uintptr_t)input,to=(uintptr_t)destination->Buffer;
        if(total>destination->MaximumLength)return STATUS_BUFFER_OVERFLOW;
        if(!destination->Buffer)return STATUS_INVALID_PARAMETER;
        /* Source and destination buffers may overlap; snapshot before widening. */
        if(saved.Length && ((to>=from && to-from<saved.Length) || (from>=to && from-to<total))) {
            snapshot=RtlAllocateHeap(ShzProcessHeap(),0,saved.Length);
            if(!snapshot)return STATUS_NO_MEMORY;
            for(unsigned i=0;i<saved.Length;++i)snapshot[i]=input[i];
            input=snapshot;
        }
    }
    utf8_mbstowcs(destination->Buffer,units,&written,input,saved.Length);
    destination->Buffer[units]=0;
    if(snapshot)RtlFreeHeap(ShzProcessHeap(),0,snapshot);
    return STATUS_SUCCESS;
}
