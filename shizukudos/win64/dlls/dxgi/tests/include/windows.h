/* SPDX-License-Identifier: GPL-2.0-only
 * Narrow host test ABI fixture; production uses mingw-w64 Windows headers.
 */
#ifndef SHZ_DXGI_HOST_WINDOWS_H
#define SHZ_DXGI_HOST_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
typedef int32_t HRESULT;
typedef uint32_t UINT;
typedef struct { uint32_t Data1; uint16_t Data2, Data3; uint8_t Data4[8]; } GUID;
typedef const GUID *REFIID;
#define WINAPI
#define DLLAPI
#define DXGI_ERROR_INVALID_CALL ((HRESULT)0x887a0001u)
#define DXGI_ERROR_UNSUPPORTED ((HRESULT)0x887a0004u)
#define FAILED(hr) ((HRESULT)(hr) < 0)
#endif
