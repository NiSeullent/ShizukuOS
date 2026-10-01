# DirectX·Direct2D·DirectWrite 구현과 실제 검증 상태

2026-10-01 사용자의 요구를 [전체 필수 그래픽 목록](../benchmarks/modern-graphics-requirements-6970.json)에
추가했다. DirectDraw, Direct3D 9·10·10.1·11·12, DXGI, Direct2D,
DirectWrite를 모두 유지한다. 입력·오디오 계열도 같은 요구 목록에 남긴다.
아래 결과는 전체 API·COM 인터페이스 지원율이나 현대 앱 동작 완료가 아니다.

## 실제 입력과 현재 기능 경계

6970의 실제 기본 부팅 아카이브는 SHA-256
`2f3a3facad9f15187ed33e37088082afa3f8c5df2a7e00f4ef42e1af503e16f0`다.
멤버 141개 중 `SHZ\SYS64` DLL 43개를 별도로 고정해 조사했다.
빌드 디렉터리에는 추가 DLL이 있으므로 두 입력을 혼동하지 않는다.
실제 아카이브에는 `DWRITE.DLL`이 있지만 `DDRAW`, `D3D9`, `D3D10`,
`D3D10_1`, `D3D11`, `D3D12`, `DXGI`, `D2D1`이 없다. 이 관찰은
독립 Kernel64 아카이브에 관한 것이며, 원래 Windows 98의 구형 라이브러리
존재·동작을 판정한 결과가 아니다.

| 계열 | 확인한 구현·입력 | 완료에 필요한 실제 동작 |
| --- | --- | --- |
| DirectDraw | `ntwddm`에는 원래 소프트웨어 표면·복사·발행 core가 있다. 현대 COM runtime은 해당 아카이브에 없다. | COM 표면·lock·clip·flip, lost-surface 복원, native display bridge와 실제 화면 |
| D3D9 | 실제 AMD64 아카이브에 DLL 없음. Wine 계열 포팅은 공통 winsys와 shader/resource backend가 필요하다. | 정직한 장치 caps, shader/indexed draw, texture·buffer·reset·present·정리 |
| D3D10·10.1 | 실제 아카이브에 DLL 없음. DXGI 장치·표면·실제 shader pipeline도 미제공이다. | 장치·views·state·shader·렌더·readback·오류·해제 |
| D3D11 | ONLYOFFICE Qt5Gui의 일반 import가 실제 앱 생성 전에 실패했다. 이번 private resource core는 D3D11 COM device가 아니다. | 실제 `D3D11CreateDevice`·context·DXBC 처리·texture/view/buffer·render·DXGI present·Office 편집 |
| D3D12 | 실제 DLL과 Vulkan device backend·DXIL/명령 실행 경로 없음 | 장치·descriptor·command list·queue·barrier·fence·실제 draw/compute·동기화 |
| DXGI | cb43의 새 DXGI 후보는 명시적 `DXGI_ERROR_UNSUPPORTED` 반환 실험이다. 기본 아카이브에는 그 후보도 없다. | 실제 factory·adapter/output·swap chain·present/resize·mode·오류 계약 |
| Direct2D | 실제 `D2D1.DLL` 없음. 기존 테마 painter·private 삼각형은 Direct2D가 아니다. | 실제 factory·render target·path/stroke/gradient·transform/clip/alpha·bitmap·text·정리 |
| DirectWrite | Wine 11.0 + FreeType 2.13.3 포팅 DLL이 실제 아카이브에 포함된다. 이름 하나의 존재를 전체 텍스트 성공으로 세지 않는다. | 실제 font/fallback·한글/Latin/복잡 문자의 layout·glyph metrics·bitmap raster·수명·visible output |
| DirectInput·XInput·DirectSound·XAudio2·X3DAudio | 전체 필수 목록 유지. 이번 private graphics core가 입력/음성 backend를 제공하지는 않는다. | 실제 장치·events·buffer/stream·callback·mix/spatial·disconnect·정리 |

DirectWrite의 실제 export는 `DWriteCreateFactory` 서수 1이다. 해당 DLL은
ADVAPI32·GDI32·KERNEL32·NTDLL·USER32에 각각 7·12·63·7·4개 import를
사용한다. cb43의 `wineport/modules.json`은 Wine 소스를 정적으로 FreeType과
연결하고, `tests/dwrite/factory.c`는 font collection·glyph metric·text layout·
실제 glyph-run alpha bitmap을 시험하도록 작성되어 있다. 새 독립 DirectWrite
게스트 검증은 별도 에이전트가 소유한다. 기존 source 시험의 존재를 새 실제
게스트 성공으로 바꾸지 않았다.

## 이번에 구현한 실제 공통 기반

[graphics_backend](../ntwddm/graphics_backend/README.md)는 원래 resource
소유권·binding·mapping 구현과 동료 5abe의 진짜 Mesa 26.2.3 TGSI/raster
포팅을 연결한다. 실제 shader 해석과 pixels를 유지하며 allocator·해제·
depth·색 복사·독립 readback을 하나의 64비트 컴포넌트에 묶었다.

* RGBA8/D32 실소유 버퍼, 전역 단조 cookie, device별 stale/foreign handle 거부
* exclusive map, map 중 사용/최종해제/파괴 거부, 별도의 binding reference
* 실제 clear·copy와 transactional triangle render, 실패 시 pixels/statistics 보존
* 정상 caller와 각 중첩 heap/math callback의 x87/MXCSR 저장·masked 실행·복원
* 64×64 이하, mip/layer/sample 각각 1인 명시적 profile. 다른 요청은 할당 전 실패

`NTG_TEXTURE_MEMORY_LIMIT` 2 MiB는 **device별 texture 저장 공간만** 제한한다.
shader context는 별도 4 MiB/context·전역 최대 16개, scratch는 draw당 최대
32 KiB다. 하드웨어 가속, D3D feature level, sampler/texture shader,
full Gallium·OpenGL/Vulkan, DXBC/DXIL, COM ABI, DXGI swap chain을 제공했다고
판정하지 않는다. 최종 DLL 이름도 `NTGSW.DLL`, export 14개도 private
`ntg_*`다. 성공하는 빈 `D3D11CreateDevice`나 가짜 adapter를 추가하지 않았다.

## 수정본의 고정 증거

초기 v1/v2 host/PE 결과는 보존했다. 독립 검토에서 raster 상태 코드 영역,
FP scope 전 subnormal 비교, nested provider FP 상태, probe mapping layout과
정리 순서 문제를 확인했으므로 게스트에 실행하지 않았다. 이를 수정한 새 v3는
다음과 같다.

| 검증 | 실제 결과 |
| --- | --- |
| 정상 host + ASan/UBSan | 각각 **1,714** assertions PASS |
| 의미 있는 회귀 | 진짜 Mesa varying/constant/SQRT pixels, depth·padding, stale/foreign/mapped 수명, binding retain, scratch·shader NOMEM, 실제 비유한 shader output 오류와 stats 보존 |
| FP 회귀 | unmasked subnormal MXCSR, BUSY/error 경로, allocation/math rounding·exception drift 격리와 실제 SQRT 결과 |
| DLL | AMD64 PE32+, 실제 실행 section의 private export 14개, OS/CRT import 0개, parsed DIR64 relocations |
| DLL SHA-256 | `09bf19fa09c994d6aca6110c024faa93a0f5d2b2835928b69db96cd2b76e6829` |
| v3 receipt SHA-256 | `f2503ebaef06403ef27a0fb44b7953a8bfa7e8bfc09ce3cfd965addec1253fe6` |
| 새 guest gate 시험 | 잘못된 PID/nonce·partial/timeout/fault/exit/proc_wait·누락 정리·단일 화면 pixel 오류 등을 거부하는 **23** tests PASS |

v3 경로는 `ntwddm/graphics_backend/build/mesa-resources-amd64-v3`다.
고정된 Windows ABI probe를 새 nonce
`678d07d78db948b98e9110f98d690383`로 실제 별도 Kernel64 게스트에서
실행했다. `build/graphics-mesa-run-v1/graphics-acceptance.json`은 **PASS**다.
실제 child PID 60의 **66** 검증, 32×32 triangle **496** samples,
독립 RGBA **4,096** bytes, depth/padding 및 모든 allocator block 해제가
통과했다. 실제 창에서 GetPixel **16,384** pixels를 확인하고, 별도 QEMU
framebuffer rectangle `[114,133,242,261]`의 **16,384** pixels도 독립 계산과
일치했다. root 에이전트가 최종 receipt와 화면을 다시 확인했다.

child는 정상 exit 0으로 끝났고, kernel의 원래 `proc_wait` 반환도 0으로
정상 회수됐다. QEMU의 실제 host 반환 1은 별도로 보존했다. 고정된
`standalone_dev.h`의 ISA-debug-exit 계약과 실제 `SHZ-EXIT:0`에 따라
guest 0의 인코딩임을 검증했으며 child 반환과 혼동하지 않았다.
QEMU PID 3298630의 `/dev/kvm`, VM 및 vCPU fd를 확인했고 실제 명령에는
NIC이 없었다. 모든 원본·sealed 입력이 유지됐고 시험 VM은 종료됐다.
최저 디스크 여유는 **25,298,604,032 bytes**, 최대 guest 쓰기는
**2,578,260 bytes**로 원래 20 GiB·256 MiB·16 MiB 제한을 지켰다.

| 고정 증거 | SHA-256 |
| --- | --- |
| `build/graphics-mesa-run-v1/graphics-acceptance.json` | `f3c69d1ca3360ec8c983ad54aa164624c8be781cb8a14d4500834e75730b09c9` |
| `build/graphics-mesa-run-v1/theme-screen.png` | `f0e7d8d74289f6d9d3d307b6253b5a952b4e901c65b0f9a0abd5738c0d219cb2` |
| `build/graphics-mesa-run-v1/theme-screen.ppm` | `b8864ec354034225998072dc9d4581dcaa0052fbfef839bd7d32bf7dfa535353` |
| `build/graphics-mesa-run-v1/serial.log` | `cf0d1425c650319c3d7abe2c5cb3a387c1f0d58276c39c1d1293ca9d609e4721` |
| `build/graphics-mesa-prep-v2/prepared.json` | `dd811fe7d511240f6a92d1b22c43dc5b80d957db9d4f5927c9f960d86d938cf6` |

이는 private Mesa resource/rendering과 실제 화면 pixels의 게스트 성공이다.
모든 DirectX/Direct2D/전체 DirectWrite·native Windows 98·Office 기능 완료
flags는 여전히 false다. 작은 tracked [handoff](../ntwddm/graphics_backend/handoff.json)는
원래 소스·upstream receipt·실제 결과 경로를 연결하며, 바이너리·disk·화면은
Git 밖의 위 private 증거 디렉터리에 보존한다.

## 소스와 upstream 적용 방향

새 resource/FP/시험/빌드/게스트 consumer는 GPL-2.0-only 원래 프로젝트 코드다.
Mesa 공식 archive
`1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f`에서
검토된 원본 49개·prepared 7개 및 모든 해당 license를 고정·복사하고, 동료
source에 쓰지 않는다. upstream MIT·SoftFloat BSD·BSL 등의 notices를
유지한다. peer recipe는 읽고 검증하며 실행하지 않았다.

다음 runtime port는 단순 DLL 포장이 아니다. Wine D3D11의
[실제 생성 코드](https://raw.githubusercontent.com/wine-mirror/wine/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/d3d11/d3d11_main.c)는
DXGI factory·adapter·device layer를 거쳐 실제 backend device를 요구한다.
이를 private typed TGSI profile만으로 지원한 feature level이라고 선언할 수
없다. Wine/ReactOS resource 수명 코드는 검토했지만 복사하지 않았다.
[Microsoft resource 계약](https://learn.microsoft.com/en-us/windows/win32/direct3d11/overviews-direct3d-11-resources)과
[D3D11 장치 계약](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/nf-d3d11-d3d11createdevice)을
실제 shader/resource/device 기능과 함께 이식해야 한다.

Direct2D의 D3D 연동은 [DXGI surface와 BGRA 장치 계약](https://learn.microsoft.com/en-us/windows/win32/direct2d/direct2d-and-direct3d-interoperation-overview)을
필요로 한다. Wine의 [고정 D2D build 의존성](https://raw.githubusercontent.com/wine-mirror/wine/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/d2d1/Makefile.in)도
별도 검토했다. DirectWrite/font/WIC·path·brush·text를 실제 렌더링에 연결하는
slice가 남아 있다. D3D12의 [vkd3d-proton](https://github.com/HansKristian-Work/vkd3d-proton)은
실제 Vulkan backend를 요구하므로, 동봉 SwiftShader DLL이나 Mesa 파일 이름만
존재하는 것으로 장치 실행을 대체할 수 없다. Mesa LLVMpipe 문서도
[실제 소프트웨어 driver/compiler 조건](https://docs.mesa3d.org/drivers/llvmpipe.html)을
구분한다. 현재 private scalar TGSI는 완전한 GL/Vulkan driver가 아니다.

## 다음 D3D11·DXGI 포팅의 구체적 경계

현재 cb43의 `build/shizukudos/win64/wineport/wineport-result.json`이 실제
컴파일한 Wine 모듈은 cryptbase·cryptsp·crypt32·rsaenh·dwrite·propsys·
dwmapi·imagehlp·wintrust·cryptnet이다. D3D11·DXGI·WineD3D·D2D1은
그 receipt에 없다. `build/upstream/wine` HEAD는 정확히
`db11d0fe6a169c457e23d007e20404643d067aa8`이며 COM/IDL 및 생성된
D3D11·DXGI headers는 있다. sparse 작업 트리의 D3D11·DXGI·WineD3D·D2D1
디렉터리는 생성된 Makefile만 남아 있으므로 실제 C 소스 checkout으로
간주하지 않는다. 다만 같은 고정 commit의 로컬 Git 객체에서 다음 원본을
읽을 수 있음을 확인했다. 별도의 새 slice에 원본 closure와 notices를
고정하는 데 네트워크 fetch나 peer sparse-checkout 변경은 필요하지 않다.

| 읽기만 한 Wine 원본 | SHA-256 |
| --- | --- |
| `dlls/d3d11/d3d11_main.c` | `73ab4450d70fcb7ebd4aa1c9ee185836f71ae3344e05a500ed4838e2f6ccedee` |
| `dlls/d3d11/device.c` | `1098b9cc387aeadd6b6ab7fe26fdccc99f2f40ad9292499573cba4322a510636` |
| `dlls/dxgi/dxgi_main.c` | `933632db94d03c8db6413adc2678706b81002ac44baea0b82b70d7922bd33a3d` |
| `dlls/dxgi/factory.c` | `fa4440e565a6723e73782a4d08f29b89bc98edcf460427029bacf64f3fcfea87` |
| `dlls/wined3d/wined3d_private.h` | `1a3bdaab5cc0b150f5a78063c5539f99173aea1d8c3887ec63d0a40ea180414a` |
| `libs/vkd3d/libs/vkd3d-shader/vkd3d_shader_main.c` | `fcf115a5355b1de0377ff196ae82fa2c97a177bcca66db169347fe5ea818d55a` |

Mesa 26.2.3의 실제 native 빌드 단위는 `tgsi_exec`, `tgsi_parse`,
`tgsi_build`, `tgsi_util`, `tgsi_info`, `half_float`, `softfloat`와 검토된
shader/raster glue다. full `pipe_screen`, `pipe_context`, Gallium winsys는
컴파일하지 않았다. 5abe의 고정 원본 audit tree에는 softpipe의
`sp_screen.c`, `sp_context.c`, `sp_texture.c`와 NIR 소스가 존재하지만,
`src/gallium/frontends/d3d10umd`, `nine`, `wgl`은 없다. 현대 Mesa archive에
이 이름의 frontend가 있다고 가정하지 않는다. Wine의 GL/Vulkan adapter
원본도 로컬 Git 객체에 있지만 현재 Kernel64에는 그 adapter가 요구하는
검증된 GL/Vulkan 장치·loader·winsys가 없다. 앱 동봉 Vulkan DLL은 장치
시험 결과를 대체하지 않는다.

다음 실제 작업은 네 가지 계약을 하나의 소스와 시험으로 연결해야 한다.

1. **winsys와 표시:** 실제 HWND/client 크기, BGRA/RGBA 표면, display 모드,
   clip·resize·파괴, present와 완료 동기화를 소유하는 소프트웨어 winsys를
   만든다. 이번 probe의 SetPixel은 화면 증거용 consumer이므로 DXGI
   swap chain이나 창 수명 bridge로 재분류하지 않는다. native Win98의
   32비트 표시 bridge는 독립 ABI와 실행 시험이 추가로 필요하다.
2. **실제 device와 COM:** Wine의 factory→adapter→device 연결에 실제
   backend 객체를 넣고 IUnknown identity, QueryInterface, AddRef/Release,
   device/context/resource/view 관계와 부분 실패 rollback을 검증한다.
   caps·format/feature-level 조회는 실제 pipeline 능력에서 계산한다.
   현재 64×64·단일 sample·affine triangle만으로 D3D feature level을
   선언할 수 없다. `D3D11CreateDevice`나 factory를 성공 반환만 하는
   shim으로 제공하지 않는다.
3. **자원과 pipeline:** D3D buffer/texture usages·CPU access·Map·Copy,
   BGRA 및 요청 format, views·samplers·입력 layout·index/vertex buffer,
   raster/depth/blend state와 draw 실행을 실제로 연결한다. 필요한 범위를
   실행한 뒤 readback, 재생성/resize와 마지막 reference 해제까지 확인한다.
   private texture storage 한도와 shader/scratch 한도를 각각 유지하거나
   정확한 새 예산으로 바꿔야 한다.
4. **앱 bytecode:** 실제 Qt/Electron이 사용하는 vertex/pixel DXBC를 읽고
   검증·변환·실행하는 backend가 필요하다. 현재 TGSI 입력만 받아들이는
   interpreter는 DXBC compiler가 아니다. 로컬 vkd3d-shader 원본은
   검토 가능한 후보이며, 그 출력 IR의 실제 실행 backend와 dependency
   closure도 함께 포팅해야 한다. 이름만 연결해 DXBC→TGSI가 생겼다고
   판정하지 않는다. 실제 texture sampling·interpolation·shader stage
   동작을 보장하는 범위까지 확대하기 전 앱 device 성공 flag는 false다.

이 계약을 통과한 뒤 실제 `D3D11CreateDevice`·DXGI swap chain으로 생성한
resource를 렌더하고, Map/Copy readback과 독립 화면 pixels·normal exit를
확인하는 새 host/PE/guest slice를 고정한다. 그 결과가 실제 Office retry의
그래픽 선행 조건이다. Qt/CEF/CRT·테마의 다른 import 실패도 해소되어야
Office 앱 자체의 편집·저장 판정에 들어갈 수 있다. 모든 계열은 맨 위의
전체 요구 manifest를 그대로 유지하며 이 선행 slice만으로 완료하지 않는다.

## 현대 앱과 OS 통합에서 남은 실제 실패

ONLYOFFICE 9.4.0 x64 기본·Modern 실제 시험은 모두 앱 생성 전에
`qt5gui.dll needs d3d11.dll!D3D11CreateDevice: DLL not found [c0000135]`로
실패했다. 이번 private core는 그 이름을 제공하지 않으며 Office 성공으로
세지 않는다. DXGI, Qt·CEF·MSVCP140·테마의 별도 의존성도
[고정 앱 실패 분석](REQUIRED_APPS_RUNTIME_GAPS_6970.md)에 남아 있다.
Signal/Legcord 실행·메시지·통화, DOCX/XLSX/PPTX 생성·편집·저장·재열기와
native Windows 98 execution bridge도 각각 실제 게스트 검증이 필요하다.

기존 Windows 98 부팅과 테마 startup 시험은 소유 에이전트의 lane을 그대로
유지한다. 이번 컴포넌트는 source/기존 archive·원본 disk·발행자 corpus를
보존하며 private runtime/input/firmware와 own QMP만 사용한다. 저장소의
20 GiB reserve, 256 MiB guest write, 16 MiB host output 제한을 낮추지 않는다.

## Root independent stopped-trial audit

Root independently reparsed the actual child/nonce/lifetime evidence, rehashed
all original and sealed runtime/firmware inputs, verified the owned QEMU PID
was absent and all resource gates held, and checked all 16,384 actual captured
framebuffer pixels against an independently calculated barycentric color
oracle. `build/graphics-root-audit-v1/audit.json` is PASS, SHA-256
`f8398d9890dfd2be8ed569eb71b6ab2276c83215799b36fcf97bf6fed9e0f4d0`. This reuses no generated
expected screenshot and leaves the stopped evidence unchanged. Full DirectX,
native Windows 98 and application functionality remain separate false flags.
