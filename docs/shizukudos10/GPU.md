# ShizukuDOS 10.0 — GPU (그래픽 가속)

기준 시각 2026-09-29. 대상: Kernel64 **standalone 프로파일**(QEMU `-kernel` 스텁으로 부팅, Supervisor 없음).
증거 종류는 BASELINE/STATUS와 같다: `SOURCE` · `BUILT` · `HOST_TESTED` · `GUEST_RUN` · `HARDWARE` · `USER_REPORTED`,
그리고 실행하지 못한 항목은 `BLOCKED`(이유와 필요한 환경을 적는다). 이 세션의 환경: KVM 없는 클라우드 컨테이너,
Ubuntu 24.04, **QEMU 8.2.2 TCG**(`1:8.2.2+ds-0ubuntu1.18`), libvirglrenderer1 1.0.0, Mesa 25.2.8(llvmpipe), GPU 없음,
`/dev/dri` 없음.

## 1. 결론

- 이 시스템에서 "실제 그래픽 가속"이 가능한 유일한 경로는 **반가상화 virtio-gpu**다. Kernel64에는 실제 GPU(Intel/AMD/NVIDIA)
  드라이버가 없고, 만들 계획도 이 문서에는 없다.
- **2D(virtio-gpu 2D)**: 구현·게스트 실행으로 검증됨(`GUEST_RUN`, TCG). 바탕 화면은 호스트 쪽 리소스이고, 게스트는 바뀐 사각형만
  `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH`로 보낸다. 그리기 자체(GDI)는 여전히 **게스트 CPU**가 한다. 즉 2D는 "가속된 그리기"가
  아니라 "복사량을 줄인 표시 경로 + 하드웨어 커서 평면"이다.
- **3D(virgl)**: 게스트 쪽 전체 경로(기능 협상, 컨텍스트, 3D 리소스, `SUBMIT_3D`, `TRANSFER_FROM_HOST_3D`, 사용자 모드 API,
  손으로 인코딩한 virgl 명령 스트림)는 **작성됨**(`BUILT`). 명령 스트림은 호스트의 virglrenderer 1.0.0이 **실제로 실행**해
  삼각형을 그렸다(`HOST_TESTED`, Mesa llvmpipe). 그러나 **게스트 → QEMU → virglrenderer 종단 실행은 `BLOCKED`**:
  QEMU의 GL 디스플레이가 DRM render node를 요구하는데 이 호스트에는 없다(3절).
- **없는 것**: Direct3D 11/DXGI, OpenGL ICD(`opengl32.dll`/WGL), Vulkan ICD. Windows 프로그램은 GPU를 쓸 수 없다.
  `shzgpu.dll`은 Shizuku 전용 API이며 Windows API 호환을 주장하지 않는다(5절 로드맵).
- Supervisor 프로파일(실제 제품 경로)에는 디스플레이 장치가 전달되지 않으므로 GUI·GPU 호출은 전부 `STATUS_NO_SUCH_DEVICE`다.

## 2. 무엇이 가속되고 무엇이 아닌가

| 기능 | Bochs VBE 백엔드 (`-vga std`) | virtio-gpu 2D (`-device virtio-vga`) | virtio-gpu + virgl (`virtio-vga-gl`) |
| --- | --- | --- | --- |
| GDI 그리기(선, 사각형, 글꼴, BitBlt) | 게스트 CPU | 게스트 CPU | 게스트 CPU (GDI는 virgl을 쓰지 않음) |
| 화면 갱신 | CPU가 바뀐 사각형을 LFB(uncached)로 복사 | 바뀐 사각형만 전송 + flush, 호스트가 표시 | 동일 |
| 하드웨어 커서 | 없음 (`STATUS_NOT_SUPPORTED`) | 있음: 64x64 ARGB, 별도 평면 | 동일 |
| EDID / 표시 모드 정보 | 없음 | `GET_EDID`, `GET_DISPLAY_INFO` | 동일 |
| 3D 렌더링 | 없음 | 없음 (VIRGL 미협상, `STATUS_NOT_SUPPORTED`) | **호스트 GPU 드라이버가 실행** (virgl → GLSL → 호스트 GL) — 종단 실행 `BLOCKED` |
| D3D / OpenGL / Vulkan | 없음 | 없음 | 없음 (5절) |

## 3. 검증한 것 (재현 명령과 결과)

빌드: `python3 shizukudos/kbuild.py && python3 shizukudos/win64/build.py` (`BUILT`, `-Werror`, 두 커널 프로파일 모두).

| 검증 | 증거 | 결과 |
| --- | --- | --- |
| `shizukudos/tests/test_virtio_host.py`: split virtqueue 모델(`virtq.c`)을 시뮬레이션 장치로 | HOST_TESTED (ASan/UBSan) | 2,885,583 검사 PASS (65536 인덱스 wrap 포함) |
| 같은 스크립트: `kernel64/virtio_gpu.h`(명세에서 작성) vs 호스트 `<linux/virtio_gpu.h>` 코드·크기·오프셋 | HOST_TESTED | 91 검사 PASS |
| 같은 스크립트: `shzvirgl.h` 인코더 상수·패킷 배치를 고정한 virglrenderer 1.0.0 `virgl_protocol.h`/`virgl_hw.h`로 디코드 | HOST_TESTED (ASan/UBSan) | 334 검사 PASS |
| 같은 스크립트: **같은 스트림을 호스트 libvirglrenderer 1.0.0 + Mesa llvmpipe(EGL surfaceless)가 실행**, 결과 픽셀 판독 | HOST_TESTED | 64x64 중 1,291 픽셀이 무게중심 보간 색(±2/255), 2,799 픽셀이 지운 색, 모서리 6 픽셀 비교 제외. 잘못된 길이의 `DRAW_VBO`는 거부됨 |
| `run_k64_gui.py --display vga` | GUEST_RUN (TCG) | PASS, 58 검사, 15개 장면 전부 픽셀 일치 |
| `run_k64_gui.py --display virtio` | GUEST_RUN (TCG) | PASS, 63 검사. **15개 장면 전부 vga와 같은 기대 화면에 픽셀 단위로 일치** |
| virtio: 32x16 무효화 1회의 트래픽 (T_GPU_2D 커널 카운터) | GUEST_RUN | present 1회, 512 픽셀, `TRANSFER_TO_HOST_2D` 1회 2048 바이트, `RESOURCE_FLUSH` 1회 |
| 같은 구간의 QEMU 자체 기록 (`-trace virtio_gpu_*`, 두 표지에서 VM 정지 중 오프셋 기록) | GUEST_RUN | 바탕 리소스에 transfer 1회, flush 1회 `w 32, h 16, x 344, y 263` — 게스트 계수와 일치 |
| 실행 전체의 바탕 화면 갱신 | GUEST_RUN | transfer 981회 중 전체 화면(1024x768)은 3회(초기화, 테스트 패턴, 그 뒤 재합성) |
| 하드웨어 커서 | GUEST_RUN | QEMU 기록: `update x 700 y 300 res 0x2`, `move x 720 y 310`, `update res 0x0`(숨김). 커서 **이미지**는 픽셀로 검증하지 않았다 (QEMU `screendump`는 커서 평면을 포함하지 않음) |
| EDID·모드 | GUEST_RUN | EDID 1024 바이트, 헤더·체크섬 유효, 제조사 `RHT`, 선호 모드 1024x768 = QEMU에 준 `xres/yres`; `GET_DISPLAY_INFO`도 1024x768 |
| 인터럽트 | GUEST_RUN | INTx(IRQ 10, PIC)로 완료 통지. 선이 다른 드라이버 것이면 폴링으로 전환(코드 경로, 이 실행에서는 발생 안 함) |
| T_GPU_3D, VIRGL 없음(vga·virtio) | GUEST_RUN | 모든 3D 호출이 `STATUS_NOT_SUPPORTED`로 거부됨을 확인 (3D 경로 자체의 검증이 아님) |
| `run_k64_standalone.py` (디스플레이 없음) 2회 | GUEST_RUN | 2회 PASS. T_GPU_2D/3D는 `SKIP: no display device` 후 종료 코드 0 |
| `run_k64_gui.py --display virtio-gl` | **BLOCKED** | QEMU: `egl: no drm render node available` / `egl: render node init failed`. 러너는 PASS가 아니라 BLOCKED(종료 코드 2)를 보고한다 |

`shz.py test --suite win64`가 위 호스트 테스트와 vga/virtio GUI 실행, virtio-gl(PASS/BLOCKED/FAIL 구분)을 실행한다.

### 3D 종단 실행에 필요한 호스트 (`BLOCKED` 해제 조건)

- Linux 호스트에 **DRM render node**(`/dev/dri/renderD128` 등)와 그 장치용 Mesa 드라이버: Intel(iris), AMD(radeonsi),
  NVIDIA(nouveau 또는 독점 드라이버의 GBM/EGL), 또는 중첩 가상화라면 바깥 virtio-gpu(virgl). 컨테이너라면 그 노드를 넘겨 줘야 한다.
- virglrenderer와 OpenGL을 켠 QEMU (Ubuntu: `qemu-system-x86` + `hw-display-virtio-gpu-gl`/`ui-egl-headless` 모듈 — 이 호스트에 설치돼 있음).
- 명령: `python3 shizukudos/tests/run_k64_gui.py --display virtio-gl` → T_GPU_3D가 `GPU-3D: triangle verified`를 내야 PASS.
- 이 호스트에서 확인한 사실: virglrenderer 자체는 GPU 없이도 llvmpipe(EGL surfaceless)로 동작한다(위 호스트 실행 테스트).
  막힌 것은 QEMU 8.2의 `egl-headless`가 render node를 통한 GBM만 쓴다는 점이다. llvmpipe로 3D 종단을 돌려도 그것은
  **CPU 래스터화**이므로 "GPU 가속"의 증거가 되지 않는다는 점도 밝혀 둔다.
- 실제 하드웨어(`HARDWARE`)에서는 어떤 경로도 실행하지 않았다.

## 4. 구조

```
Win64 앱 ──user32/gdi32──► NtGdiPresent ──► gfx_wm.c 합성기 ──► gfx_fb_present(rect)
                                                                   │  (gfx_fb.c: 단 하나의 백엔드 훅)
         ┌─────────────────────────────────────────────────────────┴───────────────┐
         ▼                                                                         ▼
  Bochs VBE: rep movs → LFB                     gfx_virtio.c: TRANSFER_TO_HOST_2D(rect) + RESOURCE_FLUSH(rect)
                                                                   │
Win64 앱 ──shzgpu.dll──► NtShzGpu* (0xd0-0xd9) ──► gpu_sys.c ──► gfx_virtio.c (EDID, 커서, capset, CTX/3D 리소스/SUBMIT_3D/전송)
                 ▲                                                 │
           shzvirgl.h (virgl 스트림 인코더)                          ▼
                                       virtio_pci.c (modern 전송: capability, 기능 협상, split virtqueue, INTx/폴링)
                                                                   │  virtq.c (링 모델, 호스트에서도 동일 코드로 테스트)
                                                                   ▼
                              QEMU virtio-gpu ──► 2D: pixman 리소스/스캔아웃  3D: virglrenderer ──► 호스트 GL ──► GPU
```

- 백엔드 선택: `gfx_fb.c`의 표 `{virtio-gpu, Bochs VBE}`를 순서대로 시도한다. virtio-gpu가 있으면(QEMU `-device virtio-vga`)
  그것을, 없으면 BGA를 쓴다. 모드(1024x768x32)와 백 버퍼는 공통이다.
- virtio-gpu 바탕 화면: `RESOURCE_CREATE_2D`(B8G8R8X8)의 게스트 백킹이 **합성기의 백 버퍼 그 자체**이고(`ATTACH_BACKING`,
  물리 연속 구간으로 합침) 스캔아웃 0에 연결된다. present는 두 명령을 한 번의 doorbell로 보내고 두 응답을 모두 받은 뒤 반환하므로,
  반환 시점에 그 사각형은 호스트 화면에 있다.
- 명령 엔진: 요청/작은 응답은 DMA 슬롯 페이지 4개로 반송, 큰 데이터(백킹 목록, 3D 스트림, capset)는 추가 디스크립터로 전달.
  모든 장치 접근은 한 뮤텍스로 직렬화된다. 5초 안에 응답이 없으면 장치를 비활성화한다(링이 슬롯을 계속 가리키므로 재사용하지 않음).
- 3D 객체 소유권: 컨텍스트와 리소스는 만든 프로세스만 쓰고 지울 수 있다. 죽은 프로세스의 것은 다음 GPU 시스템 호출 때 회수한다.
  장치에 넘기는 메모리는 모두 커널 메모리다(사용자 페이지를 장치에 주지 않음).

### 시스템 호출과 `shzgpu.dll` (`win64/include/shzgpu.h`에 문서화)

| 호출 | 번호 | `shzgpu.dll` | 설명 |
| --- | --- | --- | --- |
| `NtShzGpuQuery` | 0xd0 | `ShzGpuQuery` | 백엔드, 기능 비트, 모드, EDID 요약, capset, virtio 기능 비트, 통계 |
| `NtShzGpuEdid` | 0xd1 | `ShzGpuGetEdid` | 스캔아웃 0의 EDID |
| `NtShzGpuCursor` | 0xd2 | `ShzGpuSetCursor/MoveCursor/HideCursor` | 하드웨어 커서 |
| `NtShzGpuCapset` | 0xd3 | `ShzGpuGetCapset` | 호스트 capset (virgl `virgl_caps_v1/v2`) |
| `NtShzGpuCtxCreate/CtxDestroy` | 0xd4/0xd5 | `ShzGpuCreateContext/DestroyContext` | virgl 컨텍스트 |
| `NtShzGpuResourceCreate/Destroy` | 0xd6/0xd7 | `ShzGpuCreateResource/DestroyResource` | `RESOURCE_CREATE_3D` + 백킹 + 컨텍스트 연결 (버퍼, 32비트 2D 텍스처) |
| `NtShzGpuSubmit` | 0xd8 | `ShzGpuSubmit` | `SUBMIT_3D` (fence: 호스트가 끝낸 뒤 응답) |
| `NtShzGpuTransfer` | 0xd9 | `ShzGpuReadback/Upload` | `TRANSFER_FROM/TO_HOST_3D` |

`shzvirgl.h`의 인코더가 다루는 것: surface, framebuffer, blend/DSA/rasterizer, TGSI **텍스트** 셰이더(virgl이 전송하는 형식;
호스트가 GLSL로 변환), vertex elements/buffers, inline write, viewport, clear, 비인덱스 draw. 텍스처 샘플링, 쿼리, streamout,
compute, 인덱스 draw는 없다.

## 5. 없는 것과 앞으로의 경로 (ICD 로드맵)

현재 Windows 프로그램이 GPU를 쓸 방법은 없다. 제안하는 순서와 대략의 노력(추정이며 측정값이 아님):

1. **OpenGL ICD (`opengl32.dll` + WGL) over virgl** — 가장 짧은 길.
   Mesa(MIT)에는 이미 Windows용 WGL 프런트엔드(`src/gallium/frontends/wgl`, `targets/libgl-gdi`)와 virgl Gallium 드라이버
   (`src/gallium/drivers/virgl`), GLSL 컴파일러(`src/compiler/glsl`, MIT)와 NIR→TGSI가 있다. 필요한 새 코드는
   **Shizuku용 virgl winsys**(리소스 생성, 전송, 제출, fence 대기를 `shzgpu.dll` 위에 구현; Mesa의 기존 winsys는 DRM과 vtest뿐)와
   SwapBuffers를 창 표면/스캔아웃에 연결하는 부분이다.
   선행 조건: Mesa가 링크하는 C 런타임(현재 테스트용 `shzcrt`뿐 — msvcrt/UCRT 호환 CRT 필요), Win32 스레드·TLS·동기화의 충분한
   구현, 커널 쪽 fence를 기다릴 수 있는 객체와 GPU 메모리 계정. 노력: 수 인월(Mesa 포팅·CRT가 대부분), 커널 쪽 수 주.
2. **Direct3D 11/DXGI** — (a) WineD3D(LGPL-2.1, D3D→GL)를 1 위에, 또는 (b) DXVK(zlib, D3D→Vulkan)를 3 위에.
   DXGI 스왑체인은 창 합성기와의 연동이 추가로 필요하다. 노력: 1 또는 3 완료 후 수 인월.
3. **Vulkan ICD** — Mesa **Venus**(MIT, Vulkan을 virtio-gpu로 직렬화) 드라이버. 커널에 `VIRTIO_GPU_F_CONTEXT_INIT`(Venus
   컨텍스트 타입), `VIRTIO_GPU_F_RESOURCE_BLOB`, virtio-pci 공유 메모리 영역(호스트 가시 메모리 매핑)이 필요하고, 호스트에는
   Vulkan 드라이버와 Venus를 지원하는 QEMU(9.2 이상)가 필요하다. 모두 현재 없음. 노력: 커널 수 주 + Mesa 포팅(1과 공유).

어느 경로도 **호스트 GPU가 있어야** 실제로 가속된다. GPU 없는 호스트에서는 llvmpipe(CPU)로 기능 검증만 가능하다.

## 6. 알려진 한계

- 스캔아웃 1개, 모드 고정(1024x768). 디스플레이 변경 이벤트는 세기만 한다. blob 리소스, 컨텍스트 타입, MSI-X, 간접
  디스크립터, `EVENT_IDX` 없음.
- 3D 리소스는 버퍼와 32비트 2D 텍스처만, 백킹 최대 16 MiB, 스트림 최대 256 KiB/제출.
- QEMU가 잘못된 3D 스트림을 게스트에 오류로 돌려주는지는 버전에 따라 다르다. 거부 동작은 호스트 테스트로만 확인했다.
- virtio-gpu와 NIC가 같은 INTx 선을 쓰면 virtio-gpu는 인터럽트 없이 폴링한다(벡터당 처리기 1개, 연결 체인 없음).
