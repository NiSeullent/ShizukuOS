# ShizukuOS 전체 구현과 승인 기준

최상위 플랫폼은 ShizukuOS이며 ShizukuOS Core가 공통 기반입니다.
[Absolute Architecture Definition](SHIZUKUOS_ARCHITECTURE_CONTRACT.md)이 시스템
구성과 최종 성공을 정의합니다. 이 문서는 그 정의와 기존 사용자 요구를 실제
검증 항목으로 연결하며 어느 항목도 통과했다고 선언하지 않습니다.

완료에는 실제 ShizukuOS 안에서 실행되는 production caller/provider/build 경로와
그 실행 증거가 필요합니다. 증거는 소스·산출물·환경·입력·결과·정상 종료·회수를
같은 실행에 연결합니다. 호스트 모델, 정적 임포트 검사, 사진, placeholder,
부팅 자체는 개발 증거이며 기능 완료를 대신하지 않습니다.

## 기존 사용자 요구의 통합 승인

| 요구 | 재사용할 구현과 실제 ShizukuOS 승인 증거 |
| --- | --- |
| 1. 공통 현대 드라이버 골격과 기본 드라이버 | `drivers/common/`, `kernel64/ntdrv*`, 기존 자원 관리와 graphics/storage/net/input. 선언한 지원 장치별 discovery, resource ownership, PnP/power, 실제 요청/전송/완료/해제를 관찰합니다. Native·Legacy·Wrapped 계층을 재사용합니다. |
| 2. 노트북 센서·트랙패드·전원·ACPI | `drivers/shz_laptop/`와 Kernel64 laptop 제공자. 실제 펌웨어/장치의 키보드·포인터·센서·배터리/AC·suspend/resume·권한 회수를 확인합니다. parser나 mocked transport만으로 승인하지 않습니다. |
| 3. 다른 세션과 협업 | 기존 비공개 조정 mailbox와 분리 작업 공간을 사용합니다. source/index/VM/media 소유자를 지키고 정확한 변경·실제 검사·실패를 인계합니다. 비공개 메모를 커밋하지 않습니다. |
| 4. 사용자 계정 분리 | `accounts/`, `sysk32_auth.c`. 보호된 지속형 등록·로그인·서로 다른 subject/profile/session과 재부팅·계정 전환·실패·교차 계정 접근 거부를 실제 셸에서 확인합니다. |
| 5. elevate 명령 | `win64/apps/elevate/`. 정확한 실행 파일/명령에 인증하고 새 elevated child를 만듭니다. parent와 기존 handle 권한은 증가하지 않습니다. 실패·취소·만료·성공을 실제 시스템에서 검증합니다. |
| 6. 권한과 샌드박싱 | process/token/object/file/mapping/async 요청을 실제 service authority에서 제한합니다. 축소 권한 handle, 금지 장치/파일/network, privileged handle 재획득과 shared-state 변경을 검증합니다. |
| 7. 자체 셸 고도화와 배경화면 | `win64/apps/shizuku_shell/`과 기존 GUI/file/theme 제공자. desktop/taskbar/start/explorer/settings를 실제 실행합니다. 애니메이션·static fallback·pause·배터리·suspend·close와 실패 처리를 확인합니다. |
| 8. 설정·elevate 인증·등록 | per-user 지속 설정과 authenticated subject를 연결합니다. 등록 권한·실패 throttling·secret clearing·reboot persistence와 실패 시 부작용 부재를 확인합니다. masking UI만으로 인증을 승인하지 않습니다. |
| 9. 보안 강화 | 실제 threat boundary를 선언합니다. unauthorized/malformed/stale/reused identity와 publication 도중 실패를 검증합니다. 선택적 legacy shared-address-space 프로필에는 구현되지 않은 격리를 주장하지 않습니다. |
| 10. Core 격리 | worker address space, memory, IRQ/resource/DMA와 fault completion을 실제로 확인합니다. CPU affinity나 별도 core에 있다는 사실만으로 격리를 승인하지 않습니다. |
| 11. 멀티에이전트·독립 worker | 개발 에이전트와 OS runtime worker를 구분합니다. runtime 기능에는 독립 주체의 실제 동시 진행·완료·실패 회수 증거가 필요합니다. |
| 12. 64비트 및 최신 앱 | 실제 x64 process의 input/render/file/network/normal exit를 확인합니다. Chromium, Legcord/Discord, 최신 오픈소스 Office와 Steam의 유용한 기능은 필수이며 import 존재·toolbar만으로 승인하지 않습니다. |
| 13. ShizukuFS | `shizukufs/`, `sfs_mount.c`. versioned format, durable ordering, crash recovery, access checks, large-file 동작을 확인합니다. 현재 v1은 ext4 on-disk format을 사용합니다. NTFS보다 우수하다는 주장은 같은 하드웨어·cache·durability 조건의 명시한 workload 측정이 있어야 합니다. |
| 14. 모던·클래식 UX와 테마 | 자체 셸의 Slade/Flute/Jade를 실제 창·controls·taskbar/start·앱에 적용하고 사용자별 저장·cold boot 복원을 확인합니다. 기존 팔레트와 레거시 개인화는 재사용 후보이며 데이터 테마 완성과 구분합니다. |
| 15. 설치와 ISO 배포 | 자체 installer의 coherent source/artifact로 boot/UEFI install, 소유한 disposable target 쓰기·독립 readback·설치 매체 분리 cold boot·기본 GOP 및 지원 장치를 검증합니다. 허용된 ISO/해시를 nginx `m98.nyase.kr`에 게시하고 외부망 homepage·전체 다운로드를 확인합니다. |

## 절대 아키텍처의 필수 승인

| 기능 | 실제 실행에서 확인할 결과 |
| --- | --- |
| 자체 셸 | 기존 ShizukuOS shell executable이 실제 설치에서 시작하고 창·입력·taskbar/start·파일·설정·종료를 수행합니다. 개념 예시마다 복제 실행 파일을 만들지 않습니다. |
| Slade / Flute / Jade 및 사용자 테마 | Slade 기본값, 세 테마의 완전한 데이터 정의와 실행 파일 교체 없는 변경 전파, 전체 metrics/effects/type/icons/controls/menu/animation/sound/wallpaper/cursor 범위를 확인합니다. |
| 소리 | `volume1/shizukuossound`를 먼저 점검하고 출처를 기록합니다. 실제 장치에서 startup/shutdown/login/logout/error/warning/notification/device events를 재생합니다. |
| ShizukuVM | 자체 API를 통한 VM 생성·실행·상태·장치·종료/회수와 가능한 hardware acceleration, 실용적 fallback을 확인합니다. QEMU 테스트 VM 실행만으로 승인하지 않습니다. |
| chkrnl | `/mode linux`, `/mode msdos`가 실제 kernel-supported execution environment를 선택합니다. 셸 preset으로 대체하지 않습니다. |
| Linux Subsystem / ShizukuLB | SHZLB.sys, Linux kernel sandbox, POSIX, ShizukuLB가 실제 process/file/device/lifetime 계약으로 연결됩니다. |
| Nix + pkgs | install/update/remove/search/add-repo/list/upgrade가 실제 Nix 환경과 동기화되고 재시작 후 일관됩니다. 별도 무관한 package DB는 승인 대상이 아닙니다. |
| Linux GUI | X session의 앱이 Shizuku Window Bridge를 통해 보통의 관리형 desktop window로 표시되며 입력·resize·close와 process lifetime이 연결됩니다. |
| Terrasphere | WebKit 기반 실제 web rendering·navigation·input·network·downloads와 coherent native UX를 확인합니다. |
| Muzik | 실제 audio/video, metadata/library/playlists/visualization과 device/exit 동작을 확인합니다. |
| Sapphire | 가벼운 photo viewing과 필요 시 editor/paint 로딩, 실제 edit/save/reopen을 확인합니다. |
| Folio | 적합한 기존 open-source Folio engine을 재사용하여 실제 document/edit/save/reopen과 native UX를 확인합니다. |
| Utilities / games / Dead Screen | 실제 설치된 utilities와 게임을 실행합니다. recoverable error dialog, 심각한 Dead Screen의 traceback, 안전한 조건의 Tetris/수박 게임과 정확한 `You session got wasted` fallback을 구분해 검증합니다. |
| 표준 장치 | ACPI, PCI/PCIe, USB/HID/storage, NVMe, SATA/AHCI, IDE, Ethernet/Wi-Fi, audio/Bluetooth, GPU/framebuffer/GOP, PS/2, keyboard/mouse/touchpad, display/storage/filesystem의 선언된 지원 범위를 실제 장치에서 확인합니다. |

최종 성공은 **boot → drivers → shell → themes → sound → networking → filesystem →
applications → browser → media → graphics → Linux subsystem → virtualization → games**의
사용 가능한 전체 시스템입니다. 부분 milestone을 공개할 때는 통과한 범위와 남은 항목을
명시합니다. 설치·boot·driver milestone이 앱·보안·Linux·VM·게임 요구를 없애지 않습니다.

이전 Windows 98·Microsoft DOS 제어군과 독립 커널 시험은 과거 입력과 범위를
보존합니다. 이 기록은 ShizukuOS의 상위 구조나 필수 주 셸을 결정하지 않습니다.
비공개 Windows media·keys·installed disks·local runtime logs는 공개하지 않습니다.
한국어·영어 홈페이지와 외부망 접근, VNC 대신 공식 페이지, acceleration과
Shizuku 기본 GOP 그래픽 요구는 계속 유효합니다.
