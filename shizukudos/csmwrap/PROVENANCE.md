# CSMWrap provenance

이 디렉터리의 코드는 Win98-Modern이 새로 작성한 것이다. 공개 CSMWrap/SeaBIOS/EDK II
구현을 복사하지 않았다.

## 참고한 동작

- 프로젝트: [CSMWrap/CSMWrap](https://github.com/CSMWrap/CSMWrap) 릴리스 3.1.2 (2026-05-09).
  저장소 LICENSE는 GNU LGPL 2.1이라고 적혀 있다. 소스는 클론하거나 옮기지 않았고,
  README와 `src/bootdev.h`의 설명만 읽었다.
- 그 설명이 고정하는 계약:
  - UEFI class 3에서 레거시 BIOS 서비스를 펌웨어 바깥에서 제공한다.
  - ExitBootServices 이후에는 UEFI Boot Services를 다시 호출하지 않는다.
  - 자신이 올라간 장치를 우선하는 부트 장치 개념(BBS)이 있다.
  - 이미 네이티브 BIOS/CSM이면 인터럽트를 가상화하지 않고 원래 벡터에 맡긴다.
  - 16비트 엔트리 뒤에야 DOS/Windows 9x 스타일 부팅이 가능하다.
- 인터럽트 번호(INT 10h, 11h, 12h, 13h, 15h, 16h, 1Ah AX=B101h)와 E820 타입 1/2는
  공개 PC BIOS 계약이다.
- GOP, 메모리 맵, Block I/O, 단순 텍스트 입력, ACPI/SMBIOS 구성 테이블의 필드
  배치는 이 저장소의 `shizukudos/uefi/efi.h`와 UEFI 2.10 공개 인터페이스를 따른다.

## 이 구현이 공개 구현과 다른 점

- SeaBIOS, PicoEFI, uACPI, flanterm을 포함하지 않는다.
- EFI 바이너리 `csmwrap.efi`를 받아 그대로 실행하지 않는다.
- ShizukuDOS 0.1(`boot.asm`/`stage2.asm`)과 x64 UEFI 진입이 이 핸드오프를 반드시
  거친다. KERNEL64 ELF64가 기록되기 전에는 하드디스크로의 체인로드를 거부한다.
- 비디오, 디스크, 메모리, ACPI, 입력, 타이머, PCI 서비스 본체는 이 코어가 채우지
  않는다. 없는 서비스는 UEFI 모드에서 CF=1이다.
