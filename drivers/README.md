# Windows 98 Shizuku's Second Edition — 드라이버

독자 구현 [AHCI 코어](ahci_native/)가 실제 QEMU 컨트롤러에서 디스크 식별과 DMA 섹터 읽기를 통과했습니다. [ShizukuDOS 시험 경로](../shizukudos/uefi_ahci/)는 UEFI 종료 후 자체 32비트 커널에서 이 코어를 실행합니다. Windows 98 저장장치 스택 연결, USB 장치 구동과 실기기 검증은 아직 남아 있습니다.

목표는 Windows 98 SE가 Intel 6세대 Core(100-series PCH) 수준의 SATA AHCI 저장 장치와 xHCI USB 컨트롤러를 사용할 수 있도록, Windows 98용 드라이버를 새로 구현하고 실제 게스트 및 실기기에서 검증하는 것이다. 구동할 보드 모델, BIOS 설정, PCI ID는 아직 정해지지 않았다.

## 이 폴더의 내용

- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md): 하드웨어 경계, Win9x 통합 경로, 단계별 완료 기준과 테스트.
- [EVIDENCE.md](EVIDENCE.md): 계획의 근거가 되는 1차 문서와 확인할 사항.
- [probe](probe/): AHCI/xHCI의 읽기 전용 capability 레지스터를 해석하는, OS와 무관한 C89 코드. 드라이버가 아니며 물리 MMIO를 스스로 매핑하지 않는다.
- [pcie](pcie/): 독자 PCI/PCI-E 설정 공간·토폴로지·ECAM·자원·DMA 제약 코어.
- [ahci_native](ahci_native/): 컨트롤러 소유권·DMA 수명·ATA 식별·단일 섹터 읽기 구현과 실패 주입 시험.
- [fat_native](fat_native/): 독자 FAT32 루트 파일 판독기. 조각난 클러스터 연결·경계·중복을 검사하고 실패 시 출력을 보존한다. 현재 합성 섹터 호스트 시험을 통과했으며 AHCI 연결과 부팅 파일 실행은 후속 단계이다.
- [xhci_native](xhci_native/): 컨트롤러 인계·DMA 명령/이벤트 링·No-Op 완료 처리. [별도 실제 게스트](../shizukudos/uefi_xhci/)에서 130개 명령을 검증했으며 USB 장치 기능은 아직 구현하지 않았다.
- [usb_native](usb_native/): USB 2.0 장치·구성 descriptor를 제한된 메모리 안에서 검사하는 독자 파서. 오류 시 출력은 유지하며, 전송·장치 설정·클래스 드라이버는 아직 포함하지 않는다.
- [Windows 98 연결 계약](../docs/NATIVE_DRIVER_INTEGRATION.md): CONFIGMG·VMM·IOS의 확인된 인터페이스와 추가 확인이 필요한 ABI, 보조 컨트롤러 소유권 및 검증 순서.

## 현재 판단

Intel 100/C230 PCH에서 SATA는 AHCI 또는 RAID 모드만 제공하고 레거시 IDE 모드는 없다. USB는 xHCI 컨트롤러를 사용하며 EHCI가 없다. 따라서 Windows 98을 디스크에서 부팅하고 USB 입력을 계속 사용하려면 각각 운영체제용 드라이버가 필요하다. BIOS의 설치 전 USB 에뮬레이션은 Windows 시작 후의 xHCI 지원을 증명하지 않는다. [Intel 100/C230 PCH 데이터시트, SATA §29.1 및 USB §35.3](https://cdrdv2-public.intel.com/332690/332690_SKL%20PCH%20EDS%20H%20Book_rev007_PUBLIC.pdf)

Windows 98/Me WDM은 최신 NT WDM과 동작 차이가 있으므로, ReactOS나 최신 Windows의 드라이버 바이너리를 그대로 넣지 않는다. [Microsoft, Differences in WDM Versions](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/differences-in-wdm-versions)

이 저장소는 Microsoft Windows 설치 파일, 드라이버 바이너리 또는 DDK를 포함하지 않는다. 실험자는 자신이 사용할 수 있는 Windows 98 SE 및 해당 개발 도구를 별도로 준비해야 한다.
