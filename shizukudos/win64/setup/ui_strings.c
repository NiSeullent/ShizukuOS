/* SPDX-License-Identifier: GPL-2.0-only
 * UI language resources. Language selection never advertises an input method. */
#include <stdint.h>
#include "ui_strings.h"
static const WCHAR *const ko[UI_COUNT]={
 L"ShizukuOS 설치",L"컴퓨터에 ShizukuOS를 설치합니다. 설치할 디스크를 직접 선택하고 변경 내용을 확인합니다.",
 L"설치할 디스크",L"디스크를 선택하세요. 확인을 마치기 전에는 아무것도 변경하지 않습니다.",
 L"설치 내용 확인",L"ShizukuOS 설치 중",L"설치가 완료되었습니다",L"설치를 완료하지 못했습니다",
 L"계속",L"뒤로",L"종료",L"지우고 설치",L"취소 요청",L"자세히",L"자세히 닫기",L"재시동",L"시스템 종료",
 L"설치 이미지와 디스크를 확인하고 있습니다.",L"설치 가능한 디스크가 없습니다. 아래 제외 사유를 확인하세요.",
 L"필요한 공간",L"선택한 디스크의 모든 파티션과 파일이 삭제됩니다. 되돌릴 수 없습니다.",
 L"새 GPT, EFI 부팅 영역과 ShizukuFS 시스템 영역을 만듭니다.",L"다른 디스크는 변경하지 않습니다.",
 L"설치 원본과 디스크를 검증하는 중",L"부팅 파일을 쓰는 중",L"부팅 파일을 다시 읽어 검증하는 중",
 L"시스템 파일을 쓰는 중",L"시스템 파일을 다시 읽어 검증하는 중",L"파티션과 부팅 구성을 기록하는 중",
 L"설치 기록과 디스크 캐시를 확인하는 중",L"현재 단계는 중단할 수 없습니다. 전원을 끄지 마세요.",
 L"취소를 요청했습니다. 안전한 중단 지점까지 기다려 주세요.",
 L"디스크 일부가 변경되었습니다. 설치가 완료되지 않았으므로 이 디스크로 부팅하지 마세요.",
 L"설치 미디어를 제거한 뒤 설치된 디스크로 시작하세요.",L"첫 부팅에서 오프라인 로컬 계정을 설정합니다.",
 L"설치 원본이나 디스크가 변경되었습니다. 디스크를 다시 선택하세요.",L"방향키 또는 마우스로 디스크를 직접 선택하세요.",
 L"현재 입력 배열: US 키보드. 한글 입력기는 아직 지원하지 않습니다.",L"설치 화면 언어",L"설치 이미지",
 L"처리한 디스크 바이트",L"검증한 시스템 파일",L"로그 저장",L"C:\\TEMP\\SHZSETUP.LOG에 저장했습니다. 재시동하면 사라질 수 있습니다.",
 L"로그를 저장하지 못했습니다.",L"취소하면 이미 변경된 디스크 내용은 복구되지 않습니다.",
 L"고정 디스크",L"이동식 디스크",L"읽기 전용이거나 사용 중인 디스크입니다.",L"파티션입니다. 전체 디스크를 선택하세요.",
 L"지원하지 않는 섹터 크기입니다.",L"이번 버전은 이동식 디스크에 설치할 수 없습니다.",L"설치 공간이 부족합니다.",
 L"원본·시스템 디스크이거나 사용 중이며 설치할 수 없습니다.",L"검증한 시스템 파일"
};
static const WCHAR *const en[UI_COUNT]={
 L"Install ShizukuOS",L"Install ShizukuOS on this computer. Choose a disk and review the changes before installing.",
 L"Choose an installation disk",L"Choose a disk. Nothing changes until you confirm the installation.",
 L"Review installation",L"Installing ShizukuOS",L"Installation complete",L"Installation could not finish",
 L"Continue",L"Back",L"Exit",L"Erase and install",L"Request cancel",L"Details",L"Hide details",L"Restart",L"Shut down",
 L"Checking the installation image and disks.",L"No available installation disk. Review the exclusion reasons below.",
 L"Required space",L"All partitions and files on the selected disk will be deleted. This cannot be undone.",
 L"Creates a new GPT, EFI boot volume and ShizukuFS system volume.",L"Other disks will not change.",
 L"Verifying source files and the target",L"Writing boot files",L"Reading back and verifying boot files",
 L"Writing system files",L"Reading back and verifying system files",L"Writing partitions and boot configuration",
 L"Verifying the install record and flushing disk caches",L"This step cannot be interrupted. Keep the computer on.",
 L"Cancellation requested. Waiting for a safe stopping point.",
 L"The disk was partially changed. Installation is incomplete; do not boot from this disk.",
 L"Remove the installation medium before starting the installed disk.",L"Set up an offline local account on first boot.",
 L"The installation source or disk changed. Select the target again.",L"Select a disk explicitly with the arrow keys or mouse.",
 L"Input layout: US keyboard. A Korean input method is not available yet.",L"Installation language",L"Installation image",
 L"Disk bytes processed",L"System files verified",L"Save log",L"Saved to C:\\TEMP\\SHZSETUP.LOG. It may be lost after restart.",
 L"Could not save the log.",L"Cancelling will not restore disk contents already changed.",
 L"Fixed disk",L"Removable disk",L"Read-only or in use.",L"Partition; choose a whole disk.",
 L"Unsupported sector size.",L"Removable installation is not supported in this version.",L"Insufficient installation space.",
 L"Source/system disk, in use, or unavailable for installation.",L"System files verified"
};
const WCHAR *setup_string(uint32_t language,enum setup_string id)
{ if(id<0||id>=UI_COUNT)return L"";return language==2?en[id]:ko[id]; }
