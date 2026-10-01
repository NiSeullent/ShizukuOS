# Section 복제 권한 검증의 정정

현재 구현과 검증 방법은 [SECTION_DUPLICATE_CONTRACT.md](SECTION_DUPLICATE_CONTRACT.md)에 기록한다.

이전에 제안한 "원본 핸들의 section-specific 권한을 항상 상한으로 사용"하는
정책은 실제 GOP VM의 NULL DACL 확장 검사와 현재 보안 설명자 변경 검사에서
실패했다. 당시 호스트 성공 기록은 보존하지만 현재 계약의 성공 근거로 사용하지
않는다. 복제 권한은 객체의 현재 보안 설명자에 따라 평가한다. NULL/부재 DACL은
확장을 허용하고, 빈 DACL은 새 section 권한을 거부한다.

`T_SEC_ACCESS`는 실제 빈 ACL/보안 설명자를 사용한다. 기존 검사를 제거하지
않으며 `T_CHROME_SECTION`의 NULL DACL 허용·빈 DACL 거부·현재 설명자 변경
검사도 유지한다. 실제 게스트 실행은 별도 검증이다. Kernel32/Kernel64는 실제
Windows 98의 MS-DOS를 대체하는 ShizukuDOS 구성요소다.
