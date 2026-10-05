/* Korean UI strings (ko-KR). Single source for the compiled table (locale.c) and the generated
 * STRINGTABLE resource (tools/gen_rc.py). \u escapes keep this file ASCII; the Hangul text is in comments.
 * Original ShizukuOS strings; no Longhorn/Windows shell source or resources were consulted. */
#ifndef SHZ_STRINGS_KO_H
#define SHZ_STRINGS_KO_H
#define SHZ_STRING_TABLE(X) \
    X(IDS_START, 101, L"\uC2DC\uC791") /* 시작 */ \
    X(IDS_PROGRAMS, 102, L"\uD504\uB85C\uADF8\uB7A8") /* 프로그램 */ \
    X(IDS_RUN, 103, L"\uC2E4\uD589...") /* 실행... */ \
    X(IDS_EXIT_SHELL, 104, L"\uC178 \uC885\uB8CC") /* 셸 종료 */ \
    X(IDS_DESKTOP, 105, L"\uBC14\uD0D5 \uD654\uBA74") /* 바탕 화면 */ \
    X(IDS_FILES, 106, L"\uD30C\uC77C") /* 파일 */ \
    X(IDS_TASKBAR, 107, L"\uC791\uC5C5 \uD45C\uC2DC\uC904") /* 작업 표시줄 */ \
    X(IDS_RUN_PROMPT, 108, L"\uC2E4\uD589\uD560 \uD504\uB85C\uADF8\uB7A8 \uACBD\uB85C\uB97C \uC785\uB825\uD558\uC2ED\uC2DC\uC624") /* 실행할 프로그램 경로를 입력하십시오 */ \
    X(IDS_ERR_LAUNCH, 109, L"\uD504\uB85C\uADF8\uB7A8\uC744 \uC2DC\uC791\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 프로그램을 시작할 수 없습니다 */ \
    X(IDS_ERR_PATH_LONG, 110, L"\uACBD\uB85C\uAC00 260\uC790 \uD55C\uB3C4\uB97C \uB118\uC5B4 \uAC74\uB108\uB6F0\uC5C8\uC2B5\uB2C8\uB2E4") /* 경로가 260자 한도를 넘어 건너뛰었습니다 */ \
    X(IDS_ERR_TRUNC, 111, L"\uD56D\uBAA9\uC774 128\uAC1C\uB97C \uB118\uC5B4 \uC77C\uBD80\uB9CC \uD45C\uC2DC\uD569\uB2C8\uB2E4") /* 항목이 128개를 넘어 일부만 표시합니다 */ \
    X(IDS_ERR_ENUM, 112, L"\uD30C\uC77C \uBAA9\uB85D\uC744 \uC77D\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 파일 목록을 읽을 수 없습니다 */ \
    X(IDS_PARENT, 113, L"\uC0C1\uC704 \uD3F4\uB354") /* 상위 폴더 */ \
    X(IDS_DIR, 114, L"\uD3F4\uB354") /* 폴더 */ \
    X(IDS_FILE, 115, L"\uD30C\uC77C") /* 파일 */ \
    X(IDS_ERR_TASKS_FULL, 116, L"\uC791\uC5C5 \uBAA9\uB85D\uC774 64\uAC1C \uD55C\uB3C4\uC5D0 \uB3C4\uB2EC\uD588\uC2B5\uB2C8\uB2E4") /* 작업 목록이 64개 한도에 도달했습니다 */ \
    X(IDS_WINDOW_LIST, 117, L"\uCC3D \uBAA9\uB85D") /* 창 목록 */ \
    X(IDS_COMPUTER, 118, L"\uB0B4 \uCEF4\uD4E8\uD130") /* 내 컴퓨터 */ \
    X(IDS_RENAME, 119, L"\uC774\uB984 \uBC14\uAFB8\uAE30") /* 이름 바꾸기 */ \
    X(IDS_ERR_RENAME, 120, L"\uC774\uB984\uC744 \uBC14\uAFC0 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 이름을 바꿀 수 없습니다 */ \
    X(IDS_ERR_FOCUS, 121, L"\uCC3D\uC744 \uC55E\uC73C\uB85C \uAC00\uC838\uC62C \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 창을 앞으로 가져올 수 없습니다 */ \
    X(IDS_VERSION, 122, L"ShizukuOS") \
    X(IDS_ERR_DRIVE, 123, L"\uB4DC\uB77C\uC774\uBE0C\uC5D0 \uC811\uADFC\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 드라이브에 접근할 수 없습니다 */ \
    X(IDS_LAUNCHED, 124, L"\uD504\uB85C\uC138\uC2A4\uB97C \uC2DC\uC791\uD588\uC2B5\uB2C8\uB2E4") /* 프로세스를 시작했습니다 */ \
    X(IDS_ERR_NOCMD, 125, L"\uC2E4\uD589\uD560 \uACBD\uB85C\uAC00 \uBE44\uC5B4 \uC788\uC2B5\uB2C8\uB2E4") /* 실행할 경로가 비어 있습니다 */ \
    X(IDS_FILES_TITLE, 126, L"\uD30C\uC77C - ShizukuOS") /* 파일 - ShizukuOS */ \
    X(IDS_EMPTY, 127, L"\uBE44\uC5B4 \uC788\uC74C") /* 비어 있음 */ \
    X(IDS_ERR_CLASS, 128, L"\uCC3D \uD074\uB798\uC2A4\uB97C \uB4F1\uB85D\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 창 클래스를 등록할 수 없습니다 */ \
    X(IDS_ERR_WINDOW, 129, L"\uCC3D\uC744 \uB9CC\uB4E4 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 창을 만들 수 없습니다 */ \
    X(IDS_ERR_FILES_LIMIT, 130, L"\uD30C\uC77C \uCC3D\uC774 8\uAC1C \uD55C\uB3C4\uC5D0 \uB3C4\uB2EC\uD588\uC2B5\uB2C8\uB2E4") /* 파일 창이 8개 한도에 도달했습니다 */ \
    X(IDS_OK, 131, L"\uD655\uC778") /* 확인 */ \
    X(IDS_CANCEL, 132, L"\uCDE8\uC18C") /* 취소 */ \
    X(IDS_ERR_SHELL, 133, L"\uC178 \uCC3D\uC73C\uB85C \uB4F1\uB85D\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 셸 창으로 등록할 수 없습니다 */ \
    X(IDS_ERR_TIMER, 134, L"\uD0C0\uC774\uBA38\uB97C \uB9CC\uB4E4 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 타이머를 만들 수 없습니다 */ \
    X(IDS_THEME, 135, L"\uD14C\uB9C8") /* 테마 */ \
    X(IDS_THEME_NEXT, 136, L"\uB2E4\uC74C \uD14C\uB9C8") /* 다음 테마 */ \
    X(IDS_THEME_CUSTOM, 137, L"\uC0AC\uC6A9\uC790 \uD14C\uB9C8") /* 사용자 테마 */ \
    X(IDS_THEME_RELOAD, 138, L"\uD14C\uB9C8 \uC0C8\uB85C \uACE0\uCE68") /* 테마 새로 고침 */ \
    X(IDS_THEME_OK, 139, L"\uD14C\uB9C8 \uC801\uC6A9") /* 테마 적용 */ \
    X(IDS_THEME_UNSUP, 140, L"\uC77C\uBD80 \uD6A8\uACFC \uBBF8\uC9C0\uC6D0") /* 일부 효과 미지원 */ \
    X(IDS_THEME_REFUSED, 141, L"\uD14C\uB9C8 \uAC70\uBD80 \uC774\uC804 \uC720\uC9C0") /* 테마 거부 이전 유지 */ \
    X(IDS_ERR_THEME, 142, L"\uD14C\uB9C8\uB97C \uC77D\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4") /* 테마를 읽을 수 없습니다 */ \
    X(IDS_THEME_NOPERSIST, 143, L"\uD604\uC7AC \uD654\uBA74\uC5D0 \uC801\uC6A9\uD588\uC9C0\uB9CC \uC800\uC7A5\uD558\uC9C0 \uBABB\uD588\uC2B5\uB2C8\uB2E4. \uB2E4\uC2DC \uC120\uD0DD\uD574 \uC800\uC7A5\uC744 \uC2DC\uB3C4\uD558\uC138\uC694.") /* 현재 화면에 적용했지만 저장하지 못했습니다. 다시 선택해 저장을 시도하세요. */ \
    X(IDS_SETTINGS, 144, L"\uC124\uC815") /* 설정 */ \
    X(IDS_PERSONALIZATION, 145, L"\uAC1C\uC778 \uC124\uC815") /* 개인 설정 */ \
    X(IDS_THEME_CHOOSE, 146, L"\uD654\uBA74\uC5D0 \uC0AC\uC6A9\uD560 \uD14C\uB9C8\uB97C \uC120\uD0DD\uD558\uC138\uC694.") /* 화면에 사용할 테마를 선택하세요. */ \
    X(IDS_SETTINGS_HINT, 147, L"\uD14C\uB9C8\uB97C \uC120\uD0DD\uD558\uBA74 \uBC14\uB85C \uC801\uC6A9\uB418\uACE0 \uC800\uC7A5\uB429\uB2C8\uB2E4.") /* 테마를 선택하면 바로 적용되고 저장됩니다. */ \
    X(IDS_SAPPHIRE, 148, L"Sapphire \u00B7 \uC0AC\uC9C4") /* Sapphire · 사진 */ \
    X(IDS_MUZIK, 149, L"Muzik \u00B7 \uC74C\uC545") /* Muzik · 음악 */ \
    X(IDS_GAMES, 150, L"\uC9C0\uB8B0 \uCC3E\uAE30") /* 지뢰 찾기 */ \
    X(IDS_SHORTCUTS, 151, L"\uBC14\uB85C\uAC00\uAE30") /* 바로가기 */ \
    X(IDS_THEME_SESSION, 152, L"\uD604\uC7AC \uC138\uC158\uC5D0 \uC801\uC6A9\uB428") /* 현재 세션에 적용됨 */ \
    X(IDS_THEME_SAVED, 153, L"\uD14C\uB9C8\uB97C \uC801\uC6A9\uD558\uACE0 \uC800\uC7A5\uD588\uC2B5\uB2C8\uB2E4.") /* 테마를 적용하고 저장했습니다. */ \
    X(IDS_THEME_RELOADED, 154, L"\uD14C\uB9C8\uB97C \uC0C8\uB85C \uACE0\uCCE4\uC2B5\uB2C8\uB2E4.") /* 테마를 새로 고쳤습니다. */ \
    X(IDS_THEME_CURRENT, 155, L"\uC0AC\uC6A9 \uC911") /* 사용 중 */ \
    X(IDS_THEME_CUSTOM_MISSING, 156, L"\uCD94\uAC00\uB41C \uD14C\uB9C8 \uC5C6\uC74C") /* 추가된 테마 없음 */ \
    X(IDS_THEME_LOAD_FAILED, 157, L"\uD14C\uB9C8\uB97C \uBD88\uB7EC\uC624\uC9C0 \uBABB\uD588\uC2B5\uB2C8\uB2E4. \uAE30\uC874 \uD14C\uB9C8\uB97C \uC720\uC9C0\uD569\uB2C8\uB2E4.") /* 테마를 불러오지 못했습니다. 기존 테마를 유지합니다. */

enum {
#define X(n,i,s) n = i,
    SHZ_STRING_TABLE(X)
#undef X
    IDS__END
};
#endif
