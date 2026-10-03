/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS native shell: Korean default labels with an English fallback table.
 * Original ShizukuOS work. No third-party strings or Microsoft assets.
 * Source encoding is UTF-8; the compiler stores wide literals as UTF-16.
 */
#ifndef SHIZUKU_SHELL_STRINGS_H
#define SHIZUKU_SHELL_STRINGS_H

enum shell_string {
    S_START, S_EXPLORER, S_RUN, S_SETTINGS, S_END_SHELL, S_END_CONFIRM, S_PROGRAMS, S_NO_PROGRAMS,
    S_UP, S_REFRESH, S_NEW_FOLDER, S_COPY, S_PASTE, S_RENAME, S_DELETE, S_OPEN,
    S_COL_NAME, S_COL_SIZE, S_COL_TYPE, S_FOLDER, S_FILE, S_PROGRAM,
    S_NEW_FOLDER_NAME, S_ITEMS, S_TRUNCATED, S_EMPTY,
    S_RUN_PROMPT, S_RUN_OK, S_CANCEL, S_RUN_TITLE, S_EXPLORER_TITLE, S_SETTINGS_TITLE,
    S_LAUNCHED, S_EXITED, S_NO_SLOT, S_FAILED, S_ERROR, S_COPIED, S_PASTED, S_DELETED, S_RENAMED, S_CREATED,
    S_DELETE_AGAIN, S_NOTHING_SELECTED, S_NOTHING_COPIED, S_SAVED, S_SAVE_FAILED,
    S_OP_LIST, S_OP_COPY, S_OP_DELETE, S_OP_RENAME, S_OP_MKDIR, S_OP_LAUNCH, S_OP_OPEN, S_OP_SAVE, S_OP_STATUS,
    S_ERR_NOT_FOUND, S_ERR_PATH, S_ERR_ACCESS, S_ERR_SHARING, S_ERR_EXISTS, S_ERR_NOTEMPTY, S_ERR_DISK, S_ERR_BADEXE,
    S_USER, S_COMPUTER, S_TIME, S_UPTIME, S_MEMORY, S_LANGUAGE, S_LANG_AUTO, S_LANG_KO, S_LANG_EN,
    S_DRIVE, S_PATH_EDIT, S_DESKTOP, S_MB, S_UNKNOWN, S_PATH_TOO_LONG, S_BAD_NAME, S_FILE_ICON,
    S_COUNT
};

static const wchar_t *const shell_ko[S_COUNT] = {
    L"시작", L"파일 탐색기", L"실행...", L"상태 및 설정", L"셸 종료", L"셸을 종료할까요? 바탕 화면이 사라집니다.", L"프로그램", L"(프로그램 없음)",
    L"위로", L"새로 고침", L"새 폴더", L"복사", L"붙여넣기", L"이름 바꾸기", L"삭제", L"열기",
    L"이름", L"크기", L"종류", L"폴더", L"파일", L"프로그램",
    L"새 폴더", L"개 항목", L"(일부만 표시)", L"(비어 있음)",
    L"실행할 프로그램이나 문서의 경로를 입력하십시오.", L"확인", L"취소", L"실행", L"파일 탐색기", L"상태 및 설정",
    L"시작됨", L"종료됨, 종료 코드", L"동시에 추적할 수 있는 프로세스 수를 초과했습니다.", L"실패", L"오류", L"복사 보관됨", L"붙여넣음", L"삭제함", L"이름 변경함", L"만듦",
    L"삭제하려면 같은 항목에서 한 번 더 누르십시오.", L"선택한 항목이 없습니다.", L"복사한 항목이 없습니다.", L"설정을 저장했습니다.", L"설정을 저장하지 못했습니다.",
    L"목록", L"복사", L"삭제", L"이름 바꾸기", L"폴더 만들기", L"실행", L"열기", L"저장", L"상태 조회",
    L"파일을 찾을 수 없음", L"경로를 찾을 수 없음", L"접근 거부됨", L"다른 프로그램이 사용 중", L"이미 있음", L"폴더가 비어 있지 않음", L"디스크 공간 부족", L"실행 파일 형식이 아님",
    L"사용자", L"컴퓨터", L"시각", L"가동 시간", L"메모리", L"언어", L"자동", L"한국어", L"English",
    L"드라이브", L"경로 입력 (Enter 확인, Esc 취소)", L"바탕 화면", L"MB", L"알 수 없음", L"경로가 너무 깁니다.", L"이름이 올바르지 않습니다.", L"파일"
};

static const wchar_t *const shell_en[S_COUNT] = {
    L"Start", L"File Explorer", L"Run...", L"Status and Settings", L"End shell", L"End the shell? The desktop will disappear.", L"Programs", L"(no programs)",
    L"Up", L"Refresh", L"New folder", L"Copy", L"Paste", L"Rename", L"Delete", L"Open",
    L"Name", L"Size", L"Type", L"Folder", L"File", L"Program",
    L"New folder", L" items", L"(partial list)", L"(empty)",
    L"Enter the path of a program or document to run.", L"OK", L"Cancel", L"Run", L"File Explorer", L"Status and Settings",
    L"Started", L"Exited, exit code", L"Too many processes are being tracked at once.", L"Failed", L"Error", L"Copy staged", L"Pasted", L"Deleted", L"Renamed", L"Created",
    L"Press again on the same item to delete it.", L"Nothing is selected.", L"Nothing has been copied.", L"Settings saved.", L"Settings could not be saved.",
    L"list", L"copy", L"delete", L"rename", L"create folder", L"launch", L"open", L"save", L"query status",
    L"file not found", L"path not found", L"access denied", L"in use by another program", L"already exists", L"folder is not empty", L"disk is full", L"not a valid executable",
    L"User", L"Computer", L"Time", L"Uptime", L"Memory", L"Language", L"Auto", L"Korean", L"English",
    L"Drive", L"Type a path (Enter accepts, Esc cancels)", L"Desktop", L"MB", L"unknown", L"Path is too long.", L"The name is not valid.", L"File"
};

#endif
