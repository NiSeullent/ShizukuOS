/* SPDX-License-Identifier: GPL-2.0-only
 * Independent native Win98 observer. Never applies colors or writes registry.
 * Source-only QA companion: a host receipt must also bind source, boot epochs,
 * private disk, log bytes and actual observer exit. A log alone is not a PASS.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>

#define COLOR_COUNT 25u
#define PROFILE_BYTES 224u
#define LOG_LIMIT 32768u
#define VALUE_LIMIT 512u
#define CASE_BYTES 60u
#define STAGE_TIMEOUT 90000u
#define CLOSE_TIMEOUT 60000u
#define CHILD_READY_TIMEOUT 15000u
#define RESTORE_TIMEOUT 30000u
#define TRANSIENT_TIMEOUT 2000u

static const char case_path[] = "C:\\VXDLAB\\SHZCASE.TXT";
static const char log_one_path[] = "C:\\VXDLAB\\SHZGLOB1.LOG";
static const char log_two_path[] = "C:\\VXDLAB\\SHZGLOB2.LOG";
static const char selector_path[] = "C:\\VXDLAB\\SHZTHEME.EXE";
static const char selector_command[] = "\"C:\\VXDLAB\\SHZTHEME.EXE\"";
static const char restore_command[] = "\"C:\\VXDLAB\\SHZTHEME.EXE\" /restore";
static const char selector_class[] = "ShizukuOSThemeSelector";
static const char profile_key[] = "Software\\ShizukuOS\\Theme";
static const char run_key[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const char witness_class[] = "ShizukuOSIndependentGlobalThemeWitness";
static const BYTE profile_magic[8] = {'S','H','Z','C','L','R','1',0};

#define CREF(r,g,b) ((DWORD)(r) | ((DWORD)(g) << 8) | ((DWORD)(b) << 16))
/* Intentionally independent of selector headers, decoder and library. */
static const DWORD shizos[COLOR_COUNT] = {
    CREF(207,207,207), CREF(19,46,69), CREF(0,120,215),
    CREF(120,128,136), CREF(240,240,240), CREF(255,255,255),
    CREF(64,80,96), CREF(0,0,0), CREF(0,0,0), CREF(255,255,255),
    CREF(160,160,160), CREF(192,192,192), CREF(160,160,160),
    CREF(0,120,215), CREF(255,255,255), CREF(240,240,240),
    CREF(160,160,160), CREF(128,128,128), CREF(0,0,0),
    CREF(240,240,240), CREF(255,255,255), CREF(96,96,96),
    CREF(224,224,224), CREF(0,0,0), CREF(255,255,225)
};

typedef struct reg_value {
    DWORD present, type, bytes;
    BYTE data[VALUE_LIMIT];
} reg_value;

typedef struct snapshot {
    DWORD colors[COLOR_COUNT];
    reg_value profile, run;
} snapshot;

typedef struct progress_deadline {
    DWORD active, start;
} progress_deadline;

static HANDLE log_handle = INVALID_HANDLE_VALUE;
static HANDLE child_handle;
static DWORD log_bytes, log_error, failure_error, phase, child_pid;
static DWORD notification_count, paint_count, witness_closed, enum_matches;
static DWORD baseline[COLOR_COUNT];
static BYTE saved_profile[PROFILE_BYTES];
static char nonce[33];
static HWND witness, selector_window;
static char previous_log[LOG_LIMIT + 1u];
static const char *failure_stage;
static DWORD child_exit_recorded;
static int selector_controls_invariants(void);
static int selector_controls_enabled(void);

static void clear_bytes(void *p, DWORD n)
{
    BYTE *q = (BYTE *)p;
    while (n--) *q++ = 0;
}

static void copy_bytes(void *d, const void *s, DWORD n)
{
    BYTE *out = (BYTE *)d;
    const BYTE *in = (const BYTE *)s;
    while (n--) *out++ = *in++;
}

static int equal_bytes(const void *a, const void *b, DWORD n)
{
    const BYTE *x = (const BYTE *)a, *y = (const BYTE *)b;
    while (n--) if (*x++ != *y++) return 0;
    return 1;
}

static DWORD text_length(const char *s)
{
    DWORD n = 0;
    while (s[n]) ++n;
    return n;
}

static DWORD little32(const BYTE *p)
{
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

static int fail(const char *stage, DWORD error)
{
    if (!failure_stage) {
        failure_stage = stage;
        failure_error = error ? error : ERROR_INVALID_DATA;
    }
    return 0;
}

static int check_progress(const progress_deadline *progress, const char *stage)
{
    if (progress && progress->active &&
        (DWORD)(GetTickCount() - progress->start) >= TRANSIENT_TIMEOUT)
        return fail(stage, ERROR_TIMEOUT);
    return 1;
}

static int note_progress(progress_deadline *progress, const char *stage)
{
    if (!progress->active) {
        progress->start = GetTickCount();
        progress->active = 1u;
    }
    /* Once observed, the deadline stays latched for this stage. A return to
     * old values cannot extend an unstable or rolled-back transaction. */
    return check_progress(progress, stage);
}

static int emit_bytes(const char *s, DWORD n)
{
    DWORD written = 0;
    if (log_error || log_handle == INVALID_HANDLE_VALUE) return 0;
    if (n > LOG_LIMIT - log_bytes) {
        log_error = ERROR_BUFFER_OVERFLOW;
        return 0;
    }
    if (!WriteFile(log_handle, s, n, &written, NULL) || written != n) {
        log_error = GetLastError();
        if (!log_error) log_error = ERROR_WRITE_FAULT;
        return 0;
    }
    log_bytes += n;
    return 1;
}

static int emit_line(const char *key, const char *value)
{
    return emit_bytes(key, text_length(key)) && emit_bytes("=", 1) &&
           emit_bytes(value, text_length(value)) && emit_bytes("\r\n", 2);
}

static int emit_number(const char *key, DWORD number)
{
    char digits[11], output[11];
    DWORD count = 0, i;
    do { digits[count++] = (char)('0' + number % 10u); number /= 10u; } while (number);
    for (i = 0; i < count; ++i) output[i] = digits[count - 1u - i];
    output[count] = 0;
    return emit_line(key, output);
}

static int emit_hex(const char *key, const BYTE *data, DWORD bytes)
{
    static const char hex[] = "0123456789abcdef";
    char output[VALUE_LIMIT * 2u + 1u];
    DWORD i;
    if (bytes > VALUE_LIMIT) return 0;
    for (i = 0; i < bytes; ++i) {
        output[i * 2u] = hex[data[i] >> 4];
        output[i * 2u + 1u] = hex[data[i] & 15u];
    }
    output[bytes * 2u] = 0;
    return emit_line(key, output);
}

static int flush_log(void)
{
    if (log_error) return 0;
    if (!FlushFileBuffers(log_handle)) {
        log_error = GetLastError();
        if (!log_error) log_error = ERROR_WRITE_FAULT;
        return 0;
    }
    return 1;
}

static int read_file(const char *path, BYTE *data, DWORD capacity, DWORD *bytes)
{
    HANDLE h;
    DWORD high = 0, size, got = 0, error = 0;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return fail("READ_FIXED_FILE_OPEN", GetLastError());
    SetLastError(NO_ERROR);
    size = GetFileSize(h, &high);
    if ((size == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) || high || size > capacity)
        error = ERROR_INVALID_DATA;
    else if (!ReadFile(h, data, size, &got, NULL) || got != size)
        error = GetLastError() ? GetLastError() : ERROR_READ_FAULT;
    if (!CloseHandle(h) && !error) error = GetLastError();
    if (error) return fail("READ_FIXED_FILE_CONTENT", error);
    *bytes = size;
    return 1;
}

static int read_case(void)
{
    BYTE data[CASE_BYTES];
    DWORD bytes, i;
    static const char prefix[] = "SHZGCASE1\r\nnonce=";
    static const char middle[] = "\r\nphase=";
    if (!read_file(case_path, data, sizeof(data), &bytes)) return 0;
    if (bytes != CASE_BYTES || !equal_bytes(data, prefix, sizeof(prefix) - 1u) ||
        !equal_bytes(data + 49u, middle, sizeof(middle) - 1u) ||
        (data[57] != '1' && data[57] != '2') || data[58] != '\r' || data[59] != '\n')
        return fail("CASE_SCHEMA", ERROR_INVALID_DATA);
    for (i = 0; i < 32u; ++i) {
        BYTE c = data[17u + i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return fail("CASE_NONCE", ERROR_INVALID_DATA);
        nonce[i] = (char)c;
    }
    nonce[32] = 0;
    phase = (DWORD)(data[57] - '0');
    return 1;
}

static int read_value(const char *key_path, const char *name, reg_value *value)
{
    HKEY key;
    LONG status;
    clear_bytes(value, sizeof(*value));
    status = RegOpenKeyExA(HKEY_CURRENT_USER, key_path, 0, KEY_QUERY_VALUE, &key);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return 1;
    if (status != ERROR_SUCCESS) return fail("REGISTRY_READ_OPEN", (DWORD)status);
    value->bytes = VALUE_LIMIT;
    status = RegQueryValueExA(key, name, NULL, &value->type, value->data, &value->bytes);
    if (RegCloseKey(key) != ERROR_SUCCESS) return fail("REGISTRY_READ_CLOSE", ERROR_INVALID_HANDLE);
    if (status == ERROR_FILE_NOT_FOUND) {
        clear_bytes(value, sizeof(*value));
        return 1;
    }
    if (status != ERROR_SUCCESS || value->bytes > VALUE_LIMIT)
        return fail("REGISTRY_READ_VALUE", (DWORD)status);
    value->present = 1;
    return 1;
}

static int equal_value(const reg_value *a, const reg_value *b)
{
    return a->present == b->present && a->type == b->type && a->bytes == b->bytes &&
           equal_bytes(a->data, b->data, a->bytes);
}

static int colors_are(const DWORD *colors, const DWORD *expected)
{
    return equal_bytes(colors, expected, COLOR_COUNT * sizeof(DWORD));
}

static int read_snapshot(snapshot *out)
{
    DWORD i;
    for (i = 0; i < COLOR_COUNT; ++i) {
        out->colors[i] = GetSysColor((int)i);
        if (out->colors[i] & 0xff000000u) return fail("SYSTEM_COLOR_HIGH_BYTE", ERROR_INVALID_DATA);
    }
    return read_value(profile_key, "Profile", &out->profile) &&
           read_value(run_key, "ShizukuOSTheme", &out->run);
}

/* Stable read-only sampling; a changing transaction is retried, never accepted. */
static int stable_snapshot(snapshot *out)
{
    snapshot second;
    if (!read_snapshot(out) || !read_snapshot(&second)) return -1;
    return colors_are(out->colors, second.colors) && equal_value(&out->profile, &second.profile) &&
           equal_value(&out->run, &second.run);
}

static int decode_profile(const reg_value *value, DWORD *style, DWORD *original)
{
    DWORD i, color, selected;
    const BYTE *data = value->data;
    if (!value->present || value->type != REG_BINARY || value->bytes != PROFILE_BYTES ||
        !equal_bytes(data, profile_magic, sizeof(profile_magic)) || little32(data + 8u) != 1u ||
        little32(data + 12u) != PROFILE_BYTES || little32(data + 20u) != COLOR_COUNT)
        return fail("PROFILE_SCHEMA", ERROR_INVALID_DATA);
    *style = little32(data + 16u);
    if (*style > 1u) return fail("PROFILE_STYLE", ERROR_INVALID_DATA);
    for (i = 0; i < COLOR_COUNT; ++i) {
        color = little32(data + 24u + i * 4u);
        selected = little32(data + 124u + i * 4u);
        if ((color | selected) & 0xff000000u || selected != (*style ? shizos[i] : color))
            return fail("PROFILE_COLOR_CONTRACT", ERROR_INVALID_DATA);
        original[i] = color;
    }
    return 1;
}

static int valid_run(const reg_value *value)
{
    return value->present && value->type == REG_SZ && value->bytes == sizeof(restore_command) &&
           equal_bytes(value->data, restore_command, sizeof(restore_command));
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int parse_hex(const char *text, DWORD bytes, BYTE *out)
{
    DWORD i;
    int a, b;
    for (i = 0; i < bytes; ++i) {
        a = hex_nibble(text[i * 2u]); b = hex_nibble(text[i * 2u + 1u]);
        if (a < 0 || b < 0) return 0;
        out[i] = (BYTE)((a << 4) | b);
    }
    return 1;
}

/* One exact occurrence, full CRLF lines, ASCII only. No substring matches. */
static const char *unique_line(DWORD bytes, const char *key, DWORD length)
{
    DWORD start = 0, end, i, key_bytes = text_length(key), matches = 0;
    const char *found = NULL;
    while (start < bytes) {
        end = start;
        while (end < bytes && previous_log[end] != '\r') {
            BYTE c = (BYTE)previous_log[end];
            if (c < 32u || c > 126u) return NULL;
            ++end;
        }
        if (end + 1u >= bytes || previous_log[end + 1u] != '\n') return NULL;
        i = end - start;
        if (i >= key_bytes + 1u && equal_bytes(previous_log + start, key, key_bytes) &&
            previous_log[start + key_bytes] == '=') {
            if (i != key_bytes + 1u + length) return NULL;
            ++matches;
            found = previous_log + start + key_bytes + 1u;
        }
        start = end + 2u;
    }
    return matches == 1u ? found : NULL;
}

static int line_is(DWORD bytes, const char *key, const char *expected)
{
    DWORD length = text_length(expected);
    const char *line = unique_line(bytes, key, length);
    return line && equal_bytes(line, expected, length);
}

static int has_line_key(DWORD bytes, const char *key)
{
    DWORD start = 0, end, key_bytes = text_length(key);
    while (start < bytes) {
        end = start;
        while (end < bytes && previous_log[end] != '\r') ++end;
        if (end + 1u >= bytes || previous_log[end + 1u] != '\n') return 1;
        if (end - start >= key_bytes + 1u && equal_bytes(previous_log + start, key, key_bytes) &&
            previous_log[start + key_bytes] == '=') return 1;
        start = end + 2u;
    }
    return 0;
}

static int bind_phase_one(void)
{
    DWORD bytes, style, original[COLOR_COUNT], final_colors[COLOR_COUNT];
    BYTE final_run[sizeof(restore_command)];
    const char *raw;
    reg_value profile;
    static const char footer[] = "EVIDENCE_COMPLETE_REQUIRES_EXTERNAL_EXIT=1\r\nOBSERVER_REQUESTED_EXIT=0\r\n";
    if (!read_file(log_one_path, (BYTE *)previous_log, LOG_LIMIT, &bytes)) return 0;
    previous_log[bytes] = 0;
    if (!line_is(bytes, "HEADER", "SHZGLOB1_V1") || !line_is(bytes, "NONCE", nonce) ||
        !line_is(bytes, "PHASE", "1") || !line_is(bytes, "INITIAL_PROFILE_PRESENT", "0") ||
        !line_is(bytes, "INITIAL_RUN_PRESENT", "0") ||
        !line_is(bytes, "CHILD_EXIT_OBSERVED", "1") || !line_is(bytes, "CHILD_EXIT_CODE", "0") ||
        !line_is(bytes, "FINAL_READBACK", "AFTER_NORMAL_CHILD_EXIT") ||
        !line_is(bytes, "FINAL_STYLE", "1") || !line_is(bytes, "FINAL_PROFILE_TYPE", "3") ||
        !line_is(bytes, "FINAL_PROFILE_BYTES", "224") || !line_is(bytes, "FINAL_RUN_TYPE", "1") ||
        !line_is(bytes, "FINAL_RUN_BYTES", "34") ||
        !line_is(bytes, "SEQUENCE", "BASELINE_SHIZOS_CLASSIC_SHIZOS") ||
        !line_is(bytes, "EVIDENCE_COMPLETE_REQUIRES_EXTERNAL_EXIT", "1") ||
        !line_is(bytes, "OBSERVER_REQUESTED_EXIT", "0") ||
        !line_is(bytes, "OS_PLATFORM", "1") || !line_is(bytes, "OS_MAJOR", "4") ||
        !line_is(bytes, "OS_MINOR", "10") || bytes < sizeof(footer) - 1u ||
        !equal_bytes(previous_log + bytes - (sizeof(footer) - 1u), footer, sizeof(footer) - 1u))
        return fail("PHASE_ONE_BINDING", ERROR_INVALID_DATA);
    /* Any failure record invalidates an otherwise complete-looking prefix. */
    if (has_line_key(bytes, "RESULT") || has_line_key(bytes, "FAIL_STAGE") ||
        has_line_key(bytes, "FAIL_ERROR")) return fail("PHASE_ONE_FAILURE_RECORD", ERROR_INVALID_DATA);
    raw = unique_line(bytes, "BASELINE", COLOR_COUNT * 8u);
    if (!raw || !parse_hex(raw, COLOR_COUNT * 4u, (BYTE *)baseline))
        return fail("PHASE_ONE_BASELINE", ERROR_INVALID_DATA);
    raw = unique_line(bytes, "FINAL_PROFILE", PROFILE_BYTES * 2u);
    if (!raw || !parse_hex(raw, PROFILE_BYTES, saved_profile))
        return fail("PHASE_ONE_PROFILE_BYTES", ERROR_INVALID_DATA);
    raw = unique_line(bytes, "FINAL_COLORS", COLOR_COUNT * 8u);
    if (!raw || !parse_hex(raw, COLOR_COUNT * 4u, (BYTE *)final_colors) ||
        !colors_are(final_colors, shizos)) return fail("PHASE_ONE_FINAL_COLORS", ERROR_INVALID_DATA);
    raw = unique_line(bytes, "FINAL_RUN_RAW", sizeof(restore_command) * 2u);
    if (!raw || !parse_hex(raw, sizeof(restore_command), final_run) ||
        !equal_bytes(final_run, restore_command, sizeof(restore_command)))
        return fail("PHASE_ONE_FINAL_RUN", ERROR_INVALID_DATA);
    clear_bytes(&profile, sizeof(profile));
    profile.present = 1; profile.type = REG_BINARY; profile.bytes = PROFILE_BYTES;
    copy_bytes(profile.data, saved_profile, PROFILE_BYTES);
    if (!decode_profile(&profile, &style, original)) return 0;
    if (style != 1u || !colors_are(original, baseline) || colors_are(baseline, shizos))
        return fail("PHASE_ONE_SAVED_STATE", ERROR_INVALID_DATA);
    return 1;
}

static LRESULT CALLBACK witness_proc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    PAINTSTRUCT paint;
    if (message == WM_SYSCOLORCHANGE) {
        ++notification_count;
        /* Repaint only this independent owned window in response to a real broadcast. */
        InvalidateRect(window, NULL, TRUE);
    } else if (message == WM_PAINT) {
        clear_bytes(&paint, sizeof(paint));
        if (BeginPaint(window, &paint)) ++paint_count;
        EndPaint(window, &paint);
        return 0;
    } else if (message == WM_CLOSE) {
        witness_closed = 1;
        return 0;
    }
    return DefWindowProcA(window, message, wp, lp);
}

static int pump_messages(void)
{
    MSG message;
    DWORD count = 0;
    while (count++ < 64u && PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
        if (message.message == WM_QUIT) return fail("OBSERVER_MESSAGE_QUIT", ERROR_CANCELLED);
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }
    if (witness_closed) return fail("WITNESS_CLOSED_EARLY", ERROR_CANCELLED);
    return 1;
}

static int create_witness(void)
{
    WNDCLASSA wc;
    HINSTANCE instance = GetModuleHandleA(NULL);
    clear_bytes(&wc, sizeof(wc));
    wc.lpfnWndProc = witness_proc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = witness_class;
    if (!RegisterClassA(&wc)) return fail("WITNESS_REGISTER", GetLastError());
    witness = CreateWindowExA(0, witness_class, "Theme QA: preparing; wait for the next instruction",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, 8,
        GetSystemMetrics(SM_CYSCREEN) - 152, 300, 144, NULL, NULL, instance, NULL);
    if (!witness) return fail("WITNESS_CREATE", GetLastError());
    if (!CreateWindowExA(0, "BUTTON", "Independent native button 1", WS_CHILD | WS_VISIBLE,
        12, 8, 264, 23, witness, (HMENU)201, instance, NULL) ||
        !CreateWindowExA(0, "BUTTON", "Independent native button 2", WS_CHILD | WS_VISIBLE,
        12, 37, 264, 23, witness, (HMENU)202, instance, NULL))
        return fail("WITNESS_BUTTON_CREATE", GetLastError());
    ShowWindow(witness, SW_SHOW);
    UpdateWindow(witness);
    return pump_messages();
}

static int sample_witness(const char *stage, const DWORD *colors, DWORD previous_notifications,
                          DWORD previous_paints, int require_broadcast,
                          const progress_deadline *progress)
{
    HDC dc;
    COLORREF pixel;
    HWND button_one, button_two;
    if (!pump_messages()) return 0;
    button_one = GetDlgItem(witness, 201); button_two = GetDlgItem(witness, 202);
    if (!IsWindowVisible(witness) || IsIconic(witness) || !button_one || !button_two ||
        !IsWindowEnabled(button_one) || !IsWindowEnabled(button_two))
        return fail("WITNESS_NOT_VISIBLE_OR_ENABLED", ERROR_INVALID_WINDOW_HANDLE);
    if (require_broadcast == 1 && (notification_count <= previous_notifications || paint_count <= previous_paints))
        return 0; /* Broadcast delivery/repaint can trail palette/persistence briefly. */
    dc = GetDC(witness);
    if (!dc) return fail("WITNESS_GET_DC", GetLastError());
    pixel = GetPixel(dc, 8, 72);
    if (!ReleaseDC(witness, dc)) return fail("WITNESS_RELEASE_DC", ERROR_INVALID_HANDLE);
    if (pixel == CLR_INVALID || pixel != colors[COLOR_BTNFACE] ||
        GetSysColor(COLOR_BTNFACE) != colors[COLOR_BTNFACE]) {
        if (require_broadcast) return 0;
        return fail("WITNESS_NATIVE_PIXEL_MISMATCH", ERROR_INVALID_DATA);
    }
    if (require_broadcast == 1) {
        if (!selector_controls_invariants())
            return fail("CHILD_CONTROLS_CHANGED_OR_OVERLAP", ERROR_INVALID_DATA);
        if (!selector_controls_enabled()) return 0;
    }
    if (!check_progress(progress, "WITNESS_IN_PROGRESS_DEADLINE")) return 0;
    return emit_line("STAGE", stage) && emit_number("WITNESS_COLORCHANGE_COUNT", notification_count) &&
        emit_number("WITNESS_PAINT_COUNT", paint_count) && emit_number("WITNESS_NATIVE_PIXEL", pixel) &&
        emit_hex("ACTUAL_COLORS", (const BYTE *)colors, COLOR_COUNT * sizeof(DWORD));
}

static BOOL CALLBACK find_selector(HWND window, LPARAM ignored)
{
    DWORD pid = 0;
    char name[80];
    int bytes;
    (void)ignored;
    GetWindowThreadProcessId(window, &pid);
    if (pid != child_pid) return TRUE;
    bytes = GetClassNameA(window, name, sizeof(name));
    if (bytes == (int)(sizeof(selector_class) - 1u) &&
        equal_bytes(name, selector_class, sizeof(selector_class) - 1u)) {
        selector_window = window;
        ++enum_matches;
    }
    return TRUE;
}

static int overlap(const RECT *a, const RECT *b)
{
    return a->left < b->right && a->right > b->left &&
           a->top < b->bottom && a->bottom > b->top;
}

static int place_witness(void)
{
    RECT child_rect, own_rect;
    int screen_x = GetSystemMetrics(SM_CXSCREEN), screen_y = GetSystemMetrics(SM_CYSCREEN);
    int x[4], y[4];
    DWORD i;
    if (screen_x < 316 || screen_y < 160 || !GetWindowRect(selector_window, &child_rect))
        return fail("NONOVERLAP_SCREEN_OR_RECT", ERROR_INVALID_DATA);
    x[0] = 8; x[1] = screen_x - 308; x[2] = 8; x[3] = screen_x - 308;
    y[0] = screen_y - 152; y[1] = screen_y - 152; y[2] = 8; y[3] = 8;
    for (i = 0; i < 4u; ++i) {
        own_rect.left = x[i]; own_rect.right = x[i] + 300;
        own_rect.top = y[i]; own_rect.bottom = y[i] + 144;
        if (!overlap(&own_rect, &child_rect)) {
            if (!SetWindowPos(witness, HWND_TOP, x[i], y[i], 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW))
                return fail("WITNESS_POSITION", GetLastError());
            UpdateWindow(witness);
            return pump_messages();
        }
    }
    return fail("WITNESS_SELECTOR_OVERLAP", ERROR_INVALID_DATA);
}

static int record_child_exit(void)
{
    DWORD code;
    if (child_exit_recorded) return 1;
    if (!GetExitCodeProcess(child_handle, &code) || code == STILL_ACTIVE)
        return fail("CHILD_EXIT_CODE_READ", GetLastError());
    child_exit_recorded = 1;
    if (!emit_number("CHILD_EXIT_OBSERVED", 1u) || !emit_number("CHILD_EXIT_CODE", code)) return 0;
    if (code != 0u) return fail("CHILD_EXIT_NONZERO", code);
    return 1;
}

static int child_running(void)
{
    DWORD wait = WaitForSingleObject(child_handle, 0);
    if (wait == WAIT_TIMEOUT) return 1;
    if (wait == WAIT_OBJECT_0) {
        record_child_exit();
        return fail("CHILD_EXIT_BEFORE_REQUIRED_SEQUENCE", ERROR_INVALID_DATA);
    }
    return fail("CHILD_WAIT_FAILED", GetLastError());
}

/* Ownership/class/visibility/geometry are hard invariants. Enabled is a
 * separate transient state because the selector disables both controls while
 * applying and persisting its transaction. */
static int selector_controls_invariants(void)
{
    HWND a, b;
    DWORD owner = 0, owner_a = 0, owner_b = 0;
    RECT own_rect, child_rect;
    char class_a[16], class_b[16];
    int bytes_a, bytes_b;
    DWORD i;
    if (!selector_window || !IsWindowVisible(selector_window) || IsIconic(selector_window)) return 0;
    GetWindowThreadProcessId(selector_window, &owner);
    a = GetDlgItem(selector_window, 101); b = GetDlgItem(selector_window, 102);
    if (owner != child_pid || !a || !b || !IsWindowVisible(a) || !IsWindowVisible(b)) return 0;
    GetWindowThreadProcessId(a, &owner_a); GetWindowThreadProcessId(b, &owner_b);
    bytes_a = GetClassNameA(a, class_a, sizeof(class_a));
    bytes_b = GetClassNameA(b, class_b, sizeof(class_b));
    if (owner_a != child_pid || owner_b != child_pid || bytes_a != 6 || bytes_b != 6) return 0;
    for (i = 0; i < 6u; ++i) {
        if (class_a[i] >= 'A' && class_a[i] <= 'Z') class_a[i] += 'a' - 'A';
        if (class_b[i] >= 'A' && class_b[i] <= 'Z') class_b[i] += 'a' - 'A';
    }
    if (!equal_bytes(class_a, "button", 6u) || !equal_bytes(class_b, "button", 6u)) return 0;
    if (!GetWindowRect(witness, &own_rect) || !GetWindowRect(selector_window, &child_rect) ||
        overlap(&own_rect, &child_rect)) return 0;
    return 1;
}

static int selector_controls_enabled(void)
{
    HWND a = GetDlgItem(selector_window, 101), b = GetDlgItem(selector_window, 102);
    return a && b && IsWindowEnabled(a) && IsWindowEnabled(b);
}

static int launch_selector(void)
{
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    char command[sizeof(selector_command)];
    DWORD start = GetTickCount();
    progress_deadline progress = {0, 0};
    clear_bytes(&startup, sizeof(startup)); clear_bytes(&process, sizeof(process));
    startup.cb = sizeof(startup);
    copy_bytes(command, selector_command, sizeof(command));
    if (!CreateProcessA(selector_path, command, NULL, NULL, FALSE, 0, NULL,
                        "C:\\VXDLAB", &startup, &process))
        return fail("CHILD_CREATE_NO_ARGUMENTS", GetLastError());
    child_handle = process.hProcess; child_pid = process.dwProcessId;
    if (!CloseHandle(process.hThread)) return fail("CHILD_THREAD_HANDLE_CLOSE", GetLastError());
    if (!emit_line("CHILD_COMMAND", selector_command) || !emit_number("CHILD_PID", child_pid) || !flush_log())
        return fail("CHILD_LAUNCH_LOG", log_error);
    while ((DWORD)(GetTickCount() - start) < CHILD_READY_TIMEOUT) {
        if (!pump_messages() || !child_running()) return 0;
        if (!check_progress(&progress, "CHILD_READY_IN_PROGRESS_DEADLINE")) return 0;
        enum_matches = 0; selector_window = NULL;
        if (!EnumWindows(find_selector, 0)) return fail("CHILD_WINDOW_ENUM", GetLastError());
        if (enum_matches > 1u) return fail("CHILD_DUPLICATE_SELECTOR_WINDOWS", ERROR_INVALID_DATA);
        if (enum_matches == 1u && IsWindowVisible(selector_window)) {
            if (!place_witness()) return 0;
            if (selector_controls_invariants()) {
                if (selector_controls_enabled()) {
                    if (!check_progress(&progress, "CHILD_READY_IN_PROGRESS_DEADLINE")) return 0;
                    return emit_line("CHILD_NATIVE_GUI_CONTROLS", "CLASS_PID_101_102_ENABLED");
                }
                if (!note_progress(&progress, "CHILD_READY_IN_PROGRESS_DEADLINE")) return 0;
            }
        }
        Sleep(125);
    }
    return fail("CHILD_NATIVE_GUI_TIMEOUT", ERROR_TIMEOUT);
}

static int emit_snapshot(const snapshot *state)
{
    return emit_number("PROFILE_TYPE", state->profile.type) &&
        emit_number("PROFILE_BYTES", state->profile.bytes) &&
        emit_hex("PROFILE_RAW", state->profile.data, state->profile.bytes) &&
        emit_number("RUN_TYPE", state->run.type) && emit_number("RUN_BYTES", state->run.bytes) &&
        emit_hex("RUN_RAW", state->run.data, state->run.bytes);
}

static int wait_transition(DWORD expected_style, DWORD previous_style, int previous_absent,
                           const char *name)
{
    DWORD start = GetTickCount();
    progress_deadline progress = {0, 0};
    DWORD prior_notifications = notification_count, prior_paints = paint_count;
    DWORD original[COLOR_COUNT], style;
    snapshot state;
    int stable;
    if (!SetWindowTextA(witness, expected_style ? "Theme QA: now choose ShizukuOS" :
                                               "Theme QA: now choose Classic"))
        return fail("WITNESS_INSTRUCTION", GetLastError());
    if (!emit_line("AWAITING_TRANSITION", name) || !flush_log()) return 0;
    while ((DWORD)(GetTickCount() - start) < STAGE_TIMEOUT) {
        if (!pump_messages() || !child_running()) return 0;
        if (!check_progress(&progress, "TRANSITION_IN_PROGRESS_DEADLINE")) return 0;
        if (!selector_controls_invariants()) return fail("CHILD_CONTROLS_CHANGED_OR_OVERLAP", ERROR_INVALID_DATA);
        if (!selector_controls_enabled()) {
            if (!note_progress(&progress, "TRANSITION_IN_PROGRESS_DEADLINE")) return 0;
            Sleep(125);
            continue;
        }
        stable = stable_snapshot(&state);
        if (stable < 0) return 0;
        if (!stable) {
            if (!note_progress(&progress, "TRANSITION_IN_PROGRESS_DEADLINE")) return 0;
            Sleep(125);
            continue;
        }
        if (!check_progress(&progress, "TRANSITION_IN_PROGRESS_DEADLINE")) return 0;
        if (state.profile.present) {
            if (!decode_profile(&state.profile, &style, original)) return 0;
            if (!colors_are(original, baseline)) return fail("PROFILE_BASELINE_CHANGED", ERROR_INVALID_DATA);
            if (style == expected_style && colors_are(state.colors, expected_style ? shizos : baseline) &&
                valid_run(&state.run)) {
                if (sample_witness(name, state.colors, prior_notifications, prior_paints, 1, &progress)) {
                    if (!check_progress(&progress, "TRANSITION_IN_PROGRESS_DEADLINE")) return 0;
                    if (!emit_snapshot(&state) || !flush_log()) return fail("TRANSITION_EVIDENCE", log_error);
                    if (expected_style == 1u) copy_bytes(saved_profile, state.profile.data, PROFILE_BYTES);
                    return 1;
                }
                if (failure_stage || log_error) return fail("TRANSITION_WITNESS_OPERATION", log_error);
            }
            if ((previous_absent && style != expected_style) ||
                (!previous_absent && style != expected_style && style != previous_style))
                return fail("TRANSITION_WRONG_PROFILE_SEQUENCE", ERROR_INVALID_DATA);
        } else {
            if (!previous_absent) return fail("TRANSITION_PROFILE_DISAPPEARED", ERROR_INVALID_DATA);
            style = previous_style;
        }
        /* Unchanged previous state is allowed while waiting for a real UI action. */
        if ((previous_absent ? !state.profile.present : style == previous_style) &&
            colors_are(state.colors, previous_style ? shizos : baseline) &&
            (previous_absent ? !state.run.present : valid_run(&state.run))) {
            /* No progress observed yet: it is legitimate to wait for user input.
             * If progress was already observed, its deadline remains latched. */
        } else {
            if (!note_progress(&progress, "TRANSITION_IN_PROGRESS_DEADLINE")) return 0;
        }
        Sleep(125);
    }
    return fail("TRANSITION_TIMEOUT", ERROR_TIMEOUT);
}

static int await_child_close(void)
{
    DWORD start = GetTickCount(), wait;
    SetWindowTextA(witness, "Theme QA: close the selector normally");
    if (!emit_line("AWAITING", "ACTUAL_CHILD_GUI_CLOSE") || !flush_log()) return 0;
    while ((DWORD)(GetTickCount() - start) < CLOSE_TIMEOUT) {
        if (!pump_messages()) return 0;
        wait = WaitForSingleObject(child_handle, 0);
        if (wait == WAIT_OBJECT_0) return record_child_exit();
        if (wait != WAIT_TIMEOUT) return fail("CHILD_CLOSE_WAIT_FAILED", GetLastError());
        Sleep(125);
    }
    return fail("CHILD_GUI_CLOSE_TIMEOUT", ERROR_TIMEOUT);
}

static int final_readback(DWORD expected_style)
{
    progress_deadline progress = {0, 0};
    DWORD original[COLOR_COUNT], style;
    snapshot state;
    int stable;
    for (;;) {
        if (!pump_messages() || !check_progress(&progress, "FINAL_READBACK_IN_PROGRESS_DEADLINE")) return 0;
        stable = stable_snapshot(&state);
        if (stable < 0) return 0;
        if (!stable) {
            if (!note_progress(&progress, "FINAL_READBACK_IN_PROGRESS_DEADLINE")) return 0;
            Sleep(125);
            continue;
        }
        if (!check_progress(&progress, "FINAL_READBACK_IN_PROGRESS_DEADLINE")) return 0;
        if (!decode_profile(&state.profile, &style, original)) return 0;
        if (style != expected_style || !colors_are(original, baseline) ||
            !colors_are(state.colors, expected_style ? shizos : baseline) || !valid_run(&state.run))
            return fail("FINAL_STATE_CHANGED_AFTER_ACCEPTED_SEQUENCE", ERROR_INVALID_DATA);
        if (!check_progress(&progress, "FINAL_READBACK_IN_PROGRESS_DEADLINE")) return 0;
        return emit_line("FINAL_READBACK", "AFTER_NORMAL_CHILD_EXIT") &&
            emit_number("FINAL_STYLE", style) &&
            emit_hex("FINAL_COLORS", (const BYTE *)state.colors, sizeof(state.colors)) &&
            emit_number("FINAL_PROFILE_TYPE", state.profile.type) &&
            emit_number("FINAL_PROFILE_BYTES", state.profile.bytes) &&
            emit_hex("FINAL_PROFILE", state.profile.data, state.profile.bytes) &&
            emit_number("FINAL_RUN_TYPE", state.run.type) && emit_number("FINAL_RUN_BYTES", state.run.bytes) &&
            emit_hex("FINAL_RUN_RAW", state.run.data, state.run.bytes) && flush_log();
    }
}

static int phase_one(void)
{
    snapshot state;
    int stable = stable_snapshot(&state);
    if (stable != 1) return fail("INITIAL_SNAPSHOT_UNSTABLE", ERROR_INVALID_DATA);
    if (state.profile.present || state.run.present)
        return fail("INITIAL_PROFILE_OR_RUN_NOT_ABSENT", ERROR_INVALID_DATA);
    copy_bytes(baseline, state.colors, sizeof(baseline));
    if (colors_are(baseline, shizos)) return fail("INITIAL_BASELINE_ALREADY_SHIZOS", ERROR_INVALID_DATA);
    if (!emit_number("INITIAL_PROFILE_PRESENT", 0u) || !emit_number("INITIAL_RUN_PRESENT", 0u) ||
        !emit_hex("BASELINE", (const BYTE *)baseline, sizeof(baseline)) ||
        !emit_snapshot(&state) || !sample_witness("INITIAL_BASELINE", baseline, 0, 0, 0, NULL) || !flush_log()) return 0;
    if (!launch_selector() || !wait_transition(1u, 0u, 1, "SHIZOS_FIRST")) return 0;
    if (!wait_transition(0u, 1u, 0, "CLASSIC_ORIGINAL_BASELINE")) return 0;
    if (!wait_transition(1u, 0u, 0, "SHIZOS_SAVED")) return 0;
    if (!emit_line("SEQUENCE", "BASELINE_SHIZOS_CLASSIC_SHIZOS") || !flush_log()) return 0;
    return await_child_close() && final_readback(1u);
}

static int phase_two(void)
{
    DWORD start = GetTickCount(), style, original[COLOR_COUNT];
    progress_deadline progress = {0, 0};
    snapshot state;
    int stable, restored = 0;
    if (!emit_line("RESTORE_PROCESS_EXTERNAL_EXIT", "NOT_OBSERVED_NO_PROCESS_HANDLE") ||
        !emit_line("COLD_BOOT_IDENTITY", "REQUIRES_EXTERNAL_SAME_COW_SECOND_EPOCH_RECEIPT") ||
        !emit_hex("BASELINE", (const BYTE *)baseline, sizeof(baseline)) || !flush_log()) return 0;
    while ((DWORD)(GetTickCount() - start) < RESTORE_TIMEOUT) {
        if (!pump_messages()) return 0;
        if (!check_progress(&progress, "COLD_BOOT_IN_PROGRESS_DEADLINE")) return 0;
        stable = stable_snapshot(&state);
        if (stable < 0) return 0;
        if (!stable) {
            if (!note_progress(&progress, "COLD_BOOT_IN_PROGRESS_DEADLINE")) return 0;
            Sleep(125);
            continue;
        }
        if (!check_progress(&progress, "COLD_BOOT_IN_PROGRESS_DEADLINE")) return 0;
        if (!decode_profile(&state.profile, &style, original)) return 0;
        if (style != 1u || !colors_are(original, baseline) ||
            !equal_bytes(state.profile.data, saved_profile, PROFILE_BYTES) || !valid_run(&state.run))
            return fail("COLD_BOOT_SAVED_VALUES_CHANGED", ERROR_INVALID_DATA);
        if (colors_are(state.colors, shizos)) {
            /* Mode 2 permits a short pending repaint without requiring a
             * broadcast that may have happened before this window existed. */
            if (sample_witness("COLD_BOOT_AUTOMATIC_SHIZOS_BEFORE_CHILD", state.colors, 0, 0, 2, &progress)) {
                if (!check_progress(&progress, "COLD_BOOT_IN_PROGRESS_DEADLINE")) return 0;
                if (!emit_snapshot(&state) || !flush_log()) return 0;
                restored = 1;
                break;
            }
            if (failure_stage || log_error) return 0;
            if (!note_progress(&progress, "COLD_BOOT_IN_PROGRESS_DEADLINE")) return 0;
            Sleep(125);
            continue;
        }
        if (!colors_are(state.colors, baseline)) {
            if (!note_progress(&progress, "COLD_BOOT_IN_PROGRESS_DEADLINE")) return 0;
        }
        Sleep(125);
    }
    if (!restored) return fail("COLD_BOOT_AUTOMATIC_RESTORE_TIMEOUT", ERROR_TIMEOUT);
    SetWindowTextA(witness, "Theme QA: automatic restore observed; choose Classic");
    if (!launch_selector() || !wait_transition(0u, 1u, 0, "COLD_BOOT_CLASSIC_RETURN")) return 0;
    if (!emit_line("SEQUENCE", "AUTOMATIC_SHIZOS_BEFORE_CHILD_CLASSIC_RETURN") || !flush_log()) return 0;
    return await_child_close() && final_readback(0u);
}

static DWORD run_observer(void)
{
    OSVERSIONINFOA version;
    DWORD success = 0, wait;
    if (!read_case()) return 2u;
    if (phase == 2u && !bind_phase_one()) return 3u;
    log_handle = CreateFileA(phase == 1u ? log_one_path : log_two_path, GENERIC_WRITE,
        FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_handle == INVALID_HANDLE_VALUE) return 4u;
    emit_line("HEADER", phase == 1u ? "SHZGLOB1_V1" : "SHZGLOB2_V1");
    emit_line("NONCE", nonce); emit_number("PHASE", phase);
    emit_number("OBSERVER_PID", GetCurrentProcessId());
    emit_line("OBSERVER_ROLE", "INDEPENDENT_NATIVE_READ_ONLY_THEME_OBSERVER");
    emit_line("PROCESS_SELF_LOG_IS_NOT", "EXTERNAL_EXIT_OR_BOOT_OR_SOURCE_PROOF");
    clear_bytes(&version, sizeof(version)); version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version)) fail("OS_IDENTITY_QUERY", GetLastError());
    else {
        emit_number("OS_PLATFORM", version.dwPlatformId); emit_number("OS_MAJOR", version.dwMajorVersion);
        emit_number("OS_MINOR", version.dwMinorVersion); emit_number("OS_BUILD_RAW", version.dwBuildNumber);
        emit_number("OS_BUILD_LOW_WORD", version.dwBuildNumber & 0xffffu);
        if (version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
            version.dwMajorVersion != 4u || version.dwMinorVersion != 10u)
            fail("OS_NOT_NATIVE_WIN98_4_10", ERROR_OLD_WIN_VERSION);
    }
    if (!failure_stage && !log_error && flush_log() && create_witness())
        success = phase == 1u ? phase_one() : phase_two();
    if (!success && !failure_stage) fail("EVIDENCE_OR_LOG_OPERATION", log_error);
    if (child_handle) {
        wait = WaitForSingleObject(child_handle, 0);
        if (wait == WAIT_OBJECT_0 && !child_exit_recorded) record_child_exit();
        else if (wait == WAIT_TIMEOUT) {
            emit_line("CHILD_EXTERNAL_EXIT", "NOT_OBSERVED_LEFT_RUNNING_NO_TERMINATION");
            success = 0;
        } else if (wait != WAIT_OBJECT_0) {
            fail("CHILD_FINAL_WAIT", GetLastError()); success = 0;
        }
        if (!CloseHandle(child_handle)) { fail("CHILD_PROCESS_HANDLE_CLOSE", GetLastError()); success = 0; }
        child_handle = NULL;
    }
    if (witness && !DestroyWindow(witness)) { fail("WITNESS_DESTROY", GetLastError()); success = 0; }
    if (failure_stage || log_error) success = 0;
    if (success) {
        emit_line("EVIDENCE_COMPLETE_REQUIRES_EXTERNAL_EXIT", "1");
        emit_number("OBSERVER_REQUESTED_EXIT", 0u);
    } else {
        emit_line("RESULT", "FAIL");
        emit_line("FAIL_STAGE", failure_stage ? failure_stage : "LOG_WRITE_OR_FLUSH");
        emit_number("FAIL_ERROR", failure_error ? failure_error : log_error);
        emit_number("OBSERVER_REQUESTED_EXIT", 5u);
    }
    if (!flush_log()) success = 0;
    if (!CloseHandle(log_handle)) success = 0;
    log_handle = INVALID_HANDLE_VALUE;
    return success ? 0u : 5u;
}

void mainCRTStartup(void)
{
    ExitProcess(run_observer());
}
