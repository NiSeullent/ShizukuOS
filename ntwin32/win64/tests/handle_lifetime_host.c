/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the real NTW64 client through public APIs. Only the Win32 device,
 * clock and error callbacks are modeled; no Windows, VMM or Kernel64 executes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ntw64.c"

static unsigned long test_checks;
static const char *test_scenario;
static DWORD test_error, test_clock;
static unsigned test_create_requests, test_release_requests, test_started, test_released;
static uint32_t test_next_pid = 1, test_remote[4];
static int test_auto_exit = 1, test_create_failure, test_release_failure;
static uint8_t test_queue[8][SHZ_MSG_SLOT_SIZE] __attribute__((aligned(8)));
static unsigned test_head, test_tail;
#define CHECK(x) do { ++test_checks; if (!(x)) { fprintf(stderr, "FAIL %s line %d: %s\n", test_scenario, __LINE__, #x); exit(1); } } while (0)

void SetLastError(DWORD error) { test_error = error; }
DWORD GetLastError(void) { return test_error; }
void Sleep(DWORD milliseconds) { test_clock += milliseconds; }
DWORD GetTickCount(void) { return test_clock; }
HANDLE CreateFileA(const char *path, DWORD access, DWORD sharing, void *security,
                   DWORD disposition, DWORD flags, HANDLE template_handle)
{
    CHECK(strcmp(path, "\\\\.\\NTWRAP9X.VXD") == 0);
    CHECK(!access && !sharing && !security && disposition == OPEN_EXISTING &&
          flags == FILE_FLAG_DELETE_ON_CLOSE && !template_handle);
    return (HANDLE)(uintptr_t)0xd10c;
}

static void test_enqueue(uint32_t opcode, uint16_t flags, uint64_t request_id,
                         int32_t status, const void *payload, uint16_t bytes)
{
    shz_msg_hdr_t *header;
    CHECK(test_head - test_tail < 8 && bytes <= SHZ_MSG_MAX_INLINE);
    uint8_t *message = test_queue[test_head++ % 8];
    memset(message, 0, SHZ_MSG_SLOT_SIZE);
    header = (shz_msg_hdr_t *)message;
    header->opcode = opcode; header->flags = flags;
    header->request_id = request_id; header->status = status;
    header->payload_length = bytes;
    if (bytes) memcpy(message + sizeof *header, payload, bytes);
}

static void test_exit_event(uint32_t pid)
{
    shz_w64_event_t event = {0};
    event.pid = pid; event.state = SHZ_W64_PS_EXITED; event.exit_code = 7;
    test_enqueue(SHZ_OP_W64_PROCESS_EXITED, SHZ_MSGF_ONEWAY, 0, SHZ_OK, &event, sizeof event);
}

BOOL DeviceIoControl(HANDLE handle, DWORD code, void *input, DWORD input_bytes,
                     void *output, DWORD output_bytes, DWORD *returned, void *overlapped)
{
    CHECK(handle == (HANDLE)(uintptr_t)0xd10c && returned && !overlapped);
    if (code == NTWV_IOCTL_W64_OPEN) {
        struct ntwv_w64_open info = {0};
        CHECK(!input && !input_bytes && output_bytes == sizeof info);
        info.magic = NTWV_W64_MAGIC; info.size = sizeof info;
        info.abi_major = SHZ_ABI_MAJOR; info.abi_minor = SHZ_ABI_MINOR;
        info.channel_id = 2; info.self_domain = 5; info.peer_domain = 4; info.generation = 1;
        memcpy(output, &info, sizeof info); *returned = sizeof info;
        return TRUE;
    }
    if (code == NTWV_IOCTL_W64_RECV) {
        CHECK(!input && !input_bytes && output_bytes == SHZ_MSG_SLOT_SIZE);
        if (test_head == test_tail) { SetLastError(NTWV_ERROR_NO_MORE_ITEMS); return FALSE; }
        memcpy(output, test_queue[test_tail++ % 8], SHZ_MSG_SLOT_SIZE);
        *returned = SHZ_MSG_SLOT_SIZE;
        return TRUE;
    }
    CHECK(code == NTWV_IOCTL_W64_SEND && input_bytes >= sizeof(shz_msg_hdr_t));
    CHECK(output_bytes == sizeof(int32_t));
    shz_msg_hdr_t request;
    memcpy(&request, input, sizeof request);
    CHECK(input_bytes == sizeof request + request.payload_length && request.request_id != 0);
    const uint8_t *payload = (const uint8_t *)input + sizeof request;
    if (request.opcode == SHZ_OP_W64_CREATE_PROCESS) {
        shz_w64_create_t arguments;
        shz_w64_event_t event = {0};
        unsigned remote_slot;
        ++test_create_requests;
        CHECK(request.payload_length == sizeof arguments + 2);
        memcpy(&arguments, payload, sizeof arguments);
        CHECK(arguments.path_chars == 1 && arguments.cmdline_chars == 0 &&
              arguments.cwd_chars == 0 && arguments.block_bytes == 2);
        CHECK(payload[sizeof arguments] == 't' && payload[sizeof arguments + 1] == 0);
        if (test_create_failure == 1) {
            test_enqueue(request.opcode, SHZ_MSGF_REPLY, request.request_id, SHZ_E_NOMEM, NULL, 0);
        } else if (test_create_failure == 2) {
            event.state = SHZ_W64_PS_FAILED; event.status = (int32_t)0xc0000034u;
            test_enqueue(request.opcode, SHZ_MSGF_REPLY, request.request_id, SHZ_OK, &event, sizeof event);
        } else if (test_create_failure == 3) {
            test_create_failure = 0;
            SetLastError(ERROR_GEN_FAILURE);
            return FALSE;
        } else {
            for (remote_slot = 0; remote_slot < 4 && test_remote[remote_slot]; ++remote_slot) { }
            CHECK(remote_slot < 4);
            test_remote[remote_slot] = event.pid = test_next_pid++;
            event.state = SHZ_W64_PS_STARTED;
            ++test_started;
            test_enqueue(request.opcode, SHZ_MSGF_REPLY, request.request_id, SHZ_OK, &event, sizeof event);
            if (test_auto_exit) test_exit_event(event.pid);
        }
        test_create_failure = 0;
    } else if (request.opcode == SHZ_OP_W64_RELEASE) {
        shz_w64_kill_t release;
        unsigned remote_slot;
        ++test_release_requests;
        CHECK(request.payload_length == sizeof release);
        memcpy(&release, payload, sizeof release);
        for (remote_slot = 0; remote_slot < 4 && test_remote[remote_slot] != release.pid; ++remote_slot) { }
        CHECK(remote_slot < 4);
        if (test_release_failure == 1) {
            test_enqueue(request.opcode, SHZ_MSGF_REPLY, request.request_id, SHZ_E_BUSY, NULL, 0);
        } else {
            test_remote[remote_slot] = 0; ++test_released;
            test_enqueue(request.opcode, SHZ_MSGF_REPLY, request.request_id,
                         test_release_failure == 2 ? SHZ_E_NOENT : SHZ_OK, NULL, 0);
        }
        test_release_failure = 0;
    } else {
        shz_w64_info_t info = {0};
        CHECK(request.opcode == SHZ_OP_W64_QUERY && request.payload_length == 0);
        info.abi_major = SHZ_ABI_MAJOR; info.abi_minor = SHZ_ABI_MINOR;
        info.subsystem_version = SHZ_W64_SUBSYS_VERSION;
        test_enqueue(request.opcode, SHZ_MSGF_REPLY, request.request_id, SHZ_OK, &info, sizeof info);
    }
    *(int32_t *)output = SHZ_OK; *returned = sizeof(int32_t);
    return TRUE;
}

static HANDLE test_create(void)
{
    static const uint16_t path[] = {'t', 0};
    HANDLE result = NULL;
    CHECK(NtwCreateProcess64W(path, NULL, NULL, &result));
    CHECK(result != NULL);
    return result;
}

static void test_join_close(HANDLE handle)
{
    DWORD code = 0;
    CHECK(NtwWaitProcess64(handle, 0, &code) && code == 7);
    CHECK(NtwCloseProcess64(handle));
    CHECK(!NtwWaitProcess64(handle, 0, &code) && GetLastError() == NTW64_ERROR_INVALID_HANDLE);
}

static void test_exhaustion(void)
{
    HANDLE stale[8] = {0};
    unsigned index, generation;
    DWORD code;
    for (index = 0; index < 8; ++index) {
        for (generation = 1; generation <= 8191; ++generation) {
            HANDLE active = test_create();
            /* The original implementation revives stale[0] on creation 8192. */
            if (index && generation == 1)
                CHECK(!NtwWaitProcess64(stale[0], 0, &code) && GetLastError() == NTW64_ERROR_INVALID_HANDLE);
            CHECK(((uintptr_t)active & 7u) == index);
            CHECK((((uintptr_t)active >> 3) & 0x1fffu) == generation);
            if (generation == 1) stale[index] = active;
            else CHECK(!NtwWaitProcess64(stale[index], 0, &code) && GetLastError() == NTW64_ERROR_INVALID_HANDLE);
            test_join_close(active);
        }
    }
    static const uint16_t path[] = {'t', 0};
    HANDLE rejected = (HANDLE)(uintptr_t)1;
    const unsigned creates = test_create_requests;
    CHECK(!NtwCreateProcess64W(path, NULL, NULL, &rejected));
    CHECK(rejected == NULL && GetLastError() == ERROR_TOO_MANY_OPEN_FILES);
    CHECK(test_create_requests == creates); /* exhaustion must precede remote launch */
    CHECK(test_started == 65528 && test_released == test_started);
    for (index = 0; index < 8; ++index)
        CHECK(!NtwWaitProcess64(stale[index], 0, &code) && GetLastError() == NTW64_ERROR_INVALID_HANDLE);
}

static void test_failure_paths(void)
{
    static const uint16_t path[] = {'t', 0};
    static const DWORD errors[] = {ERROR_NOT_ENOUGH_MEMORY, ERROR_FILE_NOT_FOUND, ERROR_GEN_FAILURE};
    HANDLE stale = test_create(), next;
    unsigned failure;
    DWORD code;
    test_join_close(stale);
    for (failure = 1; failure <= 3; ++failure) {
        HANDLE rejected = (HANDLE)(uintptr_t)1;
        test_create_failure = (int)failure;
        CHECK(!NtwCreateProcess64W(path, NULL, NULL, &rejected));
        CHECK(!rejected && GetLastError() == errors[failure - 1]);
        CHECK(test_started == 1);
    }
    next = test_create();
    CHECK((((uintptr_t)next >> 3) & 0x1fffu) == 2 && ((uintptr_t)next & 7u) == 0);
    CHECK(!NtwWaitProcess64(stale, 0, &code) && GetLastError() == NTW64_ERROR_INVALID_HANDLE);
    CHECK(NtwWaitProcess64(next, 0, &code) && code == 7);
    test_release_failure = 1;
    CHECK(!NtwCloseProcess64(next) && GetLastError() == ERROR_BUSY);
    CHECK(NtwWaitProcess64(next, 0, &code) && code == 7); /* failed close retains the live handle */
    CHECK(NtwCloseProcess64(next));
    next = test_create();
    CHECK((((uintptr_t)next >> 3) & 0x1fffu) == 3);
    CHECK(NtwWaitProcess64(next, 0, &code) && code == 7);
    test_release_failure = 2;
    CHECK(NtwCloseProcess64(next)); /* remote NOENT is the existing rundown policy */
    next = test_create();
    CHECK((((uintptr_t)next >> 3) & 0x1fffu) == 4);
    test_join_close(next);
    CHECK(test_started == test_released);
}

static void test_deferred_close(void)
{
    ntw64_info_t info;
    DWORD code;
    test_auto_exit = 0;
    HANDLE stale = test_create();
    CHECK(NtwCloseProcess64(stale));
    CHECK(test_release_requests == 0); /* closing a running process leaves it running */
    CHECK(!NtwWaitProcess64(stale, 0, &code) && GetLastError() == NTW64_ERROR_INVALID_HANDLE);
    test_exit_event(1);
    CHECK(NtwQuerySubsystem64(&info)); /* pump the process's real EXITED frame */
    test_auto_exit = 1;
    test_release_failure = 1;
    HANDLE second = test_create(); /* failed deferred release keeps slot zero occupied */
    CHECK(((uintptr_t)second & 7u) == 1 && (((uintptr_t)second >> 3) & 0x1fffu) == 1);
    test_join_close(second);
    HANDLE reused = test_create();
    CHECK(((uintptr_t)reused & 7u) == 0 && (((uintptr_t)reused >> 3) & 0x1fffu) == 2);
    CHECK(!NtwWaitProcess64(stale, 0, &code) && GetLastError() == NTW64_ERROR_INVALID_HANDLE);
    test_join_close(reused);
    CHECK(test_started == test_released);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    test_scenario = argv[1];
    if (!strcmp(argv[1], "exhaustion")) test_exhaustion();
    else if (!strcmp(argv[1], "failure-paths")) test_failure_paths();
    else if (!strcmp(argv[1], "deferred-close")) test_deferred_close();
    else CHECK(0);
    printf("PASS %s: %lu actual client checks, %u starts/%u releases\n",
           test_scenario, test_checks, test_started, test_released);
    return 0;
}
