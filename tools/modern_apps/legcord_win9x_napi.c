/* Actual Node-API adapter for the unchanged native source-read lease helper.
 * SPDX-License-Identifier: GPL-2.0-only
 * Requires real x86 Win98SE and the frozen Electron/Node runtime; no shim API.
 */
#define WIN32_LEAN_AND_MEAN
#define NAPI_VERSION 8
#define NAPI_EXTERN
#include <windows.h>
#include <node_api.h>
#include <stdbool.h>
#include <string.h>
#include "legcord_win9x_source_lease.h"

_Static_assert(sizeof(void *) == 4, "Only the actual PE32 Win98 profile");
#define API_LIST(X) \
    X(napi_get_cb_info) X(napi_is_array) X(napi_get_array_length) \
    X(napi_get_element) X(napi_typeof) X(napi_get_value_string_utf8) \
    X(napi_create_object) X(napi_create_function) X(napi_define_properties) \
    X(napi_get_boolean) X(napi_get_undefined) X(napi_wrap) X(napi_unwrap) \
    X(napi_throw_error) X(napi_throw_type_error) X(napi_get_global) \
    X(napi_get_named_property) X(napi_get_node_version) X(napi_get_version) \
    X(napi_add_env_cleanup_hook)
typedef struct api_table {
#define FIELD(name) __typeof__(&name) name;
    API_LIST(FIELD)
#undef FIELD
} api_table;
typedef struct environment environment;
typedef struct lease_object {
    environment *owner;
    legcord_source_lease *native;
    struct lease_object *next;
} lease_object;
struct environment {
    api_table api;
    lease_object *objects;
    unsigned refs;
    unsigned active;
    BOOL closing;
};

static void environment_unref(environment *state)
{
    if (!--state->refs) HeapFree(GetProcessHeap(), 0, state);
}

static void release_native(lease_object *object)
{
    legcord_source_lease *native = object->native;
    object->native = NULL; /* publish release before any callback/re-entry */
    if (native) {
        --object->owner->active;
        legcord_win9x_ReleaseSourceReadLeases(native);
    }
}

static void finalize_object(napi_env env, void *data, void *hint)
{
    lease_object *object = (lease_object *)data;
    environment *state = object->owner;
    lease_object **link = &state->objects;
    (void)env; (void)hint;
    while (*link && *link != object) link = &(*link)->next;
    if (*link == object) *link = object->next;
    release_native(object);
    HeapFree(GetProcessHeap(), 0, object);
    environment_unref(state);
}

static void cleanup_environment(void *data)
{
    environment *state = (environment *)data;
    lease_object *object;
    state->closing = TRUE;
    for (object = state->objects; object; object = object->next)
        release_native(object);
    /* Object finalizers may precede or follow this hook. Their separate
     * references keep the state alive, without making any JS calls here. */
    environment_unref(state);
}

static napi_status callback_info(napi_env env, napi_callback_info info,
                                size_t *argc, napi_value *argv,
                                napi_value *receiver, environment **owner)
{
    /* Bootstrap the per-environment table without a mutable global table.
     * Every signature is taken directly from the exact public API header. */
    __typeof__(&napi_get_cb_info) get_info = (__typeof__(&napi_get_cb_info))
        GetProcAddress(GetModuleHandleA(NULL), "napi_get_cb_info");
    void *data = NULL;
    napi_status status;
    if (!get_info) return napi_generic_failure;
    status = get_info(env, info, argc, argv, receiver, &data);
    *owner = (environment *)data;
    return status;
}

static napi_value error(environment *state, napi_env env, const char *message,
                        BOOL type_error)
{
    if (type_error) state->api.napi_throw_type_error(env, "ERR_WIN98_SOURCE_LEASE", message);
    else state->api.napi_throw_error(env, "ERR_WIN98_SOURCE_LEASE", message);
    return NULL;
}

static lease_object *receiver_object(environment *state, napi_env env,
                                     napi_value receiver)
{
    lease_object *object = NULL;
    lease_object *known;
    BOOL owned = FALSE;
    if (receiver && state->api.napi_unwrap(env, receiver, (void **)&object) == napi_ok) {
        /* An unrelated addon may wrap an entirely different data structure.
         * Check membership without dereferencing that foreign raw pointer. */
        for (known = state->objects; known; known = known->next)
            if (known == object) { owned = TRUE; break; }
    }
    if (!owned) {
        error(state, env, "Call the native lease method on its actual returned object", TRUE);
        return NULL;
    }
    return object;
}

static napi_value held(napi_env env, napi_callback_info info)
{
    environment *state = NULL;
    napi_value receiver, result;
    lease_object *object;
    size_t argc = 0;
    if (callback_info(env, info, &argc, NULL, &receiver, &state) != napi_ok || !state)
        return NULL;
    object = receiver_object(state, env, receiver);
    if (!object) return NULL;
    if (state->api.napi_get_boolean(env, object->native != NULL, &result) != napi_ok)
        return NULL;
    return result;
}

static napi_value release(napi_env env, napi_callback_info info)
{
    environment *state = NULL;
    napi_value receiver, result;
    lease_object *object;
    size_t argc = 0;
    if (callback_info(env, info, &argc, NULL, &receiver, &state) != napi_ok || !state)
        return NULL;
    object = receiver_object(state, env, receiver);
    if (!object) return NULL;
    release_native(object);
    if (state->api.napi_get_undefined(env, &result) != napi_ok) return NULL;
    return result;
}

static BOOL ascii_dos_path(const char *path, size_t length)
{
    size_t index, start = 3;
    if (length < 4 || length >= MAX_PATH ||
            !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) ||
            path[1] != ':' || path[2] != '\\') return FALSE;
    for (index = 3; index <= length; ++index) {
        unsigned char value = (unsigned char)path[index];
        if (index < length && (value < 32 || value > 126 || value == ':' ||
                value == '*' || value == '?' || value == '/' || value == '"' ||
                value == '<' || value == '>' || value == '|')) return FALSE;
        if (index == length || value == '\\') {
            size_t count = index - start;
            char device[9]; size_t base = 0;
            if (!count || (count == 1 && path[start] == '.') ||
                    (count == 2 && path[start] == '.' && path[start + 1] == '.') ||
                    path[index - 1] == '.' || path[index - 1] == ' ') return FALSE;
            while (base < count && base < 8 && path[start + base] != '.') {
                char letter = path[start + base];
                device[base++] = letter >= 'a' && letter <= 'z' ? letter - ('a' - 'A') : letter;
            }
            device[base] = 0;
            if (!strcmp(device, "CON") || !strcmp(device, "PRN") ||
                    !strcmp(device, "AUX") || !strcmp(device, "NUL") || !strcmp(device, "CLOCK$") ||
                    (base == 4 && device[3] >= '1' && device[3] <= '9' &&
                     ((!memcmp(device, "COM", 3)) || (!memcmp(device, "LPT", 3))))) return FALSE;
            start = index + 1;
        }
    }
    return path[length] == 0;
}

static BOOL local_drive(const char *path)
{
    char root[4] = { path[0], ':', '\\', 0 };
    UINT type = GetDriveTypeA(root);
    return type == DRIVE_FIXED || type == DRIVE_REMOVABLE ||
        type == DRIVE_CDROM || type == DRIVE_RAMDISK;
}

static napi_value acquire(napi_env env, napi_callback_info info)
{
    environment *state = NULL;
    napi_value args[2], result;
    size_t argc = 2;
    uint32_t count, index, previous;
    bool array = false;
    LPCSTR *paths = NULL;
    char *storage;
    legcord_source_lease *native = NULL;
    lease_object *object = NULL;
    napi_status status;
    const char *failure = "Native acquisition or Node-API object creation failed";
    BOOL type_error = FALSE;
    if (callback_info(env, info, &argc, args, NULL, &state) != napi_ok || !state)
        return NULL;
    if (state->closing) return error(state, env, "The actual runtime environment is closing", FALSE);
    if (argc != 1 || state->api.napi_is_array(env, args[0], &array) != napi_ok || !array ||
            state->api.napi_get_array_length(env, args[0], &count) != napi_ok ||
            !count || count > 256)
        return error(state, env, "Pass one nonempty, bounded complete path array", TRUE);
    if (state->active >= 16) return error(state, env, "Bounded native lease capacity exceeded", FALSE);
    paths = (LPCSTR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                              count * (sizeof(LPCSTR) + MAX_PATH));
    if (!paths) return error(state, env, "Cannot allocate bounded path storage", FALSE);
    storage = (char *)(paths + count);
    for (index = 0; index < count; ++index) {
        napi_value value;
        napi_valuetype type;
        size_t length, written;
        paths[index] = storage + index * MAX_PATH;
        if (state->api.napi_get_element(env, args[0], index, &value) != napi_ok ||
                state->api.napi_typeof(env, value, &type) != napi_ok || type != napi_string ||
                state->api.napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok ||
                length < 4 || length >= MAX_PATH ||
                state->api.napi_get_value_string_utf8(env, value, (char *)paths[index], MAX_PATH, &written) != napi_ok ||
                written != length || !ascii_dos_path(paths[index], length)) {
            failure = "Every path must be an exact representable ASCII DOS file path";
            type_error = TRUE; goto failed;
        }
        for (previous = 0; previous < index; ++previous) {
            if (!lstrcmpiA(paths[index], paths[previous])) {
                failure = "Duplicate source paths are not a complete unique inventory";
                type_error = TRUE; goto failed;
            }
        }
        if (!local_drive(paths[index])) {
            failure = "Source leases require actual local media, not a mapped network drive";
            goto failed;
        }
    }
    /* Array element getters can re-enter JS/native acquisition. Recheck the
     * bound after all such calls and before opening any native handles. */
    if (state->closing || state->active >= 16) {
        failure = "Runtime closing or reentrant lease capacity exceeded"; goto failed;
    }
    if (!legcord_win9x_AcquireSourceReadLeases(paths, count, &native)) {
        failure = "Actual Win98 native read lease rejected this tree"; goto failed;
    }
    HeapFree(GetProcessHeap(), 0, paths); paths = NULL;
    object = (lease_object *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object) goto failed;
    object->native = native; native = NULL;
    object->owner = state;
    ++state->refs; ++state->active;
    object->next = state->objects; state->objects = object;
    status = state->api.napi_create_object(env, &result);
    if (status != napi_ok) goto failed;
    {
        napi_property_descriptor properties[] = {
            { "held", NULL, NULL, held, NULL, NULL, napi_enumerable, state },
            { "release", NULL, release, NULL, NULL, NULL, napi_enumerable, state }
        };
        status = state->api.napi_define_properties(env, result, 2, properties);
    }
    if (status != napi_ok) goto failed;
    /* Only the returned object owns this pointer. Detached methods unwrap
     * their receiver and fail, rather than retaining a stale callback pointer. */
    if (state->api.napi_wrap(env, result, object, finalize_object, NULL, NULL) != napi_ok)
        goto failed;
    return result;
failed:
    if (paths) HeapFree(GetProcessHeap(), 0, paths);
    if (native) legcord_win9x_ReleaseSourceReadLeases(native);
    if (object) finalize_object(env, object, NULL);
    return error(state, env, failure, type_error);
}

static BOOL equal_string(environment *state, napi_env env, napi_value value,
                         const char *expected)
{
    char text[64]; size_t count;
    napi_valuetype type;
    return state->api.napi_typeof(env, value, &type) == napi_ok && type == napi_string &&
        state->api.napi_get_value_string_utf8(env, value, text, sizeof(text), &count) == napi_ok &&
        count == strlen(expected) && !strcmp(text, expected);
}

static BOOL runtime_matches(environment *state, napi_env env)
{
    napi_value global, process, versions, value;
    const napi_node_version *node;
    uint32_t version;
    OSVERSIONINFOA os = { 0 };
    os.dwOSVersionInfoSize = sizeof(os);
    if (!GetVersionExA(&os) || os.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
            os.dwMajorVersion != 4 || os.dwMinorVersion != 10 || LOWORD(os.dwBuildNumber) != 2222 ||
            state->api.napi_get_node_version(env, &node) != napi_ok || !node ||
            node->major != 24 || node->minor != 18 || node->patch != 0 ||
            state->api.napi_get_version(env, &version) != napi_ok || version < NAPI_VERSION ||
            state->api.napi_get_global(env, &global) != napi_ok ||
            state->api.napi_get_named_property(env, global, "process", &process) != napi_ok ||
            state->api.napi_get_named_property(env, process, "versions", &versions) != napi_ok)
        return FALSE;
#define REQUIRE_STRING(object, name, expected) \
    if (state->api.napi_get_named_property(env, object, name, &value) != napi_ok || \
        !equal_string(state, env, value, expected)) return FALSE
    REQUIRE_STRING(process, "platform", "win32");
    REQUIRE_STRING(process, "arch", "ia32");
    REQUIRE_STRING(versions, "electron", "43.2.0");
    REQUIRE_STRING(versions, "chrome", "150.0.7871.129");
    REQUIRE_STRING(versions, "node", "24.18.0");
#undef REQUIRE_STRING
    return TRUE;
}

NAPI_MODULE_INIT()
{
    environment *state;
    HMODULE executable = GetModuleHandleA(NULL);
    napi_value function;
    BOOL complete = TRUE;
    state = (environment *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*state));
    if (!state) return NULL;
#define LOAD(name) state->api.name = (__typeof__(&name))GetProcAddress(executable, #name); \
                  if (!state->api.name) complete = FALSE;
    API_LIST(LOAD)
#undef LOAD
    if (!complete) {
        if (state->api.napi_throw_error)
            error(state, env, "The actual executable does not export every required Node-API function", FALSE);
        HeapFree(GetProcessHeap(), 0, state);
        return NULL;
    }
    if (!runtime_matches(state, env)) {
        error(state, env, "Require actual Win98SE x86 Electron43.2.0 / Node24.18.0", FALSE);
        HeapFree(GetProcessHeap(), 0, state);
        return NULL;
    }
    state->refs = 1;
    if (state->api.napi_add_env_cleanup_hook(env, cleanup_environment, state) != napi_ok) {
        error(state, env, "Cannot establish the real environment cleanup hook", FALSE);
        HeapFree(GetProcessHeap(), 0, state);
        return NULL;
    }
    if (state->api.napi_create_function(env, "acquire", NAPI_AUTO_LENGTH, acquire, state, &function) != napi_ok)
        return error(state, env, "Cannot establish the actual lease callback", FALSE);
    {
        napi_property_descriptor property = { "acquire", NULL, NULL, NULL, NULL,
                                              function, napi_enumerable, NULL };
        if (state->api.napi_define_properties(env, exports, 1, &property) != napi_ok)
            return error(state, env, "Cannot export the actual lease adapter", FALSE);
    }
    return exports;
}
