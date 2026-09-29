/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: FormatMessageA/W, ExpandEnvironmentStringsA/W.
 *
 * FormatMessage sources: FORMAT_MESSAGE_FROM_STRING; FORMAT_MESSAGE_FROM_HMODULE (RT_MESSAGETABLE resource 1 of the module, NULL means
 * the executable); FORMAT_MESSAGE_FROM_SYSTEM, which knows the English text of the sms_table Win32 error codes below (the codes this
 * runtime and its callers produce) and reports every other id as ERROR_MR_MID_NOT_FOUND. Only English exists: another language id
 * fails with ERROR_RESOURCE_LANG_NOT_FOUND.
 * Insert syntax: %1..%99 with optional !printf-style! type: s S c C d i u x X o p with flags - + space 0 #, width and precision
 * (or *), and the l, ll, h, I64 size prefixes; floating point types are not supported (the call fails with ERROR_NOT_SUPPORTED).
 * A "*" takes the arguments n, n+1 for width and precision and the value from the one after them, as Windows documents.
 * Escapes: %0 (end of message), %n (line break), %r, %t, %b/%space (blank), %. %! %%. MAX_WIDTH_MASK: 0xFF turns hard line breaks in
 * the definition into blanks, 1..0xFE additionally wraps lines at blanks so that they are at most that wide.
 */
#include "k32.h"

typedef struct { WCHAR *p; size_t len, cap; int oom; } wbuf;

static void wb_put(wbuf *b, WCHAR c)
{
    if (b->oom) return;
    if (b->len + 2 > b->cap) {
        const size_t ncap = b->cap ? b->cap * 2 : 256;
        WCHAR *np = b->p ? RtlReAllocateHeap(ShzProcessHeap(), 0, b->p, ncap * sizeof(WCHAR)) : RtlAllocateHeap(ShzProcessHeap(), 0, ncap * sizeof(WCHAR));
        if (!np) { b->oom = 1; return; }
        b->p = np;
        b->cap = ncap;
    }
    b->p[b->len++] = c;
    b->p[b->len] = 0;
}
static void wb_puts(wbuf *b, const WCHAR *s, size_t n) { size_t i; for (i = 0; i < n; ++i) wb_put(b, s[i]); }
static void wb_free(wbuf *b) { if (b->p) RtlFreeHeap(ShzProcessHeap(), 0, b->p); b->p = 0; }

/* ---------------------------------------------------------------- system messages */
static const struct { DWORD id; const char *text; } sms_table[] = {
    { 0, "The operation completed successfully.\r\n" },
    { 1, "Incorrect function.\r\n" },
    { 2, "The system cannot find the file specified.\r\n" },
    { 3, "The system cannot find the path specified.\r\n" },
    { 4, "The system cannot open the file.\r\n" },
    { 5, "Access is denied.\r\n" },
    { 6, "The handle is invalid.\r\n" },
    { 8, "Not enough memory resources are available to process this command.\r\n" },
    { 13, "The data is invalid.\r\n" },
    { 14, "Not enough memory resources are available to complete this operation.\r\n" },
    { 15, "The system cannot find the drive specified.\r\n" },
    { 18, "There are no more files.\r\n" },
    { 21, "The device is not ready.\r\n" },
    { 24, "The program issued a command but the command length is incorrect.\r\n" },
    { 31, "A device attached to the system is not functioning.\r\n" },
    { 32, "The process cannot access the file because it is being used by another process.\r\n" },
    { 33, "The process cannot access the file because another process has locked a portion of the file.\r\n" },
    { 38, "Reached the end of the file.\r\n" },
    { 50, "The request is not supported.\r\n" },
    { 80, "The file exists.\r\n" },
    { 87, "The parameter is incorrect.\r\n" },
    { 109, "The pipe has been ended.\r\n" },
    { 111, "The file name is too long.\r\n" },
    { 112, "There is not enough space on the disk.\r\n" },
    { 120, "This function is not supported on this system.\r\n" },
    { 121, "The semaphore timeout period has expired.\r\n" },
    { 122, "The data area passed to a system call is too small.\r\n" },
    { 123, "The filename, directory name, or volume label syntax is incorrect.\r\n" },
    { 126, "The specified module could not be found.\r\n" },
    { 127, "The specified procedure could not be found.\r\n" },
    { 131, "An attempt was made to move the file pointer before the beginning of the file.\r\n" },
    { 145, "The directory is not empty.\r\n" },
    { 158, "The segment is already unlocked.\r\n" },
    { 183, "Cannot create a file when that file already exists.\r\n" },
    { 193, "%1 is not a valid Win32 application.\r\n" },
    { 203, "The system could not find the environment option that was entered.\r\n" },
    { 206, "The filename or extension is too long.\r\n" },
    { 234, "More data is available.\r\n" },
    { 258, "The wait operation timed out.\r\n" },
    { 259, "No more data is available.\r\n" },
    { 267, "The directory name is invalid.\r\n" },
    { 288, "Attempt to release mutex not owned by caller.\r\n" },
    { 298, "Too many posts were made to a semaphore.\r\n" },
    { 317, "The system cannot find message text for message number 0x%1 in the message file for %2.\r\n" },
    { 487, "Attempt to access invalid address.\r\n" },
    { 995, "The I/O operation has been aborted because of either a thread exit or an application request.\r\n" },
    { 997, "Overlapped I/O operation is in progress.\r\n" },
    { 998, "Invalid access to memory location.\r\n" },
    { 1001, "Recursion too deep; the stack overflowed.\r\n" },
    { 1004, "Invalid flags.\r\n" },
    { 1113, "No mapping for the Unicode character exists in the target multi-byte code page.\r\n" },
    { 1460, "This operation returned because the timeout period expired.\r\n" },
    { 1812, "The specified image file did not contain a resource section.\r\n" },
    { 1813, "The specified resource type cannot be found in the image file.\r\n" },
    { 1814, "The specified resource name cannot be found in the image file.\r\n" },
    { 1815, "The specified resource language ID cannot be found in the image file.\r\n" },
};

static int lang_is_english(DWORD lang)
{
    /* neutral (0), neutral/default (0x400), system default (0x800), en-US (0x409), neutral English (0x009) */
    return lang == 0 || lang == 0x0400 || lang == 0x0800 || lang == 0x0409 || lang == 0x0009;
}

/* ---------------------------------------------------------------- template sources */
static WCHAR *widen_heap(const char *s, size_t n)                    /* UTF-8 -> heap copy, terminated */
{
    WCHAR *w = RtlAllocateHeap(ShzProcessHeap(), 0, (n + 2) * sizeof(WCHAR));
    int r;
    if (!w) return 0;
    r = n ? k32_utf8_to_wide(s, (int)n, w, (int)n + 1) : 0;
    w[n ? (r > 0 ? r : 0) : 0] = 0;
    return w;
}

static WCHAR *message_from_module(HMODULE mod, DWORD id, DWORD lang)
{
    HRSRC r = lang ? FindResourceExW(mod, (LPCWSTR)(ULONG_PTR)11, (LPCWSTR)(ULONG_PTR)1, (WORD)lang)
                   : FindResourceW(mod, (LPCWSTR)(ULONG_PTR)1, (LPCWSTR)(ULONG_PTR)11);
    const MESSAGE_RESOURCE_DATA *d;
    DWORD b;
    if (!r) return 0;
    d = LockResource(LoadResource(mod, r));
    if (!d) return 0;
    for (b = 0; b < d->NumberOfBlocks; ++b) {
        const MESSAGE_RESOURCE_BLOCK *blk = &d->Blocks[b];
        if (id >= blk->LowId && id <= blk->HighId) {
            const BYTE *e = (const BYTE *)d + blk->OffsetToEntries;
            DWORD i;
            const MESSAGE_RESOURCE_ENTRY *ent;
            for (i = blk->LowId; i < id; ++i) e += ((const MESSAGE_RESOURCE_ENTRY *)e)->Length;
            ent = (const MESSAGE_RESOURCE_ENTRY *)e;
            if (ent->Flags & MESSAGE_RESOURCE_UNICODE) {
                const WCHAR *t = (const WCHAR *)ent->Text;
                size_t n = 0, max = (ent->Length - 4) / sizeof(WCHAR);
                WCHAR *w;
                while (n < max && t[n]) ++n;
                w = RtlAllocateHeap(ShzProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
                if (!w) return 0;
                memcpy(w, t, n * sizeof(WCHAR));
                w[n] = 0;
                return w;
            } else {
                size_t n = 0, max = (size_t)ent->Length - 4;
                while (n < max && ent->Text[n]) ++n;
                return widen_heap((const char *)ent->Text, n);
            }
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- insert formatting */
typedef struct { DWORD_PTR *argv; int nargs; int ansi; int failed; DWORD err; } fmt_state;

static DWORD_PTR arg_at(const fmt_state *st, int index1)               /* 1-based */
{
    return index1 >= 1 && index1 <= st->nargs ? st->argv[index1 - 1] : 0;
}

static void put_number(wbuf *out, unsigned long long v, int neg, int base, int upper, int flags_left, int flags_zero, int plus, int space, int alt,
                       int width, int prec)
{
    WCHAR digits[72];
    int nd = 0, total, pad, i;
    const char *set = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    WCHAR sign = 0, prefix[2] = { 0, 0 };
    int plen = 0;
    if (v == 0 && prec == 0) nd = 0;
    else { do { digits[nd++] = (WCHAR)(unsigned char)set[v % (unsigned)base]; v /= (unsigned)base; } while (v); }
    if (neg) sign = '-'; else if (plus) sign = '+'; else if (space) sign = ' ';
    if (alt && base == 16 && nd) { prefix[0] = '0'; prefix[1] = upper ? 'X' : 'x'; plen = 2; }
    if (alt && base == 8 && (!nd || digits[nd - 1] != '0')) digits[nd++] = '0';
    total = nd + (sign ? 1 : 0) + plen;
    if (prec > nd) total += prec - nd;
    pad = width > total ? width - total : 0;
    if (!flags_left && !(flags_zero && prec < 0)) for (i = 0; i < pad; ++i) wb_put(out, ' ');
    if (sign) wb_put(out, sign);
    for (i = 0; i < plen; ++i) wb_put(out, prefix[i]);
    if (!flags_left && flags_zero && prec < 0) for (i = 0; i < pad; ++i) wb_put(out, '0');
    for (i = nd; i < prec; ++i) wb_put(out, '0');
    while (nd) wb_put(out, digits[--nd]);
    if (flags_left) for (i = 0; i < pad; ++i) wb_put(out, ' ');
}

/* Formats insert `n` with spec text [spec, spec+len) (without the enclosing '!'). */
static void format_insert(wbuf *out, fmt_state *st, int n, const WCHAR *spec, size_t len)
{
    int left = 0, zero = 0, plus = 0, space = 0, alt = 0, width = -1, prec = -1, stars = 0, ll = 0, l = 0, h = 0, w = 0;
    size_t i = 0;
    WCHAR type;
    DWORD_PTR v;
    int idx = n;
    for (; i < len; ++i) {
        if (spec[i] == '-') left = 1; else if (spec[i] == '0') zero = 1; else if (spec[i] == '+') plus = 1;
        else if (spec[i] == ' ') space = 1; else if (spec[i] == '#') alt = 1; else break;
    }
    if (i < len && spec[i] == '*') { width = (int)(LONG)arg_at(st, idx + stars); ++stars; ++i; if (width < 0) { left = 1; width = -width; } }
    else if (i < len && spec[i] >= '0' && spec[i] <= '9') { width = 0; while (i < len && spec[i] >= '0' && spec[i] <= '9') width = width * 10 + (spec[i++] - '0'); }
    if (i < len && spec[i] == '.') {
        ++i;
        if (i < len && spec[i] == '*') { prec = (int)(LONG)arg_at(st, idx + stars); ++stars; ++i; if (prec < 0) prec = -1; }
        else { prec = 0; while (i < len && spec[i] >= '0' && spec[i] <= '9') prec = prec * 10 + (spec[i++] - '0'); }
    }
    for (;;) {
        if (i + 2 < len + 0 && spec[i] == 'I' && spec[i + 1] == '6' && spec[i + 2] == '4') { ll = 1; i += 3; }
        else if (i + 1 < len && spec[i] == 'l' && spec[i + 1] == 'l') { ll = 1; i += 2; }
        else if (i < len && spec[i] == 'l') { l = 1; ++i; }
        else if (i < len && spec[i] == 'h') { h = 1; ++i; }
        else if (i < len && spec[i] == 'w') { w = 1; ++i; }
        else break;
    }
    if (i >= len) { st->failed = 1; st->err = ERROR_INVALID_PARAMETER; return; }
    type = spec[i];
    v = arg_at(st, idx + stars);
    switch (type) {
    case 'd': case 'i': {
        const long long sv = ll ? (long long)v : (long long)(int)(unsigned)v;
        put_number(out, sv < 0 ? (unsigned long long)(-(sv + 1)) + 1ull : (unsigned long long)sv, sv < 0, 10, 0, left, zero, plus, space, 0, width, prec);
        break;
    }
    case 'u': put_number(out, ll ? (unsigned long long)v : (unsigned long long)(unsigned)v, 0, 10, 0, left, zero, 0, 0, 0, width, prec); break;
    case 'x': case 'X': put_number(out, ll ? (unsigned long long)v : (unsigned long long)(unsigned)v, 0, 16, type == 'X', left, zero, 0, 0, alt, width, prec); break;
    case 'o': put_number(out, ll ? (unsigned long long)v : (unsigned long long)(unsigned)v, 0, 8, 0, left, zero, 0, 0, alt, width, prec); break;
    case 'p': put_number(out, (unsigned long long)v, 0, 16, 1, left, 1, 0, 0, 0, 16, -1); break;
    case 'c': case 'C': {
        WCHAR c;
        const int wide = (type == 'c') != (st->ansi != 0);              /* %c is a wide char in FormatMessageW, %C in FormatMessageA */
        int pad = width > 1 ? width - 1 : 0, k;
        c = wide || l || w ? (WCHAR)(unsigned short)v : (WCHAR)(unsigned char)v;
        if (h) c = (WCHAR)(unsigned char)v;
        if (!left) for (k = 0; k < pad; ++k) wb_put(out, ' ');
        wb_put(out, c);
        if (left) for (k = 0; k < pad; ++k) wb_put(out, ' ');
        break;
    }
    case 's': case 'S': {
        int wide = (type == 's') != (st->ansi != 0);
        const WCHAR *ws = 0;
        WCHAR *tmp = 0;
        size_t n_chars = 0;
        int pad, k;
        if (l || w) wide = 1;
        if (h) wide = 0;
        if (!v) {
            static const WCHAR nul[] = { '(', 'n', 'u', 'l', 'l', ')', 0 };
            ws = nul;
            n_chars = 6;
        } else if (wide) {
            ws = (const WCHAR *)v;
            while (ws[n_chars] && (prec < 0 || (int)n_chars < prec)) ++n_chars;
        } else {
            const char *s = (const char *)v;
            size_t bl = 0;
            while (s[bl] && (prec < 0 || (int)bl < prec)) ++bl;
            tmp = widen_heap(s, bl);
            if (!tmp) { st->failed = 1; st->err = ERROR_NOT_ENOUGH_MEMORY; return; }
            ws = tmp;
            n_chars = k32_wlen(tmp);
        }
        pad = width > (int)n_chars ? width - (int)n_chars : 0;
        if (!left) for (k = 0; k < pad; ++k) wb_put(out, ' ');
        wb_puts(out, ws, n_chars);
        if (left) for (k = 0; k < pad; ++k) wb_put(out, ' ');
        if (tmp) RtlFreeHeap(ShzProcessHeap(), 0, tmp);
        break;
    }
    default:
        st->failed = 1;
        st->err = ERROR_NOT_SUPPORTED;                                  /* floating point and rarely used types */
        break;
    }
}

/* Returns the highest insert index a template refers to (including the extra arguments of '*'), or -1 on a malformed insert. */
static int max_insert(const WCHAR *t)
{
    int best = 0;
    for (; *t; ++t) {
        if (*t == '%' && t[1] >= '0' && t[1] <= '9' && t[1] != '0') {
            int n = 0, stars = 0;
            ++t;
            while (*t >= '0' && *t <= '9' && n < 100) n = n * 10 + (*t++ - '0');
            if (n > 99) return -1;
            if (*t == '!') {
                const WCHAR *e = t + 1;
                while (*e && *e != '!') { if (*e == '*') ++stars; ++e; }
                if (!*e) return -1;
                t = e;
            } else {
                --t;
            }
            if (n + stars > best) best = n + stars;
            if (*t == 0) break;
        }
    }
    return best;
}

static void wrap_lines(wbuf *b, int width)
{
    size_t i, line_start = 0, last_space = (size_t)-1;
    for (i = 0; i < b->len; ++i) {
        if (b->p[i] == '\n' || (b->p[i] == '\r' && i + 1 < b->len && b->p[i + 1] == '\n')) {
            if (b->p[i] == '\r') ++i;
            line_start = i + 1;
            last_space = (size_t)-1;
            continue;
        }
        if (b->p[i] == ' ') last_space = i;
        if ((int)(i - line_start) >= width && last_space != (size_t)-1 && last_space >= line_start) {
            /* replace the last blank of the line with a line break (grows by one character) */
            wb_put(b, 0);
            memmove(b->p + last_space + 2, b->p + last_space + 1, (b->len - last_space - 1) * sizeof(WCHAR));
            b->p[last_space] = '\r';
            b->p[last_space + 1] = '\n';
            ++b->len;
            b->p[b->len] = 0;
            i = last_space + 1;
            line_start = i + 1;
            last_space = (size_t)-1;
        }
    }
}

/* Expands the template; result in `out`. Returns 0 on success or a Win32 error. */
static DWORD expand_template(const WCHAR *tpl, DWORD flags, int ansi, DWORD_PTR *argv, int nargs, wbuf *out)
{
    fmt_state st;
    const int width = (int)(flags & FORMAT_MESSAGE_MAX_WIDTH_MASK);
    size_t i = 0;
    st.argv = argv; st.nargs = nargs; st.ansi = ansi; st.failed = 0; st.err = 0;
    while (tpl[i] && !st.failed) {
        const WCHAR c = tpl[i];
        if (c != '%') {
            if (width && (c == '\r' || c == '\n')) {                              /* hard line breaks become blanks */
                if (c == '\r' && tpl[i + 1] == '\n') ++i;
                wb_put(out, ' ');
            } else {
                wb_put(out, c);
            }
            ++i;
            continue;
        }
        ++i;
        {
            const WCHAR e = tpl[i];
            if (e >= '1' && e <= '9') {
                int n = 0;
                size_t start = i - 1;
                while (tpl[i] >= '0' && tpl[i] <= '9') n = n * 10 + (tpl[i++] - '0');
                if (tpl[i] == '!') {
                    size_t s = i + 1, k = s;
                    while (tpl[k] && tpl[k] != '!') ++k;
                    if (!tpl[k]) { st.failed = 1; st.err = ERROR_INVALID_PARAMETER; break; }
                    if (flags & FORMAT_MESSAGE_IGNORE_INSERTS) wb_puts(out, tpl + start, k + 1 - start);
                    else format_insert(out, &st, n, tpl + s, k - s);
                    i = k + 1;
                } else {
                    if (flags & FORMAT_MESSAGE_IGNORE_INSERTS) wb_puts(out, tpl + start, i - start);
                    else {
                        static const WCHAR ds[] = { 's' };
                        format_insert(out, &st, n, ds, 1);
                    }
                }
                continue;
            }
            switch (e) {
            case 0: wb_put(out, '%'); break;
            case '0': goto done;
            case 'n': wb_put(out, '\r'); wb_put(out, '\n'); ++i; break;
            case 'r': wb_put(out, '\r'); ++i; break;
            case 't': wb_put(out, '\t'); ++i; break;
            case 'b': case ' ': wb_put(out, ' '); ++i; break;
            default: wb_put(out, e); ++i; break;                                /* %% %. %! and unknown escapes */
            }
        }
    }
done:
    if (out->oom) return ERROR_NOT_ENOUGH_MEMORY;
    if (st.failed) return st.err;
    if (width && width != 0xFF) wrap_lines(out, width);
    return out->oom ? ERROR_NOT_ENOUGH_MEMORY : 0;
}

static DWORD format_message(DWORD flags, const void *source, DWORD id, DWORD lang, void *buffer, DWORD size, va_list *args, int ansi)
{
    WCHAR *tpl = 0;
    int free_tpl = 0, nargs = 0;
    DWORD_PTR argv[100];
    wbuf out = { 0, 0, 0, 0 };
    DWORD err, result;
    const int src_bits = (flags & FORMAT_MESSAGE_FROM_STRING ? 1 : 0) | (flags & FORMAT_MESSAGE_FROM_HMODULE ? 2 : 0) | (flags & FORMAT_MESSAGE_FROM_SYSTEM ? 4 : 0);
    if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER ? !buffer : (!buffer && size)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!src_bits || ((flags & FORMAT_MESSAGE_FROM_STRING) && (flags & (FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM)))) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (flags & ~(DWORD)(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_FROM_HMODULE |
                         FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_MAX_WIDTH_MASK)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (flags & FORMAT_MESSAGE_FROM_STRING) {
        if (!source) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
        if (ansi) { tpl = widen_heap((const char *)source, (size_t)lstrlenA((const char *)source)); free_tpl = 1; }
        else tpl = (WCHAR *)source;
    } else {
        if (flags & FORMAT_MESSAGE_FROM_HMODULE) {
            tpl = message_from_module((HMODULE)source, id, lang);
            free_tpl = tpl != 0;
        }
        if (!tpl && (flags & FORMAT_MESSAGE_FROM_SYSTEM)) {
            unsigned i;
            if (!lang_is_english(lang)) { shz_set_last_error(ERROR_RESOURCE_LANG_NOT_FOUND); return 0; }
            for (i = 0; i < sizeof sms_table / sizeof sms_table[0]; ++i)
                if (sms_table[i].id == (id & 0xFFFF)) { tpl = widen_heap(sms_table[i].text, strlen(sms_table[i].text)); free_tpl = 1; break; }
        }
        if (!tpl) { shz_set_last_error(flags & FORMAT_MESSAGE_FROM_HMODULE && !(flags & FORMAT_MESSAGE_FROM_SYSTEM) ? ERROR_MR_MID_NOT_FOUND : ERROR_MR_MID_NOT_FOUND); return 0; }
    }
    if (!tpl) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    if (!(flags & FORMAT_MESSAGE_IGNORE_INSERTS)) {
        const int maxn = max_insert(tpl);
        int i;
        if (maxn < 0) { if (free_tpl) RtlFreeHeap(ShzProcessHeap(), 0, tpl); shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
        nargs = maxn;
        if (nargs && !args) { if (free_tpl) RtlFreeHeap(ShzProcessHeap(), 0, tpl); shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
        if (nargs) {
            if (flags & FORMAT_MESSAGE_ARGUMENT_ARRAY) {
                const DWORD_PTR *arr = (const DWORD_PTR *)args;
                for (i = 0; i < nargs; ++i) argv[i] = arr[i];
            } else {
                va_list ap = *args;
                for (i = 0; i < nargs; ++i) argv[i] = va_arg(ap, DWORD_PTR);
            }
        }
    }
    err = expand_template(tpl, flags, ansi, argv, nargs, &out);
    if (free_tpl) RtlFreeHeap(ShzProcessHeap(), 0, tpl);
    if (err) { wb_free(&out); shz_set_last_error(err); return 0; }
    if (!out.p) wb_put(&out, 0), out.len = 0;
    /* deliver */
    if (!ansi) {
        if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
            const size_t chars = out.len + 1 > size ? out.len + 1 : size;
            WCHAR *mem = LocalAlloc(LMEM_FIXED, chars * sizeof(WCHAR));
            if (!mem) { wb_free(&out); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
            memcpy(mem, out.p, (out.len + 1) * sizeof(WCHAR));
            *(WCHAR **)buffer = mem;
        } else {
            if (out.len + 1 > size) { wb_free(&out); shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
            memcpy(buffer, out.p, (out.len + 1) * sizeof(WCHAR));
        }
        result = (DWORD)out.len;
    } else {
        int need = 0;
        char *dst;
        if (out.len) {
            char *probe = RtlAllocateHeap(ShzProcessHeap(), 0, out.len * 4 + 4);
            if (!probe) { wb_free(&out); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
            need = k32_wide_to_utf8(out.p, (int)out.len, probe, (int)(out.len * 4 + 4));
            if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
                const size_t bytes = (size_t)need + 1 > size ? (size_t)need + 1 : size;
                dst = LocalAlloc(LMEM_FIXED, bytes);
                if (!dst) { RtlFreeHeap(ShzProcessHeap(), 0, probe); wb_free(&out); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
                *(char **)buffer = dst;
            } else {
                if ((DWORD)need + 1 > size) { RtlFreeHeap(ShzProcessHeap(), 0, probe); wb_free(&out); shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
                dst = buffer;
            }
            memcpy(dst, probe, (size_t)need);
            dst[need] = 0;
            RtlFreeHeap(ShzProcessHeap(), 0, probe);
        } else {
            need = 0;
            if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
                dst = LocalAlloc(LMEM_FIXED, size > 1 ? size : 1);
                if (!dst) { wb_free(&out); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
                *(char **)buffer = dst;
            } else {
                if (size < 1) { wb_free(&out); shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
                dst = buffer;
            }
            dst[0] = 0;
        }
        result = (DWORD)need;
    }
    wb_free(&out);
    shz_set_last_error(0);
    return result;
}

K32API DWORD WINAPI FormatMessageW(DWORD flags, LPCVOID source, DWORD id, DWORD lang, LPWSTR buf, DWORD size, va_list *args)
{
    return format_message(flags, source, id, lang, buf, size, args, 0);
}
K32API DWORD WINAPI FormatMessageA(DWORD flags, LPCVOID source, DWORD id, DWORD lang, LPSTR buf, DWORD size, va_list *args)
{
    return format_message(flags, source, id, lang, buf, size, args, 1);
}

/* ---------------------------------------------------------------- ExpandEnvironmentStrings */
K32API DWORD WINAPI ExpandEnvironmentStringsW(LPCWSTR src, LPWSTR dst, DWORD size)
{
    wbuf out = { 0, 0, 0, 0 };
    size_t i = 0;
    DWORD needed;
    if (!src) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    while (src[i]) {
        if (src[i] != '%') { wb_put(&out, src[i++]); continue; }
        {
            size_t e = i + 1;
            while (src[e] && src[e] != '%') ++e;
            if (!src[e]) { wb_puts(&out, src + i, k32_wlen(src + i)); break; }            /* an unmatched % is literal */
            {
                WCHAR name[260], *val = 0;
                const size_t nl = e - i - 1;
                int found = 0;
                if (nl && nl < 260) {
                    DWORD vn;
                    memcpy(name, src + i + 1, nl * sizeof(WCHAR));
                    name[nl] = 0;
                    shz_set_last_error(0);
                    vn = GetEnvironmentVariableW(name, 0, 0);                              /* size including the terminator */
                    if (vn || GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
                        val = RtlAllocateHeap(ShzProcessHeap(), 0, ((size_t)vn + 1) * sizeof(WCHAR));
                        if (val) {
                            const DWORD got = GetEnvironmentVariableW(name, val, vn + 1);
                            if (got <= vn) { wb_puts(&out, val, got); found = 1; }
                            RtlFreeHeap(ShzProcessHeap(), 0, val);
                        }
                    }
                }
                if (!found) wb_puts(&out, src + i, e - i + 1);                            /* undefined: left unchanged */
                i = e + 1;
            }
        }
    }
    if (out.oom) { wb_free(&out); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    needed = (DWORD)out.len + 1;
    if (size >= needed && dst) { if (out.len) memcpy(dst, out.p, out.len * sizeof(WCHAR)); dst[out.len] = 0; }
    wb_free(&out);
    return needed;
}

K32API DWORD WINAPI ExpandEnvironmentStringsA(LPCSTR src, LPSTR dst, DWORD size)
{
    WCHAR *w, *o;
    DWORD need, r;
    int bytes;
    if (!src) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    w = widen_heap(src, (size_t)lstrlenA(src));
    if (!w) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    need = ExpandEnvironmentStringsW(w, 0, 0);
    o = RtlAllocateHeap(ShzProcessHeap(), 0, ((size_t)need + 1) * sizeof(WCHAR));
    if (!o) { RtlFreeHeap(ShzProcessHeap(), 0, w); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    r = ExpandEnvironmentStringsW(w, o, need);
    RtlFreeHeap(ShzProcessHeap(), 0, w);
    {
        char *tmp = RtlAllocateHeap(ShzProcessHeap(), 0, (size_t)need * 4 + 4);
        if (!tmp) { RtlFreeHeap(ShzProcessHeap(), 0, o); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
        bytes = k32_wide_to_utf8(o, (int)r, tmp, (int)(need * 4 + 4));         /* includes the terminator */
        RtlFreeHeap(ShzProcessHeap(), 0, o);
        if (bytes > 0 && dst && size >= (DWORD)bytes) memcpy(dst, tmp, (size_t)bytes);
        RtlFreeHeap(ShzProcessHeap(), 0, tmp);
    }
    return bytes > 0 ? (DWORD)bytes : 0;
}
