/* SPDX-License-Identifier: GPL-2.0-only
 * shlwapi.dll path and string helpers. Expected values are the documented ones (MSDN "Path Functions" / "String
 * Functions" pages, including the PathCanonicalize example "A:\name_1\.\name_2\..\name_3" -> "A:\name_1\name_3")
 * and the unambiguous consequences of the documented rules. Behaviour that real shlwapi derives from the locale
 * (linguistic collation) is deliberately not asserted; see the header of dlls/shlwapi/shlwapi.c. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include "u_check.h"

#define WEQ(a, lit) u_wide_eq((const unsigned short *)(a), (const unsigned short *)(lit))

/* run a mutating path function on a copy of `in` */
static int buf_is(const WCHAR *buf, const WCHAR *expect) { return WEQ(buf, expect); }

int main(void)
{
    WCHAR b[MAX_PATH], out[MAX_PATH];
    LPWSTR r;
    int i;

    /* ---------------- PathFindFileName / PathFindExtension / PathRemoveExtension ---------------- */
    {
        static const WCHAR p1[] = L"C:\\dir\\file.txt", p2[] = L"file.txt", p3[] = L"C:/dir/file.txt", p4[] = L"C:file.txt", p5[] = L"C:\\dir\\sub\\";
        U_CHECK("PathFindFileName(C:\\dir\\file.txt) = file.txt", PathFindFileNameW(p1) == p1 + 7 && WEQ(PathFindFileNameW(p1), L"file.txt"));
        U_CHECK("PathFindFileName(file.txt) returns the whole string", PathFindFileNameW(p2) == p2);
        U_CHECK("PathFindFileName accepts '/' as a separator", PathFindFileNameW(p3) == p3 + 7);
        U_CHECK("PathFindFileName skips a drive prefix", PathFindFileNameW(p4) == p4 + 2);
        U_CHECK("PathFindFileName(path ending in '\\') names the last directory", WEQ(PathFindFileNameW(p5), L"sub\\"));
        U_CHECK("PathFindFileName(NULL) = NULL", PathFindFileNameW(0) == 0);
    }
    {
        static const WCHAR e1[] = L"C:\\dir\\file.txt", e2[] = L"file.tar.gz", e3[] = L"C:\\dir.d\\file", e4[] = L"file.", e5[] = L"noext";
        U_CHECK("PathFindExtension(C:\\dir\\file.txt) = .txt", PathFindExtensionW(e1) == e1 + 11);
        U_CHECK("PathFindExtension(file.tar.gz) = .gz (last dot)", PathFindExtensionW(e2) == e2 + 8);
        U_CHECK("a dot inside a directory name is not an extension (points at the terminator)", PathFindExtensionW(e3) == e3 + 13);
        U_CHECK("PathFindExtension(file.) = \".\"", PathFindExtensionW(e4) == e4 + 4);
        U_CHECK("PathFindExtension(noext) points at the terminator", PathFindExtensionW(e5) == e5 + 5);
        U_CHECK("PathFindExtension(NULL) = NULL", PathFindExtensionW(0) == 0);
    }
    lstrcpyW(b, L"C:\\dir\\file.txt"); PathRemoveExtensionW(b);
    U_CHECK("PathRemoveExtension(file.txt)", buf_is(b, L"C:\\dir\\file"));
    lstrcpyW(b, L"C:\\dir\\file"); PathRemoveExtensionW(b);
    U_CHECK("PathRemoveExtension without extension leaves the path alone", buf_is(b, L"C:\\dir\\file"));
    lstrcpyW(b, L"a.b.c"); PathRemoveExtensionW(b);
    U_CHECK("PathRemoveExtension removes only the last extension", buf_is(b, L"a.b"));

    /* ---------------- PathMatchSpec ---------------- */
    {
        static const struct { const WCHAR *file, *spec; BOOL expect; const char *name; } m[] = {
            { L"file.txt", L"*.txt", TRUE, "*.txt matches file.txt" },
            { L"file.txt", L"*.doc", FALSE, "*.doc does not match file.txt" },
            { L"file.txt", L"*.doc;*.txt", TRUE, "the second of two ';' separated specs matches" },
            { L"FILE.TXT", L"*.txt", TRUE, "matching ignores case" },
            { L"file.txt", L"FILE.*", TRUE, "matching ignores case (spec upper case)" },
            { L"a.txt", L"?.txt", TRUE, "? matches exactly one character" },
            { L"ab.txt", L"?.txt", FALSE, "? does not match two characters" },
            { L"readme", L"*", TRUE, "* matches everything" },
            { L"", L"*", TRUE, "* matches the empty string" },
            { L"readme", L"r*e", TRUE, "r*e matches readme" },
            { L"readme", L"r*x", FALSE, "r*x does not match readme" },
            { L"abcabc", L"a*c", TRUE, "a*c matches abcabc (backtracking)" },
            { L"File.TXT", L" *.doc; *.txt", TRUE, "leading blanks of each spec are skipped" },
            { L"file.txt", L"file.txt", TRUE, "exact spec" },
            { L"file.txt", L"file.tx", FALSE, "shorter exact spec does not match" },
            { L"file.tx", L"file.txt", FALSE, "longer exact spec does not match" },
            { L"\x00c4PFEL.TXT", L"\x00e4pfel.*", TRUE, "case folding covers Latin-1 (A-umlaut)" },
            { L"\x0416.txt", L"\x0436.txt", TRUE, "case folding covers Cyrillic (Zhe)" },
            { L"a.txt", L"", FALSE, "an empty spec matches nothing" },
        };
        for (i = 0; i < (int)(sizeof m / sizeof m[0]); ++i)
            U_CHECK(m[i].name, PathMatchSpecW(m[i].file, m[i].spec) == m[i].expect);
    }

    /* ---------------- classification ---------------- */
    U_CHECK("PathIsRelative: ..\\a, a\\b, file", PathIsRelativeW(L"..\\a") && PathIsRelativeW(L"a\\b") && PathIsRelativeW(L"file"));
    U_CHECK("PathIsRelative: C:\\a, \\a, \\\\srv\\sh are absolute", !PathIsRelativeW(L"C:\\a") && !PathIsRelativeW(L"\\a") && !PathIsRelativeW(L"\\\\srv\\sh"));
    U_CHECK("PathIsUNC", PathIsUNCW(L"\\\\server\\share") && !PathIsUNCW(L"C:\\a") && !PathIsUNCW(L"\\a") && !PathIsUNCW(0));
    U_CHECK("PathIsRoot true: C:\\  \\  \\\\server  \\\\server\\share", PathIsRootW(L"C:\\") && PathIsRootW(L"\\") && PathIsRootW(L"\\\\server") && PathIsRootW(L"\\\\server\\share"));
    U_CHECK("PathIsRoot false: C:\\a  C:  \\\\server\\share\\dir  empty", !PathIsRootW(L"C:\\a") && !PathIsRootW(L"C:") && !PathIsRootW(L"\\\\server\\share\\dir") && !PathIsRootW(L""));

    /* ---------------- backslash and file spec editing ---------------- */
    lstrcpyW(b, L"C:\\dir"); r = PathAddBackslashW(b);
    U_CHECK("PathAddBackslash appends and returns a pointer to the terminator", buf_is(b, L"C:\\dir\\") && r == b + 7 && *r == 0);
    lstrcpyW(b, L"C:\\dir\\"); r = PathAddBackslashW(b);
    U_CHECK("PathAddBackslash leaves an existing trailing backslash", buf_is(b, L"C:\\dir\\") && r == b + 7);
    lstrcpyW(b, L"C:\\dir\\"); PathRemoveBackslashW(b);
    U_CHECK("PathRemoveBackslash removes the trailing backslash", buf_is(b, L"C:\\dir"));
    lstrcpyW(b, L"C:\\"); PathRemoveBackslashW(b);
    U_CHECK("PathRemoveBackslash keeps the root backslash", buf_is(b, L"C:\\"));

    {
        static const struct { const WCHAR *in, *out; BOOL changed; } rf[] = {
            { L"C:\\dir\\file", L"C:\\dir", TRUE },
            { L"C:\\dir\\sub\\file.txt", L"C:\\dir\\sub", TRUE },
            { L"C:\\file", L"C:\\", TRUE },
            { L"C:\\dir\\", L"C:\\dir", TRUE },
            { L"\\file", L"\\", TRUE },
            { L"\\\\server\\share\\file", L"\\\\server\\share", TRUE },
            { L"file", L"", TRUE },
            { L"C:\\", L"C:\\", FALSE },
            { L"", L"", FALSE },
        };
        for (i = 0; i < (int)(sizeof rf / sizeof rf[0]); ++i) {
            char nm[80];
            BOOL ch;
            lstrcpyW(b, rf[i].in);
            ch = PathRemoveFileSpecW(b);
            snprintf(nm, sizeof nm, "PathRemoveFileSpec case #%d", i);
            U_CHECK(nm, ch == rf[i].changed && buf_is(b, rf[i].out));
        }
    }
    lstrcpyW(b, L"C:\\dir\\sub\\file.txt");
    U_CHECK("PathStripToRoot(C:\\dir\\sub\\file.txt) = C:\\", PathStripToRootW(b) && buf_is(b, L"C:\\"));
    lstrcpyW(b, L"C:\\dir\\file.txt"); PathStripPathW(b);
    U_CHECK("PathStripPath keeps only the file name", buf_is(b, L"file.txt"));
    lstrcpyW(b, L"file.txt"); PathStripPathW(b);
    U_CHECK("PathStripPath of a bare name is unchanged", buf_is(b, L"file.txt"));
    {
        static const WCHAR s1[] = L"C:\\dir\\f", s2[] = L"\\\\server\\share\\dir", s3[] = L"relative\\p";
        U_CHECK("PathSkipRoot(C:\\dir\\f) = dir\\f", PathSkipRootW(s1) == s1 + 3);
        U_CHECK("PathSkipRoot(\\\\server\\share\\dir) = dir", PathSkipRootW(s2) == s2 + 15);
        U_CHECK("PathSkipRoot of a relative path is NULL", PathSkipRootW(s3) == 0);
    }

    /* ---------------- canonicalize / combine / append ---------------- */
    {
        static const struct { const WCHAR *in, *out; const char *name; } c[] = {
            { L"A:\\name_1\\.\\name_2\\..\\name_3", L"A:\\name_1\\name_3", "MSDN example A:\\name_1\\.\\name_2\\..\\name_3" },
            { L"C:\\a\\.\\b", L"C:\\a\\b", "a '.' component is dropped" },
            { L"C:\\a\\b\\..", L"C:\\a", "a trailing '..' removes the last component" },
            { L"C:\\a\\b\\..\\c", L"C:\\a\\c", "'..' in the middle" },
            { L"C:\\a\\..\\..\\b", L"C:\\b", "'..' cannot climb above the root" },
            { L"C:\\..", L"C:\\", "C:\\.. is C:\\" },
            { L"C:\\a\\b", L"C:\\a\\b", "an already canonical path is unchanged" },
        };
        for (i = 0; i < (int)(sizeof c / sizeof c[0]); ++i) {
            BOOL ok;
            memset(out, 0xcc, sizeof out);
            ok = PathCanonicalizeW(out, c[i].in);
            U_CHECK(c[i].name, ok && buf_is(out, c[i].out));
        }
        U_CHECK("PathCanonicalize(NULL path) fails", PathCanonicalizeW(out, 0) == FALSE && out[0] == 0);
    }
    {
        static const struct { const WCHAR *dir, *file, *out; const char *name; } cb[] = {
            { L"C:\\dir", L"file.txt", L"C:\\dir\\file.txt", "PathCombine(C:\\dir, file.txt)" },
            { L"C:\\dir\\", L"file.txt", L"C:\\dir\\file.txt", "PathCombine with a trailing backslash on dir" },
            { L"C:\\dir", L"..\\other", L"C:\\other", "PathCombine canonicalizes ..\\" },
            { L"C:\\dir", L"D:\\abs\\x", L"D:\\abs\\x", "an absolute file part replaces dir" },
            { L"C:\\a\\b", L"\\c", L"C:\\c", "\\c is relative to the root of dir" },
            { L"C:\\dir", L"", L"C:\\dir", "empty file part gives dir" },
            { 0, L"x\\y", L"x\\y", "NULL dir gives the file part" },
            { L"C:\\dir", 0, L"C:\\dir", "NULL file gives dir" },
            { L"C:\\dir", L".\\sub\\.\\f", L"C:\\dir\\sub\\f", "PathCombine removes . components" },
        };
        for (i = 0; i < (int)(sizeof cb / sizeof cb[0]); ++i) {
            memset(out, 0xcc, sizeof out);
            r = PathCombineW(out, cb[i].dir, cb[i].file);
            U_CHECK(cb[i].name, r == out && buf_is(out, cb[i].out));
        }
        U_CHECK("PathCombine(NULL, ...) = NULL", PathCombineW(0, L"a", L"b") == 0);
        U_CHECK("PathCombine(NULL dir, NULL file) = NULL", PathCombineW(out, 0, 0) == 0);
        {
            WCHAR longdir[MAX_PATH];
            for (i = 0; i < MAX_PATH - 1; ++i) longdir[i] = 'a';
            longdir[MAX_PATH - 1] = 0;
            U_CHECK("PathCombine fails (NULL) when the result would exceed MAX_PATH", PathCombineW(out, longdir, L"file") == 0);
        }
    }
    lstrcpyW(b, L"C:\\a");
    U_CHECK("PathAppend(C:\\a, b)", PathAppendW(b, L"b") && buf_is(b, L"C:\\a\\b"));
    lstrcpyW(b, L"C:\\a");
    U_CHECK("PathAppend(C:\\a, \\b) drops the leading backslash of the appended part", PathAppendW(b, L"\\b") && buf_is(b, L"C:\\a\\b"));
    lstrcpyW(b, L"C:\\a\\");
    U_CHECK("PathAppend(C:\\a\\, ..\\c) = C:\\c", PathAppendW(b, L"..\\c") && buf_is(b, L"C:\\c"));

    /* ---------------- misc path helpers ---------------- */
    {
        static const WCHAR cmd[] = L"\"C:\\Program Files\\app.exe\" /x /y", cmd2[] = L"app.exe";
        U_CHECK("PathGetArgs skips a quoted program path", PathGetArgsW(cmd) == cmd + 27 && WEQ(PathGetArgsW(cmd), L"/x /y"));
        U_CHECK("PathGetArgs without arguments points at the terminator", PathGetArgsW(cmd2) == cmd2 + 7);
    }
    lstrcpyW(b, L"app.exe /x /y"); PathRemoveArgsW(b);
    U_CHECK("PathRemoveArgs", buf_is(b, L"app.exe"));
    lstrcpyW(b, L"\"a b\""); PathUnquoteSpacesW(b);
    U_CHECK("PathUnquoteSpaces strips the quotes", buf_is(b, L"a b"));
    lstrcpyW(b, L"file");
    U_CHECK("PathAddExtension adds .txt", PathAddExtensionW(b, L".txt") && buf_is(b, L"file.txt"));
    lstrcpyW(b, L"file.doc");
    U_CHECK("PathAddExtension refuses when an extension exists", !PathAddExtensionW(b, L".txt") && buf_is(b, L"file.doc"));

    /* ---------------- file system queries use the real kernel32 ---------------- */
    U_CHECK("PathFileExists(C:\\SHZ\\SYS64\\kernel32.dll) is TRUE", PathFileExistsW(L"C:\\SHZ\\SYS64\\kernel32.dll"));
    U_CHECK("PathFileExists(nonexistent) is FALSE", !PathFileExistsW(L"C:\\SHZ\\SYS64\\no_such_file.dll"));
    U_CHECK("PathIsDirectory(C:\\SHZ\\SYS64) is TRUE", PathIsDirectoryW(L"C:\\SHZ\\SYS64"));
    U_CHECK("PathIsDirectory(a file) is FALSE", !PathIsDirectoryW(L"C:\\SHZ\\SYS64\\kernel32.dll"));
    U_CHECK("PathIsDirectory(nonexistent) is FALSE", !PathIsDirectoryW(L"C:\\SHZ\\nodir"));

    /* ---------------- strings ---------------- */
    {
        static const WCHAR s[] = L"Hello, World, hello";
        U_CHECK("StrChrW finds the first occurrence", StrChrW(s, ',') == s + 5);
        U_CHECK("StrChrW is case-sensitive", StrChrW(s, 'w') == 0);
        U_CHECK("StrChrIW ignores case", StrChrIW(s, 'w') == s + 7);
        U_CHECK("StrChrW does not match the terminator", StrChrW(s, 0) == 0);
        U_CHECK("StrRChrW finds the last occurrence", StrRChrW(s, 0, ',') == s + 12);
        U_CHECK("StrRChrW honours the end pointer", StrRChrW(s, s + 10, ',') == s + 5);
        U_CHECK("StrRChrIW ignores case", StrRChrIW(s, 0, 'H') == s + 14);
        U_CHECK("StrStrW finds a substring", StrStrW(s, L"World") == s + 7);
        U_CHECK("StrStrW is case-sensitive", StrStrW(s, L"world") == 0);
        U_CHECK("StrStrIW ignores case", StrStrIW(s, L"WORLD") == s + 7 && StrStrIW(s, L"HELLO") == s);
        U_CHECK("StrStrW finds a match at the very end", StrStrW(s, L"hello") == s + 14 && StrStrW(s, L"lo") == s + 3);
        U_CHECK("StrStrW: needle longer than the haystack", StrStrW(L"ab", L"abc") == 0 && StrStrIW(L"ab", L"ABC") == 0);
        U_CHECK("StrStrIW folds Latin-1 (E-acute)", StrStrIW(L"caf\x00c9 noir", L"\x00e9 N") != 0);
    }
    U_CHECK("StrCmpW: equal strings give 0", StrCmpW(L"abc", L"abc") == 0);
    U_CHECK("StrCmpW: sign follows the first difference", StrCmpW(L"abc", L"abd") < 0 && StrCmpW(L"abd", L"abc") > 0 && StrCmpW(L"ab", L"abc") < 0);
    U_CHECK("StrCmpW is case-sensitive", StrCmpW(L"abc", L"ABC") != 0);
    U_CHECK("StrCmpIW ignores case", StrCmpIW(L"abc", L"ABC") == 0 && StrCmpIW(L"abc", L"ABD") < 0 && StrCmpIW(L"B", L"a") > 0);
    U_CHECK("StrCmpNW compares at most n characters", StrCmpNW(L"abcdef", L"abcxyz", 3) == 0 && StrCmpNW(L"abcdef", L"abcxyz", 4) < 0);
    U_CHECK("StrCmpNIW compares at most n characters, ignoring case", StrCmpNIW(L"ABCdef", L"abcxyz", 3) == 0 && StrCmpNIW(L"ABCdef", L"abcxyz", 4) < 0);
    U_CHECK("StrCmpNIW(\"C:\\\\Windows\", \"c:\\\\windows\\\\x\", 10) prefix test", StrCmpNIW(L"C:\\Windows\\System", L"c:\\windows\\x", 10) == 0);
    U_CHECK("StrCmpNW stops at a common terminator", StrCmpNW(L"ab", L"ab", 10) == 0);
    U_CHECK("StrIsIntlEqualW", StrIsIntlEqualW(TRUE, L"abc", L"abd", 2) && !StrIsIntlEqualW(TRUE, L"abc", L"ABC", 3) && StrIsIntlEqualW(FALSE, L"abc", L"ABC", 3));
    U_CHECK("StrSpnW / StrCSpnW / StrPBrkW", StrSpnW(L"aabbcc", L"ab") == 4 && StrCSpnW(L"aabbcc", L"c") == 4 && StrCSpnIW(L"aabbCC", L"c") == 4 &&
            StrPBrkW(L"hello world", L" ,") != 0 && *StrPBrkW(L"hello world", L" ,") == ' ' && StrPBrkW(L"hello", L"xyz") == 0);

    {
        int v = -1;
        LONGLONG v64 = 0;
        U_CHECK("StrToInt(\"123\") = 123", StrToIntW(L"123") == 123);
        U_CHECK("StrToInt(\"-45\") = -45", StrToIntW(L"-45") == -45);
        U_CHECK("StrToInt(\"12abc\") stops at the first non-digit", StrToIntW(L"12abc") == 12);
        U_CHECK("StrToInt(\"abc\") = 0", StrToIntW(L"abc") == 0);
        U_CHECK("StrToInt(NULL) = 0", StrToIntW(0) == 0);
        U_CHECK("StrToIntEx decimal", StrToIntExW(L"2147483647", STIF_DEFAULT, &v) && v == 2147483647);
        U_CHECK("StrToIntEx negative decimal", StrToIntExW(L"-2147483648", STIF_DEFAULT, &v) && v == (int)0x80000000);
        U_CHECK("StrToIntEx with STIF_SUPPORT_HEX parses 0x1F", StrToIntExW(L"0x1F", STIF_SUPPORT_HEX, &v) && v == 31);
        U_CHECK("StrToIntEx with STIF_SUPPORT_HEX parses lower-case 0xff", StrToIntExW(L"0xff", STIF_SUPPORT_HEX, &v) && v == 255);
        U_CHECK("StrToIntEx without the flag stops at the 'x' (value 0)", StrToIntExW(L"0x1F", STIF_DEFAULT, &v) && v == 0);
        U_CHECK("StrToIntEx(\"xyz\") fails", !StrToIntExW(L"xyz", STIF_DEFAULT, &v));
        U_CHECK("StrToIntEx(\"0x\" with no digits) fails under STIF_SUPPORT_HEX", !StrToIntExW(L"0x", STIF_SUPPORT_HEX, &v));
        U_CHECK("StrToInt64Ex handles values above 32 bits", StrToInt64ExW(L"9000000000", STIF_DEFAULT, &v64) && v64 == 9000000000LL);
        U_CHECK("StrToInt64Ex negative", StrToInt64ExW(L"-9000000000", STIF_DEFAULT, &v64) && v64 == -9000000000LL);
    }

    lstrcpyW(b, L"  Hello  ");
    U_CHECK("StrTrim(\"  Hello  \", \" \") -> Hello", StrTrimW(b, L" ") && buf_is(b, L"Hello"));
    lstrcpyW(b, L"Hello");
    U_CHECK("StrTrim with nothing to trim returns FALSE", !StrTrimW(b, L" ") && buf_is(b, L"Hello"));
    lstrcpyW(b, L"xxabcxx");
    U_CHECK("StrTrim with a multi-character set", StrTrimW(b, L"xy") && buf_is(b, L"abc"));
    lstrcpyW(b, L"   ");
    U_CHECK("StrTrim of an all-blank string leaves an empty string", StrTrimW(b, L" ") && buf_is(b, L""));

    memset(out, 0xcc, sizeof out);
    r = StrCpyNW(out, L"abcdefgh", 5);
    U_CHECK("StrCpyNW copies at most n-1 characters and terminates", r == out && buf_is(out, L"abcd"));
    lstrcpyW(out, L"abc");
    StrCatBuffW(out, L"defgh", 6);
    U_CHECK("StrCatBuffW never overflows a 6-character buffer", buf_is(out, L"abcde"));
    lstrcpyW(out, L"abc");
    StrCatBuffW(out, L"de", 16);
    U_CHECK("StrCatBuffW appends when there is room", buf_is(out, L"abcde"));
    {
        LPWSTR d = StrDupW(L"duplicate me");
        U_CHECK("StrDupW returns a distinct copy", d && WEQ(d, L"duplicate me") && d != 0);
        U_CHECK("...that LocalFree releases", d && LocalFree(d) == 0);
        U_CHECK("StrDupW(NULL) = NULL", StrDupW(0) == 0);
    }
    return u_finish("t_u_shlwapi");
}
