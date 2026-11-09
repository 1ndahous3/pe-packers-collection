/* Extra bundle entry; shared EXE/DLL sources and markers stay unchanged. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void WINAPI FixtureEntry(void);
typedef void (CALLBACK *FixtureCallback)(HWND, HINSTANCE, LPSTR, int);

static void BundlePath(WCHAR *path, const WCHAR *name)
{
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!length || length >= MAX_PATH)
        ExitProcess(10);
    while (length && path[length - 1] != L'\\')
        --length;
    if (!length || length + (DWORD)lstrlenW(name) >= MAX_PATH)
        ExitProcess(10);
    lstrcpyW(path + length, name);
}

static BOOL DllWaitRequested(void)
{
    const WCHAR *p = GetCommandLineW();
    BOOL quoted = FALSE;
    while (*p && (quoted || (*p != L' ' && *p != L'\t'))) {
        if (*p == L'"')
            quoted = !quoted;
        ++p;
    }
    while (*p == L' ' || *p == L'\t')
        ++p;
    return lstrcmpW(p, L"--dll-wait") == 0;
}

static BOOL DataValid(const WCHAR *path)
{
    BYTE buffer[256];
    DWORD count, total = 0, hash = 2166136261u, i;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &count, NULL)) {
            CloseHandle(file);
            return FALSE;
        }
        if (!count)
            break;
        total += count;
        for (i = 0; i < count; ++i)
            hash = (hash ^ buffer[i]) * 16777619u;
    }
    CloseHandle(file);
    return total == 4131 && hash == 0x7b0e4553u;
}

void WINAPI BundleEntry(void)
{
    WCHAR path[MAX_PATH];
    HMODULE dll;
    FARPROC run, wait;
    union { FARPROC generic; FixtureCallback callback; } invoke;
    BundlePath(path, L"fixture-bundle.dll");
    dll = LoadLibraryW(path);
    if (!dll)
        ExitProcess(10);
    run = GetProcAddress(dll, "RunFixture");
    wait = GetProcAddress(dll, "WaitFixture");
    if (!run || !wait || run != GetProcAddress(dll, (LPCSTR)3) ||
        wait != GetProcAddress(dll, (LPCSTR)4))
        ExitProcess(12);
    BundlePath(path, L"fixture-data.bin");
    if (!DataValid(path))
        ExitProcess(11);
    if (DllWaitRequested()) {
        invoke.generic = wait;
        invoke.callback(NULL, dll, "", 0);
        ExitProcess(13); /* WaitFixture must not return. */
    }
    invoke.generic = run;
    invoke.callback(NULL, dll, "", 0);
    FreeLibrary(dll);
    FixtureEntry();
}
