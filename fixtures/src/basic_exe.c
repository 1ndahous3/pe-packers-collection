#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "secrets.h"

static DWORD g_bias = 7;
static const char g_text[] = "pe-fixture:basic-exe:ok\n";
/* A stored address deliberately gives the image a base relocation. */
static const char *volatile g_message = g_text;

/* Only a single --wait argument is recognized; keep the fixture CRT-free. */
static BOOL WaitRequested(void)
{
    const WCHAR *command = GetCommandLineW();
    const WCHAR *option = L"--wait";
    BOOL quoted = FALSE;

    /* Skip argv[0], including a quoted executable path containing spaces. */
    while (*command && (quoted || (*command != L' ' && *command != L'\t'))) {
        if (*command == L'"')
            quoted = !quoted;
        ++command;
    }
    while (*command == L' ' || *command == L'\t')
        ++command;
    quoted = *command == L'"';
    if (quoted)
        ++command;
    while (*option && *command == *option) {
        ++command;
        ++option;
    }
    if (*option)
        return FALSE;
    if (quoted) {
        if (*command != L'"')
            return FALSE;
        ++command;
    }
    while (*command == L' ' || *command == L'\t')
        ++command;
    return *command == L'\0';
}

static void WaitFixture(void)
{
    for (;;)
        Sleep(1000);
}

void WINAPI FixtureEntry(void)
{
    DWORD written = 0;
    DWORD length = (DWORD)(sizeof(g_text) - 1);

    if (35 + g_bias != 42)
        ExitProcess(2);
    if (!FixtureSecretsValid())
        ExitProcess(4);
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
                   g_message, length, &written, NULL) || written != length)
        ExitProcess(3);
    if (WaitRequested())
        WaitFixture();
    ExitProcess(0);
}
