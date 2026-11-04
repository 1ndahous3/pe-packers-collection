#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "secrets.h"

static DWORD g_attached;
static DWORD g_bias = 7;
static const char g_text[] = "pe-fixture:basic-dll:ok";
static const char *volatile g_message = g_text;

BOOL WINAPI FixtureDllEntry(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        g_attached = 1;
    else if (reason == DLL_PROCESS_DETACH)
        g_attached = 0;
    return TRUE;
}

DWORD __cdecl FixtureAdd(DWORD left, DWORD right)
{
    return g_attached ? left + right + g_bias : 0;
}

const char *__cdecl FixtureMessage(void)
{
    if (!g_attached || lstrlenA(g_message) != sizeof(g_text) - 1)
        return NULL;
    return g_message;
}

/* These callbacks have the ABI required by rundll32. */
void CALLBACK RunFixture(HWND window, HINSTANCE instance, LPSTR command, int show)
{
    const char *message = FixtureMessage();
    DWORD written = 0;
    DWORD length = (DWORD)(sizeof(g_text) - 1);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    (void)window;
    (void)instance;
    (void)command;
    (void)show;

    if (!message || FixtureAdd(12, 23) != 42 || FixtureAdd(0xffffffffu, 1) != 7)
        ExitProcess(2);
    if (!FixtureSecretsValid())
        ExitProcess(4);
    if (!WriteFile(output, message, length, &written, NULL) || written != length ||
        !WriteFile(output, "\n", 1, &written, NULL) || written != 1)
        ExitProcess(3);
}

/* Wait outside DllMain so the Windows loader can finish initialization. */
void CALLBACK WaitFixture(HWND window, HINSTANCE instance, LPSTR command, int show)
{
    RunFixture(window, instance, command, show);
    for (;;)
        Sleep(1000);
}
