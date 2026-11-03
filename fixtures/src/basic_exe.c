#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "secrets.h"

static DWORD g_bias = 7;
static const char g_text[] = "pe-fixture:basic-exe:ok\n";
/* A stored address deliberately gives the image a base relocation. */
static const char *volatile g_message = g_text;

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
    ExitProcess(0);
}
