#include "secrets.h"

/* Public synthetic test data. Hashes include string terminators where present. */
#pragma section(".rdata$marks", read)
__declspec(allocate(".rdata$marks")) static const char g_readonly[] =
    "PE_FIXTURE_RDATA_SECRET_v1_7c91";

#pragma section(".data$marks", read, write)
__declspec(allocate(".data$marks")) static wchar_t g_writable[] =
    L"PE_FIXTURE_DATA_SECRET_v1_b42e";

/* This is data, never an instruction stream or a function entry point. */
/* LINK deliberately merges initialized data into the executable .text section. */
#pragma section(".markx", read, execute)
__declspec(allocate(".markx")) static const unsigned char g_code_marker[] = {
    0x9d, 0x24, 0xe7, 0x51, 0x03, 0xba, 0x68, 0xcf, 0x42, 0x8a, 0xd0, 0x16, 0xf5, 0x7b, 0x31, 0xac,
    0x60, 0xde, 0x09, 0x83, 0x4f, 0xc2, 0x75, 0x18, 0xb6, 0x3d, 0xea, 0x90, 0x27, 0x5c, 0x01, 0xf8
};

#define BLOCK 'P','E','_','S','E','C','R','E','T','_','B','L','O','C','K','!'
#define BLOCK8 BLOCK, BLOCK, BLOCK, BLOCK, BLOCK, BLOCK, BLOCK, BLOCK
#pragma section(".secret", read)
__declspec(allocate(".secret")) static const char g_repeated[512] = {
    BLOCK8, BLOCK8, BLOCK8, BLOCK8
};

static DWORD HashBytes(const void *memory, DWORD size)
{
    const volatile unsigned char *bytes = (const volatile unsigned char *)memory;
    DWORD hash = 2166136261u;
    DWORD i;
    for (i = 0; i < size; ++i)
        hash = (hash ^ bytes[i]) * 16777619u;
    return hash;
}

BOOL FixtureSecretsValid(void)
{
    return HashBytes(g_readonly, sizeof(g_readonly)) == 0xd741476du &&
           HashBytes(g_writable, sizeof(g_writable)) == 0xb4a6a536u &&
           HashBytes(g_code_marker, sizeof(g_code_marker)) == 0x9a18438cu &&
           HashBytes(g_repeated, sizeof(g_repeated)) == 0x1a489d05u;
}
