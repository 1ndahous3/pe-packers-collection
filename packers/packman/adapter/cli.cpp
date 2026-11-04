// Collection driver around the unmodified Packman 1.0 engine.
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include "CPackmanPacker.h"
#include "Loader/loaderstructs.h"

static_assert(sizeof(LOADER_STRUCT) == 52, "Loader ABI");
static_assert(sizeof(KERNEL_IAT) == 24, "IAT ABI");
static_assert(sizeof(IMAGE_BASE_RELOCATION) == IMAGE_SIZEOF_BASE_RELOCATION, "SDK ABI");

int wmain(int argc, wchar_t **argv) {
    std::puts("Packman 1.0 - local MSVC source build / collection CLI");
    if (argc != 5) {
        std::puts("Usage: packman-cli input output plugin normal|max-old|max-new");
        return 2;
    }
    HANDLE file = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        std::printf("INPUT ERROR: %lu\n", GetLastError());
        return 3;
    }
    // Read the DOS and NT headers separately; do not assume a particular e_lfanew.
    IMAGE_DOS_HEADER dos = {};
    IMAGE_NT_HEADERS32 pe = {};
    DWORD count = 0;
    bool valid = ReadFile(file, &dos, sizeof(dos), &count, NULL) &&
                 count == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
                 dos.e_lfanew >= static_cast<LONG>(sizeof(dos));
    if (valid) {
        LARGE_INTEGER offset;
        offset.QuadPart = dos.e_lfanew;
        valid = SetFilePointerEx(file, offset, NULL, FILE_BEGIN) &&
                ReadFile(file, &pe, sizeof(pe), &count, NULL) &&
                count == sizeof(pe) && pe.Signature == IMAGE_NT_SIGNATURE;
    }
    CloseHandle(file);
    if (!valid) {
        std::puts("INPUT ERROR: invalid PE header");
        return 3;
    }
    // The engine uses PE32 structures but its own IsPE check does not reject PE32+.
    if (pe.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        std::puts("UNSUPPORTED: native i386 PE32 only (CLI guard)");
        return 2;
    }
    if (pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress) {
        std::puts("UNSUPPORTED: managed PE (CLI guard)");
        return 2;
    }
    PACKMANPACKER_OPTIONS options = {};
    if (!std::wcscmp(argv[4], L"normal")) {
        // Preserve the original section layout.
    } else if (!std::wcscmp(argv[4], L"max-old")) {
        options.bMax = TRUE;
    } else if (!std::wcscmp(argv[4], L"max-new")) {
        options.bMax = TRUE;
        options.bNewHeader = TRUE;
    } else {
        std::puts("Unknown packing mode");
        return 2;
    }
    options.bFilterCode = TRUE;
    options.bRetainOverlay = TRUE;
    options.dwFileAlignment = 0x200;
    lstrcpy(options.pszSectionName, L".PACKMAN");
    CPackmanPacker packer;
    packer.SetOptions(&options);
    if (!packer.SetCompressionLibrary(argv[3])) {
        std::printf("PLUGIN ERROR: %lu\n", GetLastError());
        return 4;
    }
    DWORD size = packer.PackFile(argv[1], argv[2]);
    if (!size) {
        std::puts("PACK FAILED");
        return 5;
    }
    std::printf("PACKED: %lu bytes\n", size);
    return 0;
}
