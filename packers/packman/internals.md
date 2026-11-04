# Packman internals

## Source build

The [official 1.0 source archive](https://sourceforge.net/projects/packmanpacker/files/1.0.0.0/packman.source-1.0.rar/download) includes the packer engine, GUI, plugins, assembly loaders and HTML help. The SourceForge folder name `1.0.0.0` is not a separate tested release. Its changelog mentions the earlier `0.0.0.1`; that version is not included here.

The [build helper](build.py) compiles the engine and plugins without editing upstream files. The [adapter](adapter/) replaces the GUI with calls to `CPackmanPacker`, supplies a MASM equivalent of `loaderstructs.h` instead of the obsolete `h2inc` step, and defines the old SDK relocation-size constant. Static CRT linking avoids extra runtime DLLs. Legacy assembly objects require `/SAFESEH:NO` at link time.

LZMA must retain the original Release definitions `COMPRESS_MF_BT`, `COMPRESS_MF_BT4` and `_LZMA_PROB32`. Its assembly decoder uses DWORD probabilities; changing that ABI causes an undersized work buffer and a startup access violation. This is a build requirement, not an input-file repair.

Packman's original PE check uses PE32 structures without an explicit machine/magic gate. The collection CLI adds that gate and rejects amd64 before calling the engine. This matches the project's stated 32-bit scope; it does not establish how the blocked original GUI would handle PE32+.

## Layout and loading

- **Normal:** compresses sections at their original locations. The loader decompresses into scratch memory, then copies bytes back. The original section layout remains recognizable alongside the added `.PACKMAN` section.
- **Max, old header:** combines the section layout and stores section payloads together. The loader expands them directly to their original RVAs. The old header form is retained, with packing-related modifications.
- **Max, new header:** uses the same expansion model with a newly constructed, smaller header. Both Max DLL profiles have a substantially different section table from the original.

Code filtering is enabled in the collection profile; the loader reverses it before running the payload. Overlay retention is enabled, stripping and optional original-header restoration are disabled. This is an explicit CLI profile, not a claim to reproduce every GUI default.

The source's `Help/Topic Files/AdvancedTopics_PackingMethodDetails.htm` warns that Max changes shared-section and initialized-TLS behavior. The baseline fixtures do not cover those cases. `AdvancedTab_RetainHeader.htm` describes optional restoration of the original header at runtime; that option is not tested here.

## Relocation and recovery

The retained files expose only an empty relocation block to the Windows loader. Packman's private relocation data and `RelocationHandler.asm` apply the payload's fixups after expansion. An almost-empty public relocation directory therefore does not imply that these DLLs cannot rebase.

For a normal check, use the [generator](generate.py). For an exact memory check, start a retained EXE with `--wait` or a DLL with `WaitFixture`, wait for its success line, find the actual module base, and compare every complete marker at `base + manifest RVA` with the [x86 manifest](../../fixtures/bin/x86/manifest.json). All retained profiles passed this comparison.

To force DLL relocation, create the x86 `rundll32` process suspended, reserve the DLL's preferred image range with `VirtualAllocEx(MEM_RESERVE, PAGE_NOACCESS)`, then resume it. Confirm the loaded module has a different base. All DLL profiles passed normal execution and exact marker recovery in wait mode under this collision test. Terminate the owned wait process after inspection.

These checks establish runtime recovery of the fixture's behavior and secrets, not byte-identical restoration of the original disk PE or its headers. No external unpacker was tested. Resources, TLS, shared sections and managed PE are outside this baseline. EXE Max behavior remains unknown because Defender quarantined the generated files before runtime checks.
