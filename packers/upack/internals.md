# UPack / WinUpack internals

## Identity and acquisition

The author's Readme.txt in the linked distributions identifies UPack as the console program and WinUpack as its GUI version. The SAC `upack039.zip` and `wupck039.zip` archives contain the same 0.39final readme; their respective binaries are `Upack.exe` and `WinUpackE.exe`. The 0.399 readme explicitly describes a later correction without a GUI build, adding the optional `-brute` resource mode.

SAC and Infania copies of `upack399.rar` matched byte-for-byte. These public mirrors provide the tools and author documentation, so only executables are retained locally. The author's historical addresses were `dwing.51.net` and `wex.cn/dwing`; acquisition uses the working distribution links in [README.md](README.md). Buildable sources are not included. SAC's similarly named `upack10b.zip` is an unrelated archive extractor, not a newer PE packer.

The two CLI builds produced x86 EXE/DLL outputs differing only in the optional header's minor linker-version tag for these fixtures. The 0.39 GUI produced exactly the same bytes as its CLI under the matched profile. This does not establish equivalence for other inputs or for 0.399's `-brute` mode.

## Packed layout and runtime recovery

The default profile preserves exports and relocation information. The output has a virtual `.Upack` section with no raw bytes, and a `.rsrc` section containing the packed material and loader. Both sections are readable, writable and executable. These cases use ordinary DOS/PE header placement; do not assume every UPack output matches historical examples with overlapping headers or a different stub profile.

The author documents LZMA and an E8/E9 code transformation. The packing log reports import rebuilding, relocation handling and code transformation before compression. The loader restores code/data and imports before invoking the original entry point; original secret RVAs remain useful for runtime inspection.

The on-disk base-relocation directory contains an empty block. That is not proof that rebasing is unsupported: `DYNAMIC_BASE` and `NX_COMPAT` survive, and every retained EXE/DLL was observed running away from its preferred image base. Successful pointer checks and exact marker recovery demonstrate runtime restoration in those runs. UPack's runtime fixups should be distinguished from the small loader-visible relocation directory. Deliberate base collisions and unusual relocation types were not tested.

## Verification and reproduction

[generate.py](generate.py) pins each tool, checks shared input hashes, packs temporary copies and validates PE machine/type and DLL names/ordinals. It requires exact success stdout, exit zero and empty stderr, then verifies `--wait` or `WaitFixture` by name and ordinal 4. Full marker visibility on disk is checked separately from the runtime checksums. GUI automation sets the complete profile and waits for its terminal log; it does not rely on exit status alone.

For exact memory-marker verification, launch a retained EXE with `--wait`, or its DLL through matching `rundll32` with `WaitFixture`. After the fixture success line, locate that image's actual module base in the owned process. Use `ReadProcessMemory` at `module base + marker.rva`, comparing the complete bytes with each marker's `hex` value in the shared manifest. All four markers matched in both file types for both versions. Terminate only the test process afterwards; no memory dumps or reports need to be retained. This research check is separate from the generator's checksum verification and does not prove byte-identical PE reconstruction.

The supplied manuals document no native file-unpacking command. Third-party unpackers, TLS, resources, overlay content and alternate compression/stripping profiles are outside these baseline tests.

## Why amd64 fails

The author manuals for 0.39final and 0.399 say Windows PE, without explicitly claiming AMD64 or PE32+ support. Analysis of both CLI builds confirms a PE32 parser and x86 output loader. The shared amd64 EXE/DLL rejection is an unsupported format with a misleading diagnostic, not an ImageBase configuration problem.

The parser reads a DWORD at `OptionalHeader + 28` as ImageBase. In PE32+ that location holds the **upper half** of the 64-bit ImageBase, whose field starts at offset 24; see the [PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only). Both CLI builds apply the following unsigned range check to that DWORD:

```text
if not force and (base < 0x10000 or base >= 0x7fff0000):
    return error 1018  // Exceptional image base
```

A debugger confirmed that the original amd64 fixture supplies `1` to this check. The parser also reads NumberOfRvaAndSizes at the PE32 position, interpreting part of PE32+'s heap-size field as the directory count. Bypassing the first check cannot correct this layout mismatch.

Temporary amd64 builds linked with `/BASE:0x400000` for EXE and `/BASE:0x10000000` for DLL passed all five fixture CTest checks. Both packers still rejected them: the incorrectly read DWORD becomes zero. The packer's `-rlc 400000` option also leaves the original fixtures rejected. With `-force`, both versions report `Completed!` but produce PE32/i386 files instead of PE32+/AMD64, with ImageBase 1 and no original DLL exports. Windows refuses the forced EXE with error 193. These outputs are not usable fixtures and are not retained.

To reproduce the diagnosis, use disposable amd64 copies with `Upack.exe <copy> -test`, then `-rlc 400000 -test`, and finally `-force` on a fresh copy. Inspect output machine, optional-header magic and exports even when the tool prints success. For the low-base control, configure a separate x64 fixture build with `-DCMAKE_EXE_LINKER_FLAGS=/BASE:0x400000` and `-DCMAKE_SHARED_LINKER_FLAGS=/BASE:0x10000000`, build Release and run CTest before passing its files to UPack. Shared fixtures and published x86 outputs require no changes.

The normal rejection leaves input bytes unchanged. CLI exits zero; WinUpack's equivalent diagnostic is `[ERROR:1018] Exceptional image base`, with normal GUI close exit 2. The generator recognizes this exact rejection for the pinned builds; other errors remain failures.
