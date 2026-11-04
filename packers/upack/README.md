# UPack / WinUpack

[UPack 0.39final](https://www.sac.sk/download/pack/upack039.zip) · [WinUpack 0.39final](https://www.sac.sk/download/pack/wupck039.zip) · [UPack 0.399](https://www.sac.sk/download/pack/upack399.rar) · [Distribution mirror](https://ftpmirror.infania.net/pub/pc/pack/) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_WinUpack.2.sg)

UPack (Ultimate PE Packer), by dwing, is a compact LZMA-based PE32 compressor. WinUpack is its GUI version. The public distributions include author documentation but no buildable packer sources; 0.399 is a later console-only correction.

## Versions and fixtures

| Version / tools | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [0.39final](tools/0.39-final/bin/) | [Verified](packed-fixtures/0.39-final/fixture-x86-exe/packed.exe) | [Verified](packed-fixtures/0.39-final/fixture-x86-dll/packed.dll) | Unsupported PE32+ (error 1018) | CLI and English GUI produce byte-identical fixtures. |
| [0.399](tools/0.399/bin/Upack.exe) | [Verified](packed-fixtures/0.399/fixture-x86-exe/packed.exe) | [Verified](packed-fixtures/0.399/fixture-x86-dll/packed.dll) | Unsupported PE32+ (error 1018) | Same profile; the new `-brute` resource mode is not used. |

These builds parse PE32+ as PE32; changing ImageBase or using `-force` does not provide amd64 support. See the [diagnosis](internals.md#why-amd64-fails).

Profile: LC=3, FB=128, preserve overlay, exports and relocations. Inputs and packed outputs need no patches. All retained files pass normal execution, secret checks and wait mode; DLL names/ordinals are preserved. Full secret markers are absent on disk and were verified byte-for-byte in running process memory. ASLR and NX flags remain set, and rebased execution was observed.

## Building and packing

Extract only the executables from the linked archives into the corresponding `tools/<version>/bin/`. From the collection root:

```powershell
python packers/upack/generate.py --version 0.39-final
python packers/upack/generate.py --version 0.399
```

Use `--frontend gui` with 0.39final to reproduce the WinUpack comparison, or `--output PATH` for a separate run. The helper checks diagnostics as well as file changes: both frontends report the amd64 rejection with a normal exit code. Options, acquisition and verification are documented in [generate.py](generate.py).

## Auxiliary files

- [generate.py](generate.py): generation and PE/runtime/secret checks.
- [gui.py](gui.py): process-owned WinUpack automation with the same packing profile.
- [internals.md](internals.md): version identity, PE32+ limitations, packed layout and runtime verification.
