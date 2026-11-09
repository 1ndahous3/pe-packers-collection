# SimpleDpack

[Repository](https://github.com/YuriSizuku/win-SimpleDpack) · [0.5.3 binaries](https://github.com/YuriSizuku/win-SimpleDpack/releases/tag/v0.5.3)

An open-source EXE compressor using LZMA and an appended native loader, with x86 and amd64 variants.

## Versions and fixtures

| Version / tools | x86 EXE | amd64 EXE | DLL | Notes |
| --- | --- | --- | --- | --- |
| [0.5.3](tools/0.5.3/bin/) | [Pass](packed-fixtures/0.5.3/fixture-x86-exe/) | [Pass](packed-fixtures/0.5.3/fixture-amd64-exe/) | Both fail at runtime | Official binaries and loader DLLs; unchanged inputs. |

Both EXEs pass normal execution, wait mode and all secret checksums on Windows 11 x64. No complete marker remains visible on disk. ASLR/DEP flags are retained, but outer relocations are stripped; the ASLR flag alone does not establish working rebasing. Packed EXEs require the matching VC++ Runtime/UCRT.

## Building and packing

Use the official binaries with their matching shell DLLs. The source includes a Visual Studio solution; rebuilding it was not tested.

```powershell
python packers/simpledpack/generate.py --output C:/Temp/simpledpack-new
python packers/simpledpack/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): acquisition, prerequisites, commands and negative probes.
- [internals.md](internals.md): loader behavior and DLL limitations.
