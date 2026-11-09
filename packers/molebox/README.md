# MoleBox

[Repository](https://github.com/sudachen/Molebox) · [Official build 6000](https://github.com/sudachen/Molebox/releases/download/6000/molebox_gpl.zip) · [Manual](https://sudachen.github.io/Molebox/) · [VC++ 2010 runtime](https://www.microsoft.com/en-us/download/details.aspx?id=26999)

An application packager with compression, encryption and a virtual filesystem. DLLs and data can live inside an EXE and remain accessible through normal Windows APIs. Its virtualization concerns files and registry access.

## Versions and fixtures

| Version / tool | x86 EXE | Standalone DLL | amd64 EXE | Notes |
| --- | --- | --- | --- | --- |
| [4.6000](tools/4.6000/bin/) | [Default / store, ordinary and bundled](packed-fixtures/4.6000/fixture-x86-exe/) | Rejected for both architectures | Misidentified as .NET; output rejected by Windows | Official CLI plus required DLLs. No input or output patches. |

All retained outputs pass normal execution, wait mode and secret checksums on Windows 11 x64. The extra bundle also checks the embedded shared x86 DLL, its exports, its sleep loop and a data file. It works with no external companions and prefers embedded files over invalid external namesakes. Complete secret markers are absent on disk; output ASLR/DEP flags are clear.

`default` slices the main EXE; `store` uses `-s` to place the whole EXE in the package. `bundle-*` adds an entry wrapper built from [these sources](bundle/) around the unchanged shared EXE sources and embeds the unchanged shared DLL.

## Building and packing

Use the official `MxbPack.exe`; the helper documents its minimal dependencies and upstream source-build prerequisites. Bundle generation uses CMake and VS 2022. Source rebuilding of MoleBox itself was not tested.

```powershell
python packers/molebox/generate.py --output C:/Temp/molebox-new
python packers/molebox/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): download/extraction notes, packing commands, bundle construction and verification.
- [internals.md](internals.md): package modes, virtual-file checks and target limitations.
