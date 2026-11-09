# Crinkler

[Repository](https://github.com/runestubbe/Crinkler) · [3.0b binary](https://github.com/runestubbe/Crinkler/releases/download/v3.0b/crinkler30b.zip) · [Manual](https://github.com/runestubbe/Crinkler/blob/v3.0b/doc/manual.txt)

An open-source compressing linker for small x86 Windows executables. It consumes COFF objects and libraries, rather than an already linked PE, and does not virtualize application code.

## Versions and fixtures

| Version / tool | x86 EXE | DLL / amd64 | Notes |
| --- | --- | --- | --- |
| [3.0b](tools/3.0b/bin/) | [FAST profile](packed-fixtures/3.0b/fixture-x86-exe/) | Unsupported targets | Official Win64 host binary; output remains x86. Requires SSE4.2. |

The packed EXE passes normal execution, wait mode and all secret checksums on Windows 11 x64. Complete markers are absent on disk. It is built from the unchanged shared C sources, not from the published `basic.exe`; a normal PE linked from the same objects also passes verification. Crinkler's output has neither ASLR nor DEP flags. No compatibility patch is applied.

## Building and packing

The adapter uses CMake, VS 2022 and the Windows SDK to compile shared fixture sources, link a temporary baseline and invoke Crinkler. The official binary is retained; rebuilding Crinkler itself was not tested.

```powershell
python packers/crinkler/generate.py --output C:/Temp/crinkler-new
python packers/crinkler/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): acquisition, prerequisites, generation and negative probes.
- [adapter/CMakeLists.txt](adapter/CMakeLists.txt): source-derived fixture build.
- [internals.md](internals.md): linking model, entry-point handling and test limits.
