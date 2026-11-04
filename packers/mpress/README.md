# MPRESS

[2.19 download mirror](https://raw.githubusercontent.com/requaos/mPress/d743977fabb820bb292b6ec41e9c15afa6ec97c8/mpress.exe) · [Archived 0.92 download](https://web.archive.org/web/20130324025912id_/http://www.matcode.com/mpress.092.zip) · [Archived vendor website](https://web.archive.org/web/20150305181805/http://www.matcode.com/mpress.htm) · [Vendor history](https://github.com/requaos/mPress/blob/d743977fabb820bb292b6ec41e9c15afa6ec97c8/History.txt)

MPRESS compresses native PE32/PE32+ EXE/DLL files using LZMAT, with optional LZMA in later versions. This inventory covers the shared [PE fixtures](../../fixtures/README.md); .NET and Mach-O are outside its scope.

## Versions and fixtures

| Version / binary | Distribution | x86 fixtures | amd64 fixtures | Profile / notes |
| --- | --- | --- | --- | --- |
| [2.19](tools/2.19/bin/mpress.exe) | Public mirror; binary matches the [vendor ZIP](https://web.archive.org/web/20120806124233id_/http://www.matcode.com/mpress.219.zip) | [EXE](packed-fixtures/2.19/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/2.19/fixture-x86-dll/packed.dll) | [EXE](packed-fixtures/2.19/fixture-amd64-exe/packed.exe), [DLL](packed-fixtures/2.19/fixture-amd64-dll/packed.dll) | Latest published release located. `-i`, default codec selection; clears `DYNAMIC_BASE`. |
| [0.92](tools/0.92/bin/mpress.exe) | [Preserved original ZIP](tools/0.92/mpress.092.zip) | [EXE](packed-fixtures/0.92/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/0.92/fixture-x86-dll/packed.dll) | [EXE](packed-fixtures/0.92/fixture-amd64-exe/packed.exe), [DLL](packed-fixtures/0.92/fixture-amd64-dll/packed.dll) | Earliest distribution recovered. `-i`, LZMAT; retains `DYNAMIC_BASE`. |

The vendor history starts at **0.71a** (test) and **0.72b** (first stable); earlier binaries than 0.92 were not recovered.

All linked PEs use unchanged input copies and passed normal execution, wait-mode checks and all four secret checks on Windows x64 build 26100. Full secret markers are absent from packed bytes. DLL exports and `NX_COMPAT` survive; standard relocation directories do not. A retained ASLR flag alone does not establish working rebasing.

MPRESS has no native disk decompression command. External unpackers and recovered dumps have not been tested.

## Auxiliary files

- [generate.py](generate.py) — acquisition, packing commands and matrix verification; see its docstring and `--help`.
- [internals.md](internals.md) — codec selection, PE transformations, version identification and recovery considerations.
