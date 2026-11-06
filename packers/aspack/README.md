# ASPack

[Website](http://www.aspack.com/aspack.html) · [Current vendor download](http://www.aspack.com/files/aspack.zip) · [2.12 mirror](https://ftp.ntu.edu.tw/pub/cpatch/a/aspack/source/aspack212.zip)

ASPack is a Win32 executable compressor for EXE and DLL files. The distributions below were tested with the shared [PE fixtures](../../fixtures/README.md).

## Versions and fixtures

| Version / binary | x86 fixtures | amd64 fixtures | Profile / notes |
| --- | --- | --- | --- |
| [2.2, SUN DVD](tools/2.2/bin/ASPack.exe) | [EXE](packed-fixtures/2.2/fixture-x86-exe/packed.exe); DLL runtime timeout | Unsupported | Unchanged EXE input. Packer faults after writing; output independently verified. |
| [2.11, SUN DVD](tools/2.11/bin/ASPack.exe) | [EXE](packed-fixtures/2.11/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/2.11/fixture-x86-dll/packed.dll) | Unsupported | Clear `NX_COMPAT` in temporary inputs, as for 2.12. |
| [2.43](tools/2.43/bin/ASPack.exe) | [EXE](packed-fixtures/2.43/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/2.43/fixture-x86-dll/packed.dll) | Unsupported | Vendor build 2.43.1.26; unchanged inputs. |
| [2.12](tools/2.12/bin/ASPack.exe) | [EXE](packed-fixtures/2.12/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/2.12/fixture-x86-dll/packed.dll) | Unsupported | Clear `NX_COMPAT` in temporary inputs for compatibility with its loader. |

Retained cases use normal compression, Windows import-DLL loading, resource compression and overlay preservation. Export compression is off. Linked files passed normal execution, wait-mode checks and all four runtime secret checks on Windows x64 build 26100; DLL export names and ordinals survive.

The complete `.data` marker remains visible in packed EXEs and DLLs; DLLs also expose the `.rdata` marker. These small fixtures grow after packing. ASPack has no native disk decompressor; external unpacking was not tested.

The rare [2.11 archive](tools/2.11/Aspack%202.11.rar) and [2.2 archive](tools/2.2/ASPack%202.2.rar) came from [SUN DVD](https://archive.org/details/cracklb-2010). Their modification history is unverified. A [public 2.11 installer](http://ftp.ntu.edu.tw/pub/cpatch/a/aspack/source/aspack211.zip) is available, but its installed files have not been matched to this build. No failed DLL output is retained.

## Auxiliary files

- [generate.py](generate.py) — acquisition, dependencies, packing profiles, commands and verification; see its docstring and `--help`.
- [gui.py](gui.py) — process-owned handling of completion and built-in trial prompts.
- [internals.md](internals.md) — DEP compatibility, PE transformations and recovery observations.
