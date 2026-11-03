# UPX

[Releases and downloads](https://github.com/upx/upx/releases) · [Website](https://upx.github.io/) · [Repository](https://github.com/upx/upx) · [Release history](https://raw.githubusercontent.com/upx/upx/devel/NEWS)

UPX compresses executable files. This inventory uses the shared [PE fixtures](../../fixtures/README.md); the results below apply to those inputs and the recorded packing options.

## Versions and fixtures

Linked fixtures passed packing and execution. Native PE testing/decompression is available from 0.90.

| Version / binary | Source | x86 fixtures | amd64 fixtures | Packing options | Notes |
| --- | --- | --- | --- | --- | --- |
| [5.3.0](tools/5.3.0/bin/upx.exe) | [Official ZIP](https://github.com/upx/upx/releases/download/v5.3.0/upx-5.3.0-win64.zip) | [EXE](packed-fixtures/5.3.0/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/5.3.0/fixture-x86-dll/packed.dll) | [EXE](packed-fixtures/5.3.0/fixture-amd64-exe/packed.exe), [DLL](packed-fixtures/5.3.0/fixture-amd64-dll/packed.dll) | `-9 --strip-relocs=0` | Native restore passes; restored files are not byte-identical. |
| [0.90](tools/0.90/bin/upx.exe) | [CHIP ISO](https://archive.org/details/CCD0705) | [EXE](packed-fixtures/0.90/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/0.90/fixture-x86-dll/packed.dll) | Unsupported | `-9` | Native restore passes; header and relocation differences remain. |
| [0.83](tools/0.83/bin/upx.exe) | [CHIP ISO](https://archive.org/details/CCD0705) | [EXE](packed-fixtures/0.83/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/0.83/fixture-x86-dll/packed.dll) | Unsupported | `-9` | No native PE restore; original section names are lost. |
| [0.82](tools/0.82/bin/upx.exe) | [ZIP mirror](https://www.digiater.nl/openvms/decus/vmslt99b/net/upx082w.zip), [CHIP ISO](https://archive.org/details/CCD0705) | [EXE](packed-fixtures/0.82/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/0.82/fixture-x86-dll/packed.dll) | Unsupported | `-9` | No native PE restore; mirror and ISO binaries match. |
| [0.80](tools/0.80/bin/upx.exe) | [CHIP ISO](https://archive.org/details/CCD0705) | [EXE](packed-fixtures/0.80/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/0.80/fixture-x86-dll/packed.dll) | Unsupported | `-9 --force-compress` | Force is required for these x86 inputs; no native PE restore. |

Only packed PEs are kept under `packed-fixtures/`. No imported samples are present. Rare tools and the [0.82 distribution archive](tools/0.82/upx082w.zip) are preserved locally.

## Auxiliary files

- [generate.py](generate.py) — fixture generation and verification.
- [internals.md](internals.md) — technical observations and reproduction notes.

Usage and examples are in each script's docstring and `--help`.
