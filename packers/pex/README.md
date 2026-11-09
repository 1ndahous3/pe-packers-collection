# PeX

[Author description mirror](https://www.compression.ru/arctest/self/pex.htm) · [Preserved distribution and sources](tools/0.99/pex-0.99.rar) · [SUN DVD source](https://archive.org/details/cracklb-2010)

A small PE32 compressor/protector by bart, using aPLib, encryption and optional import/BPX protection. No code virtualization is involved.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [0.99](tools/0.99/bin/) | [Default and minimal profiles](packed-fixtures/0.99/fixture-x86-exe/) | Rejected, unchanged | Rejected, unchanged | Rare distribution includes MASM sources and the author manual. |

Both profiles pass normal execution, wait mode and all secret checksums on Windows 11 x64. No complete marker is visible on disk. Temporary inputs clear `DYNAMIC_BASE`, `NO_SEH` and `NX_COMPAT`; packed output is unmodified. Minimal retains relocations and disables import/BPX protection, while keeping alignment enabled.

## Building and packing

Extract `pex.exe` from the retained RAR. No stable standalone public download was verified. `src.RAR` contains sources, compiled resources and aPLib; its machine-specific MASM batch files require adaptation and were not run.

```powershell
python packers/pex/generate.py
python packers/pex/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): acquisition, CLI switches, input preparation and verification.
- [internals.md](internals.md): loader and format limitations.
