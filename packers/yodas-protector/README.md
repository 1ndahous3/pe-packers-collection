# Yoda's Protector

[Project](https://sourceforge.net/projects/yodap/) · [Public binaries](https://sourceforge.net/projects/yodap/files/Yoda%20Protector/1.03/) · [Earlier sources](https://sourceforge.net/projects/yodap/files/Yoda%20Protector/1.02/)

A PE32 compressor/encryptor with a polymorphic loader and optional protection features, without application-code virtualization. It is separate from Yoda's Crypter.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.03.2](tools/1.03.2/bin/) | [Minimal profile](packed-fixtures/1.03.2/fixture-x86-exe/) | Packing completes; no callback before timeout in rundll32 | Packer crashes during processing | Distributed as `yP1.03.zip`; GUI and version resource identify 1.03.2. |
| [1.03.3](tools/1.03.3/bin/) | [Minimal profile](packed-fixtures/1.03.3/fixture-x86-exe/) | Packing completes; no callback before timeout in rundll32 | Packer crashes during processing | Distributed as `yP1.03.3.zip`. |

Both retained EXEs pass normal execution, wait mode and all secret checksums on Windows 11 x64. The complete repeat marker in `.secret` stays visible on disk; the other complete markers are hidden.

Temporary inputs clear `DYNAMIC_BASE`, `NO_SEH` and `NX_COMPAT` before packing. Compression is set to 10; all optional protection and advanced settings are off. Packed outputs are unmodified. DLL loading, forced rebasing and external PE reconstruction have no verified working result here.

## Building and packing

The public ZIPs provide standalone `yP.exe` and a manual. Keep only the executable in `bin`. Public 1.02 sources contain Visual C++ projects, inline assembly and compression dependencies; they were inspected, not rebuilt, and are not an exact source match for these releases.

```powershell
python packers/yodas-protector/generate.py --version 1.03.2
python packers/yodas-protector/generate.py --version 1.03.3
```

## Auxiliary files

- [generate.py](generate.py): download URLs, input preparation, generation and verification.
- [gui.py](gui.py): bounded GUI automation with settings restoration.
- [internals.md](internals.md): section handling, compatibility and reproduction notes.
