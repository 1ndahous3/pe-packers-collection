# Yoda's Crypter

[Project files](https://sourceforge.net/projects/yodap/files/Yoda%20Crypter/) · [1.2 binary and sources](https://sourceforge.net/projects/yodap/files/Yoda%20Crypter/1.2/) · [1.3 binary and sources](https://sourceforge.net/projects/yodap/files/Yoda%20Crypter/1.3/)

A PE32 polymorphic encryptor with optional protection features, without code virtualization. Version 1.2 is yoda's MASM implementation; 1.3 is Ashkbiz Danehkar's C++ port. This is separate from Yoda's Protector.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.2](tools/1.2/bin/) | [Minimal profile](packed-fixtures/1.2/fixture-x86-exe/) | [Minimal profile](packed-fixtures/1.2/fixture-x86-dll/) | Unsupported PE32+; GUI does not complete | No complete secret marker visible on disk; export directory encrypted. |
| [1.3](tools/1.3/bin/) | [Minimal profile](packed-fixtures/1.3/fixture-x86-exe/) | Fails DLL initialization in rundll32 | Unsupported PE32+; GUI does not complete | `.rdata` is skipped, leaving its complete ASCII marker visible. |

Retained files pass normal execution, wait mode and all secret checksums on Windows 11 x64. The 1.2 DLL passes RunFixture, WaitFixture and ordinal 4; its encrypted exports cannot be checked by the usual static parser.

Temporary inputs have `DYNAMIC_BASE` and `NO_SEH` cleared before encryption; DEP stays enabled. All optional GUI protections are disabled. Default protection settings still crash these fixtures. Forced rebasing, other DLL exports and external file reconstruction remain unverified.

## Building and packing

The public ZIPs provide standalone `yC.exe`. Sources are included with 1.2 (MASM/MAKE.BAT) or in `yC1.3src.zip` (Visual C++ 7.0); neither source build was reproduced.

```powershell
python packers/yodas-crypter/generate.py --version 1.2
python packers/yodas-crypter/generate.py --version 1.3
```

## Auxiliary files

- [generate.py](generate.py): acquisition, input preparation, profiles and checks.
- [gui.py](gui.py): bounded automation of the original GUI.
- [internals.md](internals.md): loader behavior and compatibility observations.
