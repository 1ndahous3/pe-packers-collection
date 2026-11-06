# PESpin

[Archived x86 download](https://web.archive.org/web/20131104154610id_/http://pespin.w.interia.pl/pespin133.rar) · [Archived amd64 download](https://web.archive.org/web/20140412162406id_/http://pespin.w.interia.pl/pespin_v122_x64.zip) · [Vendor website](https://web.archive.org/web/20140709045746/http://pespin.w.interia.pl/)

PESpin is a freeware compressor/protector with encrypted layers, polymorphic loaders and import protection. Its x86 and amd64 editions are separate branches. This inventory uses the shared [PE fixtures](../../fixtures/README.md).

## Versions and fixtures

| Version / binary | Distribution | x86 fixtures | amd64 fixtures | Profile / notes |
| --- | --- | --- | --- | --- |
| [1.304 — archive label](tools/1.304/bin/PESpin.exe) | [Preserved SUN DVD RAR](tools/1.304/PESpin%201.304.rar) | Not verified: no usable packing UI on this host | Not tested | Acquisition only; not integrated into the generator. |
| [1.33 — x86](tools/1.33/bin/PESpin.exe) | [Preserved vendor RAR](tools/1.33/pespin133.rar) | [EXE](packed-fixtures/1.33/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/1.33/fixture-x86-dll/packed.dll) | Outside this branch | API redirection; reduced protection profile. Temporary inputs: clear `NO_SEH`; also reorder DLL export-name strings. No post-packing patch. |
| [1.22 — amd64](tools/1.22/bin/PESpin_x64.exe) | [Preserved vendor ZIP](tools/1.22/pespin_v122_x64.zip) | Outside this branch | [EXE](packed-fixtures/1.22/fixture-amd64-exe/packed.exe), [DLL](packed-fixtures/1.22/fixture-amd64-dll/packed.dll) | UCL, import resolution via Hash, checksum enabled; unchanged input copies. |

Linked files passed normal execution, wait-mode checks and all four runtime secret checks on Windows x64 build 26100. No full secret marker is visible in their packed bytes. Loader overhead increases the size of these small fixtures.

Reproduce into a fresh output directory; identical packed hashes are not assumed. No native disk decompressor is documented, and external unpackers have not been tested.

The older 1.304 distribution comes from [SUN DVD](https://archive.org/details/cracklb-2010); its archive label has not been confirmed through a working UI.

## Auxiliary files

- [generate.py](generate.py) — acquisition, profiles, commands and verification, including reproduction of the original DLL failure; see its docstring and `--help`.
- [gui.py](gui.py) — process-owned GUI driver for PESpin 1.33.
- [internals.md](internals.md) — loader mechanisms, compatibility findings and recovery considerations.
