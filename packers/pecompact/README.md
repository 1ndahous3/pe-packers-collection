# PECompact

[Archived 3.11 beta download](https://web.archive.org/web/20140903090728id_/http://www.bitsum.com/files/beta/pec2setup.zip) · [Archived Student download](https://web.archive.org/web/20070815120309id_/http://www.bitsum.com/files/pec2student.zip) · [Website](https://bitsum.com/portfolio/pecompact/) · [2.x manual](https://bitsum.com/docs/pec2/PECompact%20Documentation/00overview.htm)

PECompact compresses native 32-bit Windows EXE/DLL files using pluggable codecs and loaders. This inventory uses the shared [PE fixtures](../../fixtures/README.md); editions are distinguished below.

## Versions and fixtures

| Version / binary | Distribution | x86 fixtures | amd64 fixtures | Profile / notes |
| --- | --- | --- | --- | --- |
| [3.11.00.02 beta — original trial](tools/3.11.00.02/bin/PEC2.exe) | [Preserved vendor ZIP](tools/3.11.00.02/pec2setup.zip) | [EXE](packed-fixtures/3.11.00.02/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/3.11.00.02/fixture-x86-dll/packed.dll) | EXE and DLL explicitly rejected as PE64 | Both inputs used unchanged; packer clears `NO_SEH`. Generation requires an active evaluation period. |
| [2.79 Student/Freeware](tools/2.79/bin/PEC2.exe) | [Preserved original ZIP](tools/2.79/pec2student.zip) | [EXE](packed-fixtures/2.79/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/2.79/fixture-x86-dll/packed.dll) | EXE and DLL explicitly rejected as PE64 | EXE requires clearing `NO_SEH` in a temporary input copy; DLL uses the unchanged input. |

Passing profiles use LZMA2 payload compression, aPLib/default loader, level 9 and retained fixups. Linked packed files passed execution and all four runtime secret checks on Windows x64 build 26100 under WOW64. No full secret marker is visible in them. ASLR/NX flags and relocations remain present; loader overhead makes these small fixtures larger.

PECompact has no native PE decompression command. External unpackers and recovered dumps have not been tested. No imported samples are included.

## Auxiliary files

- [generate.py](generate.py) — acquisition/extraction instructions, packing commands, matrix verification and the reproducible `NO_SEH` experiment. Usage is in its docstring and `--help`.
- [internals.md](internals.md) — loader behavior, compatibility observations and recovery considerations.
