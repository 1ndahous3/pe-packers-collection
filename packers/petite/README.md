# Petite

[Official download](https://www.un4seen.com/files/petite24.zip) · [Website](https://www.un4seen.com/petite/) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_Petite.2.sg)

Petite is a free native Win32 EXE/DLL compressor with console and GUI frontends. This inventory uses the console version and the shared [PE fixtures](../../fixtures/README.md).

## Versions and fixtures

| Version / binary | Distribution | x86 fixtures | amd64 fixtures | Profile / notes |
| --- | --- | --- | --- | --- |
| [2.4](tools/2.4/bin/petite.exe) | Official ZIP linked above; only the console executable is retained | [EXE](packed-fixtures/2.4/fixture-x86-exe/packed.exe), [DLL](packed-fixtures/2.4/fixture-x86-dll/packed.dll) | EXE and DLL explicitly rejected as non-x86 | Level 9, relocations retained; default import mangling and integrity check. |

Both packed files use unchanged input copies and passed normal execution, wait-mode checks and all four secret checks on Windows x64 build 26100 under WOW64. No full secret marker remains visible. DLL exports, ASLR/NX flags and a relocation directory remain present.

The PE64 rejection returns exit code zero without producing a file; the generator checks the diagnostic and output explicitly. Packing is not byte-deterministic on the tested host; use a fresh output directory for reproduction. Petite has no native disk decompressor.

## Auxiliary files

- [generate.py](generate.py) — acquisition, packing commands, matrix verification and alternate profiles; see its docstring and `--help`.
- [internals.md](internals.md) — loader behavior, compatibility and recovery considerations.
