# MEW

[11 SE v1.2 download](https://www.sac.sk/download/pack/mew11.zip) · [Distribution mirror](https://ftpmirror.infania.net/pub/pc/pack/mew11.zip) · [Historical developer/download links](https://in4k.github.io/wiki/exe-packers-tweakers-and-linkers)

MEW, by Northfox, is a freeware x86 EXE packer using aPPack and optional LZMA. The public distribution includes the author's manual and release history, but no buildable sources. This inventory uses the shared [benign PE fixtures](../../fixtures/README.md).

## Versions and fixtures

| Version / binary | x86 EXE | x86 DLL | amd64 EXE / DLL | Profile / notes |
| --- | --- | --- | --- | --- |
| [11 SE v1.2](tools/11-se-1.2/bin/mew11.exe) | [Packed EXE](packed-fixtures/11-se-1.2/fixture-x86-exe/packed.exe) | Unsupported: output loses DLL bit and exports | Unsupported: misleading .NET diagnostic | Default options; unchanged input and output. Result matches aPPack-only mode; LZMA runtime coverage is not established. |

The retained EXE passed normal execution, `--wait` and all four secret checksum checks on Windows x64 build 26100. No complete secret marker remains visible. MEW clears ASLR/DEP flags and strips the relocation directory; the output relies on a fixed base and DEP opt-out. Failed/unsupported output is discarded.

## Building and packing

Extract `mew11.exe` from the linked ZIP. Use [generate.py](generate.py) (`--help`) with `--version 11-se-1.2`; it documents extraction, commands and alternate options. The helper handles MEW's relative-filename requirement and checks the GUI result, since exit zero alone does not establish success.

## Auxiliary files

- [generate.py](generate.py): generation, input identity and runtime/secret verification.
- [gui.py](gui.py): bounded CLI execution and process-owned status capture.
- [internals.md](internals.md): compression coverage, PE layout and failure modes.
