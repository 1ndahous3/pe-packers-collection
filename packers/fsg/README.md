# FSG

[1.33 download](https://www.sac.sk/download/pack/fsg133.zip) · [2.0 download](https://www.sac.sk/download/pack/fsg20.zip) · [Distribution mirror](https://ftpmirror.infania.net/pub/pc/pack/) · [Historical developer/download links](https://in4k.github.io/wiki/exe-packers-tweakers-and-linkers)

FSG (Fast Small Good), by dulek and bart of xtreeme, is a freeware aPLib-based packer for small x86 Windows executables. Both distributions include the authors' `xt.nfo`; neither contains buildable packer sources. This inventory uses the shared [benign PE fixtures](../../fixtures/README.md).

## Versions and fixtures

| Version / binary | x86 EXE | x86 DLL | amd64 EXE / DLL | Profile / notes |
| --- | --- | --- | --- | --- |
| [2.0](tools/2.0/bin/fsg.exe) | [Packed EXE](packed-fixtures/2.0/fixture-x86-exe/packed.exe) | Unsupported | Unsupported | **Modified output:** an entry-point trampoline makes the original header loader reachable on this Windows host. The temporary packer copy needs the same fix; the stored tool and fixture input are unchanged. |
| [1.33](tools/1.33/bin/fsg.exe) | [Packed EXE](packed-fixtures/1.33/fixture-x86-exe/packed.exe) | Unsupported | Unsupported | Clear `NX_COMPAT` and `DYNAMIC_BASE` in the temporary input. Packed output is otherwise unchanged. |

Both linked files passed normal execution, `--wait` and all four secret checksum checks on Windows x64 build 26100. No complete secret marker is visible in either packed file. The profiles depend on DEP opt-out; they do not establish compatibility with mandatory DEP. Raw 2.0 output fails to load on this host and is not retained.

## Building and packing

Use the prebuilt binaries from the linked distributions. Extraction, commands, controlled settings and negative controls are documented in [generate.py](generate.py) (`--help`). Use `--version 1.33`, or `--version 2.0 --entry-trampoline` for the recorded profiles.

## Auxiliary files

- [generate.py](generate.py): generation, compatibility preparation and runtime/secret checks.
- [gui.py](gui.py): bounded packing and diagnostic dialogs, scoped to the started process.
- [internals.md](internals.md): loader behavior, format limits and reproduction notes.
