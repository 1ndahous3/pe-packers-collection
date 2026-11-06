# Packman

[Project](https://sourceforge.net/projects/packmanpacker/) · [Official binary](https://sourceforge.net/projects/packmanpacker/files/1.0.0.0/packman-1.0.rar/download) · [Official source](https://sourceforge.net/projects/packmanpacker/files/1.0.0.0/packman.source-1.0.rar/download) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_Packman.2.sg)

Packman, by Brandon LaCombe, is a native PE32 EXE/DLL compressor with aPLib and LZMA plugins. The 1.0 cases use the published engine with a small collection CLI and plugins rebuilt using MSVC 2022. The original GUI executable was blocked by Windows Defender (error 225); its runtime behavior was not verified.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [0.0.0.1, original DVD GUI](tools/0.0.0.1/bin/Packman.exe) | [Verified](packed-fixtures/0.0.0.1/fixture-x86-exe/default.exe) | Export verification fails; not retained | No validated output | Built-in compression, alignment 512; no stripping/null-relocation options or input/output patches. |
| [1.0, local MSVC 2022 build](tools/1.0-msvc2022/bin/) | [Normal](packed-fixtures/1.0-msvc2022/fixture-x86-exe/) | [Normal, Max old/new header](packed-fixtures/1.0-msvc2022/fixture-x86-dll/) | Unsupported; explicitly rejected by the collection CLI | Both aPLib and LZMA; filenames identify backend and mode. |

Retained files pass normal execution, secret checks and wait mode, including DLL export names and ordinals. Full markers are absent on disk. The 1.0 cases also passed exact marker-byte checks in memory. The 1.0 DLL profiles also pass forced rebasing. LZMA Normal outputs are larger than these tiny inputs.

Max EXEs were produced but quarantined before execution on the research host. They remain runtime-unverified and are not retained. The generator skips these profiles; this is a host limitation, not an established Packman failure.

## Building and packing

From the collection root:

```powershell
python packers/packman/build.py
python packers/packman/generate.py --version 1.0-msvc2022
```

The retained tools are ready to use; rebuilding is optional. Requirements, source download, exact options and selection switches are documented in the helpers.

An [official 0.0.0.1 release](https://sourceforge.net/projects/packmanpacker/files/0.0.0.1/packman-0.0.0.1.rar/download) is listed on SourceForge, but a replacement download could not be verified. The [DVD archive](tools/0.0.0.1/Packman%200.0.0.1.rar) is therefore retained; its version label is the archive attribution. Reproduce its EXE with `python packers/packman/generate.py --version 0.0.0.1 --arch x86 --kind exe`.

## Auxiliary files

- [build.py](build.py) and [adapter/](adapter/): download and rebuild the official source with the collection CLI.
- [generate.py](generate.py): pack and verify shared fixtures.
- [gui.py](gui.py): process-owned automation for the early GUI.
- [internals.md](internals.md): layouts, build requirements and recovery observations.
