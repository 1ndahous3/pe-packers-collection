# Packman

[Project](https://sourceforge.net/projects/packmanpacker/) · [Official binary](https://sourceforge.net/projects/packmanpacker/files/1.0.0.0/packman-1.0.rar/download) · [Official source](https://sourceforge.net/projects/packmanpacker/files/1.0.0.0/packman.source-1.0.rar/download) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_Packman.2.sg)

Packman, by Brandon LaCombe, is a native PE32 EXE/DLL compressor with aPLib and LZMA plugins. The collection uses the published 1.0 engine with a small collection CLI and plugins rebuilt using MSVC 2022. The original GUI executable was blocked by Windows Defender (error 225); its runtime behavior was not verified.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.0, local MSVC 2022 build](tools/1.0-msvc2022/bin/) | [Normal](packed-fixtures/1.0-msvc2022/fixture-x86-exe/) | [Normal, Max old/new header](packed-fixtures/1.0-msvc2022/fixture-x86-dll/) | Unsupported; explicitly rejected by the collection CLI | Both aPLib and LZMA; filenames identify backend and mode. |

Retained files pass normal execution, secret checks and wait mode, including DLL export names and ordinals. Full markers are absent on disk and match the originals byte-for-byte in memory. All DLL profiles also pass forced rebasing. LZMA Normal outputs are larger than these tiny inputs.

Max EXEs were produced but quarantined before execution on the research host. They remain runtime-unverified and are not retained. The generator skips these profiles; this is a host limitation, not an established Packman failure.

## Building and packing

From the collection root:

```powershell
python packers/packman/build.py
python packers/packman/generate.py --version 1.0-msvc2022
```

The retained tools are ready to use; rebuilding is optional. Requirements, source download, exact options and selection switches are documented in the helpers.

## Auxiliary files

- [build.py](build.py) and [adapter/](adapter/): download and rebuild the official source with the collection CLI.
- [generate.py](generate.py): pack and verify shared fixtures.
- [internals.md](internals.md): layouts, build requirements and recovery observations.
