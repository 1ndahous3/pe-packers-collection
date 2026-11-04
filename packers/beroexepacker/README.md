# BeRoEXEPacker

[Download](https://www.rosseaux.net/downloads/bep.zip) · [Author website and options](https://blog.rosseaux.net/page/875fbe6549aa072b5ee0ac9cefff4827/BeRoEXEPacker) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_BeRoEXEPacker.2.sg)

BeRoEXEPacker (BEP), by Benjamin Rosseaux, is a PE32 compressor with several compression backends. The official download contains only `bep.exe`; buildable packer sources were not found.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.00.2017.01.27](tools/1.00.2017.01.27/bin/bep.exe) | [Verified](packed-fixtures/1.00.2017.01.27/fixture-x86-exe/) | [Verified at preferred base](packed-fixtures/1.00.2017.01.27/fixture-x86-dll/) | Unsupported; emits invalid PE32 output | DLL forced rebasing fails; use `+X=0` for these small fixtures. |

Each x86 directory contains profiles named `lzbrr`, `lzbrs`, `lzbra`, `lzmau`, `lzbrcm0` and `ctx1`. All pass normal execution, secret checks and wait mode, including DLL export names/ordinals. Full markers are hidden on disk and were verified byte-for-byte in process memory. LZBRCM0 outputs are larger than these tiny inputs.

The profile disables the x86 filter and optional stripping except debug data. EXE relocation tables are nevertheless removed. Forced filters `+X=1/2` hang the tested DLL; neither those outputs nor invalid amd64 outputs are retained. See [internals.md](internals.md) for reproduction and limits.

## Building and packing

Extract `bep.exe` from the official ZIP with password `beroexepacker` into the linked tool directory. From the collection root:

```powershell
python packers/beroexepacker/generate.py --version 1.00.2017.01.27
```

Use `--algorithm lzbrr` to select a profile, or `--output PATH` for a separate run. Exact options, acquisition and checks are documented in the helper.

## Auxiliary files

- [generate.py](generate.py): reproducible packing, verification and rejection of incompatible amd64 outputs.
- [internals.md](internals.md): profiles, packed layout, relocation limitations and runtime recovery.
