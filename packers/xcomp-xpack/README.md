# XComp / XPack

[Author website and manual](http://www.soft-lab.de/JoKo/index_old.htm) · [0.97 download](http://www.soft-lab.de/JoKo/XComp097.zip) · [0.98 download](http://www.soft-lab.de/JoKo/XComp098.zip)

JoKo's PE32 compressor and rebuilder for EXE/DLL. XComp stores compressed data in place; XPack appends it to the rebuilt image. Both provide console and GUI interfaces without code virtualization.

## Versions and fixtures

| Version / tools | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [0.97](tools/0.97/bin/) | [XComp/XPack, LZSS/LZRW](packed-fixtures/0.97/fixture-x86-exe/) | [XComp/XPack, LZSS/LZRW](packed-fixtures/0.97/fixture-x86-dll/) | Unsupported; input unchanged | Default compression level; relocations retained. |
| [0.98](tools/0.98/bin/) | [XComp/XPack, LZSS/LZMA](packed-fixtures/0.98/fixture-x86-exe/) | [XComp LZSS/LZMA; XPack LZSS](packed-fixtures/0.98/fixture-x86-dll/) | Unsupported; input unchanged | XPack LZMA DLL fails with stack overflow in rundll32. |

All retained files pass normal execution, wait mode and secret checksums on Windows 11 x64. DLL export names/ordinals survive, including wait through ordinal 4. No complete marker remains visible on disk.

The output profiles clear only `DYNAMIC_BASE`; raw ASLR executions fail on unrelocated application addresses. DEP stays enabled. Inputs and packer tools are unmodified. Forced DLL rebasing and external file reconstruction remain unverified; no native unpack command is provided.

## Building and packing

Extract the console binaries from the public ZIPs above. Version 0.98 also needs `Xlzma.dll` and `Xlzss.dll`. No installation is required; buildable sources were not established.

```powershell
python packers/xcomp-xpack/generate.py --version 0.97
python packers/xcomp-xpack/generate.py --version 0.98
```

## Auxiliary files

- [generate.py](generate.py): acquisition, exact options, compatibility fix and verification.
- [internals.md](internals.md): storage differences, relocation behavior and DLL limits.
