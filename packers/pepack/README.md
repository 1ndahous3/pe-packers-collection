# PE-PaCK

[Download (SAC)](https://www.sac.sk/download/pack/pepack10.zip) · [Mirror](https://ftpmirror.infania.net/pub/pc/pack/pepack10.zip) · [Author's manual](https://www.compression.ru/arctest/self/pepack.htm) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_PE-PACK.sg)

PE-PaCK, by ANAKiN, is a native PE32 EXE/DLL compressor based on PE-SHiELD, with most protection routines removed. It uses aPLib for code/data and an additional DELTA/RLE stage for relocations. The collection uses the original public 1.0 binary.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.0](tools/1.0/bin/) | [Default / fast](packed-fixtures/1.0/fixture-x86-exe/) | [Default / fast](packed-fixtures/1.0/fixture-x86-dll/) | Unsupported; packer crashes / times out | All retained cases use the header fixes below and run at their preferred image base. |

**Output header fixes:** restore execute permission on the original code and `PEPACK!!` sections, then clear `DYNAMIC_BASE`. Stock outputs fail under DEP; enabling execution alone exposes a relocation failure. `NX_COMPAT`, payload/stub bytes, shared originals and the packer binary remain unchanged. This does not repair relocation handling: both DLL profiles fail the forced base-collision check.

Retained files pass normal execution, secret checks and wait mode, including DLL export names/ordinals. Complete secret markers are hidden on disk and match the originals byte-for-byte in memory. Both compression profiles produce files larger than these tiny inputs.

## Building and packing

Extract `PEPACK.EXE` from either linked archive into the tool directory. The distribution contains no packer sources. From the collection root:

```powershell
python packers/pepack/generate.py --version 1.0
```

## Auxiliary files

- [generate.py](generate.py): acquisition, packing commands, header fixes and verification.
- [internals.md](internals.md): loader behavior, DEP/rebasing failures and recovery checks.
