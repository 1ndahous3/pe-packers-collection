# RLPack Basic

[Author website (historical)](http://rlpack.jezgra.net/) · [Distribution mirror](https://www.stahuj.cz/utility_a_ostatni/komprese/rlpack-basic-edition/download/) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_RLPack.2.sg)

RLPack Basic, by Reversing Labs, compresses native PE32 EXE/DLL files using aPLib 0.43 or LZMA 4.30. The mirrored distribution includes the original binaries and MASM sources. Full Edition and iBox are outside this case.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.21 Basic](tools/1.21-basic/bin/) | [aPLib / LZMA, both loader modes](packed-fixtures/1.21-basic/fixture-x86-exe/) | [aPLib / LZMA, dynamic loader](packed-fixtures/1.21-basic/fixture-x86-dll/) | Unsupported; invalid EXE output / packer crash on DLL | All retained cases use the resource workaround below. |

**Input workaround:** the generator adds one small RCDATA resource to a temporary copy. Stock RLPack corrupts these fixtures when no resource directory is present. Existing code, data, RVAs and exports are preserved; shared originals and the packer binary are unchanged.

All retained files pass normal execution, secret checks and wait mode, including DLL export names/ordinals. Complete secrets are hidden on disk and match the originals byte-for-byte in memory. Both DLL profiles also pass forced rebasing.

The Windows DLL loader option works for EXE; it crashes the packer for DLL and is skipped there. Outputs clear `DYNAMIC_BASE` and `NX_COMPAT`; EXE relocation directories are removed. LZMA outputs are larger than the shared originals.

## Building and packing

Extract `RLPack.exe`, `lzma.dll` and `Importer.dll` from the linked distribution into the tool directory. From the collection root:

```powershell
python packers/rlpack/generate.py --version 1.21-basic
```

The GUI briefly opens/minimizes during packing. Download, source-build notes, switches and selection options are documented in the helper.

## Auxiliary files

- [generate.py](generate.py): input adaptation, packing and verification.
- [internals.md](internals.md): resource-less input failure, loader behavior and recovery checks.
