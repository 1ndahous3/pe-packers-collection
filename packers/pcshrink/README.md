# PCShrink

[0.71 distribution](https://ftpmirror.infania.net/pub/pc/pack/pcsnk071.zip) · [Compatible aPLib dependency](https://jeyndoe.github.io/edump/pages/files/51c6_19.06.2008_CRACKLAB.rU.tgz)

Phrozen Crew PE Shrinker is a legacy x86 compressor using aPLib, section merging and import/resource restructuring.

## Versions and fixtures

| Version / tools | x86 EXE | x86 DLL | amd64 | Notes |
| --- | --- | --- | --- | --- |
| [0.71 beta + aPLib 0.26b](tools/0.71/bin/) | [Merge / no-merge](packed-fixtures/0.71/fixture-x86-exe/) | DLL initialization fails | EXE fails; DLL packing crashes | Packer unchanged; temporary EXE inputs have NX_COMPAT cleared. |

Both retained profiles pass normal execution, wait mode and all secret checksums on Windows 11 x64. Complete markers are absent on disk. ASLR's flag remains set, but the packer removes relocations; rebasing is not supported. Raw EXE inputs produce a DEP-related runtime failure.

## Building and packing

The public distribution omits `aplib.dll`. The linked 0.26b DLL supplies the compatible old API; newer aPLib versions are not interchangeable. No buildable packer source was established. Generation controls the GUI and checks its success dialog before executing the result.

```powershell
python packers/pcshrink/generate.py --output C:/Temp/pcshrink-new
python packers/pcshrink/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): acquisition, compatibility preparation and verification.
- [gui.py](gui.py): bounded GUI driver and explicit settings.
- [internals.md](internals.md): dependency ABI, layout changes and limitations.
