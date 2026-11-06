# UPX research notes

[Inventory](README.md) · [Official history](https://raw.githubusercontent.com/upx/upx/devel/NEWS)

These observations apply to the shared fixtures and packing profiles in the inventory. [generate.py](generate.py) documents the generation and verification workflow; [compare_pe.py](../../tools/compare_pe.py) provides structural comparisons when investigating restoration differences.

## Packing constraints

- The reviewed legacy tools reject amd64 inputs with a PE-header error. The architecture of the packer executable does not establish supported input architectures. Forced packing of amd64 inputs was not tested.
- UPX 0.80 also rejects the baseline x86 headers unless `--force-compress` is used. Those forced outputs execute correctly, but the header field responsible for the rejection has not been isolated. The other reviewed legacy versions accept the x86 fixtures without force.
- Modern runs use `-9 --strip-relocs=0` to retain relocations. Legacy recipes use `-9`; the older tools advertise a different form of the relocation option. Use the version-specific examples in the generator rather than assuming modern switches apply to old tools.

## Header preservation

Changing only a section name is a useful test for information loss: generate two temporary variants with different names and compare their packed outputs.

UPX 0.80, 0.82 and 0.83 produce identical packed bytes for the two variants and the unmodified baseline. At least the original section name is discarded, so complete lossless reconstruction of the original headers is impossible from those packed files alone. This experiment does not establish which other header fields are preserved.

UPX 0.90 produces different packed variants and restores their respective section names during native decompression. This demonstrates improved preservation, not exact recovery of every PE field.

## Native decompression and reconstruction

The 0.8x tools have a `-d` command for other formats, but PE testing and decompression return `CantUnpackException: not yet implemented`. The preserved 0.82 manual and official history place PE decompression at 0.90, consistent with the local runs. Both 0.90 and 5.3.0 reject the stored 0.8x outputs as incompatible or obsolete; they cannot serve as native recovery references for those cases.

For the x86 fixtures, the 0.90 decoder restores the section table, entry point, image base, protection flags and exports. It clears the Debug and IAT directory entries, normalizes the imported DLL name's case and drops import hints. A cleared IAT directory entry does not mean that the working import tables are gone.

Active relocation types and targets are preserved, but 0.90 appends an empty relocation block and an incomplete trailing fragment. Successful integrity testing, decompression and execution therefore do not prove that the relocation directory is serialized correctly. Forced rebasing remains untested.

UPX 5.3.0 can decode the same 0.90 outputs. It restores the Debug and relocation directory entries without the incomplete relocation tail, while leaving the IAT directory entry cleared. Decoder choice therefore affects the recovered structure even when both results run successfully.

Modern native restoration also retains structural and behavioral properties without necessarily reproducing every original byte. Import-name normalization is one observed difference. The separate `--exact` mode was not tested; byte equality is not a success criterion for the profiles used here.

## Marker visibility

Only the full `text-binary` marker remains visible as raw bytes in all recorded packed outputs. The full `rdata-ascii`, `data-utf16` and `secret-repeat` sequences are absent, while packed execution still passes the embedded checksum checks.

Native restoration with 0.90 and 5.3.0 recovers all marker values. For 0.8x, execution checks demonstrate availability at runtime, but there is no native restored file to inspect. Marker recovery alone does not establish correct reconstruction of the entire PE.

## Reproducing the observations

Run from the collection root on Windows with WOW64 and the shared fixtures available. The generator makes temporary variants, runs execution checks and removes restoration outputs.

```powershell
python packers/upx/generate.py --version 0.83 --arch x86 --verification legacy-pe --check-header-loss
python packers/upx/generate.py --version 0.90 --arch x86 --pack-arg=-9 --check-section-names --inspect-restoration
```

The first command checks section-name loss; the second checks preservation and prints header, import, relocation and marker differences. The generator's docstring and `--help` cover the 0.80 force option, modern profiles and alternate packing settings.

To compare decoders, take a temporary copy of the same 0.90 packed PE and use each selected UPX version's `-t` and `-d` commands. Compare each restored file with the shared original using `python tools/compare_pe.py ORIGINAL RESTORED`, then apply the [fixture execution and marker checks](../../fixtures/README.md#use-in-a-packer-case). Inspect relocation structure as well as runtime behavior.

## Tool acquisition and source builds

The legacy executables were recovered from Alpx 1.27.6 on [CHIP Romania July 2005 / CCD0705](https://archive.org/details/CCD0705); their own `--version` output confirmed identification. The [0.82 distribution mirror](https://www.digiater.nl/openvms/decus/vmslt99b/net/upx082w.zip) contains the same executable as the ISO and supplies the preserved manual. Buildable sources for the reviewed 0.8x versions were not located; the official history places the full GPL source release at 0.99.

For modern UPX, use the official release or the [source build guide](https://github.com/upx/upx/blob/7c7bea44146c7ad6e17cb2d0bb9566805b44a91a/README.SRC). This optional recipe requires Visual Studio 2022 C++ tools, CMake and Git and **has not been run locally**:

```powershell
git clone --branch v5.3.0 --recurse-submodules https://github.com/upx/upx.git upx-source
cmake -S upx-source -B upx-build -G "Visual Studio 17 2022" -A x64
cmake --build upx-build --config Release
```

Different compression-library builds can change packed bytes even when the UPX version and options match.

## Scope limits

These findings cover the shared baseline and recorded profiles. TLS callbacks, resources, overlays, signed images, C++ initialization and exception handling, forced rebasing, cross-process DLL sharing and other Windows versions remain untested. Third-party unpackers, memory dumping and emulation have not yet been evaluated.

## UPX 1.25 and 3.04

UPX 1.25 and 3.04 accept `-9 --strip-relocs=0` for x86 EXE/DLL. Native test/decompression, restored markers and execution/wait checks pass; restored files still differ from the originals. Both reject the amd64 fixtures. Reproduce with `--version 1.25 --arch x86` or `--version 3.04 --arch x86`.
