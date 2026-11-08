# PKLITE32

[SAC download](https://www.sac.sk/download/pack/pkl3211.exe) · [Infania mirror](https://ftpmirror.infania.net/pub/pc/pack/pkl3211.exe) · [Vendor description mirror](https://www.compression.ru/arctest/self/pklite32.htm) · [OEP script](https://github.com/xshows/ollydbg-script/blob/a6900722c747719ffe312dddd0ad2fa12b8ac97b/PKLite32/PKlite32%201.1OEP%20Find.txt) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_PKLITE.2.sg)

PKLITE32 by PKWARE compresses native PE32 executables and libraries. It is separate from DOS/Win16 PKLITE. The public shareware build provides a GUI; its manual's CLI and scripting interfaces belong to Professional.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.1 shareware](tools/1.1-shareware/bin/) | [Padded default](packed-fixtures/1.1-shareware/fixture-x86-exe/) | [Padded default](packed-fixtures/1.1-shareware/fixture-x86-dll/) | Explicitly rejected; no output | Default section selection; relocations preserved. |

**Input preparation:** the small unmodified fixtures are rejected for insufficient size reduction. The retained profile adds a 64 KiB zero-filled `.pad` section to temporary copies before packing. The generator reproduces this preparation from the shared originals.

Both packed files pass normal execution, wait mode, secret checksums and exact secret-byte checks in memory. DLL export names and ordinals survive; wait mode also passes through ordinal 4. ASLR and DEP flags are preserved; both kinds were verified at randomized load addresses. Outputs are saved exactly as produced by the packer, with no compatibility patches or startup notices.

Only the ASCII marker remains visible on disk, in the skipped `.rdata` section. Native disk decompression is not documented; exact file reconstruction by an external unpacker remains unverified.

## Building and packing

Extract only `PKLIT32W.EXE` from either public distribution above; installation and bundled legacy system libraries are unnecessary on the tested host. No buildable packer source was established.

```powershell
python packers/pklite32/generate.py --version 1.1-shareware
```

## Auxiliary files

- [generate.py](generate.py): acquisition, input preparation, commands and verification.
- [gui.py](gui.py): GUI automation, selection checks and temporary preferences.
- [internals.md](internals.md): size threshold, layout and recovery observations.
