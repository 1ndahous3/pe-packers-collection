# PE Diminisher

References: [public download](https://ftpmirror.infania.net/pub/pc/pack/ped.zip), [historical description](https://protools.narod.ru/packers.htm).

Teraphy’s educational Win32 packer uses aPLib section compression and an added loader. No instruction VM is involved.

## Inventory

| Version | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| 0.1 | Pass with ASLR/DEP flags cleared on the input copy | Packing succeeds; rundll32 fails to reach the fixture | Packer crashes | Default section selection; `.reloc` remains uncompressed |

[Packed fixtures](packed-fixtures/0.1) pass normal execution, the wait scenario and all four runtime secret checksums. No complete secret marker remains visible on disk. DLL and amd64 failures are not retained.

## Building and packing

Use the downloadable `ped.exe` in [tools](tools/0.1/bin). Open a disposable input and select **Encrypt File**. No source build is required. The helper prepares the compatibility flags and verifies both the prepared input and packed result.

## Auxiliary files

- [Generation and verification](generate.py)
- [GUI driver](gui.py)
- [Technical notes](internals.md)
