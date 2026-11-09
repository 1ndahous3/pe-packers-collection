# EXE32Pack

References: [public download](https://ftpmirror.infania.net/pub/pc/pack/exe32pck.zip), [SAC catalogue](https://www.sac.sk/files.php?d=7&l=E).

SteelBytes’ Win32 executable compressor offers two compression methods and optional uncompressed exports. No instruction VM is involved.

## Inventory

| Version | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| 1.42 | Pass: M1 / M2 | Pass: M1 / M2, compressed exports and `/NE` | Rejected | Unchanged inputs; `/F` allows growth on small fixtures |

[Packed fixtures](packed-fixtures/1.42) pass normal execution, wait mode and all runtime secret checksums. Default profiles hide all complete markers. DLL `/NE` profiles leave `rdata-ascii` visible. Compressed exports are checked at runtime, including the callback ordinals; `/NE` also passes the static export comparison. ASLR/DEP flags remain set.

## Building and packing

The [binary](tools/1.42/bin) runs directly; its help banner confirms 1.42. Use explicit `/M:1` or `/M:2`, `/F` for the small fixtures, and optional `/NE` for DLLs. The helper contains commands and checks; no input or output patches are required.

## Auxiliary files

- [Generation and verification](generate.py)
- [Technical notes](internals.md)
