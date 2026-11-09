# Windows PE Packer

References: [repository](https://github.com/czs108/Windows-PE-Packer), [tested source](https://github.com/czs108/Windows-PE-Packer/tree/8cce60ac258c75b89c2c5f57745d8914f2ecb21e).

Chenzs108’s educational x86 packer rewrites imports, encodes selected sections and inserts a native loader. It performs neither compression nor instruction virtualization.

## Inventory

| Version | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| 0 — source build | Pass: default / secret-as-data | Rejected | Rejected | Local MSVC/MASM build; no upstream release number |

[Packed fixtures](packed-fixtures/0) pass normal execution, wait mode and all runtime secret checksums with ASLR/DEP flags retained. The unchanged input leaves `secret-repeat` visible; renaming only its `.secret` section to `DATA` on the input copy hides it too. No packed-output patch is applied.

## Building and packing

The [binary](tools/0/bin) is built from the linked source commit. The build helper adapts include paths, old SDK declarations and MSVC linkage; packing and loader logic remain unchanged. Upstream documents MinGW/MASM32, while this build uses VS 2022 v143/MASM and a static runtime. The packing helper records commands and verifies both profiles.

## Auxiliary files

- [Source build and toolchain details](build.py)
- [Generation and verification](generate.py)
- [Technical notes](internals.md)
