# Petite internals

## Profile and compatibility

The official [distribution](https://www.un4seen.com/files/petite24.zip) contains the console tool, an optional GUI and `petite.txt`. The manual is the source for the option semantics below. No installation or source build is needed.

The recorded profile uses level 9 and `-s0` to retain relocation information. A separate output file disables automatic backups; `-p0` suppresses progress and `-n` prevents overwrites. Import mangling, export compression and the loader's integrity check retain their defaults. See [generate.py](generate.py) for commands.

Both x86 fixtures work without header changes. Petite 2.4 explicitly rejects amd64 EXE/DLL files as non-x86 but returns zero. Successful generation therefore requires an output file, structural checks and execution; exit status alone is insufficient. The generator recognizes the observed rejection separately from failures.

## Loader and PE transformations

For these fixtures, Petite replaces the original section layout with an unnamed section and `petite`. The entry point moves into the loader, and the visible import table contains USER32 and KERNEL32. DLL export names and ordinals survive.

ASLR/NX flags and a loader-facing relocation directory remain present. This does not mean that the original relocation table or section layout survived unchanged: Petite also reports compressing the original relocation data. Forced rebasing and DLL address collisions have not been tested.

The manual describes import mangling as a runtime transformation and warns about data imports. With `-m1`, an unpacker should not assume that a post-initialization import table is intact.

Repeated packing with the recorded profile produces varying bytes on the tested host, even with matching input bytes and timestamps. Disabling only integrity checking did not make both fixture types repeatable. An experiment disabling both mangling and integrity checking (`-m0 -v0`) passed the EXE but timed out in the DLL runtime check; that profile is not retained. The exact source of byte variation was not isolated. Reproduce into a fresh output directory and verify behavior rather than expecting identical packed hashes. Differing existing artifacts are always preserved.

All four full secret markers disappear from packed bytes and pass checksum checks at runtime. This validates the fixture paths, not every original byte or section permission. The baseline does not exercise TLS, resources or exception handling.

## Recovery and scope

There is no native Petite decompressor. The `-d` switch controls debug-information stripping; it is not an unpacking command. The manual also notes that file overlays are stripped and DLL export tables stay available to the Windows loader.

A recovered PE needs a usable entry point, imports, code/data and exports, plus appropriate relocation handling and protections. Use execution and secret checks against the shared originals, then compare structure; byte-exact reconstruction is not assumed. External unpackers and recovered dumps have not been tested.
