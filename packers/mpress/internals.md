# MPRESS internals

## Version identity and available material

The [vendor history](https://github.com/requaos/mPress/blob/d743977fabb820bb292b6ec41e9c15afa6ec97c8/History.txt) begins with 0.71a and labels 0.72b as the first stable version. The [early vendor page](https://web.archive.org/web/20080314143837/http://www.matcode.com/mpress.htm) links 0.75b and 0.77, but the archive index contains only redirects for those downloads. Among the successful vendor ZIP captures inspected, 0.92 is the earliest recovered distribution. This is an availability boundary, not a claim that MPRESS began at 0.92.

The latest release located is 2.19. The pinned [public mirror](https://github.com/requaos/mPress/tree/d743977fabb820bb292b6ec41e9c15afa6ec97c8) supplies the same executable as the archived vendor ZIP, plus the original history and FAQ. It does not contain a buildable MPRESS source tree. Acquisition instructions belong to [generate.py](generate.py).

## Compression and loader

Early releases use LZMAT. The history records optional LZMA for PE32 in 2.00 and PE32+ in 2.01. The two codecs have different loaders, so a version label alone does not describe the decompressor being exercised.

For the small shared fixtures, 2.19's default selection produced byte-identical results to explicit `-m` (force LZMAT). These cases therefore do not exercise its LZMA path. Reproduce this comparison with the generator's default profile and `--pack-arg=-m`, writing the latter to a separate `--output` directory. The `-i` option accepts a result even if packing increases its size; it is not an unpacking option.

The [vendor FAQ](https://github.com/requaos/mPress/blob/d743977fabb820bb292b6ec41e9c15afa6ec97c8/FAQ.TXT) describes in-place decompression and explicitly states that there is no disk decompression option. For versions 2.01–2.04, the historical `-d` switch selected encoder defaults; it was not an unpacker and was removed in 2.05.

## Observed PE transformations

Both recorded releases replace the original section layout with `.MPRESS1` and `.MPRESS2`, marked readable, writable and executable. The entry point moves into the loader. Visible imports reduce to KERNEL32; DLL export names and ordinals remain available.

The packed fixtures retain `NX_COMPAT`, but writable executable sections remain, so that flag does not imply preservation of the original section protections. Their standard relocation directories are empty. Version 0.92 retains `DYNAMIC_BASE`; 2.19 clears it. Ordinary EXE execution and DLL loading succeeded, but forced rebasing and DLL address collisions were not tested. Do not infer absence of internal fixup data from an empty PE relocation directory, or working ASLR from the flag alone.

No input-header workaround was needed. All four full secret markers disappear from packed bytes and pass their checksum checks during execution. This demonstrates runtime recovery for the fixture paths, not recovery of the original file layout. TLS, exception handling, resources and managed code are outside this fixture baseline.

## Identification and recovery

The history says version identification was added in 1.05. Older output attribution should use the known generating binary and its console banner. [DiE's rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_MPRESS.2.sg) includes overlapping version ranges, especially for x64; a detector range is not an exact version.

An external unpacker needs to recover code/data, the original entry point and imports, preserve useful exports, and handle fixups and section permissions. [RetDec's MPRESS plugin](https://github.com/avast/retdec/blob/master/src/unpackertool/plugins/mpress/mpress.cpp) is a useful implementation reference for LZMAT/LZMA decoding and PE reconstruction; it has not been validated against these cases. Validate any recovered file with fixture execution and secret checks, then inspect structural differences. Byte-for-byte equality is not a default recovery requirement.
