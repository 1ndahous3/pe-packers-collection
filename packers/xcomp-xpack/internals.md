# XComp / XPack internals

## Related tools and algorithms

The author's [manual](http://www.soft-lab.de/JoKo/index_old.htm) describes the same rebuilding operations in both tools. XComp places compressed data at its original location; XPack stores it after the rebuilt image, increasing the mapped image size. Version 0.97 offers LZSS/LZRW and a compression-level setting. Version 0.98 replaces LZRW with LZMA through external compression DLLs. Retained profiles use both algorithms without stripping exports.

The command's `-re` switch is asymmetric: it preserves EXE relocations but removes DLL relocations. The generator supplies it only for EXEs. `-b` suppresses backup files; packing still replaces the temporary input. `-p` means no packing, not unpacking.

## Loading and compatibility

The loader decompresses merged application sections, restores imports and adjusts memory permissions before transferring control. The raw files retain the input's ASLR flag. In debugger runs the packed EXE was randomized and successfully reached restored application code, but that code still contained references to its preferred addresses. The packed relocation directory was insufficient to repair them.

Clearing only output `DYNAMIC_BASE` resolves these fixture failures. All remaining bytes and the DEP flag are preserved. This is a fixed-address profile, not a demonstration of working ASLR or forced DLL rebasing. The generator's `clear_aslr()` reproduces the patch; run its documented raw command without that step to inspect the failure.

XPack 0.98's LZMA DLL has an additional limitation: its decompressor reserves workspace through repeated pushes. A debugger run under the unmodified x86 rundll32 host ends in stack overflow in that allocation loop, before the callback. Clearing ASLR does not fix it. XComp LZMA and XPack LZSS pass with the same DLL. Use `--probe-failed` to reproduce the failed profile; its output is not kept as a working fixture. No host-stack change or loader patch is applied.

## Validation and recovery

Both versions silently leave PE32+ inputs unchanged with exit zero. Therefore a successful process exit alone is not a packing result. The helper checks input changes, output messages and runtime behavior separately.

The retained EXEs and DLLs pass normal/wait execution and all four marker checksums. Full markers disappear from the packed files; DLL names and ordinals remain intact. These checks establish runtime recovery, not byte-exact restoration of the original disk layout or headers. External unpackers remain untested. The author's static-TLS-callback exclusion is outside this baseline's coverage.
