# SimpleDpack research notes

The packer compresses multiple original sections with LZMA, appends code derived from its shell DLL, replaces imports with the shell's dependencies and transfers control back after decompression and import repair. The shell's runtime dependencies remain in generated files. The source excludes resources from its general compression path; our baseline has no resources.

The loader restores sections at the original image base. The packer strips the outer relocation directory and sets RELOCS_STRIPPED while leaving DYNAMIC_BASE set. Passing runtime tests therefore does not demonstrate ASLR compatibility or forced rebasing. The source revision and generation commands are pinned in the helper.

DLL input is not reliably rejected. Both architectures produce files whose export data is unavailable in the on-disk layout. Bounded rundll32 checks fail: x86 times out, amd64 exits without the fixture success line. The x86 packer also faults after writing the output. In the source, allocation uses GetModuleHandle(NULL), and decompression/entry transfer assume the original executable image base. This EXE-specific startup path is unsuitable for ordinary DLL initialization and export loading; no working standalone DLL case was established.

Use `--probe-failed` to reproduce these failures. Only verified EXEs are retained. Normal/wait success verifies all marker checksums, not byte-identical reconstruction of original PE headers. No native unpack-to-disk operation was established.
