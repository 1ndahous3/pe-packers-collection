# Fatpack research notes

## Two storage modes

The resource profile stores the LZMA-compressed input as RCDATA and maps the decompressed PE into allocated memory. The section profile appends `.fpack`, rebases the outer loader and reserves enough section space for the restored image. It avoids a separate allocation for the image and clears the outer loader's DYNAMIC_BASE flag. The upstream code labels this mode experimental.

The packer includes separate console/GUI stubs for each mode. ResourceAdder embeds all four into the packer at build time; the generated tool needs no adjacent stub files. Our baseline EXE selects the console variants. Both profiles hide the complete markers on disk and recover all runtime checksums and wait behavior without changing inputs or patching outputs.

## Validation limits

Upstream input validation checks PE validity, amd64 and native code, but does not reject IMAGE_FILE_DLL. Passing our amd64 DLL therefore produces an EXE stub without its exports. This cannot serve as a rundll32 fixture; these outputs are inspected but not executed or retained. x86 inputs produce no file. Exit zero alone proves nothing because upstream main returns zero on errors too.

TLS support is implemented by the author's manual mapper, alongside relocation, import, delayed-import and exception handling. These paths require richer fixtures to validate; the baseline contains no TLS or C++ initialization. Behavioral success here does not establish a byte-identical dump or general loader equivalence.

Use `--probe-failed` for the unsupported matrix cells. The generator docstring pins the source revision and records the successful build recipe. No native unpack-to-disk mode was established.
