# PE Diminisher research notes

The loader decompresses selected sections in memory using aPLib. Original section names remain, and an extra `.teraphy` section holds the loader. The default selection compresses the export-bearing section too, so static export parsing is not a sufficient DLL runtime test.

Two independent compatibility problems affect the shared x86 EXE. Clearing only NX_COMPAT leaves an ASLR-rebased image that faults inside aPLib decoding: the original relocation directory still targets data in compressed sections. Clearing only DYNAMIC_BASE instead faults at the loader entry: the new section lacks execute permission while DEP is enabled. Clearing both flags on the temporary input makes normal execution, all secret checks and the wait loop pass. NO_SEH can remain unchanged. This does not establish forced-rebase support.

The x86 DLL reports successful compression but never reaches RunFixture in bounded rundll32 tests, including with ASLR/DEP/NO_SEH cleared. Its compressed export table is also unreadable before loader execution. Neither amd64 kind is usable: both crash the packer with an access violation. Failed files are disposable probes, not reference fixtures.

Run the helper with `--probe-failed` to reproduce the distinctions. GUI success alone is insufficient; the common Open dialog must finish initializing before its filename is assigned. No binary patch is applied to the packer or its output.
