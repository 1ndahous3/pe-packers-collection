# ASPack internals

## Versions and execution model

The [vendor package](http://www.aspack.com/files/aspack.zip) contains the 2.43 manual and change history. Its current executable reports build 2.43.1.26 and uses protection-library dependencies; these protect the packer itself and are not required alongside packed fixtures. The older English 2.12 installer is available from the [NTU mirror](https://ftp.ntu.edu.tw/pub/cpatch/a/aspack/source/).

ASPack compresses code/data and restores them in its loader. The recorded profile uses normal compression, resource compression, preserved overlays and Windows loading of imported DLLs. The alternative built-in DLL-loading mode and export compression were not exercised. Neither distribution supplies buildable packer sources; the manual explicitly states that ASPack cannot decompress its output back to disk.

## DEP compatibility

With unchanged x86 inputs, 2.12 produces an EXE that fails with an execute access violation and a DLL that fails its callback check. An x86 debugger stops at the loader entry in `.aspack`: the section lacks executable permission and is mapped read/write. This is a DEP failure before the fixture code runs.

Clearing only `NX_COMPAT` in a temporary input allows both cases to pass. Clearing `NO_SEH` alone does not fix the EXE; it is left unchanged in retained cases. No system mitigation settings or packed bytes are patched. This workaround depends on the host's DEP policy and is not a guarantee under mandatory DEP.

2.43 marks its loader executable and passes both fixtures without input changes. The vendor history records improved DEP compatibility beginning with 2.2, and improved EXE ASLR compatibility in 2.24; 2.2 is covered separately below.

To reproduce, use [generate.py](generate.py) with `--version 2.12` or `--version 2.43` and a fresh `--output`. Add `--keep-nx --arch x86 --kind exe` to 2.12 for the original failure. For diagnosis, stop an x86 debugger on access violations and inspect the fault type, entry-point section permissions and mapped page protection.

## Format limits and recovery

Both versions reject PE32+ EXE/DLL inputs without output. 2.43 explicitly reports that only 32-bit executables are supported; 2.12 reports a generic `Unknown error`. The generator recognizes that old diagnostic only for the recorded build and amd64 inputs; it never treats an arbitrary unknown error as unsupported.

Packed files retain original section names and add `.aspack` and `.adata`. They retain the ASLR flag and a small loader-facing relocation directory; this does not establish that every original relocation is exposed there. Forced address collisions, TLS, resources and advanced exception scenarios were not tested.

DLL export names and ordinals survive in both versions. All runtime secrets pass checksum checks, but complete string markers can remain visible in packed bytes: the `.data` marker in both kinds and the `.rdata` marker in DLLs. The `.text` and `.secret` markers are not visible in full. A visible marker may occur as literals in compressed data; it does not prove that its entire original section was left unpacked.

For a recovered file, verify usable code/data, imports, exports, entry point, protections and fixups, then run the callback and secret checks. Runtime recovery here is not a byte-exact disk reconstruction or validation of a third-party unpacker.

## Additional DVD releases

2.11 passes both x86 cases using the same temporary `NX_COMPAT` adjustment as 2.12. Its amd64 diagnostic is a generic path error despite existing input files; no output is produced.

2.2 reaches 100%, writes the file, then raises an access violation in the packer. The pinned-build GUI adapter recognizes only this observed completion fault and still requires independent output validation. The EXE passes without input changes. The DLL does not reach its callback, including with the older NX adjustment; it is not retained. Use `--version 2.2 --arch x86 --kind exe` for the passing profile. Explicit DLL probes run with bounded process containment.
