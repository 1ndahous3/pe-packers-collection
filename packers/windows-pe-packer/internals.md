# Windows PE Packer research notes

The native boot segment decodes a second loader stage, which restores selected sections, rebuilds imports, applies original relocations when required, restores section permissions and transfers control to the original entry point. Section encoding adds a fixed byte value; decoding subtracts it. There is no compression or instruction VM.

Selection is based on the names `.text`, `.data`, `.rdata`, `CODE` and `DATA`. The shared fixture’s `.secret` section is outside that list, so its full marker survives although the original section names are cleared. The second profile renames just that section to `DATA` before packing: all four markers then disappear from the on-disk bytes, while runtime checksums and wait behavior still pass. No content or protection flags change in the prepared input.

The packer clears several directories, including the normal relocation directory, and stores original relocation information for its loader. Retained ASLR/DEP bits and successful ordinary execution do not establish forced-rebase, TLS-callback, delay-import or general application compatibility. These tiny fixtures exercise the basic loader path only.

Both DLL architectures are explicitly rejected; amd64 EXE fails the platform check. Those errors still return exit code zero. Require a success diagnostic and a newly created output before runtime testing.

The source has no identified release for this snapshot, hence version 0. `build.py` reproduces a local MSVC build from pinned public source and MASM32 include revisions, with narrowly scoped build-compatibility changes. The original MinGW toolchain and byte equivalence to another build were not tested. Full upstream sources, SDK headers, archives and intermediate files need not be copied into this collection.
