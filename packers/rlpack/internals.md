# RLPack internals

## Distribution and scope

The [mirrored RLPack.zip](https://www.stahuj.cz/utility_a_ostatni/komprese/rlpack-basic-edition/download/) identifies itself as Basic Edition 1.21 in its executable resources, source and help. `Source/RLP.asm` is the packer; `Stub_aplib.asm` and `Stub_lzma.asm` provide its loaders. The archive also supplies `Importer.dll` and `lzma.dll`. The original author site is unavailable; sources remain obtainable with this public distribution.

The shared manual describes Basic, Full and iBox. Basic's stubs implement compression, import recovery and relocations; the manual's VM/protection features should not be attributed to these cases. Generation uses the distributed binaries, without a rebuild or patch.

## Resource-less input failure

In `RLP.asm`, `PEHeader` initially points into the mapped input. The resource-handling branch redirects it to the output header. When the input has no resource directory, that branch is skipped, but the subsequent section-layout code still writes through `PEHeader`. It consequently alters the input section table before compression.

On the unmodified EXE fixtures, normal packing exits successfully but the payload returns its secret-check failure code. A debugger breakpoint at the original entry point shows that the read-only marker was not restored. For DLL, the copied export directory is corrupt. Enabling Windows DLL loader without resources also produces malformed section layouts. These are packing failures, not failures of an external unpacker.

The [generator](generate.py) appends a valid `.rsrc` section with a single RCDATA item to a disposable x86 copy. It updates the necessary PE header fields while preserving all existing section headers and bytes, RVAs, imports, exports and entry point. It checks the adapted input before packing. Both compression backends then pass the fixture checks. This is an input compatibility workaround; it does not fix the packer's source or weaken the secret checks.

To reproduce the failure, pack a temporary copy of an unmodified shared x86 fixture with the helper's switches, omitting `add_resource()`. Inspect the packed headers and stop at the original entry point to compare secrets. To reproduce the working case, use the normal generator. Never give the in-place packer a shared original.

## Loader behavior and limitations

The packed image combines payload sections into a virtual `.packed` area and stores compressed blocks and loader data separately. The loader expands data to the original RVAs, reverses its code filter and reconstructs imports using hashed API names. The DLL loader also applies a private compressed relocation stream; the public relocation directory contains only an empty block.

The `w` switch asks Windows to preload dependent DLLs. It works for both EXE backends on these fixtures. With the adapted DLL, packing crashes with `0xC0000005`; partially modified temporary files are discarded. Windows Error Reporting identifies `Importer.dll` as the faulting module; the underlying helper-library defect was not further investigated.

The output header clears `DYNAMIC_BASE` and `NX_COMPAT`. EXE files have no public base-relocation directory even though relocation stripping was not requested. DLLs nevertheless load correctly when their preferred base is occupied. This is a specific tested behavior, not general ASLR/DEP compatibility.

An amd64 EXE probe returned success with mixed i386 machine / PE32+ headers. The amd64 DLL probe crashed the packer. Invalid outputs were not executed; the generator skips amd64 before invoking RLPack.

## Recovery checks

Start a retained EXE with `--wait`, or load a DLL with `WaitFixture`. After the success line, compare each complete marker from the [x86 manifest](../../fixtures/bin/x86/manifest.json) at the actual module base plus its original RVA. All retained profiles passed exact byte comparisons.

For a DLL collision test, start x86 `rundll32` suspended, reserve the DLL's preferred image range with `VirtualAllocEx(MEM_RESERVE, PAGE_NOACCESS)`, resume it and confirm a different loaded base. Both retained DLLs reached wait readiness and recovered all marker bytes under this condition. Terminate the owned wait process after inspection.

These checks verify runtime behavior and marker recovery. They do not establish byte-identical disk unpacking, restoration of original headers, TLS compatibility or general resource handling. No external unpacker was tested.

## Full Edition from SUN DVD

The ROGUE archive contains a repackaged installer, a key-file utility and iBox. Extract the installer with innoextract instead of installing it. The retained tool reports Full Edition 1.21. Its key file is read directly by RLPack; `license.reg` is not imported into Windows Registry. The adjacent watermark state is also a runtime dependency.

Full uses a different GUI/project workflow from Basic. The generator selects the Full stub, aPLib or LZMA, CRC and memory protection. Anti-cracking/VM options, import redirection, iBox, stripping, passwords and downloads are disabled. It supplies explicit Open and Save paths in a disposable directory.

Both x86 kinds pass without Basic's added-resource workaround. Full's PE64 EXE output mixes i386 machine with PE32+ headers; DLL packing did not complete. Neither is executed or published. The archived iBox and more aggressive protection options remain future research material.
