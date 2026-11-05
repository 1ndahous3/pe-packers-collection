# PE-PaCK internals

## Compression and loading

The author's `PEPACK.TXT`, included in both [public distributions](README.md), describes aPLib compression of code/data and DELTA/RLE followed by aPLib for relocations. Resource compression is configurable; icons and version information normally stay readable. Our fixtures have no resources, so those options were not exercised. `-spd` produces a different compressed stream in both tested PE kinds.

The packed images retain the original section names and RVAs and add `PEPACK!!`. Entry code in the original code section transfers control to the loader. The public relocation directory contains only a dummy block with an ABSOLUTE entry; the loader handles the payload's relocations privately. Export names and ordinals remain intact.

## DEP and relocation failures

Stock outputs preserve `NX_COMPAT` and `DYNAMIC_BASE` but mark every section readable/writable without execute permission. A debugger stops at an execute access violation at the packed entry point before decompression starts.

Restoring execute permission on the original executable section and `PEPACK!!` gets past that fault. When Windows rebases the EXE, the private relocation decoder subsequently writes through an invalid target outside the image. Clearing `DYNAMIC_BASE` allows the tested EXE and DLL to run at their preferred bases. The generator makes only these header edits; it does not patch the decoder, compressed stream or payload, and keeps `NX_COMPAT` set.

To reproduce the distinction, pack a disposable fixture with the commands in [generate.py](generate.py), then launch the raw output under the x86 Windows debugger with first-chance access violations enabled. Inspect the entry section's execute permission. Repeat with only execute flags restored, checking the actual module base against `ImageBase`: a rebased EXE reaches the separate relocation fault. Finally apply the complete helper fix and verify execution at the preferred base. Failed probes may open Windows error-reporting dialogs; close only their own processes.

The manual mentions an encoder limitation with unsorted relocations from older linkers. That warning does not establish the cause of this observed decoder failure; the relocation stream has not been repaired.

## Recovery and base-collision checks

For exact recovery checks, launch each retained EXE with `--wait`, or its DLL through x86 `rundll32` with `WaitFixture`. After readiness, locate the module with Toolhelp, confirm its actual base, and use `ReadProcessMemory` at base plus each secret RVA from the shared fixture manifest. Compare the full marker bytes, not just their checksums. All default/fast EXE/DLL cases passed at their preferred bases. Normal execution and DLL wait invocation by name and ordinal also passed.

To test the DLL limitation, create its `rundll32` host suspended, reserve the DLL's preferred image range with `VirtualAllocEx`, and resume the host. Both profiles failed to reach the readiness callback within four seconds; each owned host was then terminated. Clearing `DYNAMIC_BASE` therefore supplies a working baseline, not safe arbitrary rebasing: address collisions can still force relocation.

Separate amd64 probes crashed or timed out without usable packed output; no amd64 output was executed. The generator skips that architecture. TLS, resources and external disk unpacking were not tested. The manual documents no built-in decompressor, and successful runtime/secret recovery does not establish exact reconstruction of the original PE headers or file.
