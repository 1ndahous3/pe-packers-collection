# WWPack32 internals

## Section selection and compression

The author's `WWPACK.DOC` in the [distribution](README.md) describes compression algorithms inherited from DOS WWPACK, automatic/manual section selection, resource compression and optional relocation stripping. WWPack32 appends a `.WWP32` loader and transfers control there before the original entry point.

In the shared x86 EXE, automatic mode compresses only `.text`. The `.rdata` section contains imports and is excluded; the manual cautions against compressing import/export sections. The smaller `.data` and `.secret` sections are also left alone; relocation data is handled separately. Static inspection shows a section-size check that skips raw sizes of 512 bytes or less. Manual mode offers the larger sections but does not override that threshold. Accepting `.text` and declining `.rdata` produced the same best-level bytes as automatic mode.

The DLL follows the same section-selection pattern; its `.rdata` also holds exports.

The fastest and best profiles use levels 0 and 20. Their compressed bytes differ, but file alignment and loader overhead give the same final size for these small fixtures. Relocation stripping is explicitly disabled in both profiles; the relocation directory header remains present, but its on-disk contents are replaced with a short no-op block and zero padding. No resource data is available in these inputs to exercise resource compression.

## DEP compatibility

Stock output retains `NX_COMPAT` while creating `.WWP32` without execute permission. An x86 debugger confirms an execute access violation at the packed entry point, on a page mapped without execution rights.

To reproduce, pack a disposable input through the GUI, leave the result unchanged, and launch it under the x86 Windows debugger with first-chance access violations enabled. Inspect the fault and the entry section's page protection. Then use the generator's `fix_loader()` to add `IMAGE_SCN_MEM_EXECUTE` to `.WWP32` and repeat normal execution and wait checks. Only that section-header flag changes; the compressed stream, loader code and mitigation flags are preserved.

The fixed EXE outputs from both builds ran at their preferred image base even though `DYNAMIC_BASE` remains set. These tests do not establish arbitrary rebasing support, and no claim is made about its behavior under a forced image relocation policy.

## Runtime recovery

Start a retained EXE with `--wait`, or a DLL through x86 `rundll32` with `WaitFixture`. After its success line, enumerate its loaded modules with Toolhelp and read every manifest secret with `ReadProcessMemory` at the actual module base plus the marker RVA. Compare full bytes against the shared manifest. Both levels and all retained versions/kinds passed this check, normal execution and sustained wait mode. DLL wait mode also passed through ordinal 4.

Only the `.text` marker disappears from the packed file. The read-only string, writable string and repeated marker remain visible in the sections excluded from compression. Visibility is an observed selection policy, not a failed runtime recovery check.

The demo explicitly refuses the x86 DLL with a DLL-compression notice. Both builds reject amd64 EXE/DLL without modifying their inputs. The generator skips these unsupported cases. The manual provides no built-in decompression workflow; external disk unpacking, exact original-header recovery and TLS behavior were not tested.

## Ghosthunter build and DLL rebasing

The recovered Full archive contains only a binary. It has an embedded `Cracked by Ghosthunter` credit, product version 1.20 and file version 1.20.3.236. It enables DLL compression, but the file-signature setting remains disabled. Without a registered original or patch description, the exact modifications cannot be attributed further; this is not treated as an unmodified vendor Full distribution.

Adding execute permission is sufficient for preferred-base DLL loading. Forced rebasing still fails: the packer replaces the original base-relocation table with a short block of `IMAGE_REL_BASED_ABSOLUTE` no-op entries, pads the rest with zeros, and leaves the original directory Size in the optional header. That size includes an invalid zero-sized trailing block. Reducing only the directory Size to the first block's actual length makes both profiles load at an alternate base. The generator validates the no-op entries and zero padding before applying this additional DLL fix; it does not alter loader code or packed data.

To reproduce, start the matching `rundll32` suspended and reserve the DLL's preferred image range with `VirtualAllocEx` before resuming. Use the original fixture as a control, then compare an output with only the DEP fix against the final output with both fixes. Require the success line, continued wait-mode execution, an actual module base different from the preferred base, and full manifest secret bytes read at that actual base. The original and final outputs pass; the intermediate output does not reach the callback. Under an x86 debugger, reserving that range with `.dvalloc /b` before the host loads the DLL provides the same address conflict.
