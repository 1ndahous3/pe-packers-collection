# PECompact research notes

## Release identity and toolchain

The archived official `pec2student.zip` supplies **2.79 Student/Freeware**, confirmed by the console banner and interactive About topic. The executable's Windows version resource is stale and reports a different version; use the console identity. The complete rare distribution is retained alongside `bin/`, including its manual and plug-in SDK examples. It does not contain a buildable compressor source tree.

The passing CLI profiles need only the compressor, default loader, LZMA2 payload codec and aPLib loader codec. Extraction and commands are documented in [generate.py](generate.py). `PEC2.exe /?` waits for keyboard input from a terminal; redirecting its streams can leave it waiting indefinitely. The archived 3.11 beta is used unchanged and remains a time-limited trial.

## Loader and recovery

Bitsum describes a staged loader: an entry stub transfers control through SEH to a decoder, which expands the primary loader into allocated memory. That loader reconstructs the program before transferring control to the original entry point. Its private import/relocation metadata need not use standard PE layouts. See the [vendor's interoperability notes](https://bitsum.com/pec2av.htm).

For an emulator or dumper, exception dispatch, executable memory allocation, imports and relocations therefore matter before the original code runs. Codecs and loaders are independent choices; the recorded profile pins both rather than relying on automatic codec selection. PECompact 2.x was rewritten, so these observations should not be transferred to 1.x without testing.

## The NO_SEH compatibility case

The original x86 EXE runs correctly, but packing it unchanged with 2.79 succeeds and then produces an access violation on the tested host. Clearing only `IMAGE_DLLCHARACTERISTICS_NO_SEH` in a temporary input copy gives a passing packed EXE. This fits the documented SEH loader and [Microsoft's definition of the flag](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics), which prohibits handlers in the image.

The generator makes this preparation explicit and preserves the shared original. ASLR and NX remain enabled; `/Sf:No` retains fixups. Changing import restoration, section merging, memory protection or fixup stripping alone did not resolve the original-input failure. The DLL passes without input preparation.

In 3.11.00.02 beta, both unchanged x86 inputs pack and execute successfully; the packer itself clears `NO_SEH` in both outputs. This agrees with the vendor's [3.03-series change log](https://bitsum.com/changelog/pecompact/pec_old_history.php), which extends that handling to all modules. These fixtures do not exercise a SafeSEH table, so the result does not verify the separate SafeSEH fixes listed there.

Run the generator with `--version 2.79 --check-no-seh` to reproduce the failing unmodified EXE and the passing prepared case using temporary files. The normal matrix also checks that both amd64 inputs are explicitly rejected and remain unchanged.

## What the saved cases establish

- All four complete markers disappear from the packed byte streams; execution verifies their checksums after runtime reconstruction. This demonstrates recovery needed by the fixture, not complete restoration of an original PE file.
- Packing merges the original section layout and adds loader data. The resulting `.rsrc` section is executable; a section name alone does not identify its contents or permissions. Retaining the NX header flag does not preserve the original per-section access rights.
- DLL export names and ordinals remain available, and `RunFixture` works through x86 `rundll32`. Some export-directory metadata points into data reconstructed at runtime: a parser expecting every referenced string to be backed by raw file bytes can reject this packed DLL.
- The loader overhead outweighs compression for these small inputs. Larger output is not a packing failure.
- There is no native command that restores a PE to disk. A future dump needs separate checks of imports, exports, relocations, markers and execution; the current results make no claim about external unpacker output.
