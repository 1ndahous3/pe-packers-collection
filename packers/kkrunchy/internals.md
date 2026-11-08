# kkrunchy internals

## Engines and source lineage

The [author's article](https://fgiesen.wordpress.com/2011/01/24/x86-code-compression-in-kkrunchy/) describes the two engines: LZ77 with arithmetic coding, followed by PAQ-style context mixing. Both apply a reversible x86 instruction filter before compression. This separates instruction components into streams; decompression alone does not yet produce executable original code.

The official source inventory identifies [kkrunchy/](https://github.com/farbrausch/fr_public/tree/8c8f82c2ae01133370e649bbc05916e7aceecadd/kkrunchy) as the recovered alpha source and [kkrunchy_k7/](https://github.com/farbrausch/fr_public/tree/8c8f82c2ae01133370e649bbc05916e7aceecadd/kkrunchy_k7) as a4/asm07. These trees help explain the releases but were not rebuilt or established as byte-identical source matches. The older website's statement that sources are unavailable is superseded by this repository.

For a source build, follow each tree's `HOW_TO_BUILD.txt` and Win32 solution. K7 uses NASM to assemble a depacker in RDF format and links its fixups itself; the build notes explicitly warn that YASM is unsuitable for that path. Stable upstream binaries and sources remain linked rather than duplicated as archives.

## Loading and the ASLR failure

`EXEPacker::Pack` constructs a compact PE header, lowers the preferred image base, merges the image into one read/write/execute `kkrunchy` section, and supplies its own entry point. The restored application code and data keep their original virtual addresses. Imports are represented differently: the packed files expose only `LoadLibraryA` and `GetProcAddress`, and the loader resolves the application's imports before transferring control.

The packer copies `DllCharacteristics`, including `DYNAMIC_BASE`, while these outputs have no base-relocation directory. In local debugger runs Windows relocated each raw output, but loader operands still referenced the preferred addresses. All three builds failed with an access violation before reaching the fixture.

The retained profile packs the unchanged input and clears only that output flag through `without_aslr()` in [generate.py](generate.py). Normal execution and wait mode then pass in every version. `NX_COMPAT` stays enabled; the merged executable/writable section remains a property of the packer. This restores fixed-address loading, not ASLR support. The warning about an image base below the Win9x minimum is separate from this modern Windows failure.

To reproduce the failure, use the helper's documented raw packing command, launch its result before applying the fix, and inspect the first access violation. Compare the actual module base with its preferred base and the loader's absolute operands. Do not change the original fixture or disable host protections.

## Format limits and diagnostics

The x86 DLL fixtures are explicitly rejected because they contain exports. Exit status is nevertheless zero, so success requires an actual output and runtime checks. TLS exclusion comes from the author and source validation; the baseline does not exercise TLS.

PE32+ is not safely validated. The parser assumes PE32 structures: the amd64 trials produced access violations, assertions or an inverse-filter error, with no output. The generator skips these inputs by default; `--probe-unsupported` repeats the bounded parser probes. These observations do not imply partial amd64 support.

Packed headers declare only five data-directory entries for these resource-free inputs. A reader must honor `NumberOfRvaAndSizes` and the optional-header size rather than interpreting the following section header as relocation, TLS or CLR entries. The collection's shared PE reader was corrected for this case.

## Recovery target

All four complete markers disappear from the packed bytes and match exactly in waiting-process memory, including the binary marker embedded in `.text`. The instruction filter therefore round-trips this fixture's non-code bytes successfully; this is not a guarantee for arbitrary data in code sections.

Read recovered markers at the original preferred image base plus their manifest RVAs, not at the packed module base plus those RVAs. The generator checks these addresses after the fixture reports readiness. A dumper must also account for restored imports, the original entry point and the changed section layout.

There is no native disk expansion option. Successful execution and marker recovery do not establish restoration of the original PE headers, padding or file layout. External file reconstruction remains untested. Repeat packing produced identical files in the local check; the generator still refuses to overwrite a different artifact.
