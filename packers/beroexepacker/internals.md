# BeRoEXEPacker internals

## Distribution and profiles

The current author-linked ZIP and executable banner identify version 1.00.2017.01.27. The archive contains only `bep.exe`, with no buildable packer sources. The stable official download is linked in [README.md](README.md); the retained executable is pinned in [generate.py](generate.py).

The fixtures cover six compression families: LZBRS, LZBRR, LZBRA, LZMA, LZBRCM and CTX1, selecting LZMAU and LZBRCM0 rather than every level. LZBRCM0 keeps memory use modest. Different loader overheads matter for tiny inputs: successful packing can make a file larger. This is not a compression benchmark.

The general website description calls LZMA the default, while the executable help distinguishes LZBRR for small inputs. For both shared x86 fixtures, no-option packing produced exactly the same bytes as explicit LZBRR with `+X=0` and the retained profile. Do not infer the actual filter or algorithm from the general description alone.

## Layout and recovery

The outputs have a virtual `packerBY` section with no raw bytes, plus `bero^fr ` containing packed data and the loader; both are RWX. The loader-visible import table contains `LoadLibraryA` and `GetProcAddress`. The packing warning about ignoring the IAT directory does not mean all original imports were lost: normal execution and repeated `Sleep` calls work after runtime import rebuilding.

The packed DLL keeps the four named exports and their ordinals. The EXE and DLL preserve `NX_COMPAT` and `DYNAMIC_BASE`, but flags alone do not establish rebasing support. No input or output patches are needed for normal execution.

All profiles hide the complete secret markers on disk and restore them exactly in memory. To reproduce the byte comparison, launch an EXE with `--wait`, or a DLL through x86 `rundll32` with `WaitFixture`. After the exact success line, locate the actual module base in that owned process and compare `ReadProcessMemory(base + marker.rva)` against each manifest marker's full `hex` bytes. Terminate the test process afterwards. The generator performs runtime checksum checks; this separate memory check does not establish byte-identical reconstruction of the original PE file.

## x86 filter limitation

The help recommends `+X=0` for very small files. Explicit `+X=1` hung the shared DLL with every tested compression family; `+X=2` also hung the LZBRR DLL. These runs did not reach fixture stdout within the bounded test. LZBRR no-option output and explicit `+X=0` were byte-identical and worked. The underlying filter defect was not isolated.

To reproduce, pack disposable copies of the shared x86 DLL with `+ca=lzbrr +x=0`, then change only the filter to `+x=1` or `+x=2`. Invoke `RunFixture` through x86 `rundll32` with a timeout. The retained profiles use `+X=0`; changing the filter requires fresh runtime and secret checks.

## Relocation limitation

Even with relocation stripping disabled, the packed EXE has `RELOCS_STRIPPED` and no base-relocation directory. All observed EXE runs used the preferred base. Keeping `DYNAMIC_BASE` in the optional header therefore does not make these outputs suitable ASLR references.

Packed DLLs contain `IMAGE_REL_BASED_HIGH` fixups and run successfully at their preferred base. All six profiles failed a forced-base-collision test: RunDLL reported `Invalid access to memory location` before the callback's success line. The presence of a relocation directory is not sufficient evidence of correct runtime relocation.

To reproduce the collision without changing system settings or patching a PE, create the x86 `rundll32` test process suspended, reserve the DLL's preferred image range in that process with `VirtualAllocEx`, then resume it. Use the packed DLL with `RunFixture` and a bounded wait; terminate only that owned process. The ordinary control run leaves the address available. This collision check is separate from generation, which validates ordinary loading and wait modes. Correcting the loader's rebasing behavior remains outside the retained baseline.

## Unsupported inputs and scope

The author explicitly targets 32-bit EXE/DLL. Nevertheless, the shared amd64 fixtures are accepted with exit zero and `Done...`; the result is i386/PE32 with ImageBase 1, and the DLL loses its exports. Windows rejects the resulting EXE with error 193. This is consistent with reading a PE32+ header using PE32 field positions, not an AMD64 packing path. The generator verifies this specific incompatible result on a temporary copy and discards it without execution.

The executable help documents no native file-unpacking mode. TLS, resources, overlays with content, import-by-hash/ordinal modes, special headers, 64k mode and third-party unpackers were not covered. The shared originals remain unchanged.
