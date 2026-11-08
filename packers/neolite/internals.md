# NeoLite internals

## Distribution and profiles

The SAC and Infania ZIPs are identical. Their `NeoLte20.EXE` is a 16-bit Wise installer, while the embedded console and compression library are ordinary Win32 binaries. [prepare.py](prepare.py) extracts just those members and validates the ZIP, stream CRCs and executable hashes. The console identifies itself as evaluation version 2.00; the library's version resource says 2.00 Release 1. Installation and shell extensions are unnecessary.

The distribution's `readme.txt` describes two modes: reversible compression and maximum/irreversible compression. The CLI uses reversible mode by default; `-e` disables native expansion. `-j` is needed to keep outputs that grow, and `-r` preserves EXE relocation data. The retained profiles leave import/resource compression and NeoDataSim at their defaults. Resource, TLS and overlay behavior is not exercised by the shared fixtures.

## Packed layout and secrets

The loader lives in `.neolit`; the original section entries remain but their raw data is moved into the packed stream. The original relocation section is renamed `Oreloc`, and a new `.reloc` serves the loader. Imports are rebuilt during startup; DLL export names and ordinals remain accessible. The loader restores the original code's execution permissions, so adding execute permission to the packed `.text` header does not resolve the observed failure.

In both profiles, the complete binary code marker remains visible in EXEs and DLLs. The ASCII marker also remains visible in EXEs, while the other complete markers disappear. Compression can retain short literal sequences and is not a guarantee of hiding every secret. All runtime checksums pass after startup. During wait mode, all full manifest secret sequences also match bytes read from the actual loaded module with `ReadProcessMemory`. File growth here reflects loader and trial overhead, not a failure to compress the small payload.

## Rebasing compatibility

Raw outputs retain `DYNAMIC_BASE`. Under an x86 debugger, both the EXE and DLL reach restored original code at a different image base, but its absolute references still point at the preferred base. The EXE raises a read access violation in its entry function; the DLL faults while initializing its data, and rundll32 reports DLL initialization failure. This is a relocation failure, not an execute-permission fault.

To reproduce, use the raw CLI commands in [generate.py](generate.py) on disposable shared inputs and enable first-chance access violations in an x86 Windows debugger. For the EXE, answer the trial notice with No. Compare the actual loaded module base with its preferred image base and the absolute address used by the faulting instruction.

The generator clears only `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` in the output optional header. With preferred-base loading, both profiles pass execution and wait checks while preserving `NX_COMPAT`, the relocation directory and compressed data. Both corrected DLL profiles also pass a forced address-conflict rebase, sustained wait mode and full secret-byte checks at the alternate base. EXE forced rebasing and system-wide mandatory ASLR remain untested. Shared originals and packer binaries remain unchanged.

Under ASLR the DLL's in-memory optional-header `ImageBase` equals its randomized load address. With `DYNAMIC_BASE` cleared, an address-conflict relocation leaves that field at the preferred address and the same packed loader succeeds. This distinguishes the failing ASLR path from ordinary DLL relocation; clearing the flag does not remove relocation information.

To reproduce the address-conflict check, launch x86 rundll32 in an x86 debugger and reserve the preferred DLL image range with `.dvalloc /b <preferred-base> <image-size>` before continuing to `WaitFixture`. Require an actual module base different from the preferred base, the success line and continued execution. Read every manifest secret at the actual base plus its marker RVA and compare full bytes. Use PID-owned processes and bounded cleanup; the ordinary generator checks do not reserve addresses.

## Native and external recovery

`NeoLiteCli.exe -x` on raw reversible output reconstructs the complete original bytes for both kinds. This includes PE headers, imports, exports, relocations, padding and all secret sequences. After the collection's header fix, native recovery preserves that change: the result differs from the shared original only in `DYNAMIC_BASE`. Recovered files pass normal and wait-mode checks. The generator verifies both raw recovery and the expected final recovery, keeping restored files temporary.

Irreversible output is still unpacked by its runtime loader, but native disk expansion exits with the explicit cannot-uncompress diagnostic and creates no output. This is a loss of exact-reconstruction metadata, not encryption or a VM protector.

[Russ Dill's unpacker](https://github.com/russdill/Neo-Executable-Decompressor/blob/b88c93369e7faf4c087e3973e1028038ed510526/neolite_unpack.py) independently reconstructs both raw reversible fixtures exactly. On corrected fixtures it retains the same `DYNAMIC_BASE` difference. Its format implementation describes section streams and reversible patch data used to restore original bytes. Treat its general support claims separately from these tested cases.

To reproduce the external check, download the linked pinned script, install its `pefile` dependency in a temporary Python environment, and run `python neolite_unpack.py <packed-file> <temporary-output>`. Compare against the shared original with the documented header difference. The unmodified script fails on both irreversible fixtures: its IAT reconstruction passes an RVA directly as a file offset to `struct.unpack_from`, beyond the reconstructed file. No external-unpacker fix or irreversible recovered PE is retained.
