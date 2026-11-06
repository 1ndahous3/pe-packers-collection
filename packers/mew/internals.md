# MEW internals

## Distribution and compression

The [SAC package](https://www.sac.sk/download/pack/mew11.zip) and [Infania mirror](https://ftpmirror.infania.net/pub/pc/pack/mew11.zip) were byte-identical. `manual.html` and `northfox.nfo` identify this release as **MEW 11 SE v1.2** and describe its options. The history distinguishes earlier executable modifiers from the later compressor; detector labels or the short name “MEW 1.1” should not substitute for identifying a distribution.

Default mode tries aPPack and LZMA; `-dont_use_lzma` restricts it to aPPack, and `-lzma_special` enables the documented E8/E9 transform for LZMA. On the shared x86 EXE, all three modes produced identical bytes and passed execution and wait-mode checks. The retained file therefore covers the aPPack path; merely enabling LZMA does not establish that its decoder is exercised.

Reproduce with [generate.py](generate.py), `--version 11-se-1.2 --arch x86 --kind exe` and a fresh `--output`. Compare default output with `--pack-arg=-dont_use_lzma` and `--pack-arg=-lzma_special`. The distribution supplies no buildable packer sources or documented disk-decompression command.

## PE layout and recovery

MEW replaces the original section layout with two sections and loader-facing imports. Bytes of its loader occupy section-name fields, so those fields are not reliable textual labels. The shared PE inspector escapes non-ASCII bytes rather than rejecting such a file.

The recorded output has no ASLR/DEP flags or standard relocation directory, and its sections lack execute permission. It runs at a fixed base with DEP opt-out on the recorded host. Neither input nor output is patched to obtain this result; it does not establish compatibility with mandatory DEP or forced rebasing.

All four secret checksums pass at runtime, including in `--wait` mode, while the complete markers are absent from packed bytes. This verifies usable code/data recovery for this fixture. It does not establish restoration of original headers or byte-exact disk contents, nor test an external unpacker. For recovered files, verify entry point, imports, code/data, execution and secrets independently. Resources, TLS and overlays are not exercised by this fixture.

## CLI and unsupported inputs

The CLI requires care: absolute or quoted input paths in our probes could return zero without changing the file. A simple relative filename from its directory works. The helper also supplies a simple program name as `argv[0]` while selecting the actual executable path separately. The manual's `*` substitution for spaces is unnecessary with the helper's fixed temporary filenames.

MEW's transient, untitled progress dialog contains the terminal status and reason. The helper reads its Static controls by the launched PID until automatic exit; it requires both `Packing procedure ready!` and validated output. The executable is never modified, and all packing work happens in a disposable directory.

The author explicitly excludes DLL and 64-bit support, but the CLI does not reject them consistently:

- **x86 DLL:** reports success and writes a packed file, but clears the DLL characteristic and removes all exports. This is not a working DLL fixture, regardless of the success message; it is discarded before publication.
- **amd64 EXE/DLL:** reports `Packing procedure failed!` with `Don't support .NET applications!`, exits zero and leaves the input unchanged. The inputs are native PE32+ with no CLR directory. The helper recognizes this misleading diagnostic only for the pinned release and known amd64 fixtures.

The generator runs the full matrix by default, verifies original hashes, and keeps only passing packed PEs. A changed file, zero exit code or success dialog alone is insufficient.

## MEW 5 / 0.1 beta

This earlier Northfox tool encodes the code section rather than compressing the whole image. Its header-resident decoder and unchanged file size distinguish it from MEW 11. Only the code marker disappears; the other three remain visible.

Raw EXE output fails the current Windows loader with `STATUS_INVALID_IMAGE_FORMAT`. The retained profile adds an executable section containing a relative jump to the original header decoder, and clears output `DYNAMIC_BASE`/`NX_COMPAT` for fixed-base header execution. Decoder and encoded payload bytes remain unchanged. Normal execution and wait mode then pass. This does not establish rebasing or mandatory-DEP compatibility.

The DLL did not reach its callback; PE64 probes produced malformed/truncated files. Those variants are discarded and skipped by the normal generator. Reproduce the EXE with `--version 5-0.1-beta`; direct raw command: `mew5.exe input.exe -o coded.exe`.
