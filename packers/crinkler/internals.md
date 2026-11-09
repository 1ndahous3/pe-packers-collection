# Crinkler research notes

## A linker, not a PE-to-PE compressor

Crinkler merges code and data from x86 COFF inputs, compresses them and emits a small executable with a decompression/import stub. Original PE sections and headers are not an input to this process. Consequently, byte equality with the ordinary fixture PE is not a recovery criterion; recovered code/data behavior and secret checksums are the useful comparison.

The adapter compiles the shared EXE and secret sources without edits or optimization, then passes the same objects to Microsoft's linker and Crinkler. The normal link preserves the four complete markers, and both executables pass the same runtime and wait checks. Crinkler can rearrange the marker sections; their original PE placement is not preserved. This case uses FAST compression without TINYHEADER, TINYIMPORT or a code transform.

## Entry point and imports

Crinkler's `/ENTRY` takes the undecorated `FixtureEntry` name. Passing Microsoft's decorated stdcall spelling fails despite the symbol being present in the object. The adapter supplies `kernel32.lib` for fixture imports and `user32.lib` for Crinkler's import-error reporting stub. The warning about an entry point away from the beginning of its section is harmless here: Crinkler inserts a jump.

The output uses compact, overlapping PE header/code structures and hash-based import resolution. Its default ASLR/DEP flags are clear; these are packer output properties, not manual patches. No native unpack-to-disk mode was established.

## Target boundaries

Win32 and Win64 release binaries describe the tool's host architecture. The supported output remains x86 EXE. All four published raw PE fixtures are rejected as unsupported input, as are compiled amd64 objects. `/DLL` is merely ignored as an unknown argument: supplying valid EXE objects still emits an EXE, not a DLL. The generator's `--probe-failed` option reproduces these distinctions without retaining probe artifacts.

These tests cover the shared fixture's normal execution, sleep loop and secret checksums. They do not establish support for general CRT initialization, TLS or C++ exception machinery. The source inspected for this release is tag `v3.0b` (`afc007676157e216bf06227c021f7c2a88da9448`).
