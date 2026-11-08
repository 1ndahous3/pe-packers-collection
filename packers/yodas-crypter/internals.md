# Crypter research notes

## Loader and section handling

Both versions generate polymorphic byte transformations with junk instructions, encrypt application sections and decrypt them in memory. The loader itself is encrypted too. Import information is moved into loader data and reconstructed at startup. This is encryption, not a compression ratio comparison or a VM interpreter.

The public sources explain an observable difference: 1.2 encrypts the fixture's `.rdata`, including DLL exports. These exports become usable after initialization. The 1.3 port explicitly skips `.rdata`, `.edata`, `.idata` and `.tls` in addition to resources, relocations and its own section. Its ASCII marker therefore remains readable on disk. Do not infer whole-file secrecy from the other hidden markers.

## Modern PE flags and runtime limits

Both loaders use SEH internally, including transfer to the original entry point. Clearing optional debugger checks does not remove this mechanism or all built-in debugger detection. Our original `NO_SEH` flag is incompatible with that startup path. ASLR is a separate obstacle: clearing only NO_SEH or only DYNAMIC_BASE still crashes the EXE. Clearing both on a temporary input before encryption works; DEP can remain enabled. There is no post-encryption patch that could accidentally invalidate a checksum.

Reproduce with the generator's minimal profile: all six optional GUI boxes off. Normal and wait execution succeed for both EXEs and the 1.2 DLL. The 1.3 DLL produces a RunDLL initialization-failure dialog; no successful DLL profile was established. Default settings (CRC, import destruction, anti-dump and API redirection on) crash the prepared EXEs too; the individual responsible option was not isolated.

The parsers and generated loader are 32-bit. Both amd64 fixture kinds leave their temporary inputs unchanged and fail to produce a completion dialog within the bounded GUI attempt. This is not a clean explicit rejection. `--probe-failed` repeats these attempts without executing PE32+ output or retaining failed files.

## Recovery and reproducibility

Successful callbacks verify all four runtime secret checksums; wait mode verifies liveness, including DLL name and ordinal dispatch. No byte-identical disk reconstruction or complete memory recovery is claimed. For the 1.2 DLL, static export parsing is intentionally replaced by runtime checks of the exercised exports; other exports and forced rebasing remain unverified.

Polymorphic output varies between runs. Use `--verify-only` for retained files and a fresh `--output` directory for regeneration. A native unpacking command was not established. Public source ZIPs remain linked rather than duplicated locally.
