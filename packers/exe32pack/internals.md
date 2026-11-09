# EXE32Pack research notes

Both methods compress sections and add a native loader. M1 has less loader overhead; M2 compresses the payload more but produces a larger file on these tiny fixtures. `/F` makes this useful as a test case even when the whole PE grows. Compression ratio and final file size are different measurements.

By default, DLL exports reside in compressed data. Static parsers cannot enumerate them, yet RunFixture and WaitFixture work by name and their original ordinals after DLL initialization. `/NE` skips compression of the export-bearing section, which also exposes the unrelated secret located in `.rdata`. This is a useful contrast between section-level packing and export availability.

The packed file carries a minimal relocation directory while the loader restores compressed contents. ASLR/DEP flags remain set and the ordinary x86 tests pass; forced relocation and complex TLS/SEH are outside these baseline checks.

Both amd64 kinds report `failed repack` and leave no output for either method. Exit code zero is returned even on those failures. Reproduction must check the diagnostic and output existence as well as process status. Use the helper’s `--probe-failed` option.
