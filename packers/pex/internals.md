# PeX research notes

## Profiles and loader

The retained distribution includes the packer source in `src.RAR`. Its native x86 loader decrypts/decompresses sections and rebuilds imports. Optional import redirection and BPX protection distinguish the default and minimal profiles. All complete disk markers disappear; all runtime checksums and the application wait loop recover correctly. This is behavioral verification, not exact disk reconstruction.

CLI flags disable features: `-R` keeps relocations, `-I` removes extra import protection, and `-X` removes BPX protection. Alignment must remain enabled for our fixtures. Disabling both alignment switches (`-A -L`) produced a file rejected by Windows. CLI runs always exit with -1, including success, and bypass the registry-backed GUI configuration.

## Compatibility

The unprepared default EXE faults on this host. Clearing only DYNAMIC_BASE is insufficient. The verified profile clears DYNAMIC_BASE, NO_SEH and NX_COMPAT in a temporary input before packing; no output repair is needed. DEP-enabled execution and forced rebasing are not verified working profiles.

The source explicitly checks i386 and rejects the DLL flag. Corresponding matrix probes leave input bytes unchanged. The CLI parser requires a filename ending in `.exe`, so negative DLL probes use that extension while preserving the actual DLL header. This does not convert the DLL to an EXE.

Use `--probe-failed` for these checks and a fresh `--output` directory for regeneration. The default profile strips relocations; the minimal profile retains them, without claiming the loader supports relocation. The author explicitly excludes DLL support. No native disk-unpacking workflow was established.
