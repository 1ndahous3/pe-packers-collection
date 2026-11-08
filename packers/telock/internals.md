# tElock research notes

## Loader and verification

The author's CHM manual is inside the [retained distribution](tools/0.98/telock-0.98.rar). It describes compression, polymorphic encrypted layers, section checksums, import reconstruction and optional IAT redirection. The minimal profile disables redirection and optional debugger detection; this does not remove the loader's own exception-driven and integrity-checking machinery.

All shared x86 EXE sections are processed. The default profile additionally strips the EXE relocation section; minimal retains it. Both hide all four complete disk markers and restore their runtime checksums. The application reaches its normal entry point and its wait loop; this is behavioral verification, not byte-identical PE reconstruction. The small fixture grows because loader overhead outweighs compression savings.

## Modern Windows compatibility

Raw output puts its entry point in a readable/writable section without execute permission while preserving NX_COMPAT. An x86 debugger confirms an execute access violation there. For the retained EXEs, clear DYNAMIC_BASE, NO_SEH and NX_COMPAT on a temporary input before packing; leave the resulting file untouched. This tested compatibility profile runs normally and in wait mode.

Post-packing header edits are not interchangeable with input preparation: adding execute permission or clearing mitigation flags on an already packed EXE triggers the loader's integrity-failure dialog. Recalculating the standard PE checksum alone does not repair that check. No integrity bypass or modified packer binary is retained.

For DLLs, accept the GUI prompt to redirect exports out of the mixed `.rdata` section. Packing completes, but the prepared DLL fails initialization under x86 rundll32. Clearing a DLL's NX_COMPAT bit does not disable DEP in its host. No working standard-rundll32 DLL profile was established.

Both amd64 inputs are mistakenly accepted and written out. The EXE exits with an access violation; the DLL does not reach its callback and its bounded run times out. Treat them as failed PE32+ attempts, not successful support or an explicit clean rejection. The generator's `--probe-failed` repeats all three negative cases without retaining them.

## Reproduction

Use `--verify-only` for the stored artifacts and a fresh `--output` directory for regeneration, because polymorphic bytes vary. The helper selects every relevant GUI setting, suppresses backups/settings persistence, and processes the batch in one owned session in a separate worker. The worker exits before runtime checks and temporary-file cleanup. Some repeated launches reported another instance after forced cleanup; startup retries are bounded and never close unrelated windows.

The author also documents `telock.exe -S <path>` for packing with saved settings. The collection uses explicit GUI settings instead of relying on an opaque existing INI. No native disk-unpacking workflow or reproducible source build was established.
