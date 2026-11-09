# Yoda's Protector research notes

## Loader and section handling

The public distribution's CHM describes compression, polymorphic encryption, import handling and optional anti-dump/API-redirection features. The minimal profile keeps those optional protections off; the loader still decrypts and decompresses the application before handing control back. No application-code VM is involved.

The GUI warns that our fixtures may already be protected. In the [earlier 1.02 sources](https://sourceforge.net/projects/yodap/files/Yoda%20Protector/1.02/), `PEStructure::IsValidPE` recognizes a fixed list of section-name prefixes; `.secret` is absent. `CryptPE` and the compression logic also select sections by name. This explains the observed warning and is consistent with both tested releases leaving the complete repeat marker in `.secret` visible. The other three complete markers disappear from disk, while all four runtime checksums pass. This verifies behavior, not byte-identical reconstruction of the original PE.

The packed DLL's export data is encrypted, so a static export parser cannot establish callback availability. The negative probe invokes RunFixture directly through matching x86 rundll32 in a one-process job; neither tested version reaches it before the timeout.

## Modern Windows compatibility

The original DLL is explicitly rejected because NO_SEH is set. Clear DYNAMIC_BASE and NO_SEH on temporary inputs for the legacy loader, preserving shared originals. With NX_COMPAT still present, the packed EXE faults on execution in the readable/writable loader section: it lacks execute permission. Clearing NX_COMPAT before packing produces the retained working EXEs without modifying output bytes. Clearing it only on an already packed EXE also worked with checksum protection disabled, but is not the retained workflow.

Clearing NX_COMPAT in a DLL does not disable DEP in rundll32. Prepared DLLs still fail to reach their callback; changing section execute permissions did not establish a verified DEP-compatible alternative. Do not treat successful packing as working DLL support. Both unchanged amd64 fixtures cause the packer itself to exit with an access violation during processing, rather than a clean unsupported-format message.

## Reproduction

Use `generate.py --version <version> --verify-only` for stored artifacts. Regenerate into a fresh `--output <directory>` because polymorphic output bytes vary. Add `--probe-failed` to repeat DLL and PE32+ attempts without retaining their output. The helper uses compression level 10, the `.yP` loader section and all thirteen option boxes off; it acknowledges only the known section-name warning for our fixtures.

The GUI runs in a separate bounded worker. Its HKCU settings are restored after each attempt, including GUI crashes; do not run another instance concurrently. Native disk unpacking and reproducible builds of the retained 1.03 binaries were not established. The public 1.02 source tree is a useful mechanism reference, not proof that every implementation detail is identical across versions.
