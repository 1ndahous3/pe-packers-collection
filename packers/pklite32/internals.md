# PKLITE32 internals

## Distribution and interface

SAC and Infania supply identical `pkl3211.exe` distributions. The executable is a self-extracting ZIP, so 7-Zip can extract `PKLIT32W.EXE` without installation. This GUI executable works with the host's Windows libraries; the old bundled `IMAGEHLP.DLL` and Explorer shell extension are unnecessary for these cases.

The vendor README and GUI identify release 1.1/shareware. The executable's generic version resource says 1.0.0.1 and even labels its original filename as a DLL; it is not a reliable product-version identifier. Do not merge this product with DOS/Win16 PKLITE versions.

The distribution's `PKLIT32W.HLP` documents separate `PKLIT32C.EXE` and scripting interfaces for Professional. Neither is used by this profile. The help can be read without installing WinHelp: build [HelpDeco](https://github.com/pmachapman/helpdeco/tree/785273788af17fde4fba7df7162d547f8645d7d8) with its Visual Studio project and run `helpdeco PKLIT32W.HLP /g /y` in a temporary directory, then read the generated RTF. Rebuilding the help itself is unnecessary.

## Small inputs and preparation

Default packing of each unmodified x86 fixture gives the insufficient-size-reduction notice and creates no output. This rejection concerns size, not EXE/DLL support. The shareware interface exposes no supported force-growth command.

The retained profile uses [padded_input()](generate.py) to append a read-only initialized `.pad` section containing 64 KiB of zeros. It adds a section header and adjusts the section count, image size and initialized-data size. Existing section bytes and RVAs, marker locations, imports, exports and execution code remain unchanged. Both prepared inputs pass normal execution and wait mode before packing.

For a reconstruction target, regenerate this prepared input from the shared original using `padded_input()`. A complete recovered PE should be compared to that derived input; the unmodified fixture has a different section table and image size. The additional section is only a reproducible way to satisfy the packer's size policy, and is not a new secret or behavior test. Prepared inputs are not duplicated in the repository.

## Selection and packed layout

Restoring Defaults selects `.text`, `.data`, `.secret` and `.pad`, leaves `.rdata` and `.reloc` unselected, and preserves relocations. The GUI helper reads the actual tree selections before packing. Those check marks are custom item images, not standard TreeView checkbox states.

The loader and compressed data occupy `.pklstb`. Selected sections retain their virtual positions but have no raw file data. `.rdata`, which contains imports and DLL exports in these fixtures, remains available on disk. The original relocation section becomes `.delete`, and `.relo2` holds the loader's relocation information. These names are observations of this build and profile, not general identification rules.

Consequently, the complete ASCII secret stays visible while the code, writable UTF-16 and repeated secrets disappear from packed bytes. Runtime checksums for all four pass after loading. Exact secret bytes also match when read during wait mode at each actual module base plus the manifest marker RVA; both modules were loaded away from their preferred bases. EXE and DLL wait modes, including the DLL's ordinal entry, pass without a startup dialog. `DYNAMIC_BASE` and `NX_COMPAT` survive unchanged; no output fix is applied. TLS, resources and overlays are not exercised by the baseline.

Repeated generation can change a few loader bytes and the PE checksum while retaining the tested behavior. Use `--verify-only` for stored files or a fresh `--output` directory for regeneration; the helper refuses to overwrite different existing bytes.

## Recovery scope

The documented interfaces compress, inspect and configure files; no native disk expansion command was established. The linked OEP script is a research reference and was not used to validate reconstructed files. Runtime recovery succeeds for the fixture behavior and secrets, but exact restoration of original disk layout, headers and padding remains unverified.
