# NSPack internals

## Distribution identity and scope

The [WinSite mirror distribution](https://ftp.icm.edu.pl/pub/winsite/winxp/pagemkr/nspack.zip) identifies the executable as **2.3.0.0** in its version resource. The bundled `nspack.chm` credits XingPing Liu / North Star and gives `nsdsn.com` as the developer website. Its release history ends at 2.2; the executable resource is the basis for this entry's version. The index keeps this entry separate from nPack and North Star PE Shrinker; similar names alone do not establish identity.

The manual advertises PE32, PE32+ and .NET packing for the product family. Its FAQ separately says that the public, unregistered edition disables 64-bit, .NET and directory packing and limits 32-bit input size. Our native amd64 EXE and DLL are unchanged by 2.3; the GUI reports `Unregistered version.` after identifying PE32+. This is an edition restriction, not evidence that every NSPack release lacks amd64 support. Managed inputs are not covered here.

## Modified 3.3 distribution

The [archived RAR](https://web.archive.org/web/20060319080742id_/http://bbs.pediy.com/upload/2005/8/files/nspack.v3.3.rar) passed its integrity check and is [preserved locally](tools/3.3-cracked/nspack.v3.3.rar). It contains only `NsPack.V3.3.CracKed.exe`, whose version resource reports **3.3.0.0**. The shoooo & fly attribution comes from the supplied [forum reference](https://bbs.kanxue.com/thread-18595-1.htm); the live page required bot verification during this review. The modifications have not been compared with an official 3.3 executable.

On Windows x64 build 26100, both GUI startup and CLI attempts with each of the four shared fixtures open an `Error` report before the main packing interface. All inputs remain unchanged. Windows 7 compatibility gives the same result; an XP compatibility launch was rejected as requiring elevation and was not run. The report includes an `INT 2E` system-call stub, but this alone does not establish the root cause. Packing support, output execution and secrets therefore remain untested for this build.

To reproduce, extract the preserved RAR to a temporary directory with `7z x`, then launch `NsPack.V3.3.CracKed.exe`, optionally passing the path to a disposable fixture copy. No modifications were made to the downloaded executable. The archive is retained for compatibility research; no executable is installed in `bin/`, and no 3.3 case is exposed by the generator.

## Settings and automation (2.3)

A filename on the command line invokes silent in-place compression using saved/default options. Both success and the observed amd64 rejection return zero. Validate the resulting PE and execution rather than treating that return code as proof of packing.

The [generator](generate.py) uses the GUI for x86 so the profile is explicit. Settings are applied when leaving the Settings tab; changing checkboxes without that transition can leave the old packing options active. The helper switches back to File, selects a temporary input, compresses it and closes only its own process. Backup creation, auto-run, settings persistence and context-menu integration are disabled. GUI closure normally returns the MFC dialog's `IDCANCEL` value; packed output still requires independent validation.

The profile enables resource compression, relocation stripping, minimum section count and the Windows DLL loader option. According to the author's help, the last option leaves at least one import per dependency for Windows to load; the packer handles the remaining imports. Our fixtures have only KERNEL32 imports and no resources, TLS, CLR or overlays, so they do not cover the broader resource/managed features.

## PE layout and runtime recovery (2.3)

The packed x86 files have two read/write/execute sections named `nsp0` and `nsp1`. Original section boundaries are lost. Some EXE section raw ranges can point into headers or overlap other file ranges; a dumper should not assume that the packed section table resembles a conventional linker output.

NSPack retains the input ASLR and DEP flags. The EXE has no standard relocation directory; the DLL has a minimal directory with no relocation entries. These headers alone do not establish functioning rebasing, and forced relocation was not tested. The recorded files run without clearing header flags or changing system mitigations. All DLL export names and ordinals are preserved.

Normal execution and wait mode validate all four secret checksums, while the complete markers are absent from packed bytes. This establishes usable runtime code/data recovery for these fixtures, not reconstruction of the original section table or byte-exact disk recovery. No native disk-unpack command is documented in this distribution, and no external unpacker is used as a reference.

Repeated packing of the same input changes a small number of header and loader bytes. Reproduce with a fresh `--output`, then compare structure, exports, execution, wait behavior and secrets; do not require equal hashes. The generator refuses to overwrite a different retained artifact. Use `--verify-only` to check existing cases without regenerating them.

## Modified 3.7 distribution

SUN DVD contains `Nspack3.7.Cracked.exe`, with file version 3.7.0.0. The packer is retained unchanged under the generator's common filename; the modification author/details are unknown. The GUI differs from 2.3: the old minimum-section-count control now renews the DOS stub, and reserve-file-size/compatibility options are available. The recorded profile disables both new options and keeps the existing resource/Windows-loader settings.

Both x86 fixtures pass normal execution, exports, wait mode and secret checks without header changes. Unlike 2.3, this build emits amd64 files, but both fail execution with an access violation. They are not published. Use `--version 3.7-cracked --arch x86`; an explicit `--arch amd64` reproduces the failed probes.
