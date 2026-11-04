# eXPressor internals

## Distribution and extraction

The [official ZIP](https://www.cgsoftlabs.ro/zip/eXPressor.zip) contains an Inno Setup installer. Its integrity check passed, and all three embedded `eXPressor.exe` variants report **1.8.0.1** in their version resources. The author describes Light, Standard and Professional editions; local paths retain the extractor's component labels. The `program2` splash identifies it as the Standard version.

Extract without installation using [7-Zip](https://www.7-zip.org/) and [innoextract](https://constexpr.org/innoextract/):

```text
7z x eXPressor.zip -odistribution
innoextract --collisions rename --output-dir extracted distribution/setup.exe
```

The default innoextract collision policy silently selects just one executable. With `--collisions rename`, copy these members without changing their bytes:

| Extracted member | Retained executable |
| --- | --- |
| `app/eXPressor.exe` | [default/eXPressor.exe](tools/1.8.0.1/bin/default/eXPressor.exe) |
| `app/eXPressor.exe#program2` | [program2/eXPressor.exe](tools/1.8.0.1/bin/program2/eXPressor.exe) |
| `app/eXPressor.exe#program3` | [program3/eXPressor.exe](tools/1.8.0.1/bin/program3/eXPressor.exe) |

The same extraction provides `app/eXPressor.chm`. Its `cmdline.htm`, `versions.htm`, `limitations.htm` and `howitworks.htm` describe command syntax, stub selection and behavior. The SDK contains application integration examples, not the packer's implementation.

## Packing modes and reproduction

The retained cases use Standard (`program2`) with Full stub (`/s 2`), compression level 2, standard resource compression and overlay preservation. Both PE32 and PE32+ EXE/DLL cases were verified. Light and Protection profiles are outside these cases; the manual excludes PE32+ protection.

[generate.py](generate.py) contains the CLI profile and reproducible generation/verification commands. The worker receives disposable, manifest-checked originals. With the tested single-file CLI, `/d` did not select the requested output filename: the tool wrote `<stem>Pk.<extension>`. The generator uses that name in a fresh temporary directory and publishes it as `packed.exe` or `packed.dll` after validation.

On this host, `/e` exits with an access violation after the success log and completed output. The generator records that exit code and accepts it only for the pinned build, with both output and success log present. Independent PE, normal-execution, secret and wait-mode checks determine whether the result can be retained.

## Startup false positive on modern Windows

On Windows x64 build 26100, all three original variants show `Debugger detected! You are not allowed to debug this application!` before the packing interface unless the compatibility adjustment below is applied. Unadjusted GUI and CLI probes leave inputs unchanged and produce no output.

The failing check was traced from the message-box caller in the unpacked protection code of `program2`. Its NT path reads the OS version directly from the 32-bit PEB and selects a heap field as follows:

```text
modern_heap = (OSMajorVersion == 6 && OSMinorVersion in {0, 1})
heap = PEB32.ProcessHeap
suspected_debugger = DWORD[heap + (modern_heap ? 0x44 : 0x10)] != 0
```

Only Vista and Windows 7 select the newer `ForceFlags` location. With PEB version 10.0, the check reads the old location, now containing a nonzero value unrelated to debugging. The actual `ForceFlags` is zero, as is `BeingDebugged`; the launched process has no attached debugger. See the [heap flag layout reference](https://anti-debug.checkpoint.com/techniques/debug-flags.html). The failing predicate does not enumerate processes or search for windows.

To reproduce the diagnosis without modifying the executable:

1. Launch an original variant normally and observe the debugger message. Read its WOW64 PEB with `NtQueryInformationProcess(ProcessWow64Information)` and `ReadProcessMemory`; compare the OS version and both heap fields above.
2. Launch a fresh copy with `CREATE_SUSPENDED`. Using the returned process handle, change only the two DWORDs `PEB32.OSMajorVersion` and `OSMinorVersion` to 6 and 1, then resume it. These version fields start at PEB32 offset `0xa4`; this is a process-memory diagnostic, not an on-disk patch or a global compatibility setting.
3. All three variants now pass this check and show `Program requires admin rights to run correctly!`. Acknowledging that dialog exits the process. Those test processes inherited a non-elevated token; the separate elevation test below resolves this second check.

Process-local `__COMPAT_LAYER=WIN7RTM RunAsInvoker` and `VISTARTM RunAsInvoker` did not change the PEB version on this host and retained the false positive. No unrelated process was closed, no heap data was zeroed and the original executable bytes were preserved. The version substitution confirms this startup bug. It is applied only to the packer, never to the packed fixtures.

### Elevation and visible startup

A launcher elevated through Windows UAC removes the subsequent admin-rights error in all three variants; `TokenElevation` confirmed that each child actually had an elevated token. Elevation alone still leaves `program2` at `Debugger detected!`: both elevation and the process-local PEB version adjustment are required on this host.

With both applied, `program2` (Standard) reaches the main `eXPressor - PE compressor` interface. Preserve normal visible startup (`STARTF_USESHOWWINDOW` with `SW_SHOW`, or no hide request): starting with `SW_HIDE` left its `NagReg` splash waiting for over a minute, whereas a fresh visible launch reached the main interface. Let the splash finish normally. The generator elevates only its packing worker; the fixture checks were run without elevation.

## Packed code and the x86 DLL fix

Full compression merges the original virtual sections into `.data`, keeps compressed content in `.pdata` and places the unpacking stub in `.ex_cod`. The unpacker must restore the original bytes before calling their entry point. All four full secret markers are absent from the retained files, while normal and wait-mode execution validate their runtime checksums.

The PE32 build marks the merged `.data` as readable/writable code without execute permission. The x86 EXE runs with its emitted NX opt-out, but loading the x86 DLL in DEP-enabled `rundll32` produces an execute access violation at the restored original entry point; Windows reports DLL initialization failure. This is a section-permission problem, not an ordinal change.

The generator adds only `IMAGE_SCN_MEM_EXECUTE` to that merged section in x86 DLL output, after checking that it contains the original entry point and has the expected flags. This changes one header bit. The corrected DLL passes `RunFixture` and `WaitFixture` by name and ordinal 4, without changing the host's DEP policy. PE32+ output already has execute permission on the merged section and needs no patch. Shared originals and tool binaries remain unchanged.

The packer clears `DYNAMIC_BASE` and `NX_COMPAT` in all four outputs. EXE relocation directories are removed; DLL relocation directories remain. Forced rebasing, native disk decompression and third-party unpacker recovery were not tested.

## Startup notice and wait-mode verification

The packer has a timed splash that needs visible startup. Packed Full-stub fixtures show a separate `Info` notice about the public eXPressor build, with an **OK** button. Wait for it and confirm it explicitly; launching the process alone does not reach fixture code. The generator preserves this notice and handles only its exact text in windows owned by the child PID.

Normal execution must produce the exact fixture success line, exit zero and leave stderr empty. Wait checks acknowledge the same notice, wait for the success line and then require the process to stay alive for more than two sleep intervals before terminating it. This avoids counting time spent in a message box as successful wait-mode execution.
