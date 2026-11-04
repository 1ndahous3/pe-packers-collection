# FSG internals

## Distribution and format

The [SAC downloads](https://www.sac.sk/files.php?d=7&l=F) and [Infania mirror](https://ftpmirror.infania.net/pub/pc/pack/) supplied byte-identical distribution ZIPs. Extract the nested `fsg.rar` directly; the accompanying intro/install programs are unnecessary. Keep the original packer executables in `tools/`; the generator verifies their identity and uses disposable copies. Its 2.0 configuration reproduces the settings documented in the distributed `fsg.ini`.

The authors' `xt.nfo` describes aPLib compression, merged sections and a compact loader: 197 bytes in 1.33, 158 in 2.0. The recorded outputs replace the original section layout with two sections, retain only loader-facing imports and omit a standard relocation directory. Section names are empty or partially overwritten remnants; they are not reliable labels for recovered code/data. Neither distribution documents a native command for decompressing a PE back to disk.

## FSG 1.33: DEP and fixed addresses

Unchanged fixture input produces an execute access violation at the packed entry point. Its section lacks execute permission and is mapped read/write. Clearing only `NX_COMPAT` can allow a run, but does not make it reliable: `DYNAMIC_BASE` survives while the stub uses absolute addresses and the output has no relocation directory.

The retained profile clears both flags in a temporary input, then runs that prepared input before packing. `NO_SEH` is unchanged. No packed bytes or system mitigation settings are patched. This is a fixed-base, DEP-opt-out profile, not an ASLR-capable output.

Reproduce with [generate.py](generate.py) and `--version 1.33`. Add `--keep-input-flags --arch x86 --kind exe` for the failing baseline. In an x86 debugger, stop on access violations and compare the mapped image base, loader addresses and faulting page permissions.

## FSG 2.0: entry point in the headers

The original packer is itself packed with a loader whose entry point is inside the PE headers. On Windows x64 build 26100 it exits with `STATUS_INVALID_IMAGE_FORMAT` before its GUI runs. Its raw x86 EXE output has the same entry-point arrangement and fails the same way.

The explicit `--entry-trampoline` profile appends a relative jump in the last section's remaining mapped space, points `AddressOfEntryPoint` at it and extends that section's raw size. Execution immediately jumps back to the original header loader. The helper checks the expected FSG layout and available space before making this change. Compression code, compressed data and original loader instructions are untouched.

Apply this adjustment to a temporary packer copy to run the original compression implementation, then to its output to obtain a runnable fixture. The stored tool remains the original download; **the retained packed EXE is a compatibility-adjusted artifact**, not raw FSG output. FSG 2.0 itself clears the input's ASLR/DEP flags, so the shared fixture input needs no changes. Mandatory DEP remains outside this profile.

Reproduce with `--version 2.0 --entry-trampoline`. Add `--raw-output --arch x86 --kind exe` to fix only the tool and observe the raw-output failure. Omit `--entry-trampoline` to observe the original tool's startup failure. All three paths are bounded and failed output is discarded.

## Unsupported inputs and verification

Both versions reject DLLs. Version 2.0 explicitly rejects non-i386 input; 1.33 instead reports `Missing import table!` for the amd64 EXE. That old diagnostic is classified as unsupported only for this recorded build and known amd64 input. DLL probes use an `.exe` temporary filename because 1.33 otherwise opens a file picker; the PE DLL characteristic is preserved. Version 1.33 can modify even rejected inputs, so never point it at the shared originals.

Both versions exit with `0xffffffff` after successful command-line packing. Error dialogs remain open. The helper reads only its own process's dialogs, terminates that process when necessary, and independently verifies the result. Exit code or output existence alone is insufficient.

Normal execution and wait-mode tests pass all secret checksums for the retained EXEs, while none of the four complete markers occurs in packed bytes. This establishes runtime recovery for these fixtures, not byte-exact disk reconstruction. Original headers and section boundaries are not recovery requirements. No external unpacker, TLS callbacks, delayed imports, resources or overlays were tested. For a recovered PE, check execution, imports, entry point, code/data and secrets again.
