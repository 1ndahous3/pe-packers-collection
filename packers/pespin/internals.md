# PESpin internals

## Branches and loader mechanisms

The [vendor page](https://web.archive.org/web/20140709045746/http://pespin.w.interia.pl/) identifies 1.33 as the x86 edition and 1.22 as the amd64 edition. Extracted executables matched the author's published checksums. The retained archives contain the x86 CHM manual, amd64 PDF manual and integration examples.

The x86 manual credits aPLib and describes encrypted layers, polymorphic decryption, API redirection, OEP removal and code redirection. Debug blocker uses cooperating parent/child processes. The recorded profile uses API redirection, with debugger detection, debug blocker, password and time limits disabled.

The amd64 branch offers UCL/aPLib and several import strategies: Windows loader, GetProcAddress, Hash and On Demand. The recorded profile uses UCL, Hash and checksum protection. OEP removal and debug blocker are off. On Demand and source-level marker features were not exercised; capabilities listed in the manual are not coverage claims for these fixtures.

Profiles and reproduction commands live in [generate.py](generate.py). It copies the tool and config into a temporary directory per case. The x86 helper triggers the GUI by PID/control identity; the amd64 tool supports a filename argument with auto-run/exit settings.

## x86 compatibility

The original EXE failed with an access violation after packing. Clearing `NO_SEH` alone did not repair the aggressive default profile. A passing combination clears `NO_SEH` only in the temporary input and disables anti-dump, OEP removal and code redirection, while retaining API redirection. The prepared input is also executed before packing. ASLR/NX flags remain set.

### DLL export-name layout

The original DLL has a valid, alphabetically sorted name-pointer table, but its name strings appear in a different physical order. [The PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-name-pointer-table) requires the pointer table to be sorted, not the string storage. Name pointers and ordinal indexes are parallel arrays; changing one without the other changes which function a name selects.

PESpin 1.33 preserves the function-address and ordinal-index tables but rebuilds name pointers in physical string order. On this fixture, that both breaks lexical sorting and associates names with the wrong ordinals. The apparent ordinal changes are therefore a broken name-to-function mapping, not renumbered function slots. The DLL loads, but `rundll32` reports `Missing entry: RunFixture`; the same uncorrected output succeeds when the callback is selected by its original ordinal. `GetProcAddress` also resolves the other two names to the wrong functions.

The workaround rearranges only the export-name strings and their pointers in a temporary input so that physical order matches the existing sorted pointer table. Names, ordinals, function RVAs and code remain unchanged. The prepared input and the resulting packed DLL both execute successfully. No packed bytes or packer binary are patched. Reversing the temporary string order brings the failure back, supporting the layout diagnosis. A diagnostic post-packing pointer correction also worked, but is not used for the retained case.

The DLL also requires clearing `NO_SEH`: with corrected export layout but `NO_SEH` retained, packed execution still fails with an access violation. The generator performs both preparations and checks exports before runtime. Its normal x86 DLL run tests the callback by name and original ordinal; both paths exercise all secrets. A separate temporary x86 `LoadLibrary`/`GetProcAddress` probe confirmed that all names resolve to the same addresses as their original ordinals, and directly checked `FixtureAdd` and `FixtureMessage`. No probe binary is retained.

Use `--version 1.33 --kind dll` with a fresh `--output` to reproduce success. Add `--keep-export-layout` to reproduce the export mismatch (rejected before execution or publication), or `--keep-no-seh` to reproduce the access violation. The preparation helper deliberately accepts only the fixture's contiguous export-name layout without forwarders; it is not a general DLL repair. These observations concern the recorded profile and do not establish support for arbitrary DLLs.

## PE transformations and secrets

With section renaming disabled, both editions retain the original section names and add a loader section: `.taz` on x86 and `.x64` on amd64. This does not preserve their original raw layout. The x86 output marks sections writable and executable; the amd64 loader section is also writable/executable. Visible imports include USER32, COMCTL32 and KERNEL32.

The passing outputs keep ASLR/NX flags. The x86 PE has a loader-facing relocation directory; the amd64 outputs have no standard relocation directory despite retaining a `.reloc` section name. Forced rebasing and DLL address collisions were not tested. Flags or section names alone do not establish relocation correctness.

All full secret markers disappear from packed bytes and pass checksum checks during the successful executions. This demonstrates recovery along the fixture paths, not restoration of the original file or every section's protection. TLS, resources, exceptions and advanced code markers are outside the baseline.

## Recovery criteria

Import redirection and hashed resolution complicate reconstruction: visible loader imports are not the original import table, and runtime thunks need not directly name their destination APIs. The manual's On Demand mode would require a separate case because a complete IAT may never exist simultaneously.

An external unpacker must restore usable code/data, entry point, imports, exports and appropriate fixups/protections. Verify execution and secrets, then examine structure; marker presence alone is insufficient. The x86 name-table failure illustrates why both export mapping and runtime behavior need checks. No external unpacker or recovered dump was validated here.
