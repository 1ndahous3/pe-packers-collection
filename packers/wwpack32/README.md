# WWPack32

[Author website](https://www.wwpack32.venti.pl/) · [Demo download](https://www.sac.sk/download/pack/wwp32120.zip) · [CRACKL@B SUN DVD](https://archive.org/details/cracklb-2010) · [DVD mirror](https://archive.org/details/crackl-b-sun-dvd-2010) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_WWPack32.2.sg)

WWPack32, by Piotr Warezak and Rafal Wierzbicki, is a native PE32 compressor derived from their DOS WWPACK algorithms. The collection includes the original public demo and a modified full build explicitly credited to **Ghosthunter**. The latter was recovered from CRACKL@B SUN DVD 2010; its exact changes versus a registered original are unknown.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.20 demo](tools/1.20-demo/bin/) | [Fastest / best](packed-fixtures/1.20-demo/fixture-x86-exe/) | Explicitly refused by demo | Both rejected; inputs unchanged | Original public binary; EXE header fix below. |
| [1.20 full / Ghosthunter](tools/1.20-full-ghosthunter/bin/) | [Fastest / best](packed-fixtures/1.20-full-ghosthunter/fixture-x86-exe/) | [Fastest / best](packed-fixtures/1.20-full-ghosthunter/fixture-x86-dll/) | Both rejected; inputs unchanged | Cracked build; EXE/DLL header fixes below. |

Both profiles use automatic sections with relocation stripping disabled. Retained files pass normal execution, wait mode and exact secret-byte checks in memory. DLL export names and ordinals are preserved; wait mode passes by name and ordinal 4. Both DLL profiles also pass forced rebasing after the fixes.

**Output header fixes:** all retained files add execute permission to `.WWP32` for DEP compatibility. Ghosthunter DLLs additionally trim the base-relocation directory size to its actual block; otherwise rebased loading fails. These fixes preserve the tool, compressed payload, `NX_COMPAT` and `DYNAMIC_BASE`.

Only the code marker is hidden on disk; other markers remain visible in skipped sections. These tiny outputs are larger than their inputs. EXE rebasing, TLS/resources and disk unpacking remain unverified.

## Building and packing

Use the linked demo distribution or the locally preserved [rare Full archive](tools/1.20-full-ghosthunter/WWPack32%201.20%20Full.rar). No buildable source was established. From the collection root:

```powershell
python packers/wwpack32/generate.py --version 1.20-demo
python packers/wwpack32/generate.py --version 1.20-full-ghosthunter
```

The generator operates each GUI without installation. Acquisition details and case selection are in its help.

## Auxiliary files

- [generate.py](generate.py): acquisition, profile selection, header fixes and verification.
- [gui.py](gui.py): GUI automation and handling of the startup settings warning.
- [internals.md](internals.md): section selection, loader compatibility and recovery observations.
