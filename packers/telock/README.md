# tElock

[Product listing](https://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/Telock.shtml) · [Recovered distribution](tools/0.98/telock-0.98.rar) · [SUN DVD source](https://archive.org/details/cracklb-2010) · [Packing Box recipe](https://github.com/packing-box/docker-packing-box/blob/91fd2865d3bcd620131ab126e906eb5a52c0ed67/src/conf/packers.yml#L1188)

A freeware PE32 compressor/encryptor by tE!, with polymorphic loader layers, integrity checks and optional IAT redirection. No application-code VM is involved in the tested profiles.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [0.98](tools/0.98/bin/) | [Minimal and default profiles](packed-fixtures/0.98/fixture-x86-exe/) | Packing completes; initialization fails in rundll32 | Packing completes, but outputs do not run correctly | Unmodified distribution recovered from SUN DVD; author manual included in the retained RAR. |

Both EXE profiles pass normal execution, wait mode and all secret checksums on Windows 11 x64. No complete marker remains visible on disk. Loader overhead makes these small fixtures larger after packing.

Temporary inputs clear `DYNAMIC_BASE`, `NO_SEH` and `NX_COMPAT` before packing. Output bytes are unmodified. Minimal disables IAT redirection and overlay/relocation stripping; default enables them. Optional debugger detection is off in both. DLL loading, forced rebasing and external file reconstruction have no verified working result here.

## Building and packing

Extract `telock.exe` from the RAR. The stable product listing was found, but its download could not be retrieved; the rare distribution is therefore preserved. A buildable source release was not established.

```powershell
python packers/telock/generate.py
python packers/telock/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): acquisition, input preparation, profile options and verification.
- [gui.py](gui.py): batch automation of the original application.
- [internals.md](internals.md): integrity checks, DEP behavior and reproduction notes.
