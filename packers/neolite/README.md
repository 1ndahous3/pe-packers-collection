# NeoLite

[Archived vendor website](https://web.archive.org/web/20010207200556/http://www.neoworx.com/products/neolite/) · [SAC download](https://www.sac.sk/download/pack/neolte20.zip) · [Infania mirror](https://ftpmirror.infania.net/pub/pc/pack/neolte20.zip) · [External unpacker](https://github.com/russdill/Neo-Executable-Decompressor) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_NeoLite.2.sg)

NeoLite by NeoWorx is a native PE32 compressor with reversible and irreversible packing modes. The retained public trial includes a console tool and its `Pecomp.dll` dependency; neither is modified.

## Versions and fixtures

| Version / tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [2.0 trial](tools/2.0-trial/bin/) | [Reversible / irreversible](packed-fixtures/2.0-trial/fixture-x86-exe/) | [Reversible / irreversible](packed-fixtures/2.0-trial/fixture-x86-dll/) | Explicitly rejected; no output | Both profiles use `-j -r`; irreversible adds `-e`. Output compatibility fix below. |

Retained files pass normal execution, wait mode, secret checksums and exact secret-byte checks in memory. DLL export names and ordinals survive; wait mode passes by name and ordinal 4. The binary code marker remains visible on disk in both kinds, and the ASCII marker also remains visible in EXEs; the other complete markers are hidden. These small fixtures grow because of loader overhead.

**Compatibility:** only `DYNAMIC_BASE` is cleared in packed headers. Raw outputs fail under ASLR on the current Windows host; DEP remains enabled. Corrected DLLs also pass a forced address-conflict rebase.

**Trial notice:** EXEs show a dialog; choose **No** to run the program. The verifier handles this exact notice automatically. DLL runs showed no trial dialog.

Native `-x` restores raw reversible output byte for byte. From retained output it restores the original with the same single `DYNAMIC_BASE` change; all other headers and secrets match. Irreversible files are explicitly refused by `-x`.

## Building and packing

Use either public download above; [prepare.py](prepare.py) extracts the required binaries without running the old installer. No buildable packer source was established.

```powershell
python packers/neolite/generate.py --version 2.0-trial
```

## Auxiliary files

- [prepare.py](prepare.py): acquisition and static extraction.
- [generate.py](generate.py): commands, profiles, verification and output handling.
- [runtime.py](runtime.py): trial-dialog handling and bounded execution checks.
- [internals.md](internals.md): compression, rebasing and recovery observations.
