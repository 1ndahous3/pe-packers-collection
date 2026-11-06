# NSPack

[2.3 distribution and manual](https://ftp.icm.edu.pl/pub/winsite/winxp/pagemkr/nspack.zip) · [3.3 forum reference](https://bbs.kanxue.com/thread-18595-1.htm) · [3.3 archived download](https://web.archive.org/web/20060319080742id_/http://bbs.pediy.com/upload/2005/8/files/nspack.v3.3.rar) · [Historical developer website](http://www.nsdsn.com/) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_NsPack.2.sg)

NSPack (North Star), by XingPing Liu, is a native PE compressor. The 2.3 distribution contains a standalone packer and CHM manual; no buildable source was found. These cases use the shared [benign PE fixtures](../../fixtures/README.md).

## Versions and fixtures

| Version | x86 EXE | x86 DLL | amd64 EXE / DLL | Profile / notes |
| --- | --- | --- | --- | --- |
| [3.7, cracked](tools/3.7-cracked/bin/nSpack.exe) | [Packed EXE](packed-fixtures/3.7-cracked/fixture-x86-exe/packed.exe) | [Packed DLL](packed-fixtures/3.7-cracked/fixture-x86-dll/packed.dll) | Outputs produced, but both fail execution | [Preserved SUN DVD RAR](tools/3.7-cracked/NsPack%203.7.rar); modification details unknown. Unchanged inputs. |
| [2.3](tools/2.3/bin/nSpack.exe) | [Packed EXE](packed-fixtures/2.3/fixture-x86-exe/packed.exe) | [Packed DLL](packed-fixtures/2.3/fixture-x86-dll/packed.dll) | Disabled in this public build; inputs remain unchanged | Two sections; resource compression, relocation stripping and Windows DLL loader enabled. Original tool and inputs are unmodified. |
| [3.3, cracked](tools/3.3-cracked/nspack.v3.3.rar) | Not tested | Not tested | Not tested | Startup failure on the recorded host. Third-party build attributed to shoooo & fly; preserved as an archive only. |

All retained files passed normal execution, wait mode and all four secret checksum checks on Windows x64 build 26100. DLL export names and ordinals survive; no complete secret marker remains visible in either packed file. Repeated packing varies header and loader bytes, so identical output hashes are not expected. External unpacking and forced rebasing are untested.

## Building and packing

For 2.3, extract `nspack/nSpack.exe` from the linked ZIP. Run [generate.py](generate.py) with `--version 2.3`; `--help` documents the profile, acquisition and manual reproduction. Use `--verify-only` for retained files or a fresh `--output` for another generation. For the modified 3.7 distribution from [SUN DVD](https://archive.org/details/cracklb-2010), use `--version 3.7-cracked --arch x86`; `--verify-only` also supports it. Only passing packed PEs are saved.

## Auxiliary files

- [generate.py](generate.py): generation, input identity and runtime/secret verification.
- [gui.py](gui.py): process-owned GUI automation with explicit, unsaved settings.
- [internals.md](internals.md): edition limits, PE layout and recovery observations.
