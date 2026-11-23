# packerPE32

owerosu's packer compresses the entire input PE with Windows LZNT1 and stores it in the `.pack3` section of an x86 EXE. The tested source has no version tag and is catalogued as `0`. [Author's repository](https://github.com/owerosu/packerPE32) · [Tested revision](https://github.com/owerosu/packerPE32/tree/98beeec953b7fa1b387670cee4cd3797469ceaa5)

## Inventory

| Source build | x86 EXE | x86 DLL | amd64 EXE | amd64 DLL |
| --- | --- | --- | --- | --- |
| `0` | Pass | Static recovery only | Static recovery only | Static recovery only |

Decompressing `.pack3` restored the exact original file for all four inputs, including their headers and markers. The builder emits an x86 EXE for every input. Its loader has no PE32+ or DLL entry path.

The [retained x86 EXE](packed-fixtures/0/fixture-x86-exe/packed.exe) passed normal execution, `--wait` and all four marker checksums. No complete marker was visible on disk. The 4608-byte original compressed to 1629 bytes of LZNT1 data. Including the loader and section padding, the output is 9728 bytes.

## Building and packing

Use the x86 Native Tools Command Prompt for VS 2022 at the tested revision. These commands build the [two tools](tools/0/bin/) from unmodified sources. The packed EXE requires the x86 Visual C++ runtime.

```bat
cl /nologo /O1 /MT /Febuilder.exe builder.cpp /link /Brepro /INCREMENTAL:NO
cl /nologo /O1 /MD /Festub.exe stub.cpp /link /ENTRY:main /SUBSYSTEM:CONSOLE /Brepro /INCREMENTAL:NO kernel32.lib ucrt.lib vcruntime.lib
builder.exe stub.exe basic.exe <nul
```

The builder writes `output.exe` in its working directory. Linking the stub directly to `main` keeps it small enough for this fixture. With default CRT startup, the builder emitted an empty final `.pack4` section for the x86 EXE and Windows rejected the image with error 193. The upstream section-copy loop also uses an uninitialized index, so results can depend on the compiler build.

Run the [generator](generate.py) from the collection root to repeat the four recovery checks or verify the retained EXE.

```powershell
python -B packers/packerpe32/generate.py --output packers/packerpe32/packed-fixtures
python -B packers/packerpe32/generate.py --verify-only
```
