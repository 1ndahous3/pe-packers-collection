# Shrinker

[3.4 demo download](https://ftpmirror.infania.net/pub/pc/pack/shrinker.exe) | [SAC catalog](https://www.sac.sk/files.php?d=7&l=S)

Blink's Shrinker compresses executable files. Its Win32 loader expands parts of the image on demand.

## Versions and fixtures

| Version | x86 EXE | x86 DLL | amd64 EXE and DLL |
| --- | --- | --- | --- |
| [3.4 demo](tools/3.4-demo/bin/) | [Normal and wait pass](packed-fixtures/3.4-demo/fixture-x86-exe/) | [Named and ordinal calls pass](packed-fixtures/3.4-demo/fixture-x86-dll/) | Packer exits without creating a file |

The x86 cases use a temporary input with `NO_SEH` cleared. Click **Yes** at the demo prompt when running either file. Both pass the runtime secret checks. On disk, only the DLL retains a complete marker, in `.rdata`.

## Building and packing

The two Win32 components from the demo distribution are included. Run the [generator](generate.py) from the repository root on Windows. It prepares the inputs, confirms the demo dialogs and checks each output before saving it.

```powershell
python packers/shrinker/generate.py --output C:/Temp/shrinker-cases
python packers/shrinker/generate.py --verify-only
```

See the [research notes](internals.md) for command-line options and compatibility details.
