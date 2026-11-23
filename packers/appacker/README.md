# Appacker (SerGreen)

Appacker bundles an application directory into a self-extracting .NET executable. The wrapper writes the original files to disk and starts the selected program as a child process. [Official release](https://github.com/SerGreen/Appacker/releases/tag/v1.3.11) · [Tagged source](https://github.com/SerGreen/Appacker/tree/v1.3.11)

## Inventory

| Version | x86 EXE | x86 DLL | amd64 EXE | amd64 DLL |
| --- | --- | --- | --- | --- |
| 1.3.11 | Pass | Stored only | Pass | Stored only |

Both [EXE packages](packed-fixtures/1.3.11/) have a managed PE32 outer header. The directory name identifies the native payload. Each package passed normal execution and forwarded `--wait` to its child. During the wait, the extracted EXE matched the shared original byte for byte.

Appacker stores the complete input uncompressed in the overlay, so all four markers remain visible on disk. Selecting a DLL as the main file also produced an EXE wrapper with the original DLL intact. On both architectures the wrapper failed when it tried to start the DLL as an application.

## Building and packing

Use `Appacker_v1.3.11.exe` from the official release. Put only the intended fixture in the input directory and place the output outside it. The retained packages use the default console wrapper and temporary extraction directory.

```powershell
.\Appacker_v1.3.11.exe --quiet --src C:\case\input --exe basic.exe --dst C:\case\packed.exe
```

From the collection root, run the [generator](generate.py) with a fresh output directory or verify the two retained packages in place. Across two x86 builds the wrapper's `.rsrc` bytes differed, while the entire overlay was identical.

```powershell
python -B packers/appacker/generate.py --output "$env:TEMP\appacker-fixtures"
python -B packers/appacker/generate.py --verify-only
```
