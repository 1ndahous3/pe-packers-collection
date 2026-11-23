# EZip

[Standalone compressor](https://web.archive.org/web/20040814030504id_/http://jitit.com/ftp/ezip.exe) · [Author's 1.0 page](https://web.archive.org/web/20031009010726/http://jonathanclark.com/ezip/) · [1.0 ZIP](https://web.archive.org/web/20040814030556id_/http://www.jonathanclark.com/ezip/ezip1.zip)

Jonathan Clark's Win32 executable compressor adds a loader that expands the program at startup.

## Versions and fixtures

| Version | x86 EXE | x86 DLL | amd64 EXE and DLL |
| --- | --- | --- | --- |
| [0.8 beta](tools/0.8-beta/bin/) | [Normal and wait pass](packed-fixtures/0.8-beta/fixture-x86-exe/). All secret checks pass. | Packed with exports intact. Initialization failed on Windows. | EZip warns that it requires an Intel 386-compatible executable. No usable output. |
| 1.0 distribution | Packing unverified | Packing unverified | Packing unverified |

The working EXE uses a temporary input with `DYNAMIC_BASE` cleared. DEP stays enabled. The packed file contains no complete plaintext fixture marker.

## Building and packing

The standalone binary accepts two filenames and reports version 0.8 beta. The [generator](generate.py) prepares a copy of the shared EXE, runs the packer and verifies the output before saving it.

```powershell
python packers/ezip/generate.py --output C:/Temp/ezip-cases
python packers/ezip/generate.py --verify-only
```

See the [research notes](internals.md) for the version labels, DLL behavior and the Thinstall startup issue.
