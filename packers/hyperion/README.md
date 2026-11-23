# Hyperion

[Author's site](https://nullsecurity.net/tools/binary.html) · [Release archives](https://github.com/nullsecuritynet/tools/tree/485fad8b48d3939797a365ffb7b1df3e3c378a8d/binary/hyperion/release)

Hyperion wraps a native Windows EXE in a loader that decrypts the original image at startup.

## Versions and fixtures

| Version | x86 EXE | amd64 EXE | x86 and amd64 DLL |
| --- | --- | --- | --- |
| 1.1 | [Normal and wait pass](packed-fixtures/1.1/fixture-x86-exe/) | Rejected as PE64 | Rejected as DLL |
| 2.3.1 | [Normal and wait pass](packed-fixtures/2.3.1/fixture-x86-exe/) | [Normal and wait pass](packed-fixtures/2.3.1/fixture-amd64-exe/) | Rejected as DLL |

All three retained EXEs pass the runtime secret checks. None contains a complete plaintext marker on disk. Version 2.3.1 warns that x86 support is unmaintained.

## Building and packing

Download either release ZIP from the author archive. From an **x86 Native Tools Command Prompt for Visual Studio 2022**, run the [fixture generator](generate.py) at the repository root. It builds the unmodified release in a temporary directory, uses the bundled FASM, and checks all four inputs before saving the passing EXEs. Use an ASCII path for `TEMP` if the assembler fails to start.

```text
python packers/hyperion/generate.py --archive C:/Temp/Hyperion-1.1.zip --output C:/Temp/hyperion-cases
python packers/hyperion/generate.py --archive C:/Temp/Hyperion-2.3.1.zip --output C:/Temp/hyperion-cases
python packers/hyperion/generate.py --verify-only
```

The [research notes](internals.md) describe the loader and the settings used for these cases.
