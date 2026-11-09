# AlushPacker

[Repository](https://github.com/Alon-Alush/AlushPacker) · [1.0.0 binary](https://github.com/Alon-Alush/AlushPacker/releases/tag/v1.0.0)

An open-source native EXE packer combining compression, encryption and manual image loading. It stores the payload in an added `.packed` section.

## Versions and fixtures

| Version / tool | x86 EXE | amd64 EXE | DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.0.0](tools/1.0.0/bin/) | [Pass](packed-fixtures/1.0.0/fixture-x86-exe/) | [Pass](packed-fixtures/1.0.0/fixture-amd64-exe/) | Emits EXE wrappers without exports | Official binary; default settings; no PE patches. |

Both EXEs pass normal execution, wait mode and all secret checksums on Windows 11 x64. Complete markers are absent on disk. The loader adds diagnostic stdout; the helper validates it separately. The released `-o` option fails, so generation uses the automatic output filename. Matching VC++ Runtime/UCRT installations are required.

## Building and packing

Use the official binary. Public Visual Studio sources are available; a matching release rebuild was not established. Password locking and advanced TLS/exception/delayed-import scenarios were not tested.

```powershell
python packers/alushpacker/generate.py --output C:/Temp/alush-new
python packers/alushpacker/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): acquisition, commands, output validation and negative probes.
- [internals.md](internals.md): loader behavior and CLI limitations.
