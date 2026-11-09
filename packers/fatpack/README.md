# Fatpack

[Source repository](https://github.com/Fatmike-GH/Fatpack) · [Tested revision](https://github.com/Fatmike-GH/Fatpack/tree/0d04dfa2011a1173dda30b0ff2d6095b6c8261a8) · [Author's PE loader](https://github.com/Fatmike-GH/PELoader)

An open-source amd64 EXE compressor using LZMA and a manual PE loader, with resource and section storage modes. It does not virtualize application code.

## Versions and fixtures

| Version / tool | amd64 EXE | x86 EXE / DLL | amd64 DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.5.2](tools/1.5.2/bin/) | [Resource and section profiles](packed-fixtures/1.5.2/fixture-amd64-exe/) | No output; x64-only validation | Emits an EXE wrapper without exports | Built from the pinned public source, without source modifications. |

Both retained profiles pack unchanged originals and pass normal execution, wait mode and all secret checksums on Windows 11 x64. No complete marker is visible on disk. Resource output has ASLR/DEP flags; section output clears ASLR and retains DEP. TLS, delay imports and exception unwinding are advertised features but are outside our baseline fixture checks.

## Building and packing

Build the public Visual Studio solution in Release/x64, then embed its four loader stubs with ResourceAdder. The resulting `Fatpack.exe` is standalone; build intermediates and source archives are not retained. Exact build commands are in the helper.

```powershell
python packers/fatpack/generate.py
python packers/fatpack/generate.py --verify-only
```

## Auxiliary files

- [generate.py](generate.py): source revision, build/packing commands and verification.
- [internals.md](internals.md): loader storage modes and DLL limitation.
