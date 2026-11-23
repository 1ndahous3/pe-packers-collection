# Eronana Packer

Eronana's Win32 EXE compressor stores the compressed sections and their loader in a new `.packer` section. The author published the binary as *First Release* under the tag `packer`, without a numeric version. [Official download](https://github.com/Eronana/packer/releases/download/packer/packer.zip) · [Tagged source](https://github.com/Eronana/packer/tree/6d20c9d61308410a2bc455f13672b816b9c29e97)

## Inventory

| Release | x86 EXE | x86 DLL | amd64 EXE | amd64 DLL |
| --- | --- | --- | --- | --- |
| First Release (`0`) | Pass | Rejected as DLL | Rejected as PE32+ | Rejected as PE32+ |

The [packed x86 EXE](packed-fixtures/0/fixture-x86-exe/packed.exe) shrank from 4608 to 4096 bytes. Normal execution and `--wait` passed on Windows. All four markers passed their runtime checksums. None appears in full on disk.

The output retains the original `DYNAMIC_BASE` and `NX_COMPAT` flags, but the packer strips base relocations. The same EXE failed to start in the restricted test environment with Windows error 623 (`ERROR_ILLEGAL_DLL_RELOCATION`).

## Building and packing

Use `packer.exe` from the official download. Run `packer.exe basic.exe` on a copy of the shared input to produce `basic.packed.exe`. The retained case uses default settings and the unmodified input. To build the tool, check out tag `packer` with its `compressor` submodule and use the author's Visual Studio 2015 Win32 project.

Run the [generator](generate.py) from the collection root to repeat all four packing attempts or verify the retained case.

```powershell
python -B packers/eronana-packer/generate.py --output packers/eronana-packer/packed-fixtures
python -B packers/eronana-packer/generate.py --verify-only
```
