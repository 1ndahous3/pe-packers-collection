# kkrunchy

[Official website](https://www.farbrausch.de/~fg/kkrunchy/) · [Original sources](https://github.com/farbrausch/fr_public) · [Author's compression notes](https://fgiesen.wordpress.com/2011/01/24/x86-code-compression-in-kkrunchy/) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/packer_kkrunchy.2.sg)

Fabian Giesen's native x86 EXE compressor for demoscene intros. It combines reversible code filtering with compression; it does not introduce a protection VM. DLLs, exports and TLS are outside its supported scope.

## Versions and fixtures

| Version / download | Tool | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- | --- |
| [0.23alpha](https://www.farbrausch.de/~fg/kkrunchy/kkrunchy_023a.zip) | [Binary](tools/0.23alpha/bin/) | [Default, ASLR fix](packed-fixtures/0.23alpha/fixture-x86-exe/) | Rejected: exports | Unsupported; parser failures | LZ77 + arithmetic coding; default `--good`. |
| [0.23alpha2](https://www.farbrausch.de/~fg/kkrunchy/kkrunchy_023a2.zip) | [Binary](tools/0.23alpha2/bin/) | [Default, ASLR fix](packed-fixtures/0.23alpha2/fixture-x86-exe/) | Rejected: exports | Unsupported; parser failures | PAQ-style context mixing; `--good` / `--best` have no effect. |
| [0.23a4/asm07](https://www.farbrausch.de/~fg/kkrunchy/test/kkrunchy_023a4_asm07.exe) | [Binary](tools/0.23a4-asm07/bin/) | [Default, ASLR fix](packed-fixtures/0.23a4-asm07/fixture-x86-exe/) | Rejected: exports | Unsupported; parser failures | Later K7 engine; identified as the most recent version in the upstream source inventory. |

All retained EXEs pass normal execution, `--wait`, secret checksums and exact secret-byte checks in memory on Windows 11 x64. No complete secret remains visible on disk. The tiny input does not shrink with alpha and grows with the later loaders.

**Compatibility fix:** clear only `DYNAMIC_BASE` in the packed output. Raw outputs crash under ASLR because their loaders use fixed addresses. DEP remains enabled; shared inputs and packer binaries are unmodified. No native file decompressor is provided; external reconstruction remains unverified.

## Building and packing

Download above and retain only the executable in the corresponding `bin/`. Upstream build instructions cover Visual C++ 2010 with YASM (`kkrunchy/`) or NASM (`kkrunchy_k7/`); these cases use the official binaries.

```powershell
python packers/kkrunchy/generate.py --version 0.23a4-asm07
```

Select another table version to regenerate it. Use `--verify-only` to check stored fixtures, or a fresh `--output` directory for experiments.

## Auxiliary files

- [generate.py](generate.py): acquisition, commands, compatibility fix and verification.
- [internals.md](internals.md): compression, loading, format limits and recovery notes.
