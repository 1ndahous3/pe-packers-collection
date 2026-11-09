# Squishy

[Official downloads and technical talks](https://logicoma.io/squishy/)

A demoscene PE compressor with code filtering and two compression stages, without code virtualization.

## Versions and fixtures

| Version / tool | x86 EXE | amd64 EXE | DLL | Notes |
| --- | --- | --- | --- | --- |
| [0.1.3](tools/0.1.3/bin/) | [Padded input](packed-fixtures/0.1.3/fixture-x86-exe/) | Explicit architecture assertion | x86 output loses exports; callback times out | The retained x64 host executable packs x86 targets. |
| [0.2.0](tools/0.2.0/bin/) | Explicit architecture assertion | [Padded input](packed-fixtures/0.2.0/fixture-amd64-exe/) | amd64 output loses exports; callback times out | x64 host and target. |

Retained EXEs pass normal execution, wait mode and all secret checksums on Windows 11 x64; no complete disk marker remains visible. Both internal decompression checks pass. Temporary inputs add a deterministic read-only padding section to avoid malformed output from tiny inputs. Original mitigation flags are preserved; outputs are unmodified.

## Building and packing

Extract `squishy-x64.exe` from the official version ZIP. Source builds were not established.

```powershell
python packers/squishy/generate.py --version 0.1.3
python packers/squishy/generate.py --version 0.2.0
```

## Auxiliary files

- [generate.py](generate.py): acquisition, input preparation, commands and verification.
- [internals.md](internals.md): small-file limitation and loader observations.
