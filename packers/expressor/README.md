# eXPressor

[Developer website and release history](https://www.cgsoftlabs.ro/express.html) · [Official download](https://www.cgsoftlabs.ro/zip/eXPressor.zip) · [Download page](https://www.cgsoftlabs.ro/dl.html) · [DiE rule](https://github.com/horsicq/Detect-It-Easy/blob/0b5454f21eea920a4444ae5d513da969555a221a/db/PE/protector_eXPressor.2.sg)

eXPressor, by CGSoftLabs, combines PE compression with optional protection. It supports PE32 and PE32+ packing; 64-bit protection is excluded. The public package includes a manual and API examples, but no buildable packer sources.

## Versions and fixtures

| Version / tools | x86 EXE | x86 DLL | amd64 EXE / DLL | Notes |
| --- | --- | --- | --- | --- |
| [1.8.0.1](tools/1.8.0.1/bin/) | [Verified](packed-fixtures/1.8.0.1/fixture-x86-exe/) | [Verified with section fix](packed-fixtures/1.8.0.1/fixture-x86-dll/) | [EXE](packed-fixtures/1.8.0.1/fixture-amd64-exe/) / [DLL](packed-fixtures/1.8.0.1/fixture-amd64-dll/) verified | Standard (`program2`), Full stub. Packing requires elevation and a process-local PEB version adjustment. |

All four files pass normal execution, runtime secret checks and wait mode without elevation or PEB changes. DLL export names and ordinals are preserved. Full secret markers are absent from the packed bytes.

**Startup is interactive:** the public build adds an eXPressor splash/notice. Wait for the startup window and explicitly click **OK** to continue. This also applies to `--wait` and `WaitFixture`: the success line and sleep loop are reached only after acknowledgment. The verifier waits for startup and clicks only the known vendor notice.

The x86 DLL has one output-header fix: execute permission on the merged `.data` section, required by DEP-enabled `rundll32`. Other packed outputs are unmodified. The packer faults during `/e` cleanup after writing the output; files are retained only after independent checks. See [internals.md](internals.md) for these limitations.

## Building and packing

Extract `setup.exe` from the official ZIP, then use `innoextract --collisions rename` to preserve all executable variants. Run from an ordinary terminal at the collection root:

```powershell
python packers/expressor/generate.py --version 1.8.0.1
```

The helper requests UAC for packing; fixture checks run with the caller's normal rights. Use `--verify-only` to recheck retained files, or `--output PATH` for a separate generation. Commands and requirements are documented in [generate.py](generate.py).

## Auxiliary files

- [generate.py](generate.py): packing, x86 DLL fix, verification and publication.
- [runtime.py](runtime.py): process-local compatibility, UAC worker and startup-notice handling.
- [internals.md](internals.md): extraction, startup diagnosis and output limitations.
