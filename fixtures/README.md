# Shared PE fixtures

Small, benign, unpacked programs used as common inputs for static, dynamic and emulated unpacking tests. The matrix is **x86 / amd64 × EXE / DLL**, with shared C sources and behavior.

The fixtures exercise basic loading, imports, relocations, entry points, data and DLL exports without CRT startup. Advanced scenarios such as TLS callbacks, C++ initialization and exception handling are outside this baseline.

Published originals: [x86](bin/x86/) and [amd64](bin/amd64/). Sources: [EXE](src/basic_exe.c), [DLL](src/basic_dll.c) and [CMake project](CMakeLists.txt).

## Synthetic secrets

[secrets.c](src/secrets.c) embeds public test markers whose expected bytes are defined in [secrets.json](src/secrets.json). They are identical across the matrix, allowing comparisons of packing, visibility and recovery.

| Section | Purpose |
| --- | --- |
| `.rdata` | An ASCII string in read-only data. |
| `.data` | A UTF-16 string in writable data. |
| `.text` | Binary data in an executable section; the marker itself is never executed. |
| `.secret` | A repeated block that provides easily compressible input. |

Runtime checks verify the marker bytes through checksums. Static checks verify their placement and section permissions. Compare full marker values in packed and recovered files against the original manifest; memory dumps may use different layouts. Marker recovery alone does not prove that the entire PE was restored correctly.

## Build and verification

Requirements: Windows x64 with WOW64, Visual Studio 2022 or Build Tools with the v143 C/C++ toolset and Windows SDK, CMake 3.24+ with CTest, PowerShell and Python 3.8+.

From the collection root:

```powershell
.\fixtures\scripts\build.ps1
```

The helper builds and tests both architectures, publishes originals to `fixtures/bin/`, and generates manifests after PE and marker validation. Use `-Architecture x86` or `-Architecture amd64` to select one architecture, or `-Python PATH` to select Python. Build configuration is defined by the [CMake presets](CMakePresets.json).

To repeat runtime checks without rebuilding, run from `fixtures/`:

```powershell
ctest --preset x86
ctest --preset amd64
```

CTest checks normal execution, exact argument matching and continued execution in wait mode. Wait tests require the success line and terminate only their own processes. Use the build helper to refresh published originals and manifests together. The [x86 manifest](bin/x86/manifest.json) and [amd64 manifest](bin/amd64/manifest.json) hold build metadata and references for the actual binaries and markers.

## Manual runtime checks

From the collection root in **64-bit PowerShell**:

```powershell
.\fixtures\bin\x86\basic.exe
.\fixtures\bin\amd64\basic.exe

Push-Location .\fixtures\bin\x86
try { & "$env:WINDIR\SysWOW64\rundll32.exe" '.\basic.dll,RunFixture' | Out-Host }
finally { Pop-Location }

Push-Location .\fixtures\bin\amd64
try { & "$env:WINDIR\System32\rundll32.exe" '.\basic.dll,RunFixture' | Out-Host }
finally { Pop-Location }
```

Each EXE must print `pe-fixture:basic-exe:ok`; each DLL must print `pe-fixture:basic-dll:ok`. Require exit code zero (`$LASTEXITCODE`) and no stderr. A successful `rundll32` exit alone does not prove the callback ran. The pipeline waits for the host and displays its output.

For a packed or restored DLL, run the matching command from its directory and substitute its filename, keeping `,RunFixture`.

## Waiting for a dump or debugger

Run an EXE with `--wait`, or use the DLL export `WaitFixture` instead of `RunFixture` in the commands above. Both modes perform the usual checks, print the same success line once, then loop indefinitely with `Sleep(1000)`. Terminate the process when finished.

```powershell
.\fixtures\bin\x86\basic.exe --wait
.\fixtures\bin\amd64\basic.exe --wait
```

The EXE recognizes `--wait` as its sole argument (also quoted); other arguments keep the normal behavior. `WaitFixture` has the `rundll32` callback ABI and ordinal 4; the existing exports retain their ordinals. The loop runs outside DLL initialization.

Packer generators verify this mode before saving packed files: `--wait` for EXEs, and `WaitFixture` by name and ordinal 4 for DLLs. The shared [wait checker](scripts/check_wait.py) requires the success line and continued execution, then terminates only its test process.

## Use in a packer case

Use `bin/<arch>/basic.exe` or `basic.dll` as the input for `fixture-<arch>-exe/` or `fixture-<arch>-dll/` in the [packer layout](../templates/README.md). Give the packer a temporary copy of the original verified against its manifest, then compare execution and marker recovery with the baseline above.

See the [template guide](../templates/README.md) for storage and research-note conventions and [CONTRIBUTING](../CONTRIBUTING.md) for verification criteria.
