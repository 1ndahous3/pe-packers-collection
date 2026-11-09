# MoleBox research notes

## Package and loader

The tested open-source release is tag `6000`, revision `57821f1ba998603e9bfd5d8ce194a6ae2e8a3516`; its CLI reports version `4.6000`. This entry does not infer behavior of earlier MoleBox Pro releases.

The packager compresses file blocks with zlib and encrypts them with Blowfish, while the runtime intercepts file and image-loading operations to serve embedded content. The main executable can be sliced/relinked into the loader or stored whole as a hidden package member with `-s`. Recovering only the main image does not necessarily recover the embedded DLL, data or virtual filesystem metadata.

Slicing is the default, but the advertised `-z` switch is missing from the accepted option list and is rejected. Omit it. `--autoreg none` disables automatic COM registration during packing, and `-C 0` selects embedded files when external namesakes exist. These settings do not require modifying PE inputs. Both modes produce working x86 fixtures with ASLR/DEP flags cleared by the packer.

## Exercising virtual files

The additional bundle entry uses `LoadLibraryW` for the unchanged shared DLL, checks callback exports by name and ordinal, reads a deterministic data file through `CreateFileW`/`ReadFile`, then enters the unchanged shared EXE. DLL and EXE success output covers their respective secret checksums. `--wait` pauses in the EXE; `--dll-wait` pauses in the embedded DLL after its checks.

The generator first confirms that the unpacked bundle needs its DLL and rejects corrupt data. Packed bundles then run alone in a fresh directory, and again beside deliberately invalid external namesakes. Both package modes pass these controls and both sleep loops. No companion files appear beside the EXE. This is a functional filesystem/loading test, not a system-wide trace of every runtime file operation. Registry virtualization, COM, .NET and child-process propagation remain untested.

## Target validation

Standalone DLLs are rejected as the main input even though embedding an x86 DLL works. Native amd64 EXEs are more misleading: the CLI returns success, announces .NET metadata and emits an invalid x86 wrapper. Windows rejects it with error 193. The source uses 32-bit PE header structures without first validating the optional-header format; this explains the mismatched metadata and image parameters. Exit status alone is therefore insufficient.

The helper's `--probe-failed` reproduces both rejected DLL inputs, the amd64 failure and the `-z` discrepancy. Failed outputs stay temporary. No native unpack-to-disk mode was established; runtime success does not imply byte-identical PE reconstruction.
