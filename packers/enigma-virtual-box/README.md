# Enigma Virtual Box

References: [official site](https://www.enigmaprotector.com/en/aboutvb.html), [download](https://www.enigmaprotector.com/en/downloads.html), [installer](https://www.enigmaprotector.com/assets/files/enigmavb.exe).

Free application bundler with file/registry virtualization. Its native loader emulates embedded files; this is distinct from the instruction VM in Enigma Protector.

## Inventory

| Version | x86 EXE / DLL | amd64 EXE / DLL | Extra cases | Notes |
| --- | --- | --- | --- | --- |
| 11.30 | Pass | Pass | Both EXE architectures with embedded DLL/data, stored or compressed | Unchanged inputs; ASLR/DEP retained |

[Packed fixtures](packed-fixtures/11.30) pass normal execution, wait mode and all runtime secret checksums. Main-PE secrets stay visible. Bundle cases also verify embedded DLL callbacks/ordinals, DLL wait mode and data reads, alone and with invalid external namesakes. Compression hides verbatim embedded DLL/data bytes; it does not compress the main PE.

## Building and packing

The [retained console tool](tools/11.30/bin) is extracted from the official installer without installation. It consumes an `.evb` project. The helper creates projects with extraction, temporary mapping, child sharing and registry/storage features disabled. The optional bundle build uses MSVC/CMake and reuses the [existing bundle entry](../molebox/bundle/bundle.c) with unchanged shared fixture sources.

## Auxiliary files

- [Generation, build commands and verification](generate.py)
- [Project generation](project.py)
- [Bundle CMake project](bundle/CMakeLists.txt)
- [Technical notes](internals.md)
