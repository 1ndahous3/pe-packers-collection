# Enigma Virtual Box research notes

Virtual Box adds a loader before the original entry point and handles file access to embedded content. It is a useful bundling and API-emulation case, not evidence of instruction virtualization. The standalone four-way matrix is accepted, including DLL inputs, and keeps the main image’s complete secret markers readable on disk.

`CompressFiles` applies to embedded files. Stored bundles contain the original DLL and deterministic data verbatim; compressed bundles do not. Both still expose main-EXE markers. The shared EXE/DLL use identical marker values, so simply searching for a marker in a bundle cannot identify which copy it came from. The helper additionally checks whole embedded DLL/data visibility and both components’ runtime checksums.

The bundle entry uses ordinary LoadLibrary/GetProcAddress and CreateFile/ReadFile calls. Callbacks match their original ordinals. Missing DLL and corrupt data controls fail before packing; both packed modes work alone and ignore invalid external namesakes. EXE and DLL wait scenarios both reach their original sleep loops. No files remain beside the bundled executable; these checks do not constitute a system-wide I/O trace.

Temporary executable mapping is disabled explicitly, as are virtual EXE launch, child sharing, extraction, registry virtualization and external storage. Those features, ActiveX registration and complex applications are outside this case. Standalone DLL checks preserve and compare all static exports.

The 11.30 console identifies Build 20250428 while installer metadata uses Build 20250429. Both labels belong to the same official distribution used here. The generator documents extraction and CMake reproduction; generated project/build files are temporary.
