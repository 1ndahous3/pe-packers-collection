# AlushPacker research notes

The documented packing scheme compresses the input with LZAV and encrypts it using XTEA. The native runtime stub reads `.packed`, recovers the image, resolves imports and applies memory protections before transferring control. Public sources describe TLS, delayed-import and exception support, but our baseline does not exercise those features. Do not infer complete support from the loader's diagnostic messages.

The official release packs both architectures successfully with the automatic `_packed.exe` filename. Its `-o` path creates an empty output and returns failure. The source published with tag `v1.0.0` opens the explicit output during argument parsing, leaves that stream open and later attempts to open the same path again. Omitting `-o` avoids this path without modifying the packer or payload. Source/binary equivalence was not established; the public project has evolved since the release.

The release loader prints allocation, import and section-protection diagnostics. During normal exit, CRT buffering makes these appear after the fixture's direct WriteFile output. In wait mode they remain buffered. The helper accepts only the observed diagnostic forms, requires the exact fixture line once and checks exit status/stderr separately. No diagnostic bytes are patched out of the packed files.

DLL headers do not prevent packing, but the resulting outer image is an EXE without the original exports. That does not provide a usable rundll32 DLL case. The generator inspects these negative outputs without executing or retaining them. No native unpack-to-disk command was established; successful runtime checks do not prove exact PE-header recovery.
