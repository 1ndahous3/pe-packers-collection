# Squishy research notes

## Compression and small files

Squishy filters code, compresses the application, then compresses its first-stage loader. `-d` checks the inverse of both compression stages; it does not validate Windows loading or reconstruct an original disk PE.

With our unmodified tiny EXEs, final unpadded output is smaller than the reserved header page. The raw-section size wraps to a huge unsigned value, and Windows rejects the file with ERROR_BAD_EXE_FORMAT despite successful internal checks. Add a deterministic 4 KiB read-only `.pad` section to a temporary input, using `prepare()` in the generator. Its deliberately incompressible bytes keep the output above that boundary. The prepared input itself must pass all behavioral and secret checks. No application code or marker is changed, and no output repair is applied.

## Loader and support limits

The output uses one `logicoma` section and lowers the image base to accommodate the loader. Relocations are stripped while the original mitigation flags remain. Both tested EXEs run with their original flags; forced rebasing was not verified. All complete disk markers are hidden and their runtime checksums recover correctly.

DLL input is accepted but the output export directory is discarded. Matching rundll32 does not reach RunFixture before the bounded timeout. A packer exit code of zero therefore does not establish DLL support. Wrong-architecture inputs trigger a Rust assertion and produce no file.

Use a fresh `--output` directory for generation, `--verify-only` for stored EXEs, and `--probe-failed` for the other matrix cells. Native disk unpacking and exact memory/PE reconstruction remain unverified.
