# EZip research notes

## Identifying the distributions

The [author's early download page](https://web.archive.org/web/20000824144047/http://www.jonathanclark.com/ezip/) labels the 58 KB Jitit download as version 1.0. Its own console banner identifies it as **0.8 (beta)**. The collection uses that banner for the runnable tool.

The later [executable download on the 1.0 page](https://web.archive.org/web/20031018125133id_/http://www.jonathanclark.com/ezip/ezip.exe) serves a Thinstall package. The [author's ZIP](https://web.archive.org/web/20040814030556id_/http://www.jonathanclark.com/ezip/ezip1.zip) contains a different Thinstall build. Its executable matches the one in `ANALYZE_L@B/Packers/EZip 1.0.rar` on the [SUN DVD](https://archive.org/details/cracklb-2010).

On Windows, installing to a user-writable folder copied the package unchanged and its next launch reopened the installer. In a disposable BoxedWine 20.1.2 / Wine 1.7 environment, both packages completed the file-copy stage at the default path. Their installed processes then reported a fatal Thinstall memory-write error during startup. These runs establish a packaging issue in the tested environments. The inner compressor version and its PE support remain unverified.

## Reproducing the 0.8 beta case

Run `ezip.exe fixture.exe packed.exe` in a writable directory. The CLI prints both file sizes and returns exit code 1 on a successful pack. The loader makes the small fixture larger. The original section names remain in the output with zero raw size, followed by a second `.text`, `.rdata` and `.data` for the loader.

Packing the unmodified x86 EXE produced a startup access violation on Windows. Clearing only `DYNAMIC_BASE` before packing gave a working EXE with the original DEP flag.

For the unmodified x86 DLL, the export names and ordinals survived packing, but 32-bit `rundll32` could not initialize the library. With `DYNAMIC_BASE` cleared on the input, `RunFixture` produced no readiness line within 12 seconds. For both amd64 inputs, EZip opened its architecture warning and created a zero-byte destination.
