# Shrinker 3.4 research notes

## Packing

The public `shrinker.exe` download is a 16-bit Wise installer. Its Win32 packer is `Shrink32.exe` with `Shrink32.dll` beside it. The bundled `Shrinker.hlp` describes both the command line and the Win32 loader.

Use separate input and output names. `-CA` requests output even when compression increases file size, which happens on these small fixtures. `-BQ` selects quiet batch mode. Confirm the packer's **Welcome to Shrinker!** dialog with **Ok**. For PE32+ inputs the same command returns zero without creating the requested output, so check that the file exists.

```text
Shrink32.exe input.exe packed.exe -BQ -CA
Shrink32.exe shrinker-fixture.dll packed.dll -BQ -CA
```

Separate runs on the same EXE input produced different packed bytes and passed the same runtime checks. Use a fresh output directory when regenerating the cases.

## Win32 loader

The packed entry point is in `.load`. Shrinker groups the original sections into `.shrink*` sections. The vendor describes on-demand decompression, so reaching the entry point alone does not establish that the fixture data is available. The runtime checks exercise the markers in code, read-only data, writable data and the custom section.

On the tested Windows host, packing the unmodified x86 fixtures produces an access violation (`0xC0000005`) during startup for both EXE and DLL. Clearing only the PE `NO_SEH` flag on the input allows the packed programs to reach the Blink notice and execute the fixture. Clearing the ASLR or DEP flags alone did not fix startup. The retained cases preserve both flags and the DLL's original export names and ordinals.
