# PCShrink research notes

## Required compressor library

The downloadable distribution contains the packer but omits aplib.dll. Its own compressed startup reports a missing DLL before the GUI appears. Tracing LoadLibraryA shows that the missing dependency is aPLib, not a Windows component.

The GUI advertises aPLib 0.22. We obtained 0.26b with the old five-argument `_aP_pack@20` interface and verified its output with the embedded runtime decompressor. aPLib 0.44 opens the GUI but crashes during packing; its pack interface takes six arguments. Do not replace the retained dependency based solely on its filename. This is a verified 0.71/0.26b combination, not a claim of original 0.22 output equivalence.

## Layout and compatibility

Section merging changes which original sections share a compressed block. Both retained profiles hide all complete markers and restore their runtime checksums. Export compression is disabled; resource restructuring is enabled but unexercised because the baseline has no resources. The success dialog has a stale 0.70 caption; the main window and included manual identify 0.71 beta.

Raw packed EXEs fault. Clearing only NX_COMPAT in a temporary input is sufficient; clearing ASLR alone is not. No output patch is applied. The packer removes relocation support, so the surviving DYNAMIC_BASE flag does not imply working ASLR. Original fixtures remain unchanged.

The x86 DLL reaches a rundll32 error reporting failed DLL initialization, including with ASLR/DEP/NO_SEH flags cleared. The manual already warns about incomplete DLL support and missing relocations. Native amd64 inputs are not safely rejected: EXE output fails with an illegal instruction and DLL packing faults after modifying its input. Failed files are not retained.

The helper sets the filename through the edit control because the legacy command-line parser misreads some paths. `--probe-failed` reproduces unsupported inputs. No native unpack-to-disk operation was established; runtime behavior and secrets are the recovery criteria.
