# Hyperion research notes

The retained EXEs have a new entry point and a different section layout. Their `.bss` reserves address space without contributing raw data to the file. They have no base relocation directory and the `DYNAMIC_BASE` flag is clear. The 1.1 output retains `NX_COMPAT`. Both 2.3.1 outputs clear it. These observations describe the PE headers on disk.

The loader searches for the AES key at startup. The generator limits the search to two candidates so that decryption finishes within the shared wait check's timeout. It uses unmodified copies of the shared inputs. The success line confirms that the decrypted fixture executed and validated its markers. The wait check also verifies that `--wait` reached the fixture and kept the process alive.

Both versions reject a DLL before generating a container, including when the DLL is amd64. Version 1.1 reports a separate PE64 error for the amd64 EXE. The upstream changelog records amd64 support from 2.0 and x86 deprecation from 2.3.
