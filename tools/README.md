# Shared Tools

Reusable PE analysis utilities and collection checks:

- [check_links.py](check_links.py) — check local Markdown links and heading anchors. Run `python tools/check_links.py`; external URLs are skipped.
- [compare_pe.py](compare_pe.py) — compare PE headers, sections, imports, exports and relocations. Usage is in its docstring and `--help`.
- [win_gui.py](win_gui.py) — bounded Win32 messages and PID-owned window enumeration used by packer GUI drivers.

Baseline build and verification helpers live in [fixtures/scripts](../fixtures/scripts); packer-specific helpers stay in their packer directories. Document each utility's dependencies, arguments and examples in its docstring and `--help`.
