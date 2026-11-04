"""Generate and verify PESpin fixtures using the preserved native releases.

Requirements and acquisition
----------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
Extract the preserved vendor archives with 7-Zip. Only PESpin.exe (1.33/x86)
or PESpin_x64.exe (1.22/amd64) is needed in tools/<version>/bin/.
Archives include manuals and integration examples, not packer build sources.
  https://web.archive.org/web/20131104154610id_/http://pespin.w.interia.pl/pespin133.rar
  https://web.archive.org/web/20140412162406id_/http://pespin.w.interia.pl/pespin_v122_x64.zip
The binaries are identified by the MD5 values published on the vendor page.

Examples (from the collection root)
-----------------------------------
  python packers/pespin/generate.py --version 1.22 --output C:/Temp/pespin-amd64
  python packers/pespin/generate.py --version 1.33 --kind exe --output C:/Temp/pespin-x86
  python packers/pespin/generate.py --version 1.33 --kind dll --output C:/Temp/pespin-dll-check

Use a fresh --output for reproduction; polymorphic packing need not produce
identical bytes. Without --output, packed-fixtures/<version> is used for initial
population. Different existing output is never overwritten.
Each version targets its own architecture. Both EXE and DLL are attempted unless
--kind selects one. For the original 1.33 DLL export-layout failure, add
--keep-export-layout: the export check rejects the output without publishing it.

Profiles and input preparation
------------------------------
The constants below reproduce settings captured from the vendor GUIs.
1.33: API redirection enabled; anti-dump, OEP removal, code redirection,
debug blocker, debugger detection, password and time limits disabled.
Relocation stripping/backup disabled; section names retained. NO_SEH is cleared
only in a temporary input copy, preserving ASLR/NX. --keep-no-seh reproduces the
original-input EXE failure. Clearing NO_SEH alone did not fix the more aggressive
default protector profile. For 1.33 DLLs, export-name strings are also rearranged
in a temporary input: their physical order must match the sorted name-pointer
table. Export names, ordinals and function RVAs stay unchanged. PESpin otherwise
rebuilds name pointers in physical string order, breaking name lookup. The packed
output needs no patch. The helper deliberately accepts only the fixture's simple,
contiguous export layout; it is not a general-purpose PE repair tool.
1.22: UCL, imports resolved via Hash, checksum enabled; OEP removal,
debug blocker/password disabled; section names retained. Inputs unchanged.

The executable and its config are copied into each case's temporary tool/
directory. gui.py drives 1.33's process-owned Protect file control and checks
its completion log. For 1.22, PESpin_x64.exe <input> uses settings.ini with auto_run
and exit_when_done. Retained bins receive no settings files. To investigate other
settings, edit the profile constants in a working copy and use a fresh output.

Verification
------------
Original hashes must match the shared manifests. Original, prepared and packed
executions must print the exact success line, exit zero and leave stderr empty.
DLLs use matching rundll32 with RunFixture; the x86 output is also called by its
original ordinal. All four secret checksums are covered;
complete marker visibility in packed bytes is reported separately.
Architecture, EXE/DLL kind and export names/ordinals must survive. Flags,
relocation presence and sections are observations.
Prepared inputs must preserve the original export mapping. No failed output or
reports are saved.
The manuals do not document a native disk decompressor. External unpackers and
recovered dumps are untested; runtime success is not byte-exact reconstruction.

Child processes have bounded waits (packing/runtime: 30 seconds); gui.py closes
or kills only its own process. Shared originals are checked for immutability and
temporary files are removed. Exit 1 means a failed case, exit 2 an argument error.
A failed case does not suppress the other requested cases.

Packed wait mode is required before publication: --wait for EXEs, WaitFixture
by name and ordinal 4 for DLLs. The shared fixtures/scripts/check_wait.py checks
the success line and continued execution, then terminates only its test process.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
WAIT_SPEC = importlib.util.spec_from_file_location(
    "fixture_wait", ROOT / "fixtures/scripts/check_wait.py")
WAIT_CHECK = importlib.util.module_from_spec(WAIT_SPEC)
WAIT_SPEC.loader.exec_module(WAIT_CHECK)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, cwd):
    return subprocess.run([str(x) for x in command], cwd=cwd,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=30)


def check_execution(path, arch, kind, entry="RunFixture"):
    if kind == "exe":
        command = [path]
    else:
        windows = Path(os.environ["WINDIR"])
        native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
        host = windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"
        command = [host, "./" + path.name + "," + entry]
    result = run(command, path.parent)
    require(result.returncode == 0 and
            result.stdout == f"pe-fixture:basic-{kind}:ok\n" and not result.stderr,
            f"{path.name}: runtime check failed: exit={result.returncode:#x}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


TOOLS = {'1.33': ['x86', 'PESpin.exe', 'bfe39baaf8c8989c0e8dfd034210f462'],
 '1.22': ['amd64', 'PESpin_x64.exe', '431b0ee1078ee5ac37b1f2205d401a0c']}
PROFILES = {
    '1.33': ('pespin.ini', """antidebug_prot=0
antidebug_exit=1
antidebug_msg=0
strip_overlays=1
compress_res=1
strip_reloc=0
msdos_header=0
api_redirect=1
anti_dump=0
remove_oep=0
code_redirect=0
debug_blocker=0
backup_file=0
password_prot=0
close_after=
section_user=0
section_random=0
section_leave=1
antidebug_txt=Debugger detected please close it down and restart
section_name=
"""),
    '1.22': ('settings.ini', """[options]
exit_when_done=1
auto_run=1
compress_res=1
backup_file=0
checksum=1
remove_oep=0
debug_blocker=0
section_leave=1
section_user=0
section_name=
import_resolving=2
compression=0
password_protection=0
[advanced_settings]
nanomites=100
"""),
}


def clear_no_seh(data):
    prepared = bytearray(data)
    pe_offset = struct.unpack_from("<I", prepared, 60)[0]
    require(prepared[pe_offset:pe_offset + 4] == b"PE\0\0" and
            struct.unpack_from("<H", prepared, pe_offset + 24)[0] == 0x10b,
            "NO_SEH preparation expects PE32.")
    position = pe_offset + 24 + 70
    flags = struct.unpack_from("<H", prepared, position)[0]
    require(flags & 0x400, "Expected NO_SEH in the original x86 fixture.")
    struct.pack_into("<H", prepared, position, flags & ~0x400)
    return bytes(prepared)


def prepare_dll_exports(data):
    """Reorder fixture export strings without changing its public interface.

    PESpin 1.33 reconstructs name pointers from physical string order. PE requires
    the pointer table to be sorted, but does not impose that order on the strings.
    Accept only distinct, contiguous names after the DLL name, with no forwarders.
    """
    prepared = bytearray(data)
    u16 = lambda offset: struct.unpack_from("<H", data, offset)[0]
    u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
    pe = u32(60)
    require(data[pe:pe + 4] == b"PE\0\0" and u16(pe + 24) == 0x10b
            and u16(pe + 22) & 0x2000, "Expected a PE32 DLL.")
    section_table = pe + 24 + u16(pe + 20)

    def offset(rva, size):
        for index in range(u16(pe + 6)):
            section = section_table + 40 * index
            va, raw_size, raw = u32(section + 12), u32(section + 16), u32(section + 20)
            if va <= rva and rva + size <= va + raw_size:
                result = raw + rva - va
                require(result + size <= len(data), "Truncated export data.")
                return result
        raise ValueError("Export data is not fully backed by section bytes.")

    export_rva, export_size = u32(pe + 24 + 96), u32(pe + 24 + 100)
    require(export_size >= 40, "Expected a complete export directory.")
    directory = offset(export_rva, export_size)
    count, functions = u32(directory + 24), u32(directory + 20)
    require(0 < count <= functions, "Expected named fixture exports.")
    names = offset(u32(directory + 32), count * 4)
    eat = offset(u32(directory + 28), functions * 4)
    require(all(not export_rva <= u32(eat + i * 4) < export_rva + export_size
                for i in range(functions)), "Forwarded exports are not supported.")
    entries = []
    for i in range(count):
        rva = u32(names + i * 4)
        start = offset(rva, 1)
        end = data.index(b"\0", start, directory + export_size) + 1
        require(offset(rva, end - start) == start, "Invalid export string.")
        entries.append((rva, data[start:end]))
    strings = [text for _, text in entries]
    require(strings == sorted(set(strings)), "Expected sorted, distinct export names.")
    physical = sorted(entries)
    first = physical[0][0]
    cursor = first
    for rva, text in physical:
        require(rva == cursor, "Export strings must be contiguous.")
        cursor += len(text)
    start = offset(first, cursor - first)
    end = start + cursor - first
    dll_name = offset(u32(directory + 12), 1)
    require(data.index(b"\0", dll_name, start) + 1 == start,
            "Expected export strings immediately after the DLL name.")
    require(max(directory + 40, eat + functions * 4, names + count * 4,
                offset(u32(directory + 36), count * 2) + count * 2) <= start,
            "Export strings overlap the export tables.")
    prepared[start:end] = b"".join(strings)
    cursor = first
    for i, text in enumerate(strings):
        struct.pack_into("<I", prepared, names + i * 4, cursor)
        cursor += len(text)
    return bytes(prepared)


def pack(tool, path, version, work):
    local_dir = work / "tool"
    local_dir.mkdir()
    local_tool = local_dir / tool.name
    local_tool.write_bytes(tool.read_bytes())
    filename, config = PROFILES[version]
    (local_dir / filename).write_bytes(config.replace("\n", "\r\n").encode("ascii"))
    if version == "1.33":
        spec = importlib.util.spec_from_file_location("pespin_gui", PACKER / "gui.py")
        gui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gui)
        return gui.pack_x86(local_tool, path)
    result = run([local_tool, path], local_dir)
    require(result.returncode == 0,
            f"PESpin exited with {result.returncode}: {result.stdout}{result.stderr}")
    return ""


def generate_case(args, tool, output, work, pe, arch, kind):
    manifest_path = ROOT / "fixtures/bin" / arch / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ref = next(a for a in manifest["artifacts"] if a["id"] == f"basic-{kind}-{arch}")
    source = manifest_path.parent / ref["path"]
    require(digest(source) == ref["sha256"], "Shared original differs from its manifest.")
    original_bytes = source.read_bytes()
    try:
        original = work / f"original.{kind}"
        original.write_bytes(original_bytes)
        check_execution(original, arch, kind)
        original_pe = pe.inspect_pe(original)
        for marker in ref["secrets"]:
            require(bytes.fromhex(marker["hex"]) in original_bytes,
                    f"Original marker missing: {marker['id']}")

        packed = work / f"packed.{kind}"
        prepared_bytes = (clear_no_seh(original_bytes)
                          if args.version == "1.33" and not args.keep_no_seh
                          else original_bytes)
        if args.version == "1.33" and not args.keep_no_seh:
            print(f"{arch}/{kind}: cleared NO_SEH in temporary input; ASLR/NX unchanged.")
        if args.version == "1.33" and kind == "dll" and not args.keep_export_layout:
            prepared_bytes = prepare_dll_exports(prepared_bytes)
            print("x86/dll: reordered temporary export strings; public mapping unchanged.")
        packed.write_bytes(prepared_bytes)
        if prepared_bytes != original_bytes:
            require(pe.inspect_pe(packed)["exports"] == original_pe["exports"],
                    "Input preparation changed the export mapping.")
            check_execution(packed, arch, kind)
        pack(tool, packed, args.version, work)
        packed_bytes = packed.read_bytes()
        require(packed_bytes != prepared_bytes, "Packer did not change the input.")
        packed_pe = pe.inspect_pe(packed)
        for field in ("machine", "optional_header", "kind", "exports"):
            require(packed_pe[field] == original_pe[field], f"Packed PE differs in {field}.")
        check_execution(packed, arch, kind)
        WAIT_CHECK.check_fixture(packed, arch, kind)
        if arch == "x86" and kind == "dll":
            ordinal = next(e["ordinal"] for e in original_pe["exports"]
                           if e["name"] == "RunFixture")
            check_execution(packed, arch, kind, entry=f"#{ordinal}")
            print("x86/dll: callback passed by name and original ordinal.")
        visible = [m["id"] for m in ref["secrets"]
                   if bytes.fromhex(m["hex"]) in packed_bytes]
        require(packed.read_bytes() == packed_bytes, "Execution modified the packed file.")
        require(digest(source) == ref["sha256"], "Shared original was modified.")
        require(original.read_bytes() == original_bytes, "Temporary original was modified.")
        destination = output / f"fixture-{arch}-{kind}" / packed.name
        require(not destination.exists() or destination.read_bytes() == packed_bytes,
                f"Refusing to replace different output: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            with destination.open("xb") as stream:
                stream.write(packed_bytes)
        sections = [s["name"] for s in packed_pe["sections"]]
        print(f"{arch}/{kind}: PASS; full markers visible={visible}; "
              f"bytes={len(original_bytes)}->{len(packed_bytes)}")
        print(f"  DYNAMIC_BASE={packed_pe['dynamic_base']}; "
              f"NX_COMPAT={packed_pe['nx_compatible']}; "
              f"relocations directory={bool(packed_pe['relocations_size'])}; "
              f"sections={sections}")
    finally:
        require(digest(source) == ref["sha256"], "Shared original was modified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, choices=tuple(TOOLS),
                        help="Select x86 (1.33) or amd64 (1.22).")
    parser.add_argument("--kind", choices=("exe", "dll"), action="append",
                        help="Repeat to select kinds; default: both.")
    parser.add_argument("--output", type=Path, help="Fresh version output directory.")
    parser.add_argument("--keep-no-seh", action="store_true",
                        help="Retain NO_SEH in 1.33 inputs (packed EXE/DLL fail on this host).")
    parser.add_argument("--keep-export-layout", action="store_true",
                        help="Reproduce the 1.33 DLL name/ordinal mismatch without saving output.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    if (args.keep_no_seh or args.keep_export_layout) and args.version != "1.33":
        parser.error("--keep-no-seh / --keep-export-layout only apply to 1.33.")
    arch, filename, expected_md5 = TOOLS[args.version]
    tool = PACKER / "tools" / args.version / "bin" / filename
    if not tool.is_file():
        parser.error(f"Missing packer: {tool}")
    if hashlib.md5(tool.read_bytes()).hexdigest() != expected_md5:
        parser.error("Packer does not match the vendor binary for this version.")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    spec = importlib.util.spec_from_file_location("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    print(f"PESpin {args.version}; architecture={arch}")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-pespin-") as temporary:
        work_root = Path(temporary).resolve()
        require(work_root.parent == Path(tempfile.gettempdir()).resolve(),
                "Unexpected temporary directory location.")
        for kind in dict.fromkeys(args.kind or ("exe", "dll")):
            work = work_root / f"{arch}-{kind}"
            work.mkdir()
            try:
                generate_case(args, tool, output, work, pe, arch, kind)
            except (ValueError, OSError, subprocess.TimeoutExpired, StopIteration) as error:
                failures += 1
                print(f"{arch}/{kind}: FAIL: {error}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
