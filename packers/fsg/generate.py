"""Generate and verify FSG fixtures with original public Windows binaries.

Acquisition and requirements
----------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
Download fsg133.zip / fsg20.zip from:
  https://www.sac.sk/download/pack/fsg133.zip
  https://www.sac.sk/download/pack/fsg20.zip
Mirror (byte-identical ZIPs in this research):
  https://ftpmirror.infania.net/pub/pc/pack/
Extract each ZIP, then its nested fsg.rar with 7-Zip. Copy only FSG.EXE or
fsg.exe to tools/<version>/bin/fsg.exe. Do not run intro.exe, install.exe or
xt.cracktro.exe. Read xt.nfo and, for 2.0, fsg.ini in the distribution.
Buildable packer sources were not found in these packages.

Commands from the collection root
---------------------------------
  python packers/fsg/generate.py --version 1.33
  python packers/fsg/generate.py --version 2.0 --entry-trampoline
  python packers/fsg/generate.py --version 1.33 --output C:/Temp/fsg133

Negative controls (expected failure on the recorded Windows host):
  python packers/fsg/generate.py --version 1.33 --keep-input-flags --arch x86 --kind exe
  python packers/fsg/generate.py --version 2.0 --arch x86 --kind exe
  python packers/fsg/generate.py --version 2.0 --entry-trampoline --raw-output --arch x86 --kind exe

Profiles
--------
1.33: clear NX_COMPAT and DYNAMIC_BASE in a temporary x86 EXE input. Its loader
has fixed addresses and sections without execute permission. NO_SEH is unchanged.
--keep-input-flags reproduces the original failure; shared fixtures stay intact.

2.0: inputs are unchanged. On the recorded Windows host both the original tool
and its raw output fail with STATUS_INVALID_IMAGE_FORMAT. --entry-trampoline
appends a relative jump to the original header entry point, updates AEP and the
last section's raw size, in a temporary tool copy and in its packed output.
Original tools remain intact. The compression code, compressed stream and
original loader bytes are unchanged. --raw-output skips only the output fix to
reproduce the raw-output failure. This is an explicitly modified output profile.

Packing runs `fsg.exe <temporary-file>` in place. Temporary targets use .exe
even for DLL probes because 1.33 ignores .dll command-line paths. The PE DLL bit
is preserved. For 2.0, a temporary fsg.ini fixes the vendor defaults explicitly:
empty tag; strip overlays/Delphi resources; preserve exports/version/icons.
A fresh working directory avoids inherited fsg.ini settings. New builds require
reviewing hashes and diagnostics below, not just relabeling an executable.

Verification
------------
Both releases are x86 EXE packers. Exercise the whole shared matrix; recognize
only the exact version-specific DLL/PE64 rejection messages. 1.33 may modify a
rejected input, which is why every packer input is disposable. Successful packing
exits with 0xffffffff; exit status or changed bytes alone never mean PASS.

Require input manifest hashes, PE machine/kind/exports, exact success stdout,
exit zero, empty stderr and wait mode (--wait / WaitFixture by name and ordinal
4). Runtime checks verify all four secret checksums; report full marker presence
in packed bytes separately. This is not a third-party unpacker test or byte-exact
disk recovery. No native disk-unpacking command is documented by these releases.

Save only passing packed PE files; refuse different existing output. All
processes are bounded, errors do not suppress remaining cases, and temporary
files are removed. Exit 1 means a failed case, exit 2 an argument error.
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
HASHES = {
    "1.33": "34e9c329a8dd2b4a477a52a747185bf49ec71f42cf6e94fae70b5fa23200c94e",
    "2.0": "7cd037fe5ef0d4531cb934b39570014718d2a60c01ab7a8cc74f466b6d0db417",
}
CONFIG = ("[options]\npe_tag=\nstrip_overlays=1\nstrip_exports=0\n"
          "strip_delphi=1\nstrip_version=0\nhandle_icons=0\n")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pe_offsets(data):
    require(len(data) >= 64 and data[:2] == b"MZ", "Expected a DOS header.")
    pe = struct.unpack_from("<I", data, 60)[0]
    require(pe + 24 <= len(data) and data[pe:pe + 4] == b"PE\0\0", "Invalid PE header.")
    size = struct.unpack_from("<H", data, pe + 20)[0]
    require(size >= 96 and pe + 24 + size <= len(data), "Invalid optional header.")
    return pe, pe + 24, pe + 24 + size


def entry_trampoline(data):
    """Append a jump for the recorded FSG 2.0 layout; never rewrite its loader."""
    pe, optional, sections = pe_offsets(data)
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    require(machine == 0x14c and count == 2 and
            struct.unpack_from("<H", data, optional)[0] == 0x10b,
            "Entry trampoline requires the recorded two-section PE32 layout.")
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    headers = struct.unpack_from("<I", data, optional + 60)[0]
    last = sections + 40
    require(last + 40 <= len(data) and entry + 6 <= headers <= len(data),
            "Expected an entry point in the file-backed headers.")
    require(data[entry:entry + 2] == b"\x87\x25",
            "Expected the FSG 2.0 loader entry instruction.")
    virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<4I", data, last + 8)
    image_size = struct.unpack_from("<I", data, optional + 56)[0]
    require(raw_offset >= headers and raw_offset + raw_size == len(data) and
            raw_size + 5 <= virtual_size and rva + virtual_size <= image_size,
            "No room for an appended trampoline inside the last mapped section.")
    new_entry = rva + raw_size
    require(new_entry >= headers, "Trampoline would still lie in the headers.")
    result = bytearray(data)
    result += b"\xe9" + struct.pack("<i", entry - new_entry - 5)
    struct.pack_into("<I", result, optional + 16, new_entry)
    struct.pack_into("<I", result, last + 16, raw_size + 5)
    return bytes(result)


def prepare_input(data):
    _, optional, _ = pe_offsets(data)
    result = bytearray(data)
    flags = struct.unpack_from("<H", result, optional + 70)[0]
    struct.pack_into("<H", result, optional + 70, flags & ~0x140)
    return bytes(result)


def check_execution(path, arch, kind):
    if kind == "exe":
        command = [path]
    else:
        windows = Path(os.environ["WINDIR"])
        native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
        host = windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"
        command = [host, "./" + path.name + ",RunFixture"]
    result = subprocess.run([str(p) for p in command], cwd=path.parent,
                            stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=30)
    require(result.returncode == 0 and result.stdout == f"pe-fixture:basic-{kind}:ok\n"
            and not result.stderr,
            f"{path.name}: runtime failure: exit={result.returncode:#x}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def unsupported(version, arch, kind, error):
    if version == "1.33":
        return ((kind == "dll" and error == "Sorry, FSG doesnt support DLL files.") or
                (arch == "amd64" and kind == "exe" and error == "Missing import table!"))
    return ((arch == "amd64" and error == "This file isn't valid PE file (not i386 compatible)") or
            (kind == "dll" and error == "FSG doesn't support Dynamic Link Libraries (DLL, OCX) files!"))


def generate_case(args, tool, output, work, pe, wait, gui, arch, kind):
    original_dir = ROOT / "fixtures/bin" / arch
    manifest = json.loads((original_dir / "manifest.json").read_text(encoding="utf-8"))
    ref = next(a for a in manifest["artifacts"] if a["id"] == f"basic-{kind}-{arch}")
    source = original_dir / ref["path"]
    original_bytes = source.read_bytes()
    require(digest(original_bytes) == ref["sha256"], "Shared input differs from its manifest.")
    try:
        original = work / f"original.{kind}"
        original.write_bytes(original_bytes)
        check_execution(original, arch, kind)
        original_pe = pe.inspect_pe(original)
        for marker in ref["secrets"]:
            require(bytes.fromhex(marker["hex"]) in original_bytes,
                    f"Missing original marker: {marker['id']}")
        prepared = original_bytes
        if args.version == "1.33" and arch == "x86" and kind == "exe" and not args.keep_input_flags:
            prepared = prepare_input(prepared)
        target = work / "packed.exe"
        target.write_bytes(prepared)
        check_execution(target, arch, kind)
        code, error = gui.pack(tool, target, args.version)
        if unsupported(args.version, arch, kind, error):
            print(f"{arch}/{kind}: UNSUPPORTED ({error}); temporary output discarded")
            return
        require(not error, f"FSG dialog: {error}")
        require(code == 0xffffffff, f"FSG startup/packing failed: exit={code:#x}")
        packed_bytes = target.read_bytes()
        require(packed_bytes != prepared, "FSG did not change the input.")
        if args.entry_trampoline and not args.raw_output:
            packed_bytes = entry_trampoline(packed_bytes)
            target.write_bytes(packed_bytes)
        packed_pe = pe.inspect_pe(target)
        for field in ("machine", "optional_header", "kind", "exports"):
            require(packed_pe[field] == original_pe[field],
                    f"Packed PE differs in {field}.")
        if kind == "dll":
            target = target.rename(work / "packed.dll")
        check_execution(target, arch, kind)
        wait.check_fixture(target, arch, kind)
        visible = [m["id"] for m in ref["secrets"] if bytes.fromhex(m["hex"]) in packed_bytes]
        require(target.read_bytes() == packed_bytes, "Execution modified the packed PE.")
        require(original.read_bytes() == original_bytes, "Temporary original changed.")
        require(source.read_bytes() == original_bytes, "Shared input was modified.")
        destination = output / f"fixture-{arch}-{kind}" / f"packed.{kind}"
        require(not destination.exists() or destination.read_bytes() == packed_bytes,
                f"Refusing to replace different output: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            with destination.open("xb") as stream:
                stream.write(packed_bytes)
        info = pe.inspect_pe(target)
        print(f"{arch}/{kind}: PASS; bytes={len(original_bytes)}->{len(packed_bytes)}; "
              f"full markers visible={visible}; DYNAMIC_BASE={info['dynamic_base']}; "
              f"NX_COMPAT={info['nx_compatible']}; relocations={bool(info['relocations_size'])}")
    finally:
        require(source.read_bytes() == original_bytes, "Shared input was modified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, choices=tuple(HASHES))
    parser.add_argument("--arch", action="append", choices=("x86", "amd64"))
    parser.add_argument("--kind", action="append", choices=("exe", "dll"))
    parser.add_argument("--output", type=Path, help="Alternate version output directory.")
    parser.add_argument("--keep-input-flags", action="store_true", help="1.33 negative control.")
    parser.add_argument("--entry-trampoline", action="store_true", help="2.0 Windows compatibility profile.")
    parser.add_argument("--raw-output", action="store_true", help="2.0 negative control: fix only the tool.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    if (args.keep_input_flags and args.version != "1.33") or (
            args.entry_trampoline and args.version != "2.0") or (
            args.raw_output and not args.entry_trampoline):
        parser.error("Profile options do not match the selected version.")
    source_tool = PACKER / "tools" / args.version / "bin/fsg.exe"
    tool_bytes = source_tool.read_bytes()
    require(digest(tool_bytes) == HASHES[args.version], "Unexpected FSG binary; review its provenance.")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    pe = load_module("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    wait = load_module("fixture_wait", ROOT / "fixtures/scripts/check_wait.py")
    gui = load_module("fsg_gui", PACKER / "gui.py")
    print(f"FSG {args.version}; entry trampoline={args.entry_trampoline}; raw output={args.raw_output}")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    try:
        with tempfile.TemporaryDirectory(prefix="pe-fsg-") as temporary:
            work_root = Path(temporary).resolve()
            require(work_root.parent == Path(tempfile.gettempdir()).resolve(), "Unexpected temp root.")
            tool = work_root / "fsg.exe"
            tool.write_bytes(entry_trampoline(tool_bytes) if args.entry_trampoline else tool_bytes)
            expected_tool = tool.read_bytes()
            if args.version == "2.0":
                (work_root / "fsg.ini").write_bytes(CONFIG.encode("ascii"))
            for arch in dict.fromkeys(args.arch or ("x86", "amd64")):
                for kind in dict.fromkeys(args.kind or ("exe", "dll")):
                    work = work_root / f"{arch}-{kind}"
                    work.mkdir()
                    try:
                        generate_case(args, tool, output, work, pe, wait, gui, arch, kind)
                    except (ValueError, OSError, subprocess.TimeoutExpired, StopIteration) as error:
                        failures += 1
                        print(f"{arch}/{kind}: FAIL: {error}", file=sys.stderr)
            require(tool.read_bytes() == expected_tool, "Temporary packer changed during execution.")
    finally:
        require(source_tool.read_bytes() == tool_bytes, "Stored packer was modified.")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
