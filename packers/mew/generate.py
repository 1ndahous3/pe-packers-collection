"""Generate and verify MEW fixtures with the original public Windows release.

MEW 5 acquisition/profile: extract mew5.exe from the retained
 tools/5-0.1-beta/MEW 5 0.1b.rar (SUN DVD, https://archive.org/details/cracklb-2010).
Run --version 5-0.1-beta. Raw command: mew5.exe input.exe -o coded.exe.
This is a code encoder, not the later compressor. The generator adds an entry
trampoline section, clears output ASLR/NX, then verifies execution and wait.
The original tool/input and header-decoder/payload bytes are unchanged. Only
x86 EXE is retained; DLL and PE64 failed probes are skipped. MEW 11 switches
cannot be passed to this version. See internals.md for the layout limitation.

Acquisition and requirements
----------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
Download MEW 11 SE v1.2 from:
  https://www.sac.sk/download/pack/mew11.zip
Mirror (the ZIPs were byte-identical in this research):
  https://ftpmirror.infania.net/pub/pc/pack/mew11.zip
Extract only mew11.exe to tools/11-se-1.2/bin/. It has no additional runtime
files. The ZIP also supplies the author's manual.html and northfox.nfo; read
those for options and release history. Buildable sources are not supplied.

Commands from the collection root
---------------------------------
  python packers/mew/generate.py --version 11-se-1.2
  python packers/mew/generate.py --version 11-se-1.2 --arch x86 --kind exe
  python packers/mew/generate.py --version 11-se-1.2 --output C:/Temp/mew-default
  python packers/mew/generate.py --version 11-se-1.2 --pack-arg=-dont_use_lzma --output C:/Temp/mew-appack
  python packers/mew/generate.py --version 11-se-1.2 --pack-arg=-lzma_special --output C:/Temp/mew-special

The recorded profile uses default options. Neither input nor packed output is
patched. Temporary packer/input copies are used, and packing runs in place:
  mew11.exe packed.exe
Always pass a relative input filename from its directory. Absolute input paths
silently left the file unchanged in our probes, with exit zero. The manual says
to replace spaces in the input filename with '*'; this helper uses fixed simple
filenames and does not need that conversion. argv[0] is also a simple name;
Python's executable argument selects the actual packer path.

Default compression tries aPPack and LZMA. For the shared x86 EXE, default,
-dont_use_lzma and -lzma_special produced identical bytes, so this small fixture
exercises aPPack and does not establish LZMA runtime coverage. Repeat --pack-arg
to experiment with the documented flags; use a separate --output. No backup is
requested because inputs are already disposable. A different build needs an
identity/GUI/diagnostic review before extending the version table below.

Verification and limitations
----------------------------
The default matrix is x86/amd64 x EXE/DLL. Check source manifest hashes and run
unchanged temporary originals. Require the packer's terminal GUI status as well
as its exit code, then compare PE machine, kind and export names/ordinals.
Require exact fixture success stdout, exit zero and empty stderr, followed by
--wait (or DLL WaitFixture by name and ordinal 4). Runtime checks exercise all
four secret checksums. Full marker visibility in packed bytes is a separate
observation, not a test of an external unpacker or byte-exact disk recovery.

The author excludes DLL and PE64 support. This release misleadingly reports
success for x86 DLL but removes the DLL bit and exports: discard this output.
It rejects the two amd64 inputs with "Don't support .NET applications!" and
exit zero, although these inputs are native PE32+. Recognize that diagnostic
only with this pinned build, known amd64 input, failure status and unchanged
input. Unexpected failures remain failures.

Only verified packed PEs are saved. Identical existing output is accepted;
different output is refused. All processes are bounded and temporary files are
removed. Cases continue after failure; exit 1 means a failed case, exit 2 an
argument error. Stored packers and shared original PEs are never modified.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import platform
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
_PROCESS_SPEC = importlib.util.spec_from_file_location('fixture_process', ROOT/'fixtures/scripts/isolated_process.py')
ISOLATED = importlib.util.module_from_spec(_PROCESS_SPEC)
_PROCESS_SPEC.loader.exec_module(ISOLATED)
HASHES = {"11-se-1.2": "5d34161be5f0c623d9810e39c594ee72f65ca74b9730f57ad6675c13d81e6d3f"}
HASHES["5-0.1-beta"] = "9e8e374ffe8626e4fe98e86f2a10136ef1bbe9adb550751bd52e0edb3deba2ff"
FLAGS = ("-dont_use_lzma", "-dont_pack_res", "-dont_strip_reloc", "-dont_strip_delphi",
         "-force", "-backup", "-lzma_special", "-no_slice")
READY = "Packing procedure ready!"
FAILED = "Packing procedure failed!"


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


def check_execution(path, arch, kind):
    if kind == "exe":
        command = [path]
    else:
        windows = Path(os.environ["WINDIR"])
        native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
        host = windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"
        command = [host, "./" + path.name + ",RunFixture"]
    result = ISOLATED.run([str(p) for p in command], cwd=path.parent,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=10)
    require(result.returncode == 0 and result.stdout == f"pe-fixture:basic-{kind}:ok\n"
            and not result.stderr,
            f"{path.name}: runtime failure: exit={result.returncode:#x}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def legacy_trampoline(data):
    """Make the header decoder reachable; preserve its bytes and encoded payload."""
    result = bytearray(data)
    nt = struct.unpack_from('<I', result, 0x3c)[0]
    opt = nt + 24
    require(result[nt:nt+4] == b'PE\0\0' and struct.unpack_from('<H',result,opt)[0] == 0x10b,
            'Expected MEW 5 PE32 output.')
    count = struct.unpack_from('<H',result,nt+6)[0]
    table = opt + struct.unpack_from('<H',result,nt+20)[0] + count*40
    headers = struct.unpack_from('<I',result,opt+60)[0]
    entry = struct.unpack_from('<I',result,opt+16)[0]
    section_alignment, file_alignment = struct.unpack_from('<II',result,opt+32)
    rva = struct.unpack_from('<I',result,opt+56)[0]
    require(entry < headers and table+40 <= headers and not any(result[table:table+40]),
            'Unexpected header decoder / no spare section slot.')
    require(section_alignment == 4096 and file_alignment == 512 and len(result)%512 == 0,
            'Unexpected fixture output alignment.')
    stub = b'\xe9' + struct.pack('<i',entry-rva-5)
    struct.pack_into('<8sIIIIIIHHI',result,table,b'.mewfix\0',len(stub),rva,512,len(result),0,0,0,0,0x60000020)
    struct.pack_into('<H',result,nt+6,count+1)
    struct.pack_into('<I',result,opt+16,rva)
    struct.pack_into('<I',result,opt+56,rva+4096)
    flags = struct.unpack_from('<H',result,opt+70)[0]
    struct.pack_into('<H',result,opt+70,flags & ~0x140)
    result += stub + bytes(512-len(stub))
    return bytes(result)


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
        target = work / f"packed.{kind}"
        target.write_bytes(original_bytes)
        if args.version == "5-0.1-beta":
            if arch != "x86" or kind != "exe":
                print(f"{arch}/{kind}: SKIP; MEW 5 probes did not produce a working fixture.")
                return
            raw = work / "coded.exe"
            result = subprocess.run([str(tool), target.name, "-o", raw.name], cwd=work,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
            require(result.returncode == 0 and raw.is_file(), "MEW 5 failed to encode the input.")
            target.write_bytes(legacy_trampoline(raw.read_bytes()))
            code, status, detail = 0, READY, ""
        else:
            code, status, detail = gui.pack(tool, target, args.pack_arg)
        packed_bytes = target.read_bytes()
        if (args.version == "11-se-1.2" and arch == "amd64" and code == 0 and
                status == FAILED and detail == "Don't support .NET applications!" and
                packed_bytes == original_bytes and not original_pe["clr_size"]):
            print(f"{arch}/{kind}: UNSUPPORTED (PE64 rejected as .NET; input unchanged)")
            return
        require(code == 0 and status == READY,
                f"MEW did not confirm packing: exit={code:#x}; {status!r}; {detail!r}")
        require(packed_bytes != original_bytes, "MEW did not change the input.")
        packed_pe = pe.inspect_pe(target)
        if (args.version == "11-se-1.2" and arch == "x86" and kind == "dll" and
                packed_pe["machine"] == original_pe["machine"] and
                packed_pe["optional_header"] == original_pe["optional_header"] and
                packed_pe["kind"] == "EXE" and not packed_pe["exports"]):
            print("x86/dll: UNSUPPORTED (packer reports success but removes DLL bit/exports); discarded")
            return
        for field in ("machine", "optional_header", "kind", "exports"):
            require(packed_pe[field] == original_pe[field], f"Packed PE differs in {field}.")
        check_execution(target, arch, kind)
        wait.check_fixture(target, arch, kind)
        visible = [m["id"] for m in ref["secrets"] if bytes.fromhex(m["hex"]) in packed_bytes]
        require(target.read_bytes() == packed_bytes, "Execution modified the packed PE.")
        require(original.read_bytes() == original_bytes, "Temporary original changed.")
        require(source.read_bytes() == original_bytes, "Shared input was modified.")
        destination = output / f"fixture-{arch}-{kind}" / target.name
        require(not destination.exists() or destination.read_bytes() == packed_bytes,
                f"Refusing to replace different output: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            with destination.open("xb") as stream:
                stream.write(packed_bytes)
        print(f"{arch}/{kind}: PASS; bytes={len(original_bytes)}->{len(packed_bytes)}; "
              f"full markers visible={visible}; DYNAMIC_BASE={packed_pe['dynamic_base']}; "
              f"NX_COMPAT={packed_pe['nx_compatible']}; relocations={bool(packed_pe['relocations_size'])}")
    finally:
        require(source.read_bytes() == original_bytes, "Shared input was modified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, choices=tuple(HASHES))
    parser.add_argument("--arch", action="append", choices=("x86", "amd64"))
    parser.add_argument("--kind", action="append", choices=("exe", "dll"))
    parser.add_argument("--output", type=Path, help="Alternate version output directory.")
    parser.add_argument("--pack-arg", action="append", default=[], choices=FLAGS,
                        help="Repeat documented flags, e.g. --pack-arg=-dont_use_lzma.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    if args.version == "5-0.1-beta" and args.pack_arg:
        parser.error("MEW 11 switches do not apply to MEW 5.")
    filename = "mew5.exe" if args.version == "5-0.1-beta" else "mew11.exe"
    source_tool = PACKER / "tools" / args.version / "bin" / filename
    tool_bytes = source_tool.read_bytes()
    require(digest(tool_bytes) == HASHES[args.version], "Unexpected MEW binary; review provenance.")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    pe = load_module("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    wait = load_module("fixture_wait", ROOT / "fixtures/scripts/check_wait.py")
    gui = load_module("mew_gui", PACKER / "gui.py")
    print(f"MEW {args.version}; flags={args.pack_arg or 'defaults'}")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    try:
        with tempfile.TemporaryDirectory(prefix="pe-mew-") as temporary:
            work_root = Path(temporary).resolve()
            require(work_root.parent == Path(tempfile.gettempdir()).resolve(), "Unexpected temp root.")
            tool = work_root / filename
            tool.write_bytes(tool_bytes)
            for arch in dict.fromkeys(args.arch or ("x86", "amd64")):
                for kind in dict.fromkeys(args.kind or ("exe", "dll")):
                    work = work_root / f"{arch}-{kind}"
                    work.mkdir()
                    try:
                        generate_case(args, tool, output, work, pe, wait, gui, arch, kind)
                    except (ValueError, OSError, subprocess.TimeoutExpired, StopIteration) as error:
                        failures += 1
                        print(f"{arch}/{kind}: FAIL: {error}", file=sys.stderr)
            require(tool.read_bytes() == tool_bytes, "Temporary packer changed during execution.")
    finally:
        require(source_tool.read_bytes() == tool_bytes, "Stored packer was modified.")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
