"""Generate and verify the NSPack 2.3 fixture matrix.

Acquisition and requirements
----------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only. Extract
nspack/nSpack.exe from https://ftp.icm.edu.pl/pub/winsite/winxp/pagemkr/nspack.zip
into tools/2.3/bin/. The distribution also contains nspack/nspack.chm (manual,
FAQ and history); neither the ZIP nor help is needed at runtime. FileVersion
is 2.3.0.0; its bundled help history ends at 2.2. No buildable source was found.
The original executable is pinned below. It and the shared inputs are unmodified.

Examples from the collection root
---------------------------------
  python packers/nspack/generate.py --version 2.3
  python packers/nspack/generate.py --version 2.3 --verify-only
  python packers/nspack/generate.py --version 2.3 --output C:/Temp/nspack-fresh
  python packers/nspack/generate.py --version 2.3 --arch x86 --kind dll --output C:/Temp/nspack-dll

Profile and manual reproduction
-------------------------------
Run nSpack.exe without arguments. In Settings enable Compress resources,
Strip relocations, Force compression, Generate least sections and Use Windows
DLL loader. Choose User defined section names with value nsp. Disable the other
packing options, Create backup copy, Save settings on exit, context-menu
integration and Auto run after loading. Return to File to apply the settings,
Open a disposable fixture copy, then Compress. gui.py automates these steps by
the launched PID, with a 30-second deadline and no persistent option changes.

The silent CLI is nSpack.exe <temporary-file>; it packs in place using
saved/default settings and returns zero even on rejection. The default full
matrix probes amd64 through this CLI and requires exit zero with unchanged
bytes: the pinned public build disables PE32+ packing. Its GUI says
"Unregistered version." and its FAQ explicitly lists that restriction. A
changed amd64 file is an unexpected result, not a verified packed fixture.
No registration changes, binary patches or source-header workarounds are used.

Verification
------------
Check shared input hashes and complete secret markers; run original and packed
copies with exact stdout, empty stderr and exit zero. Compare architecture,
PE kind and export names/ordinals, then check EXE --wait or DLL WaitFixture by
name and ordinal 4 with the shared checker. Runtime checksums cover all four
secrets; marker visibility is a separate static observation. No native disk
unpack command is documented in this distribution; external recovery is untested.

Only passing packed PEs are published. Repeated packing varies header and loader bytes;
byte-identical generation is not required or promised. Existing different
output is refused, never replaced. Use --verify-only for stored files, or a
fresh --output for another generation. Verification mode copies stored PEs to
a temporary directory before running them. Backups and temporary files are
removed. All subprocesses are bounded; failures do not suppress other cases.
A known amd64 rejection prints UNSUPPORTED and is not counted as a failed test.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
TOOLS = {"2.3": "bf8758c213db6f2c532ef8145fa8dbd81f9af61f78ff2eb74945daca49ca7e5e"}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, cwd):
    return subprocess.run([str(x) for x in command], cwd=cwd,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=30, startupinfo=GUI.startup_info())


def check_execution(path, arch, kind):
    if kind == "exe":
        command = [path]
    else:
        windows = Path(os.environ["WINDIR"])
        native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
        host = windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"
        command = [host, "./" + path.name + ",RunFixture"]
    result = run(command, path.parent)
    require(result.returncode == 0 and
            result.stdout == f"pe-fixture:basic-{kind}:ok\n".encode() and not result.stderr,
            f"Runtime check failed: exit={result.returncode:#x}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def case(args, tool, output, work, pe, wait, arch, kind):
    manifest_path = ROOT / "fixtures/bin" / arch / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ref = next(a for a in manifest["artifacts"] if a["id"] == f"basic-{kind}-{arch}")
    source = manifest_path.parent / ref["path"]
    require(digest(source) == ref["sha256"], "Original differs from the fixture manifest.")
    before = source.read_bytes()
    original = work / f"original.{kind}"
    packed = work / f"packed.{kind}"
    destination = output / f"fixture-{arch}-{kind}" / packed.name
    stored = None
    try:
        original.write_bytes(before)
        check_execution(original, arch, kind)
        original_pe = pe.inspect_pe(original)
        for marker in ref["secrets"]:
            require(bytes.fromhex(marker["hex"]) in before,
                    "Missing original secret: " + marker["id"])
        if arch == "amd64":
            if args.verify_only:
                require(not destination.exists(), "Unexpected stored amd64 artifact.")
                print(f"{arch}/{kind}: UNSUPPORTED by this public build; no stored fixture.")
                return
            packed.write_bytes(before)
            result = run([tool, packed], work)
            require(result.returncode == 0 and not result.stdout and not result.stderr
                    and packed.read_bytes() == before,
                    "Unexpected amd64 behavior; re-investigate before adding a fixture.")
            print(f"{arch}/{kind}: UNSUPPORTED; CLI exits zero and leaves input unchanged.")
            return
        if args.verify_only:
            stored = destination.read_bytes()
            packed.write_bytes(stored)
        else:
            packed.write_bytes(before)
            GUI.pack(tool, packed)
        data = packed.read_bytes()
        require(data != before, "NSPack did not change the input.")
        packed_pe = pe.inspect_pe(packed)
        for field in ("machine", "optional_header", "kind", "exports"):
            require(packed_pe[field] == original_pe[field], "Packed PE differs in " + field)
        require([s["name"] for s in packed_pe["sections"]] == ["nsp0", "nsp1"],
                "Unexpected section layout for the selected profile.")
        check_execution(packed, arch, kind)
        wait.check_fixture(packed, arch, kind)
        visible = [m["id"] for m in ref["secrets"] if bytes.fromhex(m["hex"]) in data]
        require(not visible, "Unexpected visible full secret markers: " + repr(visible))
        require(packed.read_bytes() == data, "Execution changed the packed copy.")
        if not args.verify_only:
            require(not destination.exists() or destination.read_bytes() == data,
                    f"Refusing different output: {destination}. Use --verify-only or a fresh --output.")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                with destination.open("xb") as stream:
                    stream.write(data)
        print(f"{arch}/{kind}: PASS; normal + wait + secrets; "
              f"full markers visible={visible}; bytes={len(before)}->{len(data)}")
        print(f"  DYNAMIC_BASE={packed_pe['dynamic_base']}; NX_COMPAT={packed_pe['nx_compatible']}; "
              f"relocation directory bytes={packed_pe['relocations_size']}")
    finally:
        require(digest(source) == ref["sha256"], "Shared original was modified.")
        require(original.read_bytes() == before, "Temporary original was modified.")
        if stored is not None:
            require(destination.read_bytes() == stored, "Stored artifact was modified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, choices=TOOLS)
    parser.add_argument("--arch", action="append", choices=("x86", "amd64"))
    parser.add_argument("--kind", action="append", choices=("exe", "dll"))
    parser.add_argument("--output", type=Path, help="Alternate version output directory.")
    parser.add_argument("--verify-only", action="store_true", help="Verify stored x86 files without repacking.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    tool = PACKER / "tools" / args.version / "bin/nSpack.exe"
    require(digest(tool) == TOOLS[args.version], "Unrecognized NSPack binary.")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    global GUI
    GUI = module("nspack_gui", PACKER / "gui.py")
    pe = module("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    wait = module("fixture_wait", ROOT / "fixtures/scripts/check_wait.py")
    print(f"NSPack {args.version}; explicit two-section profile; verify-only={args.verify_only}")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    try:
        with tempfile.TemporaryDirectory(prefix="pe-nspack-") as temporary:
            work_root = Path(temporary).resolve()
            require(work_root.parent == Path(tempfile.gettempdir()).resolve(), "Unexpected temporary root.")
            for arch in dict.fromkeys(args.arch or ("x86", "amd64")):
                for kind in dict.fromkeys(args.kind or ("exe", "dll")):
                    work = work_root / f"{arch}-{kind}"
                    work.mkdir()
                    try:
                        case(args, tool, output, work, pe, wait, arch, kind)
                    except (ValueError, OSError, subprocess.TimeoutExpired, StopIteration, KeyError) as error:
                        failures += 1
                        print(f"{arch}/{kind}: FAIL: {error}", file=sys.stderr)
    finally:
        require(digest(tool) == TOOLS[args.version], "NSPack executable was modified.")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
