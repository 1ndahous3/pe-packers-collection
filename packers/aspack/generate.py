"""Generate and verify ASPack fixtures with the retained public builds.

Requirements and acquisition
----------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
2.43: http://www.aspack.com/files/aspack.zip (vendor download).
Extract setup.exe from the ZIP, then extract the Inno Setup installer:
  innoextract -e -d extracted setup.exe
innoextract: https://constexpr.org/innoextract/
Copy ASPack.exe, aspack.dll, pcnsl.exe and English.ini from
extracted/app into tools/2.43/bin/. The retained EXE reports file version
2.43.1.26; the installer signature verified as OOO PROTEKSHEN TEKHNOLODZHI.

2.12: https://ftp.ntu.edu.tw/pub/cpatch/a/aspack/source/aspack212.zip
The original vendor URL no longer serves this release. The NTU mirror has the
English public distribution. Its Gentee
setup is not supported by innoextract. Install into a disposable directory,
copy ASPack.exe and English.ini into tools/2.12/bin/, then uninstall that
temporary installation. No packer build sources are supplied by either package.
English.ini is a runtime language resource. Other language files, manuals,
installers and extraction utilities are not needed in bin/.

Examples (from the collection root)
-----------------------------------
  python packers/aspack/generate.py --version 2.43 --output C:/Temp/aspack-2.43
  python packers/aspack/generate.py --version 2.12 --output C:/Temp/aspack-2.12
  python packers/aspack/generate.py --version 2.12 --arch x86 --kind exe --keep-nx --output C:/Temp/aspack-nx-check

Without --output, the destination is packed-fixtures/<version> for initial
population. Different existing output is never overwritten. Add new builds to
TOOLS after reviewing identity, dependencies, options and GUI behavior.

Building and packing
--------------------
ASPack consumes temporary inputs; shared fixtures are never modified. Command:
  ASPack.exe input.exe /Opacked.exe /R+ /D+ /E+ /B-
Substitute .dll for DLLs. Resource compression and Windows import-DLL loading
are enabled, overlays preserved, backups disabled. Normal compression and
uncompressed exports remain at the public build's defaults. Maximum compression
and export-compression profiles are outside these cases.

2.12 clears only NX_COMPAT in temporary x86 inputs. With --keep-nx the original
EXE fails with a DEP execute violation; the DLL fails its rundll32 check. 2.43
uses unmodified inputs. NO_SEH and ASLR are not changed during preparation.

The tool and its dependencies are copied into each temporary case directory.
gui.py handles the built-in Trial period prompt and closes the GUI on completion;
/S alone does not make these public builds reliably unattended. An expired or
otherwise unavailable trial is a tool-start failure, not unsupported PE input.
The helper selects the enabled Trial period button through the vendor dialog.

Verification
------------
The default matrix attempts x86/amd64 x EXE/DLL. Both versions target PE32.
PE32+ rejection is recognized only for the recorded version, exact diagnostic,
unchanged input and no output: 2.43 says only 32-bit executables are supported;
2.12 says Unknown error. Other errors are failures, not unsupported cases.

Check shared hashes against manifests and run original, prepared and packed
files. Require exact success output, exit zero and no stderr. DLLs use matching
rundll32 and RunFixture. All four runtime secret checksums are covered; full
marker visibility in packed bytes is reported separately. Architecture, kind
and export names/ordinals must survive. Flags, sections and relocations are
observations. There is no native disk decompressor; third-party unpacking and
forced relocation are untested.

Only passing packed PEs are retained. Temporary copies and failures are removed.
Packing waits up to 40 seconds; fixture execution up to 30. Cleanup affects only
owned processes. Exit 1 means a failed case, exit 2 an argument error; a failure
does not suppress the remaining matrix cases.

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
import shutil
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
PACK_ARGS = ["/R+", "/D+", "/E+", "/B-"]
TOOLS = {
    "2.12": ("109252cb8d6a6d07621a4bb9702994d6157b53d42f9cfac413b2d41b1475b5dd",
             ["ASPack.exe", "English.ini"]),
    "2.43": ("163b27f2b77834bcd5c83ac4c6cc7d8545bf940afaf656bdd03265729fed7692",
             ["ASPack.exe", "English.ini", "aspack.dll", "pcnsl.exe"]),
}
REJECTIONS = {"2.12": "ERROR: Unknown error !",
              "2.43": "ASPack: Only 32-bit Windows Executables are supported."}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, cwd):
    return subprocess.run([str(x) for x in command], cwd=cwd,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=30)


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
            result.stdout == f"pe-fixture:basic-{kind}:ok\n" and not result.stderr,
            f"{path.name}: runtime check failed: exit={result.returncode:#x}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


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

        prepared = work / f"prepared.{kind}"
        prepared_bytes = original_bytes
        if args.version == "2.12" and arch == "x86" and not args.keep_nx:
            prepared_bytes = clear_nx(original_bytes)
            print(f"{arch}/{kind}: cleared NX_COMPAT in temporary input; NO_SEH/ASLR unchanged.")
        prepared.write_bytes(prepared_bytes)
        if prepared_bytes != original_bytes:
            check_execution(prepared, arch, kind)
        local_tool = work / "tool"
        local_tool.mkdir()
        for name in TOOLS[args.version][1]:
            shutil.copyfile(tool.parent / name, local_tool / name)
        spec = importlib.util.spec_from_file_location("aspack_gui", PACKER / "gui.py")
        gui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gui)
        packed = work / f"packed.{kind}"
        try:
            gui.pack(local_tool / tool.name, prepared, packed, args.version, PACK_ARGS)
        except ValueError as error:
            if (arch == "amd64" and str(error) == REJECTIONS[args.version]
                    and not packed.exists() and prepared.read_bytes() == prepared_bytes):
                print(f"{arch}/{kind}: UNSUPPORTED (PE32+ rejected: {error}; no output)")
                return
            raise
        require(prepared.read_bytes() == prepared_bytes, "Packer modified the prepared input.")
        require(packed.is_file(), "Packing produced no output.")
        packed_bytes = packed.read_bytes()
        require(packed_bytes != prepared_bytes, "Packer did not change the input.")
        packed_pe = pe.inspect_pe(packed)
        for field in ("machine", "optional_header", "kind", "exports"):
            require(packed_pe[field] == original_pe[field], f"Packed PE differs in {field}.")
        check_execution(packed, arch, kind)
        WAIT_CHECK.check_fixture(packed, arch, kind)
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


def clear_nx(data):
    prepared = bytearray(data)
    offset = struct.unpack_from("<I", data, 60)[0]
    require(data[offset:offset + 4] == b"PE\0\0" and
            struct.unpack_from("<H", data, offset + 24)[0] == 0x10b,
            "NX preparation expects PE32.")
    position = offset + 24 + 70
    flags = struct.unpack_from("<H", data, position)[0]
    require(flags & 0x100, "Expected NX_COMPAT in the shared fixture.")
    struct.pack_into("<H", prepared, position, flags & ~0x100)
    return bytes(prepared)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, choices=tuple(TOOLS))
    parser.add_argument("--arch", choices=("x86", "amd64"), action="append",
                        help="Repeat to select architectures; default: both.")
    parser.add_argument("--output", type=Path, help="Alternate version output directory.")
    parser.add_argument("--kind", choices=("exe", "dll"), action="append",
                        help="Repeat to select kinds; default: both.")
    parser.add_argument("--keep-nx", action="store_true",
                        help="Reproduce 2.12 failures with unchanged x86 inputs.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    if args.keep_nx and args.version != "2.12":
        parser.error("--keep-nx applies only to 2.12.")
    tool = PACKER / "tools" / args.version / "bin/ASPack.exe"
    for name in TOOLS[args.version][1]:
        if not (tool.parent / name).is_file():
            parser.error(f"Missing dependency: {tool.parent / name}")
    if digest(tool) != TOOLS[args.version][0]:
        parser.error("ASPack.exe differs from the recorded public build.")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    spec = importlib.util.spec_from_file_location("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    print(f"ASPack {args.version}; {' '.join(PACK_ARGS)}; separate output")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-aspack-") as temporary:
        work_root = Path(temporary).resolve()
        require(work_root.parent == Path(tempfile.gettempdir()).resolve(),
                "Unexpected temporary directory location.")
        for arch in dict.fromkeys(args.arch or ("x86", "amd64")):
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
