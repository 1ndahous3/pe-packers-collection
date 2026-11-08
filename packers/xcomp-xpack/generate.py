"""Generate XComp/XPack profiles from unchanged shared fixtures.

Acquisition: download http://www.soft-lab.de/JoKo/XComp097.zip and XComp098.zip.
Keep the two console EXEs, plus Xlzma.dll and Xlzss.dll for 0.98, in the matching
tools/<version>/bin/. No installation, GUI, archived ZIP or local source copy is
needed. Buildable sources were not established; the author supplies binaries.

Python 3.8+, Windows x64 with WOW64; standard library only. From the root:
  python packers/xcomp-xpack/generate.py --version 0.97
  python packers/xcomp-xpack/generate.py --version 0.98
  python packers/xcomp-xpack/generate.py --version 0.98 --verify-only
Use a fresh --output directory for experiments. Different existing output is refused.

In a temporary directory, both console tools replace sample.exe/dll in place:
  XCompc.exe -b -lzss -re sample.exe
  XPackc.exe -b -lzss sample.dll
Repeat with -lzrw for 0.97 or -lzma for 0.98. Compression levels stay at default.
-b disables backups. -re RETAINS EXE relocations but would REMOVE DLL relocations,
so it is used only for EXEs. No -e export stripping, -t validation bypass or -p
no-packing mode is used. clear_aslr() then clears only output DYNAMIC_BASE: raw
ASLR runs reach restored code with unrelocated absolute application operands.
DEP and every other output byte remain unchanged.

Both versions/tools are tried on PE32+ inputs, which exit zero without changing
them. This is classified as unsupported only after verifying that no output was
created and the input is unchanged. XPack 0.98 LZMA DLL is a known failed profile:
its loader exhausts rundll32's stack. It is not retained; --probe-failed repeats
its bounded runtime attempt and intentionally fails if the callback does not run.
XComp LZMA DLL and both LZSS DLL profiles are retained when all checks pass.

Only packed PEs are saved. Shared hashes are checked before/after; PE identity,
exports, normal execution, wait by name/ordinal and secret checksums are required.
Full disk-marker visibility is printed. No native file-unpacking command exists.
"""
import argparse
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location("fixture_checks", ROOT / "tools/fixture_checks.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
HASHES = {'0.97': {'XCompc.exe': '5e33e701bc871198ef32e1598641e7704d7a1e74f022f924a17ee9e7ca302836', 'XPackc.exe': '1d90205303b1dc136e6c6a1a54aec4a0b0fccd3fd0e15a76ae8a35291e5b741b'}, '0.98': {'XCompc.exe': 'd9c0c33085c8efee6e181b4975ac8f722ea3293160d6fdbd8ed6c4ab53cdb3e9', 'XPackc.exe': 'cc838941079a12bd761353647ab45f9baccebac202bb47dd8a02826da10b1d33', 'Xlzma.dll': 'e55d903e8a9dbf267fdb5893c367c1870c96fced4a03d582a1ece19836ee324b', 'Xlzss.dll': '4cb25025e514cdbe3a9049acbb6f04e2215e2e10af1d1635439080d4a8b9d70d'}}


def clear_aslr(data):
    result = bytearray(data)
    nt = struct.unpack_from("<I", result, 0x3c)[0]
    CHECK.require(result[nt:nt+4] == b"PE\0\0", "Invalid PE")
    offset = nt + 24 + 70
    flags = struct.unpack_from("<H", result, offset)[0]
    CHECK.require(flags & 0x40, "Unexpected raw output flags")
    struct.pack_into("<H", result, offset, flags & ~0x40)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, choices=HASHES)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--probe-failed", action="store_true")
    args = parser.parse_args()
    bindir = PACKER / "tools" / args.version / "bin"
    for name, expected in HASHES[args.version].items():
        CHECK.require(CHECK.sha256(bindir/name) == expected, "Unexpected binary: " + name)
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    algorithms = ("lzss", "lzrw" if args.version == "0.97" else "lzma")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-xcomp-generate-") as temp:
        for arch in ("x86", "amd64"):
            for kind in ("exe", "dll"):
                source, ref = CHECK.reference(arch, kind)
                for toolname in ("XComp", "XPack"):
                    for algorithm in algorithms if arch == "x86" else algorithms[:1]:
                        failed_profile = args.version == "0.98" and toolname == "XPack" and algorithm == "lzma" and kind == "dll"
                        if failed_profile and not args.probe_failed:
                            print("XPack 0.98 LZMA DLL: known stack-overflow failure; skipped")
                            continue
                        if arch == "amd64" and args.verify_only:
                            continue
                        work = Path(temp)/f"{arch}-{kind}-{toolname}-{algorithm}"
                        work.mkdir()
                        name = f"{toolname.lower()}-{algorithm}-no-aslr.{kind}"
                        target = output / f"fixture-{arch}-{kind}" / name
                        try:
                            if args.verify_only:
                                CHECK.verify(target, arch, kind)
                                continue
                            sample = work/f"sample.{kind}"
                            sample.write_bytes(source.read_bytes())
                            flags = ["-b", "-"+algorithm] + (["-re"] if kind == "exe" else [])
                            result = CHECK.run([bindir/(toolname+"c.exe"), *flags, sample.name], work)
                            text = result.stdout.decode("cp1252", errors="replace")
                            CHECK.require(result.returncode == 0 and text.startswith(toolname+" "+args.version) and not result.stderr,
                                          f"Packer failed: {result.returncode}, {text}")
                            if arch == "amd64":
                                CHECK.require(sample.read_bytes() == source.read_bytes() and "Create outputfile" not in text and
                                              sorted(p.name for p in work.iterdir()) == [sample.name], "Unexpected PE32+ result")
                                print(f"{toolname} {arch}/{kind}: UNSUPPORTED; unchanged input, exit 0")
                                continue
                            CHECK.require(sample.read_bytes() != source.read_bytes() and "Create outputfile" in text, "No packed output")
                            final = work/name
                            final.write_bytes(clear_aslr(sample.read_bytes()))
                            CHECK.verify(final, arch, kind)
                            CHECK.publish(final.read_bytes(), target)
                        except (ValueError, OSError, subprocess.TimeoutExpired, struct.error) as error:
                            failures += 1
                            print(f"{arch}/{kind}/{toolname}/{algorithm}: FAIL: {error}", file=sys.stderr)
                        finally:
                            CHECK.require(CHECK.sha256(source) == ref["sha256"], "Shared input was modified")
    return int(failures != 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.exit(str(error))
