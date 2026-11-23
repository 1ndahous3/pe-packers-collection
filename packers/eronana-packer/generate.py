"""Generate the Eronana First Release fixture or verify the retained EXE on Windows."""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import fixture_checks as checks

TOOL = HERE / "tools/0/bin/packer.exe"
CASE = Path("0/fixture-x86-exe/packed.exe")


def verify(path):
    info = checks.PE.inspect_pe(path)
    sections = info["sections"]
    checks.require(sections[-1]["name"] == ".packer" and sections[-1]["raw_size"] > 0
                   and all(section["raw_size"] == 0 for section in sections[:-1]),
                   "Expected the compressed fixture data in .packer")
    checks.require(info["relocations_size"] == 0, "Expected stripped relocations")
    checks.verify(path, "x86", "exe")


def generate(output):
    with tempfile.TemporaryDirectory(prefix="eronana-") as tmp:
        root = Path(tmp)
        for arch in ("x86", "amd64"):
            for kind in ("exe", "dll"):
                source, _ = checks.reference(arch, kind)
                work = root / f"{arch}-{kind}"
                work.mkdir()
                shutil.copyfile(source, work / source.name)
                result = checks.run([TOOL, source.name], work)
                if arch == "x86" and kind == "exe":
                    packed = work / "basic.packed.exe"
                    checks.require(result.returncode == 0 and packed.is_file(),
                                   f"Packing failed: {result.stdout!r} {result.stderr!r}")
                    verify(packed)
                else:
                    reason = b"not a valid 32-bit PE file" if arch == "amd64" else b"not a valid exe file"
                    checks.require(result.returncode == 1 and reason in result.stdout
                                   and not any(work.glob("*.packed.exe")),
                                   f"Unexpected result for {arch} {kind}: {result.stdout!r} {result.stderr!r}")
                    print(f"{arch} {kind}: rejected ({reason.decode()})")
        checks.publish((root / "x86-exe/basic.packed.exe").read_bytes(), output / CASE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="write verified cases under this directory")
    mode.add_argument("--verify-only", action="store_true", help="check the retained EXE")
    args = parser.parse_args()
    if args.verify_only:
        verify(HERE / "packed-fixtures" / CASE)
    else:
        generate(args.output)
