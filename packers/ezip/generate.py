"""Generate or verify the EZip 0.8 beta x86 EXE case on Windows."""
import argparse
from pathlib import Path
import shutil
import struct
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import fixture_checks as checks

VERSION = "0.8-beta"
CASE = Path(VERSION) / "fixture-x86-exe" / "packed.exe"


def verify(path):
    _, ref = checks.reference("x86", "exe")
    info = checks.PE.inspect_pe(path)
    sections = info["sections"]
    originals = ref["pe"]["sections"]
    checks.require([s["name"] for s in sections] ==
                   [s["name"] for s in originals] + [".text", ".rdata", ".data"],
                   "Unexpected EZip loader layout")
    checks.require(all(s["raw_size"] == 0 for s in sections[:len(originals)]),
                   "Original sections still have raw data")
    checks.require(not info["dynamic_base"] and info["nx_compatible"] == ref["pe"]["nx_compatible"],
                   "Unexpected packed EXE flags")
    checks.verify(path, "x86", "exe")


def generate(output):
    source, _ = checks.reference("x86", "exe")
    with tempfile.TemporaryDirectory(prefix="ezip-case-") as tmp:
        work = Path(tmp)
        tool = work / "ezip.exe"
        shutil.copyfile(HERE / "tools" / VERSION / "bin" / tool.name, tool)
        data = bytearray(source.read_bytes())
        flags_offset = struct.unpack_from("<I", data, 0x3c)[0] + 24 + 70
        flags = struct.unpack_from("<H", data, flags_offset)[0]
        struct.pack_into("<H", data, flags_offset, flags & ~0x40)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        prepared = work / "fixture.exe"
        prepared.write_bytes(data)
        checks.normal(prepared, "x86", "exe")
        checks.WAIT.check_fixture(prepared, "x86", "exe")

        packed = work / "packed.exe"
        result = checks.run([tool, prepared.name, packed.name], work, timeout=20)
        checks.require(result.returncode == 1 and b"EZIP version 0.8 (beta)" in result.stdout
                       and packed.is_file(), f"EZip returned {result.returncode}: {result.stdout!r}")
        verify(packed)
        checks.publish(packed.read_bytes(), output / CASE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="write verified cases under this directory")
    mode.add_argument("--verify-only", action="store_true", help="check the retained EXE")
    args = parser.parse_args()
    if args.verify_only:
        verify(HERE / "packed-fixtures" / CASE)
    else:
        generate(args.output)


if __name__ == "__main__":
    main()
