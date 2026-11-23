"""Pack the four shared fixtures with packerPE32 and check LZNT1 recovery on Windows."""
import argparse
import ctypes
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import fixture_checks as checks

BIN = HERE / "tools/0/bin"
CASE = Path("0/fixture-x86-exe/packed.exe")


def check_recovery(packed, source):
    info = checks.PE.inspect_pe(packed)
    checks.require((info["machine"], info["optional_header"], info["kind"]) == ("0x014c", "0x010b", "EXE"),
                   "Expected the x86 PE32 EXE wrapper")
    section, = (s for s in info["sections"] if s["name"] == ".pack3")
    offset = section["raw_offset"]
    size = section["virtual_size"]  # compressed length before file alignment
    data = packed.read_bytes()
    checks.require(0 < size <= section["raw_size"] and offset + size <= len(data), "Invalid .pack3 extent")
    original = source.read_bytes()
    restored = ctypes.create_string_buffer(len(original))
    written = ctypes.c_uint32()
    decompress = ctypes.windll.ntdll.RtlDecompressBuffer
    decompress.argtypes = (ctypes.c_uint16, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                           ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
    decompress.restype = ctypes.c_int32
    status = decompress(2, restored, len(original), data[offset:offset + size], size, ctypes.byref(written))
    checks.require(status == 0 and written.value == len(original) and restored.raw == original,
                   f"LZNT1 recovery differs from {source.name} (NTSTATUS {status:#x})")


def generate(output):
    with tempfile.TemporaryDirectory(prefix="packerpe32-") as tmp:
        root = Path(tmp)
        for arch in ("x86", "amd64"):
            for kind in ("exe", "dll"):
                source, _ = checks.reference(arch, kind)
                work = root / f"{arch}-{kind}"
                work.mkdir()
                shutil.copyfile(source, work / source.name)
                shutil.copyfile(BIN / "stub.exe", work / "stub.exe")
                result = checks.run([BIN / "builder.exe", "stub.exe", source.name], work)
                packed = work / "output.exe"
                checks.require(result.returncode == 0 and packed.is_file(),
                               f"Packing {arch} {kind} failed: {result}")
                check_recovery(packed, source)
                print(f"{arch} {kind}: byte-exact static recovery", flush=True)
                if arch == "x86" and kind == "exe":
                    checks.verify(packed, arch, kind)
        checks.publish((root / "x86-exe/output.exe").read_bytes(), output / CASE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path, help="generate the matrix and save the verified x86 EXE")
    group.add_argument("--verify-only", action="store_true", help="verify the retained x86 EXE")
    args = parser.parse_args()
    if args.verify_only:
        packed = HERE / "packed-fixtures" / CASE
        source, _ = checks.reference("x86", "exe")
        check_recovery(packed, source)
        checks.verify(packed, "x86", "exe")
    else:
        generate(args.output)
