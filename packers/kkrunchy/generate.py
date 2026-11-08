"""Generate and verify kkrunchy fixtures from the shared originals.

Acquisition and building
------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
Official downloads (extract only the executable, without installation):
  0.23alpha: https://www.farbrausch.de/~fg/kkrunchy/kkrunchy_023a.zip
  0.23alpha2: https://www.farbrausch.de/~fg/kkrunchy/kkrunchy_023a2.zip
  0.23a4-asm07: https://www.farbrausch.de/~fg/kkrunchy/test/kkrunchy_023a4_asm07.exe
Place the original binary in tools/<version>/bin/ using RELEASES below.
No bundled dependency, distribution archive or source copy is needed.

Sources: https://github.com/farbrausch/fr_public
The kkrunchy/ and kkrunchy_k7/ HOW_TO_BUILD.txt files describe Visual C++ 2010
with YASM and NASM respectively. K7 requires NASM's RDF support; YASM is not a
replacement. Source builds were not used or verified for these binary profiles.

Examples from the collection root
---------------------------------
  python packers/kkrunchy/generate.py --version 0.23alpha
  python packers/kkrunchy/generate.py --version 0.23alpha2
  python packers/kkrunchy/generate.py --version 0.23a4-asm07
  python packers/kkrunchy/generate.py --version 0.23a4-asm07 --verify-only
  python packers/kkrunchy/generate.py --version 0.23a4-asm07 --output C:/Temp/kkrunchy-new

Default packing command in a temporary case directory:
  <tool.exe> --out packed.exe original.exe
0.23alpha defaults to --good; the later engines ignore --good/--best.
--refsize is a reporting target, not a compression setting. There is no native
file-unpacking option. No symbols or auxiliary map files are supplied.

The default-no-aslr profile packs an UNMODIFIED temporary input, then clears
only IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x40) in the output. kkrunchy copies
that flag but uses absolute loader addresses and omits base relocations. Raw
outputs crashed under ASLR on the tested host. DEP and every other output byte
are preserved. To reproduce the raw failure, run the command above on a copy
and execute packed.exe before applying without_aslr(). Shared inputs never change.

Matrix and verification
-----------------------
Generation attempts x86 EXE and DLL. DLL exports trigger an explicit error,
with exit zero and no output. AMD64 is unsupported and skipped by default:
--probe-unsupported also submits both PE32+ inputs in isolated jobs. Depending
on version/input the parser crashes, asserts or fails its inverse filter; this
is NOT a clean format rejection. Only the observed diagnostic classes with no
output are accepted. Timeouts and unexpected output remain failures.

Input hashes and full markers must match manifests. Only passing x86 EXEs are
published. Verify normal stdout, exit zero, empty stderr, --wait readiness and
liveness, and exact secret bytes in memory. Memory addresses are the ORIGINAL
preferred image base plus original marker RVA, not the packed module base:
kkrunchy lowers its base but restores code/data at their original addresses.
All child processes use a one-process Windows job and bounded cleanup.

--verify-only checks retained files without repacking or probing unsupported
inputs. Existing identical output is accepted; a different output is refused.
Only packed PEs are retained; temporary inputs, raw outputs and checks stay
outside the collection and are removed. Results go to stdout; exit 1 is failure.
"""
import argparse
import ctypes
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
import time

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
RELEASES = {
    "0.23alpha": ("kkrunchy.exe", "0.23 alpha",
        "70b8af13448406bebbd3639d64e161752aca325fc57a353bf31edd76af5f7b1b"),
    "0.23alpha2": ("kkrunchy_k7.exe", "0.23 alpha 2",
        "4863ce4a96b3a9ebd0b2928eeaf3aed3cf107531ff0be08604dfb2a6a69c06db"),
    "0.23a4-asm07": ("kkrunchy_023a4_asm07.exe", "0.23a4/asm07",
        "d4f6a13344d81c3e7c0d840f2f3ba100e677854b058dd5e920e954e2ebceb7b9"),
}


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ISOLATED = load("fixture_process", "fixtures/scripts/isolated_process.py")
WAIT = load("fixture_wait", "fixtures/scripts/check_wait.py")
PE = load("fixture_pe", "fixtures/scripts/manifest.py")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, cwd, timeout=30):
    return ISOLATED.run([str(x) for x in command], cwd=cwd, timeout=timeout,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)


def without_aslr(raw):
    require(raw[:2] == b"MZ", "Missing MZ header")
    nt = struct.unpack_from("<I", raw, 0x3c)[0]
    require(raw[nt:nt + 4] == b"PE\0\0" and
            struct.unpack_from("<H", raw, nt + 24)[0] == 0x10b, "Expected PE32")
    offset = nt + 24 + 70
    flags = struct.unpack_from("<H", raw, offset)[0]
    require(flags & 0x40, "Raw output lacks the expected DYNAMIC_BASE flag")
    fixed = bytearray(raw)
    struct.pack_into("<H", fixed, offset, flags & ~0x40)
    return bytes(fixed)


def check_normal(path):
    result = run([path], path.parent, 10)
    require(result.returncode == 0 and result.stdout == b"pe-fixture:basic-exe:ok\n"
            and not result.stderr,
            f"Runtime failed: exit={result.returncode:#x}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def check_memory(path, ref):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    read = kernel.ReadProcessMemory
    read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    read.restype = ctypes.c_int
    expected_line = b"pe-fixture:basic-exe:ok\n"
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        with ISOLATED.running([str(path), "--wait"], cwd=path.parent,
                              stdin=subprocess.DEVNULL, stdout=output,
                              stderr=errors) as process:
            deadline = time.monotonic() + 10
            while os.fstat(output.fileno()).st_size < len(expected_line):
                require(process.poll() is None, "Memory probe exited before readiness")
                require(time.monotonic() < deadline, "Memory probe readiness timeout")
                time.sleep(0.02)
            output.seek(0)
            require(output.read() == expected_line, "Unexpected memory-probe stdout")
            original_base = int(ref["pe"]["image_base"], 16)
            for marker in ref["secrets"]:
                expected = bytes.fromhex(marker["hex"])
                buffer = ctypes.create_string_buffer(len(expected))
                count = ctypes.c_size_t()
                require(read(int(process._handle), original_base + marker["rva"],
                             buffer, len(expected), ctypes.byref(count)),
                        f"ReadProcessMemory failed: {ctypes.get_last_error()}")
                require(count.value == len(expected) and buffer.raw == expected,
                        f"Recovered secret differs: {marker['id']}")
            require(process.poll() is None, "Memory probe exited unexpectedly")
            process.kill()
            process.wait(timeout=5)
        output.seek(0)
        errors.seek(0)
        require(output.read() == expected_line and not errors.read(),
                "Unexpected memory-probe output")


def verify(path, ref):
    data = path.read_bytes()
    info = PE.inspect_pe(path)
    for field in ("machine", "optional_header", "kind", "exports"):
        require(info[field] == ref["pe"][field], f"Packed PE differs in {field}")
    require(not info["dynamic_base"] and info["nx_compatible"], "Unexpected ASLR/DEP flags")
    require(not any(info[field] for field in ("relocations_size", "tls_size", "clr_size")),
            "Unexpected packed data directories")
    require([s["name"] for s in info["sections"]] == ["kkrunchy"], "Unexpected sections")
    check_normal(path)
    WAIT.check_fixture(path, "x86", "exe")
    check_memory(path, ref)
    visible = [m["id"] for m in ref["secrets"] if bytes.fromhex(m["hex"]) in data]
    require(not visible, f"Full markers unexpectedly visible on disk: {visible}")
    require(path.read_bytes() == data, "Runtime modified the packed file")
    print(f"x86/exe: PASS; {len(data)} bytes; wait and exact memory secrets pass; "
          "full disk markers=none; ASLR=off, DEP=on")


def generate(args, tool, banner, output, work, arch, kind, source, ref):
    data = source.read_bytes()
    if arch == "amd64" and (not args.probe_unsupported or args.verify_only):
        print(f"{arch}/{kind}: UNSUPPORTED (PE32+; parser probe skipped)")
        return
    if args.verify_only:
        if kind == "exe":
            verify(output / "fixture-x86-exe/default-no-aslr.exe", ref)
        else:
            print("x86/dll: UNSUPPORTED (exports; rejection probe skipped)")
        return
    original = work / f"original.{kind}"
    original.write_bytes(data)
    if arch == "x86" and kind == "exe":
        check_normal(original)
    packed = work / f"packed.{kind}"
    result = run([tool, "--out", packed.name, original.name], work)
    text = result.stdout.decode("cp1252", errors="replace")
    require(text.startswith(f"kkrunchy {banner} >>"), "Unexpected packer banner")
    require(not result.stderr, f"Unexpected packer stderr: {result.stderr!r}")
    require(original.read_bytes() == data, "Packer modified temporary input")
    if arch == "amd64":
        observed = (result.returncode & 0xffffffff) == 0xc0000005 or any(
            error in text for error in ("fatal error:", "(internal) unfilter failed"))
        require(observed and not packed.exists(), f"Unexpected PE32+ result: {text}")
        detail = "access violation" if result.returncode else "parser/filter error"
        print(f"{arch}/{kind}: UNSUPPORTED; observed {detail}, no output")
        return
    if kind == "dll":
        require(result.returncode == 0 and not packed.exists() and
                "ERROR: files with exports or tls data are not supported" in text,
                f"Unexpected DLL rejection: {text}")
        print("x86/dll: UNSUPPORTED; explicit exports/TLS rejection, exit 0, no output")
        return
    require(result.returncode == 0 and packed.is_file() and "ERROR:" not in text,
            f"Packing failed: exit={result.returncode:#x}, {text}")
    fixed = work / "default-no-aslr.exe"
    fixed.write_bytes(without_aslr(packed.read_bytes()))
    verify(fixed, ref)
    destination = output / "fixture-x86-exe" / fixed.name
    require(not destination.exists() or destination.read_bytes() == fixed.read_bytes(),
            f"Refusing to overwrite different output: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        with destination.open("xb") as stream:
            stream.write(fixed.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, choices=RELEASES)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--probe-unsupported", action="store_true")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required")
    name, banner, expected_hash = RELEASES[args.version]
    tool = PACKER / "tools" / args.version / "bin" / name
    require(digest(tool.read_bytes()) == expected_hash, "Unexpected packer binary")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    print(f"kkrunchy {banner}; default-no-aslr; {platform.platform()}")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-kkrunchy-generate-") as temporary:
        for arch in ("x86", "amd64"):
            manifest = ROOT / "fixtures/bin" / arch / "manifest.json"
            records = json.loads(manifest.read_text(encoding="utf-8"))["artifacts"]
            for kind in ("exe", "dll"):
                ref = next(a for a in records if a["id"] == f"basic-{kind}-{arch}")
                source = manifest.parent / ref["path"]
                require(digest(source.read_bytes()) == ref["sha256"], "Shared input hash mismatch")
                require(all(bytes.fromhex(m["hex"]) in source.read_bytes() for m in ref["secrets"]),
                        "Shared input marker missing")
                work = Path(temporary) / f"{arch}-{kind}"
                work.mkdir()
                try:
                    generate(args, tool, banner, output, work, arch, kind, source, ref)
                except (ValueError, OSError, subprocess.TimeoutExpired, struct.error) as error:
                    failures += 1
                    print(f"{arch}/{kind}: FAIL: {error}", file=sys.stderr)
                finally:
                    require(digest(source.read_bytes()) == ref["sha256"], "Shared input was modified")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
