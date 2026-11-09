"""Generate Yoda's Protector minimal profiles (Windows/Python standard library).

Public releases:
https://downloads.sourceforge.net/project/yodap/Yoda%20Protector/1.03/yP1.03.zip
https://downloads.sourceforge.net/project/yodap/Yoda%20Protector/1.03/yP1.03.3.zip
Extract yP.exe into tools/1.03.2/bin or tools/1.03.3/bin respectively. The first
archive actually contains GUI/version-resource 1.03.2. Neither needs installation.
Public 1.02 sources (yP1.02src.zip in the project's 1.02 folder) contain Visual C++
projects, inline assembly, LZO and aPLib dependencies. They were read, not built;
they are not claimed to reproduce these 1.03 binaries.

  python packers/yodas-protector/generate.py --version 1.03.2
  python packers/yodas-protector/generate.py --version 1.03.3
  python packers/yodas-protector/generate.py --version 1.03.3 --verify-only

Use --output <fresh-directory> for regeneration; polymorphic bytes vary and the
helper refuses to overwrite an existing case. Clear DYNAMIC_BASE, NO_SEH and
NX_COMPAT (0x540) on a temporary x86 input; select compression level 10, .yP loader
section and all thirteen option boxes off. Accept the known section-name warning
caused by .secret. GUI settings are restored. Packed outputs are not patched.

--probe-failed repeats x86 DLL and amd64 EXE/DLL attempts without saving outputs.
DLL runtime is checked inside a one-process job before any static export parsing:
its export data is encrypted. PE32+ attempts are never executed. GUI crashes,
timeouts and explicit rejections are reported separately, not counted as success.
Only x86 EXE is retained. Its normal/wait execution and all runtime checksums must
pass; complete marker visibility on disk is reported separately.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location("protector_checks", ROOT / "tools/fixture_checks.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
HASHES = {
    "1.03.2": "a48ae6f9abd8e767b5fa25727959b9fd7cf1ef601c520e0bf0e0e4544479cc89",
    "1.03.3": "8cfd5f5c0bec0d0d3e7d141f386b13a3cb9e1d4ca9bc07ea30663698a38df0eb",
}


def prepare(data):
    result = bytearray(data)
    nt = struct.unpack_from("<I", result, 0x3C)[0]
    flags = struct.unpack_from("<H", result, nt + 94)[0]
    CHECK.require(flags & 0x540 == 0x540, "Unexpected original compatibility flags")
    struct.pack_into("<H", result, nt + 94, flags & ~0x540)
    return bytes(result)


def generate(tool, version, output, arch, kind, failed):
    source, ref = CHECK.reference(arch, kind)
    target = output / f"fixture-{arch}-{kind}" / f"minimal-compatible.{kind}"
    CHECK.require(failed or not target.exists(), "Use --verify-only or a fresh --output directory")
    try:
        with tempfile.TemporaryDirectory(prefix="pe-yodap-generate-") as temp:
            sample = Path(temp) / f"sample.{kind}"
            before = prepare(source.read_bytes()) if arch == "x86" else source.read_bytes()
            sample.write_bytes(before)
            try:
                worker = CHECK.run([sys.executable, PACKER / "gui.py", tool, version, sample],
                                   sample.parent, timeout=60, max_processes=2)
                CHECK.require(worker.returncode == 0, f"GUI worker failed: {worker.stderr!r}")
                result = json.loads(worker.stdout)
                if "error" in result:
                    raise RuntimeError(result["error"])
                title, message = result["title"], result["message"]
                CHECK.require("File protected successfully" in message,
                              f"GUI result: {title}: {message}")
                CHECK.require(sample.read_bytes() != before, "Protector did not change input")
                if arch == "amd64":
                    print(f"{arch}/{kind}: unexpected packed output; not executed or saved", flush=True)
                    return
                if kind == "dll":
                    CHECK.normal(sample, arch, kind)
                    CHECK.WAIT.check_fixture(sample, arch, kind)
                else:
                    CHECK.verify(sample, arch, kind)
            except (ValueError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as error:
                if not failed:
                    raise
                print(f"Failed-profile probe {arch}/{kind}: {error}", flush=True)
                return
            CHECK.require(not failed, "Previously failed profile passes; review before publishing")
            CHECK.publish(sample.read_bytes(), target)
    finally:
        CHECK.require(CHECK.sha256(source) == ref["sha256"], "Shared input changed")
        CHECK.require(CHECK.sha256(tool) == HASHES[version], "Packer binary changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", choices=HASHES, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--probe-failed", action="store_true")
    args = parser.parse_args()
    tool = PACKER / "tools" / args.version / "bin/yP.exe"
    CHECK.require(CHECK.sha256(tool) == HASHES[args.version], "Unexpected Protector binary")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    if args.verify_only:
        CHECK.verify(output / "fixture-x86-exe/minimal-compatible.exe", "x86", "exe")
        return
    generate(tool, args.version, output, "x86", "exe", False)
    if args.probe_failed:
        for arch, kind in (("x86", "dll"), ("amd64", "exe"), ("amd64", "dll")):
            generate(tool, args.version, output, arch, kind, True)


if __name__ == "__main__":
    main()
