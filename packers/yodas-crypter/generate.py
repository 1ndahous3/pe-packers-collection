"""Generate the minimal Yoda's Crypter profiles (Windows/Python standard library).

Download yC1.2.zip or yC1.3.zip from the corresponding SourceForge project folder:
https://sourceforge.net/projects/yodap/files/Yoda%20Crypter/
Keep only yC.exe in tools/<version>/bin. 1.2 includes MASM sources and MAKE.BAT;
1.3 has a separate yC1.3src.zip with a Visual C++ 7.0 project. These sources were
read, not rebuilt. No installation is needed.

  python packers/yodas-crypter/generate.py --version 1.2
  python packers/yodas-crypter/generate.py --version 1.3
  python packers/yodas-crypter/generate.py --version 1.2 --verify-only

Use --output <fresh-directory> to regenerate: polymorphism changes output bytes,
so an existing artifact is never silently replaced. The GUI encrypts a temporary
copy in place. Before encryption, clear DYNAMIC_BASE and NO_SEH (0x440), keeping
DEP enabled. All six optional GUI protection boxes are cleared. The tools and
shared inputs stay unchanged; no post-encryption patch is applied.

--probe-failed also attempts 1.3 DLL and PE32+ cases, without saving their output.
PE32+ uses unchanged inputs and is not executed. Timeouts are reported as such,
not converted into a successful rejection. Default protection options were tried
separately and crash these inputs; they are not a retained profile.

Normal execution, wait by name/ordinal and all runtime secret checksums must pass.
For 1.2 DLL the on-disk export data is encrypted: check the PE header directly and
exercise RunFixture/WaitFixture/#4 at runtime, instead of asserting that a static
export parser can read it. Other exports and forced rebasing are not verified.
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
GUI = CHECK.load("crypter_gui_driver", "packers/yodas-crypter/gui.py")
HASHES = {
    "1.2": "a0f83c7f388bd5fafc112a1ce76eacce8313eefa07d2ba0c4e053d355ed7826b",
    "1.3": "337b92acf0dd3fac565b9a07ddef1bb07852b1c4a0dcaa0c4df5debd9d51c629",
}


def prepare(data):
    result = bytearray(data)
    nt = struct.unpack_from("<I", result, 0x3c)[0]
    offset = nt + 94
    flags = struct.unpack_from("<H", result, offset)[0]
    CHECK.require(flags & 0x440 == 0x440, "Unexpected original flags")
    struct.pack_into("<H", result, offset, flags & ~0x440)
    return bytes(result)


def verify(path, version, kind):
    if version != "1.2" or kind != "dll":
        return CHECK.verify(path, "x86", kind)
    _, ref = CHECK.reference("x86", kind)
    data = path.read_bytes()
    nt = struct.unpack_from("<I", data, 0x3c)[0]
    CHECK.require(data[nt:nt+4] == b"PE\0\0" and
                  struct.unpack_from("<H", data, nt+4)[0] == 0x14c and
                  struct.unpack_from("<H", data, nt+24)[0] == 0x10b and
                  struct.unpack_from("<H", data, nt+22)[0] & 0x2000,
                  "Expected x86 PE32 DLL")
    flags = struct.unpack_from("<H", data, nt+94)[0]
    CHECK.require(not flags & 0x440 and flags & 0x100, "Unexpected compatibility flags")
    CHECK.normal(path, "x86", kind)
    CHECK.WAIT.check_fixture(path, "x86", kind)
    CHECK.require(path.read_bytes() == data, "Runtime modified packed file")
    visible = [m["id"] for m in ref["secrets"] if bytes.fromhex(m["hex"]) in data]
    print(f"{path.name}: PASS normal/wait/secret checksums; full disk markers={visible}; "
          "exports checked through RunFixture/WaitFixture/#4, not statically", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", choices=HASHES, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--probe-failed", action="store_true")
    args = parser.parse_args()
    tool = PACKER / "tools" / args.version / "bin/yC.exe"
    CHECK.require(CHECK.sha256(tool) == HASHES[args.version], "Unexpected Crypter binary")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    for arch in ("x86", "amd64"):
        for kind in ("exe", "dll"):
            failed = arch == "amd64" or (args.version == "1.3" and kind == "dll")
            if failed and (not args.probe_failed or args.verify_only):
                continue
            source, ref = CHECK.reference(arch, kind)
            target = output / f"fixture-{arch}-{kind}" / f"minimal-compatible.{kind}"
            if args.verify_only:
                verify(target, args.version, kind)
                continue
            CHECK.require(failed or not target.exists(), "Use --verify-only or a fresh --output directory")
            with tempfile.TemporaryDirectory(prefix="pe-yodac-generate-") as temp:
                sample = Path(temp) / f"sample.{kind}"
                sample.write_bytes(prepare(source.read_bytes()) if arch == "x86" else source.read_bytes())
                before = sample.read_bytes()
                try:
                    title, message = GUI.pack(tool, args.version, sample)
                    CHECK.require("File encrypted successfully" in message, f"GUI result: {title}: {message}")
                    CHECK.require(sample.read_bytes() != before, "Crypter did not change input")
                    if arch == "amd64":
                        print(f"{arch}/{kind}: unexpected encrypted output; not executed or saved")
                    else:
                        verify(sample, args.version, kind)
                        if not failed:
                            CHECK.publish(sample.read_bytes(), target)
                        else:
                            raise ValueError("Previously failed profile now passes; review before publishing")
                except (ValueError, TimeoutError, subprocess.TimeoutExpired) as error:
                    if not failed:
                        raise
                    print(f"Failed-profile probe {arch}/{kind}: {error}", flush=True)
                finally:
                    CHECK.require(CHECK.sha256(source) == ref["sha256"], "Shared input changed")


if __name__ == "__main__":
    main()
