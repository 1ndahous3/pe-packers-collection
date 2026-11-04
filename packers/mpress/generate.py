"""Generate and verify MPRESS fixtures with a selected prebuilt Windows release.

Requirements and acquisition
----------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
Put mpress.exe in tools/<version>/bin/. No installation or dependencies are
needed for these two distributions. A buildable MPRESS source tree was not
found; the GitHub mirror contains the binary and vendor documentation.

0.92: extract mpress.exe from the preserved tools/0.92/mpress.092.zip:
  https://web.archive.org/web/20130324025912id_/http://www.matcode.com/mpress.092.zip
2.19: download mpress.exe from the pinned mirror:
  https://raw.githubusercontent.com/requaos/mPress/d743977fabb820bb292b6ec41e9c15afa6ec97c8/mpress.exe
The mirror executable was byte-compared with the vendor distribution:
  https://web.archive.org/web/20120806124233id_/http://www.matcode.com/mpress.219.zip
Both vendor ZIPs passed CRC checks and matched their Internet Archive capture
digests. The 2.19 archive is not retained because the public mirror is available.

Examples (from the collection root)
-----------------------------------
  python packers/mpress/generate.py --version 0.92
  python packers/mpress/generate.py --version 2.19
  python packers/mpress/generate.py --version 2.19 --arch amd64
  python packers/mpress/generate.py --version 2.19 --pack-arg=-m --output C:/Temp/mpress-lzmat

The default matrix is x86/amd64 x EXE/DLL. Packing uses:
  tools/<version>/bin/mpress.exe -i <temporary-copy>
-i accepts a compression result even when it grows. There is no backup flag:
the input is already a disposable copy. Repeat --pack-arg to add options,
for example -m (force LZMAT) on 2.19. Use a separate --output for other profiles.
Default codec selection in 2.19 produced the same files as -m for these small
fixtures; do not assume they exercise its LZMA decoder.

For another version, add its executable under tools/<version>/bin and pass
--version. The packing banner must match exactly. Review its options and
compatibility before interpreting results. mpress.exe -h lists supported formats.

Verification and outputs
------------------------
Verify each shared original against its manifest, then run a temporary original
and the packed file. Require the exact success line, exit zero and empty stderr.
DLLs call RunFixture through architecture-matching rundll32. These executions
exercise checksums of all four secrets. Full marker visibility is reported
separately; this does not test a third-party unpacker or prove byte-exact recovery.

PE architecture, EXE/DLL kind and export names/ordinals must survive. Header
flags, relocation directory presence and section names are observations, not
preservation requirements: MPRESS rewrites them. Standard relocation directories
are absent in the recorded outputs; runtime rebasing is not tested here.
There is no native disk decompression command (see the vendor FAQ).

Only passing packed PEs are saved. Shared originals are never modified;
temporary files are removed. Existing identical output is accepted; different
output is refused. Logs and recovered copies are not saved. All child processes
have a 30-second timeout. A failed case does not suppress the other cases;
exit 1 means a failure, exit 2 an argument error.

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
import re
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

        packed = work / f"packed.{kind}"
        packed.write_bytes(original_bytes)
        result = run([tool, "-i", *args.pack_arg, packed], tool.parent)
        text = result.stdout + result.stderr
        match = re.search(r"MPRESS v(\S+)", text)
        require(match is not None and match.group(1) == args.version,
                f"Packing banner does not match the selected version:\n{text}")
        require(result.returncode == 0, f"Packing failed:\n{text}")
        packed_bytes = packed.read_bytes()
        require(packed_bytes != original_bytes, "Packer did not change the input.")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, help="Version under tools/<version>/bin.")
    parser.add_argument("--arch", choices=("x86", "amd64"), action="append",
                        help="Repeat to select architectures; default: both.")
    parser.add_argument("--output", type=Path, help="Alternate version output directory.")
    parser.add_argument("--pack-arg", action="append", default=[],
                        help="Repeat to add options; -i is always included.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    if not re.fullmatch(r"[0-9][A-Za-z0-9_.-]*", args.version) or args.version.endswith("."):
        parser.error("Use a version label without path separators.")
    tool = PACKER / "tools" / args.version / "bin/mpress.exe"
    if not tool.is_file():
        parser.error(f"Missing packer: {tool}")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    spec = importlib.util.spec_from_file_location("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    print(f"MPRESS {args.version}; -i {' '.join(args.pack_arg)}")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-mpress-") as temporary:
        work_root = Path(temporary).resolve()
        require(work_root.parent == Path(tempfile.gettempdir()).resolve(),
                "Unexpected temporary directory location.")
        for arch in dict.fromkeys(args.arch or ("x86", "amd64")):
            for kind in ("exe", "dll"):
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
