"""Generate and verify Petite fixtures using the selected console release.

2.2: download https://www.un4seen.com/petite/petite22.zip
Mirror: https://ftpmirror.infania.net/pub/pc/pack/petite22.zip
Extract only PETITE.EXE to tools/2.2/bin/petite.exe; both copies match the
retained console executable. No local distribution archive is needed.
Use --version 2.2 --arch x86 --kind exe to reproduce the raw-output runtime
failure. There is no verified 2.2 fixture profile; do not infer 2.4 compatibility.
--kind exe / --kind dll select one kind. Other options below describe 2.4.

Requirements and acquisition
----------------------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
Download https://www.un4seen.com/files/petite24.zip from
https://www.un4seen.com/petite/ and extract only petite.exe to
tools/2.4/bin/. No installation or extra dependencies are needed.
petite.txt in the public ZIP documents options, limitations and version history;
petgui.exe is the optional GUI. Neither is needed in bin/. The official package
supplies prebuilt executables, not buildable packer sources.

Examples (from the collection root)
-----------------------------------
  python packers/petite/generate.py --version 2.4 --output C:/Temp/petite-2.4
  python packers/petite/generate.py --version 2.4 --arch x86 --output C:/Temp/petite-x86

Use a fresh --output directory for each reproduction: the recorded profile
does not produce byte-identical files on every run. Without --output the
destination is packed-fixtures/<version>; this is for initial population.
Existing different artifacts are deliberately preserved and replacement fails.

Default command, run in a temporary case directory:
  petite.exe -9 -s0 -p0 -n original.exe -opacked.exe
Substitute .dll for DLLs. Level 9 is used with relocations retained (-s0);
progress is disabled (-p0), and overwriting is forbidden (-n). A separate
output (-o) disables Petite's backup mechanism. Import mangling, export
compression and the loader's integrity check retain their defaults.
Inputs are unmodified copies of the shared fixtures.

Repeated --pack-arg replaces -9 -s0; -p0, -n and the separate output are always
added. Use a fresh --output for any experiment. Disabling both import mangling
and integrity checking (-m0 -v0) did not pass this DLL's runtime check. Add another version's executable
under tools/<version>/bin/ and select --version to try it. Its banner must
match exactly; review behavior and options separately.

Verification and outputs
------------------------
The default matrix attempts x86/amd64 x EXE/DLL. In 2.4, PE32+ inputs produce
"Not an x86 executable" with EXIT CODE ZERO. This is classified as unsupported
only for the known version, with that exact diagnostic, no output and an
unchanged temporary original. No placeholder is saved. Any other failure is
reported as a failed case, and the remaining cases are still attempted.

Shared input hashes must match their manifests. Original and packed executions
must print the exact success line, exit zero and leave stderr empty. DLLs call
RunFixture through the matching rundll32. Execution verifies all four secret
checksums; complete marker visibility in packed bytes is reported separately.
PE architecture, EXE/DLL kind and export names/ordinals must survive; header
flags, relocation presence and sections are reported as observations.

Petite has no native decompressor. -d strips debug information; it does not
unpack. External unpackers and recovered files are outside this generator.

Only passing packed PEs are retained. Existing identical output is accepted;
different output is refused. Shared originals are checked for immutability,
temporary files are removed, and results go to stdout. Child processes have a
30-second timeout. Exit 1 means a failed case; exit 2 an argument error.

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
_PROCESS_SPEC = importlib.util.spec_from_file_location('fixture_process', ROOT/'fixtures/scripts/isolated_process.py')
ISOLATED = importlib.util.module_from_spec(_PROCESS_SPEC)
_PROCESS_SPEC.loader.exec_module(ISOLATED)
WAIT_SPEC = importlib.util.spec_from_file_location(
    "fixture_wait", ROOT / "fixtures/scripts/check_wait.py")
WAIT_CHECK = importlib.util.module_from_spec(WAIT_SPEC)
WAIT_SPEC.loader.exec_module(WAIT_CHECK)
DEFAULT_ARGS = ["-9", "-s0"]


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
    result = ISOLATED.run([str(x) for x in command], cwd=path.parent, timeout=10,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace")
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
        flags = args.pack_arg if args.pack_arg is not None else DEFAULT_ARGS
        result = run([tool, *flags, "-p0", "-n", original.name,
                      "-o" + packed.name], work)
        text = result.stdout + result.stderr
        match = re.search(r"^Petite (\S+) - ", text)
        require(match is not None and match.group(1) == args.version,
                f"Packing banner does not match the selected version:\n{text}")
        # Petite returns zero even when it rejects an unsupported architecture.
        rejection = f"* Not an x86 executable : {original.name}"
        if (args.version == "2.4" and arch == "amd64" and result.returncode == 0
                and rejection in text.splitlines() and not packed.exists()
                and original.read_bytes() == original_bytes):
            print(f"{arch}/{kind}: UNSUPPORTED (explicit x86-only rejection; no output)")
            return
        require(result.returncode == 0, f"Packing failed:\n{text}")
        require(packed.is_file(), f"Packing produced no output:\n{text}")
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
    parser.add_argument("--kind", action="append", choices=("exe", "dll"))
    parser.add_argument("--output", type=Path, help="Alternate version output directory.")
    parser.add_argument("--pack-arg", action="append",
                        help="Repeat to replace -9 -s0; -p0 and -n are always added.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    if not re.fullmatch(r"[0-9][A-Za-z0-9_.-]*", args.version) or args.version.endswith("."):
        parser.error("Use a version label without path separators.")
    tool = PACKER / "tools" / args.version / "bin/petite.exe"
    if not tool.is_file():
        parser.error(f"Missing packer: {tool}")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    spec = importlib.util.spec_from_file_location("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    flags = args.pack_arg if args.pack_arg is not None else DEFAULT_ARGS
    print(f"Petite {args.version}; {' '.join(flags)} -p0 -n; separate output")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-petite-") as temporary:
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
