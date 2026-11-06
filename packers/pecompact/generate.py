"""Generate and verify PECompact fixtures using a selected public distribution.

Additional SUN DVD releases (https://archive.org/details/cracklb-2010):
tools/2.79-beta-d/PECompact 2.79d.rar and tools/3.00.2/PECompact 3.00.2.rar.
Extract the RAR, then its setup EXE with 7-Zip; retain the same four CLI/codec/
loader files as below. Do not substitute the bundled modified 2.79 GUI or the
optional 3.00.2 EAD loader for the tested tools. Select --version 2.79-beta-d or
--version 3.00.2. Both use the EXE-only NO_SEH preparation and reject PE64.
The beta CLI reports 2.79 beta d and needs an active evaluation period; 3.00.2
reports Retail build. --kind exe / --kind dll select one kind when needed.

Requirements
------------
Python 3.8+ on Windows x64 with WOW64; standard library only.
Paths are resolved from this script. Shared originals are checked against their
manifests and never modified. Each child process has a 30-second timeout.

Acquisition and building
------------------------
Preserved vendor distributions:
  tools/2.79/pec2student.zip (Student/Freeware):
  https://web.archive.org/web/20070815120309id_/http://www.bitsum.com/files/pec2student.zip
  tools/3.11.00.02/pec2setup.zip (original beta trial):
  https://web.archive.org/web/20140903090728id_/http://www.bitsum.com/files/beta/pec2setup.zip

Extract the ZIP and then pec2setup.exe with 7-Zip; running the installer is
unnecessary. 7-Zip 26.04 warns about the 3.11 installer PE headers, but tests
and extracts its embedded NSIS archive successfully; the outer ZIP CRC and
Internet Archive capture digest were verified.
For the recorded profile, copy PEC2.exe, pec2ldr_default.dll,
pec2codec_lzma2.dll and pec2codec_aplib.dll into tools/<version>/bin/.
The vendor archives retain the accompanying documentation; the Student archive
also includes plug-in SDK examples, not a buildable compressor source tree.

Examples (from the collection root)
-----------------------------------
  python packers/pecompact/generate.py --version 3.11.00.02
  python packers/pecompact/generate.py --version 2.79
  python packers/pecompact/generate.py --version 2.79 --check-no-seh
  python packers/pecompact/generate.py --version 2.79 --arch x86

The default command attempts x86/amd64 EXE/DLL. For 2.79 and 3.11.00.02, the
exact PE64 rejection with an unchanged input is unsupported, not a failure.
No placeholder or failed binary is saved.

The recorded profiles use LZMA2 for payloads, aPLib for the loader, compression level
9, the default loader and /Sf:No to retain fixups. /Nb is always added because
packing occurs in place on disposable copies. Other behavior uses tool defaults.
For 2.79's x86 EXE only, a temporary input copy has
IMAGE_DLLCHARACTERISTICS_NO_SEH cleared: this loader requires SEH. ASLR and NX
remain enabled. The DLL input is unchanged. In 3.11 both inputs are used
unchanged; the packer itself clears NO_SEH in its output.
--check-no-seh additionally packs the unmodified 2.79 EXE and requires the
observed access violation before verifying the prepared EXE.

Use --output PATH for a separate profile. Repeated --pack-arg=/OPTION replace
the profile arguments (except /Nb). --keep-no-seh disables EXE preparation and
is useful for diagnosing the original-input failure; it is not a passing
profile on the tested host. For a different public release, add its binaries
under tools/<version>/bin and specify that version; the console banner during
packing must match.
The input NO_SEH workaround applies to 2.79, 2.79 beta d and 3.00.2. Review a new release's
defaults separately.
PEC2.exe /? is interactive and requires a terminal; the generator never calls it.

Verification and outputs
------------------------
Originals, prepared inputs and packed files must print the exact fixture
success line, exit zero and leave stderr empty. DLLs invoke RunFixture through
the architecture-matching rundll32. Runtime fixture checks cover all four
secret checksums. Full marker visibility in packed bytes is printed separately;
it is an observation, not proof of complete recovery. PE kind, architecture,
export names/ordinals, ASLR/NX flags and relocation presence are also checked.

There is no native PE decompression check: PECompact has no counterpart to
UPX -d. External unpackers and memory dumps are outside this generator.

Only passing packed PEs are retained. Identical existing output is unchanged;
different output is refused. Results go to stdout. Temporary inputs and failed
variants are removed. Exit 1 means a failed case, exit 2 an argument error.

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
import struct
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
DEFAULT_ARGS = ["/Cl:9", "/Sf:No", "/Ch:pec2codec_lzma2.dll",
                "/Lh:pec2ldr_default.dll", "/Lch:pec2codec_aplib.dll"]
PE64_REJECTION = "PECompact can not yet compress PE+ (PE64) modules."
PE64_REJECTION_VERSIONS = {"2.79", "2.79-beta-d", "3.00.2", "3.11.00.02"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, cwd):
    return subprocess.run([str(x) for x in command], cwd=cwd,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=30)


def execution(path, arch, kind):
    if kind == "exe":
        command = [path]
    else:
        windows = Path(os.environ["WINDIR"])
        native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
        host = windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"
        command = [host, "./" + path.name + ",RunFixture"]
    return ISOLATED.run([str(x) for x in command], cwd=path.parent, timeout=10,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, encoding="utf-8", errors="replace")


def check_execution(path, arch, kind):
    result = execution(path, arch, kind)
    require(result.returncode == 0 and
            result.stdout == f"pe-fixture:basic-{kind}:ok\n" and not result.stderr,
            f"{path.name}: runtime check failed: exit={result.returncode:#x}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")


def clear_no_seh(data):
    prepared = bytearray(data)
    pe = struct.unpack_from("<I", prepared, 60)[0]
    require(prepared[pe:pe + 4] == b"PE\0\0" and
            struct.unpack_from("<H", prepared, pe + 24)[0] == 0x10b,
            "NO_SEH preparation expects a PE32 fixture.")
    pos = pe + 24 + 70
    flags = struct.unpack_from("<H", prepared, pos)[0]
    require(flags & 0x400, "Expected NO_SEH in the original x86 EXE.")
    struct.pack_into("<H", prepared, pos, flags & ~0x400)
    return bytes(prepared)


def pack(tool, path, version, flags):
    result = run([tool, path, "/Nb", *flags], tool.parent)
    text = result.stdout + result.stderr
    match = re.search(r"Version:\s+(\S+)", text)
    require(match is not None and match.group(1) == ("2.79" if version == "2.79-beta-d" else version),
            "Packing banner does not match the selected version.")
    if version == "2.79":
        require("Freeware version." in text, "Expected the preserved Freeware edition.")
    if version == "2.79-beta-d":
        require("Version: 2.79 beta d" in text and "Unregistered version." in text, "Unexpected beta d edition.")
    if version == "3.00.2":
        require("Retail build" in text, "Expected the DVD retail build.")
    return result, text


def generate_case(args, tool, flags, output, work, pe, arch, kind):
    manifest_path = ROOT / "fixtures/bin" / arch / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ref = next(a for a in manifest["artifacts"] if a["id"] == f"basic-{kind}-{arch}")
    source = manifest_path.parent / ref["path"]
    require(digest(source) == ref["sha256"], "Shared original differs from its manifest.")
    original_bytes = source.read_bytes()
    original = work / f"original.{kind}"
    original.write_bytes(original_bytes)
    check_execution(original, arch, kind)
    original_pe = pe.inspect_pe(original)
    for marker in ref["secrets"]:
        require(bytes.fromhex(marker["hex"]) in original_bytes,
                f"Original marker missing: {marker['id']}")
    try:
        prepare = (args.version in ("2.79", "2.79-beta-d", "3.00.2") and arch == "x86" and kind == "exe"
                   and not args.keep_no_seh)
        if args.check_no_seh and arch == "x86" and kind == "exe":
            raw = work / "unchanged-input.exe"
            raw.write_bytes(original_bytes)
            result, text = pack(tool, raw, args.version, flags)
            require(result.returncode == 0 and raw.read_bytes() != original_bytes,
                    f"NO_SEH experiment did not pack successfully:\n{text}")
            observed = execution(raw, arch, kind)
            require(observed.returncode & 0xffffffff == 0xc0000005 and
                    not observed.stdout and not observed.stderr,
                    "NO_SEH experiment did not reproduce the expected access violation.")
            print("x86/exe: unmodified NO_SEH input reproduces access violation.")

        packed = work / f"packed.{kind}"
        prepared_bytes = clear_no_seh(original_bytes) if prepare else original_bytes
        packed.write_bytes(prepared_bytes)
        if prepare:
            check_execution(packed, arch, kind)
            print("x86/exe: cleared NO_SEH in the temporary input; ASLR/NX unchanged.")
        result, text = pack(tool, packed, args.version, flags)
        if (args.version in PE64_REJECTION_VERSIONS and arch == "amd64" and result.returncode == 1
                and PE64_REJECTION in text and packed.read_bytes() == prepared_bytes):
            print(f"{arch}/{kind}: UNSUPPORTED (explicit PE64 rejection; input unchanged)")
            return
        require(result.returncode == 0, f"Packing failed:\n{text}")
        require(packed.read_bytes() != prepared_bytes, "Packer did not change the input.")
        check_execution(packed, arch, kind)
        WAIT_CHECK.check_fixture(packed, arch, kind)
        packed_pe = pe.inspect_pe(packed)
        for field in ("machine", "optional_header", "kind", "exports",
                      "dynamic_base", "nx_compatible"):
            require(packed_pe[field] == original_pe[field], f"Packed PE differs in {field}.")
        require(packed_pe["relocations_size"] > 0, "Packed PE has no relocations.")
        visible = [m["id"] for m in ref["secrets"]
                   if bytes.fromhex(m["hex"]) in packed.read_bytes()]
        # Verify immutability before publishing any artifact.
        require(digest(source) == ref["sha256"], "Shared original was modified.")
        require(original.read_bytes() == original_bytes, "Temporary original was modified.")
        destination = output / f"fixture-{arch}-{kind}" / packed.name
        require(not destination.exists() or destination.read_bytes() == packed.read_bytes(),
                f"Refusing to replace different output: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            # Exclusive creation also protects an artifact created concurrently.
            with destination.open("xb") as stream:
                stream.write(packed.read_bytes())
        print(f"{arch}/{kind}: PASS; full markers visible={visible}; "
              f"bytes={len(original_bytes)}->{packed.stat().st_size}")
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
                        help="Repeat to replace profile arguments; /Nb is always added.")
    parser.add_argument("--keep-no-seh", action="store_true",
                        help="Pack the unmodified EXE input (expected to fail runtime on 2.79).")
    parser.add_argument("--check-no-seh", action="store_true",
                        help="Also reproduce the 2.79 original EXE failure in temporary files.")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows is required.")
    if not re.fullmatch(r"[0-9][A-Za-z0-9_.-]*", args.version) or args.version.endswith("."):
        parser.error("Use a version label without path separators.")
    if args.check_no_seh and (args.version != "2.79" or args.keep_no_seh):
        parser.error("--check-no-seh requires the prepared 2.79 profile.")
    tool = PACKER / "tools" / args.version / "bin/PEC2.exe"
    if not tool.is_file():
        parser.error(f"Missing packer: {tool}")
    flags = args.pack_arg if args.pack_arg is not None else DEFAULT_ARGS
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    spec = importlib.util.spec_from_file_location("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    print(f"PECompact {args.version}; /Nb {' '.join(flags)}")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}")
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-pecompact-") as temporary:
        work_root = Path(temporary).resolve()
        require(work_root.parent == Path(tempfile.gettempdir()).resolve(),
                "Unexpected temporary directory location.")
        for arch in dict.fromkeys(args.arch or ("x86", "amd64")):
            for kind in dict.fromkeys(args.kind or ("exe", "dll")):
                work = work_root / f"{arch}-{kind}"
                work.mkdir()
                try:
                    generate_case(args, tool, flags, output, work, pe, arch, kind)
                except (ValueError, OSError, subprocess.TimeoutExpired, StopIteration) as error:
                    failures += 1
                    print(f"{arch}/{kind}: FAIL: {error}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
