"""Generate packed PE fixtures with a selected local UPX version.

Requirements and paths
----------------------
Python 3.8+ on Windows x64 with WOW64; no third-party modules.
Run the examples below from the collection root. Paths to shared originals,
manifests and tools are resolved relative to this script, not the working
directory. The tool is tools/<version>/bin/upx.exe; its --version must match.
Use --tool-sha256 HASH to check the selected executable against an expected
SHA-256 value when pinning a particular tool build.

Examples
--------
Modern full matrix:
  python packers/upx/generate.py --version 5.3.0

UPX 0.90, including native restoration and the section-name experiment:
  python packers/upx/generate.py --version 0.90 --arch x86 --pack-arg=-9 --check-section-names --inspect-restoration

UPX 0.82 or 0.83, whose PE test/decompression is unimplemented:
  python packers/upx/generate.py --version 0.83 --arch x86 --verification legacy-pe --check-header-loss

UPX 0.80 needs an explicit override for the modern x86 fixture headers:
  python packers/upx/generate.py --version 0.80 --arch x86 --verification legacy-pe --pack-arg=-9 --pack-arg=--force-compress --check-header-loss

Replace 0.83 with 0.82 for that release. Use --output PATH for a separate
packing profile. Repeat --pack-arg=VALUE to replace, rather than append to,
the default compression arguments.

Profiles and verification
-------------------------
Native mode defaults to -9 --strip-relocs=0 and requires original/packed/
restored execution, listing, integrity testing and decompression. It compares
restored machine, PE kind, entry point, exports and full secret values.
Legacy PE mode defaults to -9 and requires original/packed execution and
listing, plus the exact known "not yet implemented" failures for -t and -d.
It does not treat arbitrary unpacker failures as successful verification.
Early tools advertise a bare --strip-relocs flag; 0.90 uses explicit -9 to
avoid the modern default syntax. Force options are never added automatically.

The generator always adds --no-env --no-progress when packing. EXEs run
directly; DLLs invoke RunFixture through matching System32/SysWOW64 rundll32,
using Sysnative if needed from a WOW64 host and a DLL-relative argument.
Execution requires the exact fixture success line, exit 0 and empty stderr.
Each subprocess has a 30-second timeout.

--check-header-loss requires legacy mode and expects .probeA/.probeB
variants to yield identical packed bytes. --check-section-names requires
native mode and checks the opposite: distinct packed variants, followed by
restoration of their respective names. All variants must execute correctly.
--inspect-restoration prints detailed comparisons from tools/compare_pe.py,
including structural differences and incomplete relocation tails; these
observations do not impose byte-exact recovery as a success criterion.

Outputs and exit status
------------------------
Only passing packed PEs are saved to packed-fixtures/<version>/ by default.
Originals, decompressed files and experiment variants use a temporary
directory and are removed. Results and hashes go to stdout, not report files.
An identical existing output is left unchanged; a different one is refused.
Failed cases are not saved; remaining cases still run, and any failure gives
exit 1. Argument errors give exit 2. Shared originals/manifests are checked
against their recorded hashes and are never replaced.

Packed wait mode is required before publication: --wait for EXEs, WaitFixture
by name and ordinal 4 for DLLs. The shared fixtures/scripts/check_wait.py checks
the success line and continued execution, then terminates only its test process.
Native restored PEs must pass the same wait checks.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import struct
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
WAIT_SPEC = importlib.util.spec_from_file_location(
    "fixture_wait", ROOT / "fixtures/scripts/check_wait.py")
WAIT_CHECK = importlib.util.module_from_spec(WAIT_SPEC)
WAIT_SPEC.loader.exec_module(WAIT_CHECK)
DEFAULT_PACK_ARGS = ["-9", "--strip-relocs=0"]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, cwd, check=True):
    result = subprocess.run(command, cwd=cwd, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=30)
    if check and result.returncode:
        raise ValueError(f"{subprocess.list2cmdline([str(p) for p in command])}\n"
                         f"exit={result.returncode}\n{result.stdout}{result.stderr}")
    return result


def check_execution(path, arch, kind):
    if kind == "exe":
        command = [str(path)]
    else:
        windows = Path(os.environ["WINDIR"])
        native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
        host = windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"
        command = [str(host), "./" + path.name + ",RunFixture"]
    result = run(command, path.parent)
    if result.stdout != f"pe-fixture:basic-{kind}:ok\n" or result.stderr:
        raise ValueError(f"{path.name}: unexpected stdout/stderr")


def generate_case(upx, flags, output, work, pe, arch, kind, verification, header_loss,
                  section_names, comparison):
    fixture_id = f"basic-{kind}-{arch}"
    manifest_path = ROOT / "fixtures/bin" / arch / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    reference = next(a for a in manifest["artifacts"] if a["id"] == fixture_id)
    source = manifest_path.parent / reference["path"]
    if sha256(source) != reference["sha256"]:
        raise ValueError("Shared original differs from its manifest.")
    original, packed, restored = [work / f"{name}.{kind}"
                                  for name in ("original", "packed", "restored")]
    shutil.copyfile(source, original)
    check_execution(original, arch, kind)
    run([str(upx), "--no-env", "--no-progress", *flags,
         "-o", packed.name, original.name], work)
    run([str(upx), "--no-env", "-l", packed.name], work)
    check_execution(packed, arch, kind)
    WAIT_CHECK.check_fixture(packed, arch, kind)
    restored_bytes = None
    if verification == "legacy-pe":
        for option in ("-t", "-d"):
            command = [str(upx), "--no-env", option]
            if option == "-d":
                command += ["-o", restored.name]
            result = run(command + [packed.name], work, check=False)
            if result.returncode != 1 or "CantUnpackException: not yet implemented" not in result.stdout + result.stderr:
                raise ValueError(f"{option}: expected the documented legacy PE limitation, got "
                                 f"exit={result.returncode}: {result.stdout}{result.stderr}")
        if restored.exists():
            raise ValueError("Unexpected restored file in legacy PE mode.")
    else:
        run([str(upx), "--no-env", "-t", packed.name], work)
        run([str(upx), "--no-env", "--no-progress", "-d",
             "-o", restored.name, packed.name], work)
        check_execution(restored, arch, kind)
        WAIT_CHECK.check_fixture(restored, arch, kind)
        original_pe, restored_pe = pe.inspect_pe(original), pe.inspect_pe(restored)
        for field in ("machine", "optional_header", "kind", "entry_point_rva", "exports"):
            if original_pe[field] != restored_pe[field]:
                raise ValueError(f"Restored PE differs in {field}.")
        restored_bytes = restored.read_bytes()
    original_bytes, packed_bytes = original.read_bytes(), packed.read_bytes()
    visible = []
    for marker in reference["secrets"]:
        value = bytes.fromhex(marker["hex"])
        if value not in original_bytes or (restored_bytes is not None and value not in restored_bytes):
            raise ValueError(f"Marker {marker['id']} is missing.")
        if value in packed_bytes:
            visible.append(marker["id"])
    if sha256(original) != reference["sha256"] or sha256(source) != reference["sha256"]:
        raise ValueError("An original was modified.")

    if header_loss or section_names:
        # Change only the first section name in two temporary, runnable originals.
        pe_offset = struct.unpack_from("<I", original_bytes, 60)[0]
        section_offset = pe_offset + 24 + struct.unpack_from("<H", original_bytes, pe_offset + 20)[0]
        variants = []
        for label in ("A", "B"):
            variant_bytes = bytearray(original_bytes)
            variant_bytes[section_offset:section_offset + 8] = f".probe{label}\0".encode("ascii")
            variant = work / f"variant{label}.{kind}"
            variant.write_bytes(variant_bytes)
            check_execution(variant, arch, kind)
            target = work / f"variant{label}-packed.{kind}"
            run([str(upx), "--no-env", "--no-progress", *flags,
                 "-o", target.name, variant.name], work)
            check_execution(target, arch, kind)
            variants.append(target.read_bytes())
            if section_names:
                recovered = work / f"variant{label}-restored.{kind}"
                run([str(upx), "--no-env", "-t", target.name], work)
                run([str(upx), "--no-env", "-d", "-o", recovered.name, target.name], work)
                check_execution(recovered, arch, kind)
                if pe.inspect_pe(recovered)["sections"][0]["name"] != f".probe{label}":
                    raise ValueError("The original section name was not restored.")
        if header_loss:
            if variants[0] != variants[1] or variants[0] != packed_bytes:
                raise ValueError("Section-name loss experiment did not reproduce.")
            print(f"{fixture_id}: distinct section names at 0x{section_offset:x} "
                  "produce identical packed bytes; exact original headers are not recoverable.")
        else:
            if variants[0] == variants[1]:
                raise ValueError("Distinct restored section names have identical packed bytes.")
            print(f"{fixture_id}: .probeA/.probeB preserved after native decompression; "
                  "packed variants differ.")

    if comparison:
        details = comparison.compare(original_bytes, restored_bytes)
        details["secrets"] = []
        for marker in reference["secrets"]:
            value = bytes.fromhex(marker["hex"])
            position = restored_bytes.find(value)
            section = next(s for s in restored_pe["sections"]
                           if s["raw_offset"] <= position and
                           position + len(value) <= s["raw_offset"] + s["raw_size"])
            details["secrets"].append({
                "id": marker["id"], "size_bytes": len(value),
                "original_offset": marker["file_offset"], "original_rva": marker["rva"],
                "packed_offset": packed_bytes.find(value), "restored_offset": position,
                "restored_rva": section["rva"] + position - section["raw_offset"],
                "restored_section": section["name"],
            })
        print(f"{fixture_id}: restoration comparison " + json.dumps(details, sort_keys=True))

    destination = output / f"fixture-{arch}-{kind}" / f"packed.{kind}"
    if destination.exists():
        if destination.read_bytes() != packed_bytes:
            raise ValueError(f"{destination}: different artifact already exists; "
                             "choose an unused --output directory.")
        action = "unchanged"
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(packed_bytes)
        action = "saved"
    if restored_bytes is None:
        restoration = "native test/decompression unsupported; recovery not_run"
    else:
        differences = sum(a != b for a, b in zip(original_bytes, restored_bytes))
        differences += abs(len(original_bytes) - len(restored_bytes))
        restoration = f"restored differences={differences}; all markers restored"
    print(f"{fixture_id}: pass; {len(original_bytes)} -> {len(packed_bytes)} bytes; "
          f"{restoration}; {action}")
    print(f"  original SHA-256: {reference['sha256']}")
    print(f"  packed SHA-256:   {sha256(packed)}")
    print(f"  shared manifest:  {sha256(manifest_path)}")
    print(f"  visible markers:  {', '.join(visible) or 'none'}")



def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True,
                        help="UPX version under tools/<version>/bin/upx.exe.")
    parser.add_argument("--tool-sha256", help="Expected SHA-256 of the selected UPX executable (optional).")
    parser.add_argument("--output", type=Path,
                        help="Version output directory (default: packed-fixtures/<version>).")
    parser.add_argument("--pack-arg", action="append",
                        help="Repeat as --pack-arg=-9; replaces the default compression arguments.")
    parser.add_argument("--arch", choices=("x86", "amd64"), action="append",
                        help="Select an architecture; repeat for both (default: both).")
    parser.add_argument("--verification", choices=("native", "legacy-pe"), default="native",
                        help="legacy-pe expects unimplemented -t/-d and checks packed execution.")
    parser.add_argument("--check-header-loss", action="store_true",
                        help="Reproduce section-name loss with temporary PE variants (legacy-pe only).")
    parser.add_argument("--check-section-names", action="store_true",
                        help="Check native restoration of two temporary section-name variants.")
    parser.add_argument("--inspect-restoration", action="store_true",
                        help="Print native header/section/import/relocation/secret comparison; no report file.")
    args = parser.parse_args()
    if (args.check_section_names or args.inspect_restoration) and args.verification != "native":
        parser.error("--check-section-names and --inspect-restoration require native verification.")
    if args.check_header_loss and args.verification != "legacy-pe":
        parser.error("--check-header-loss requires --verification legacy-pe.")
    if os.name != "nt":
        parser.error("Windows is required for EXE/DLL runtime checks.")
    if not re.fullmatch(r"[0-9][A-Za-z0-9_.-]*", args.version) or args.version.endswith("."):
        parser.error("Use a version label such as 5.3.0, without path separators.")
    if args.tool_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", args.tool_sha256):
        parser.error("--tool-sha256 must contain 64 hexadecimal digits.")
    upx = PACKER / "tools" / args.version / "bin/upx.exe"
    if not upx.is_file():
        parser.error(f"UPX executable not found: {upx}")
    digest = sha256(upx)
    if args.tool_sha256 and digest != args.tool_sha256.lower():
        parser.error("UPX executable hash does not match --tool-sha256.")
    version = run([str(upx), "--no-env", "--version"], PACKER).stdout.splitlines()
    if not version or version[0].strip() != f"upx {args.version}":
        parser.error("UPX --version does not match the selected version directory.")
    output = (args.output or PACKER / "packed-fixtures" / args.version).resolve()
    defaults = ["-9"] if args.verification == "legacy-pe" else DEFAULT_PACK_ARGS
    flags = args.pack_arg if args.pack_arg is not None else defaults
    architectures = list(dict.fromkeys(args.arch or ("x86", "amd64")))
    print(f"UPX {args.version}; executable SHA-256: {digest}")
    print(f"Packing arguments: --no-env --no-progress {' '.join(flags)}")
    print(f"Verification: {args.verification}; architectures: {', '.join(architectures)}")
    print(f"Host: {platform.system()} {platform.version()}, {platform.machine()}, "
          f"Python {platform.python_version()}")
    spec = importlib.util.spec_from_file_location("fixture_pe", ROOT / "fixtures/scripts/manifest.py")
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    comparison = None
    if args.inspect_restoration:
        spec = importlib.util.spec_from_file_location("fixture_compare_pe", ROOT / "tools/compare_pe.py")
        comparison = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(comparison)
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pe-upx-") as temporary:
        work_root = Path(temporary).resolve()
        # Bound the directory that TemporaryDirectory will recursively clean up.
        if work_root.parent != Path(tempfile.gettempdir()).resolve():
            raise ValueError("Unexpected temporary directory location.")
        for arch in architectures:
            for kind in ("exe", "dll"):
                work = work_root / f"fixture-{arch}-{kind}"
                work.mkdir()
                try:
                    generate_case(upx, flags, output, work, pe, arch, kind,
                                  args.verification, args.check_header_loss,
                                  args.check_section_names, comparison)
                except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                    failures += 1
                    print(f"basic-{kind}-{arch}: FAIL: {error}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
