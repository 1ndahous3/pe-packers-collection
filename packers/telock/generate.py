"""Generate tElock 0.98 profiles (Windows x64/Python standard library).

Acquisition: unpack tools/0.98/telock-0.98.rar with 7-Zip; retain telock.exe in bin.
The original archive also contains the author's CHM manual. It was recovered from
ANALYZE_L@B/Protectors/tElock 0.98.rar on SUN_2010.iso in:
https://archive.org/details/cracklb-2010
Resolve the ISO URL with https://archive.org/metadata/cracklb-2010 and read its
Joliet directories over HTTP Range; no full DVD download is needed. Softpedia
lists 0.98 but its download was not retrievable in this research. No buildable
packer source was established. The retained binary is unmodified.

  python packers/telock/generate.py
  python packers/telock/generate.py --verify-only
  python packers/telock/generate.py --output <fresh-directory>

Temporary x86 inputs clear DYNAMIC_BASE, NO_SEH and NX_COMPAT (0x540) before
packing. Outputs are not patched: header changes trigger tElock integrity checks.
Both profiles keep names and smart-resource mode; optional debugger detection,
custom mutex/string, shell integration, settings saving and backups are off.
minimal: IAT redirection, overlay stripping and relocation stripping off.
default: these three options on, matching fresh GUI defaults; the differences
from stock are input preparation and disabling backup/settings persistence.

A separate GUI worker processes the batch in one session and exits before runtime
checks, releasing GUI references before temporary-file cleanup. --probe-failed also packs an
x86 DLL and both PE32+ kinds with the minimal profile, then attempts their normal
callback with bounded process jobs. Known failed outputs are reported, not saved.
The DLL export-redirection prompt is accepted. PE32+ is mistakenly accepted and
produces nonworking files, not a clean unsupported-input rejection.

Only passing EXEs are published; verify PE identity, normal/wait behavior, runtime
secret checksums, disk-marker visibility and unchanged originals. Polymorphism
changes bytes between runs: use a fresh --output instead of overwriting fixtures.
Windows can temporarily retain mapped files after child exit. Cleanup removes all
unlocked files and reports a remaining temporary directory instead of hiding it.
"""
import argparse
from pathlib import Path
import importlib.util
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


def prepare(data):
    result = bytearray(data)
    nt = struct.unpack_from("<I", result, 0x3c)[0]
    flags = struct.unpack_from("<H", result, nt+94)[0]
    CHECK.require(flags & 0x540 == 0x540, "Unexpected original flags")
    struct.pack_into("<H", result, nt+94, flags & ~0x540)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--probe-failed", action="store_true")
    args = parser.parse_args()
    tool = PACKER / "tools/0.98/bin/telock.exe"
    CHECK.require(CHECK.sha256(tool) == "5203aa4b6ad2d63fc8c7f6a05fb72b6ac75985ee8077820b47faa5a1b97c13c1", "Unexpected tElock binary")
    output = (args.output or PACKER / "packed-fixtures/0.98").resolve()
    profiles = ("minimal", "default")
    if args.verify_only:
        for profile in profiles:
            CHECK.verify(output / "fixture-x86-exe" / f"{profile}-compatible.exe", "x86", "exe")
        return
    CHECK.require(not any((output / "fixture-x86-exe" / f"{p}-compatible.exe").exists()
                          for p in profiles), "Use --verify-only or a fresh --output")
    cases = [("x86", "exe", profile) for profile in profiles]
    if args.probe_failed:
        cases += [("x86", "dll", "minimal"), ("amd64", "exe", "minimal"), ("amd64", "dll", "minimal")]
    with tempfile.TemporaryDirectory(prefix="pe-telock-generate-", ignore_cleanup_errors=True) as temp:
        work = Path(temp)
        packed = []
        command = [sys.executable, PACKER / "gui.py", "--tool", tool, "--work", work]
        originals = {}
        for arch, kind, profile in cases:
            source, ref = CHECK.reference(arch, kind)
            sample = work / f"{arch}-{profile}.{kind}"
            sample.write_bytes(prepare(source.read_bytes()) if arch == "x86" else source.read_bytes())
            originals[sample] = sample.read_bytes()
            command += ["--case", profile, sample]
            packed.append((sample, arch, kind, profile))
        result = CHECK.run(command, work, 90, max_processes=2)
        CHECK.require(result.returncode == 0 and not result.stderr,
                      f"GUI worker failed: {result.stdout!r} {result.stderr!r}")
        print(result.stdout.decode(errors="replace"), end="", flush=True)
        for sample, arch, kind, profile in packed:
            CHECK.require(sample.read_bytes() != originals[sample], "No packed output")
            CHECK.reference(arch, kind)
        for sample, arch, kind, profile in packed:
            if arch != "x86" or kind != "exe":
                try:
                    CHECK.normal(sample, arch, kind)
                except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                    print(f"Failed-profile probe {arch}/{kind}: {error}", flush=True)
                else:
                    raise ValueError(f"Previously failing {arch}/{kind} now runs; review before publishing")
                continue
            CHECK.verify(sample, arch, kind)
            CHECK.publish(sample.read_bytes(), output / "fixture-x86-exe" / f"{profile}-compatible.exe")

    if work.exists():
        print(f"Windows still holds temporary image files after child exit: {work}", file=sys.stderr)


if __name__ == "__main__":
    main()
