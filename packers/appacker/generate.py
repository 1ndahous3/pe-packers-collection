"""Generate Appacker 1.3.11 packages from the shared Windows fixtures."""
import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import fixture_checks as checks

VERSION = "1.3.11"
TOOL = HERE / "tools" / VERSION / "bin" / "Appacker_v1.3.11.exe"
READY = b"pe-fixture:basic-exe:ok\n"


def check_package(package, source):
    data = package.read_bytes()
    name = source.name.encode("ascii")
    payload = source.read_bytes()
    # BinaryWriter encodes these short ASCII filenames with a one-byte length.
    record = bytes([len(name)]) + name + struct.pack("<I", len(payload)) + payload
    info = checks.PE.inspect_pe(package)
    checks.require(info["kind"] == "EXE" and info["optional_header"] == "0x010b",
                   "Expected an outer PE32 EXE")
    checks.require(b"<SerGreen>" in data and data.endswith(record),
                   f"Missing the complete, unchanged {source.name} file record")


def check_execution(package, source, work):
    # The wrapper extracts to TEMP and starts a native child. Both belong to
    # the job so even a wait-mode timeout leaves no fixture process running.
    env = dict(os.environ, TEMP=str(work), TMP=str(work))
    options = dict(cwd=work, env=env, max_processes=2, stdin=subprocess.DEVNULL)
    result = checks.ISOLATED.run([str(package)], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=15, **options)
    if source.suffix == ".dll":
        checks.require(result.returncode != 0 and not result.stdout
                       and b"System.ComponentModel.Win32Exception" in result.stderr,
                       "Expected the wrapper to fail when starting the DLL")
        return

    checks.require(result.returncode == 0 and result.stdout.replace(b"\r\n", b"\n") == READY
                   and not result.stderr, f"Normal run failed: {result}")
    stdout = work / "stdout.txt"
    with stdout.open("wb") as out:
        proc = None
        try:
            with checks.ISOLATED.running([str(package), "--wait"], stdout=out, stderr=subprocess.PIPE, **options) as proc:
                deadline = time.monotonic() + 15
                while not stdout.stat().st_size and proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                checks.require(stdout.read_bytes().replace(b"\r\n", b"\n") == READY, "Missing wait readiness")
                try:
                    proc.wait(timeout=2.25)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    raise ValueError(f"Wait mode exited early: {proc.returncode}")
                extracted = list(work.glob(f"{package.stem}_*/{source.name}"))
                checks.require(len(extracted) == 1 and extracted[0].read_bytes() == source.read_bytes(),
                               "The live extracted EXE differs from the shared fixture")
        finally:
            # Drain the inherited pipe after closing the job so both processes
            # release the extracted image and output files before cleanup.
            if proc is not None:
                with proc:
                    _, error = proc.communicate(timeout=5)
    checks.require(stdout.read_bytes().replace(b"\r\n", b"\n") == READY and not error,
                   "Unexpected wait output")


def run_case(arch, kind, output):
    source, _ = checks.reference(arch, kind)
    case = Path(VERSION) / f"fixture-{arch}-{kind}" / "packed.exe"
    with tempfile.TemporaryDirectory(prefix="appacker-case-") as tmp:
        work = Path(tmp)
        if output is None:
            package = HERE / "packed-fixtures" / case
        else:
            inputs = work / "input"
            inputs.mkdir()
            shutil.copyfile(source, inputs / source.name)
            package = work / "packed.exe"
            result = checks.run([TOOL, "--quiet", "--src", inputs, "--exe", source.name,
                                 "--dst", package], work, max_processes=4)
            checks.require(result.returncode == 0 and package.is_file(), f"Packing failed: {result}")
        check_package(package, source)
        extract_dir = work / "runtime"
        extract_dir.mkdir()
        check_execution(package, source, extract_dir)
        if kind == "exe" and output is not None:
            checks.publish(package.read_bytes(), output / case)
    outcome = "normal, wait, byte-exact recovery" if kind == "exe" else "stored intact, DLL launch rejected"
    print(f"{arch} {kind}: {outcome}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="generate all four cases and save the working EXEs")
    mode.add_argument("--verify-only", action="store_true", help="check both retained packages")
    args = parser.parse_args()
    kinds = ("exe",) if args.verify_only else ("exe", "dll")
    for arch in ("x86", "amd64"):
        for kind in kinds:
            run_case(arch, kind, args.output)
