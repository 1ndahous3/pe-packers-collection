"""Generate or verify the Shrinker 3.4 demo cases on Windows.

Run with --output DIR to write verified cases under DIR/3.4-demo, or with
--verify-only to check the retained files. The packer and its DLL come from
the Win32 component of the Blink demo distribution. Only shared fixtures are run.
"""
import argparse
from pathlib import Path
import queue
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import fixture_checks as checks
import win_gui as gui

VERSION = "3.4-demo"
BIN = HERE / "tools" / VERSION / "bin"


def confirm(process, window_class, title, button_class, label):
    deadline = time.monotonic() + 12
    while process.poll() is None and time.monotonic() < deadline:
        for window in gui.windows(process.pid):
            if gui.class_name(window) != window_class or gui.caption(window) != title:
                continue
            for (_, cls), button in gui.controls(window).items():
                if cls == button_class and gui.caption(button) == label and gui.u.IsWindowEnabled(button):
                    if gui.u.PostMessageW(button, 0x00F5, 0, 0):  # BM_CLICK
                        return
        time.sleep(0.05)
    raise RuntimeError(f"{title!r} did not offer {label!r} (exit {process.poll()})")


def pack(kind, directory):
    source, _ = checks.reference("x86", kind)
    prepared = directory / ("shrinker-fixture.dll" if kind == "dll" else "input.exe")
    data = bytearray(source.read_bytes())
    flags_offset = struct.unpack_from("<I", data, 0x3c)[0] + 24 + 70
    flags = struct.unpack_from("<H", data, flags_offset)[0]
    struct.pack_into("<H", data, flags_offset, flags & ~0x400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH
    prepared.write_bytes(data)
    checks.normal(prepared, "x86", kind)
    checks.WAIT.check_fixture(prepared, "x86", kind)

    packed = directory / f"packed.{kind}"
    command = [BIN / "Shrink32.exe", prepared.name, packed.name, "-BQ", "-CA"]
    with checks.ISOLATED.running(command, cwd=directory, startupinfo=gui.startup_info()) as process:
        confirm(process, "TAboutBox", "Welcome to Shrinker!", "TButton", "Ok")
        checks.require(process.wait(timeout=20) == 0 and packed.is_file(),
                       f"Shrinker did not produce {packed.name}")
    return packed


def check_run(path, kind, entry, wait=False):
    command = checks.command(path, "x86", kind, entry)
    if kind == "exe" and wait:
        command.append("--wait")
    with checks.ISOLATED.running(command, cwd=path.parent, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 startupinfo=gui.startup_info()) as process:
        confirm(process, "#32770", "Shrinker demonstration version", "Button", "&Yes")
        expected = f"pe-fixture:basic-{kind}:ok\n".encode()
        if wait:
            # Start measuring liveness only once the fixture has reported readiness.
            lines = queue.Queue()
            reader = threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True)
            reader.start()
            line = lines.get(timeout=10)
            checks.require(line.replace(b"\r\n", b"\n") == expected, f"{entry}: {line!r}")
            try:
                process.wait(timeout=2.25)
            except subprocess.TimeoutExpired:
                process.kill()
            else:
                raise ValueError(f"{entry} exited during the wait check")
            expected = b""
        output, error = process.communicate(timeout=10)
        checks.require((wait or process.returncode == 0) and not error and
                       output.replace(b"\r\n", b"\n") == expected,
                       f"{entry}: exit {process.returncode}, stdout={output!r}, stderr={error!r}")


def verify(path, kind):
    _, ref = checks.reference("x86", kind)
    original = path.read_bytes()
    info = checks.PE.inspect_pe(path)
    for field in ("machine", "optional_header", "kind", "exports", "dynamic_base", "nx_compatible"):
        checks.require(info[field] == ref["pe"][field], f"Unexpected {field}: {info[field]}")
    names = [section["name"] for section in info["sections"]]
    checks.require(".shrink0" in names and ".load" in names, "Missing Shrinker sections")
    check_run(path, kind, "RunFixture")
    check_run(path, kind, "WaitFixture", wait=True)
    if kind == "dll":
        check_run(path, kind, "#3")
        check_run(path, kind, "#4", wait=True)
    checks.require(path.read_bytes() == original, "Execution modified the packed file")
    visible = [m["section"] for m in ref["secrets"] if bytes.fromhex(m["hex"]) in original]
    print(f"{kind}: normal and wait passed; complete disk markers: {visible}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="destination for generated version directories")
    mode.add_argument("--verify-only", action="store_true", help="verify the retained cases")
    args = parser.parse_args()
    for kind in ("exe", "dll"):
        relative = Path(VERSION) / f"fixture-x86-{kind}" / f"packed.{kind}"
        if args.verify_only:
            verify(HERE / "packed-fixtures" / relative, kind)
        else:
            with tempfile.TemporaryDirectory(prefix="shrinker-") as temp:
                packed = pack(kind, Path(temp))
                verify(packed, kind)
                checks.publish(packed.read_bytes(), args.output / relative)


if __name__ == "__main__":
    main()
