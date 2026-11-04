"""Verify wait readiness and liveness, then terminate only the test process.

Used by CTest and packer generators. check_fixture() tests --wait for EXEs and
WaitFixture both by name and ordinal 4 for DLLs, with the matching rundll32.
A wait run must print the normal success line and survive more than two sleep
intervals. This is a bounded smoke check, not a guarantee of indefinite uptime.
"""
import argparse
import os
from pathlib import Path
import subprocess


def check_wait(program, argument, expected_line, working_directory=None):
    process = subprocess.Popen([str(program), argument],
                               cwd=working_directory, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            output, error = process.communicate(timeout=2.25)
        except subprocess.TimeoutExpired:
            if process.poll() is not None:
                raise ValueError("Wait mode exited before it was terminated.")
            process.kill()
            output, error = process.communicate(timeout=5)
        else:
            raise ValueError(f"Wait mode exited early: {process.returncode}, "
                               f"stdout={output!r}, stderr={error!r}")
        expected = (expected_line + "\n").encode("ascii")
        if output.replace(b"\r\n", b"\n") != expected or error:
            raise ValueError(f"Wait mode did not reach readiness: "
                               f"stdout={output!r}, stderr={error!r}")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)



def check_fixture(path, arch, kind):
    path = Path(path).resolve()
    expected = f"pe-fixture:basic-{kind}:ok"
    if kind == "exe":
        check_wait(path, "--wait", expected, path.parent)
    else:
        windows = Path(os.environ["WINDIR"])
        native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
        host = windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"
        for entry in ("WaitFixture", "#4"):
            check_wait(host, "./" + path.name + "," + entry, expected, path.parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True)
    parser.add_argument("--argument", required=True)
    parser.add_argument("--working-directory")
    parser.add_argument("--expected", required=True)
    args = parser.parse_args()
    check_wait(args.program, args.argument, args.expected, args.working_directory)


if __name__ == "__main__":
    main()
