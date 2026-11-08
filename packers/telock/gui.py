"""One-session, PID-scoped automation of tElock 0.98 (Windows/stdlib).

The retained binary is copied to a temporary working directory. A fresh session
accepts the first-run Welcome message. Settings are selected by real checkbox
clicks; saving settings and shell registration stay off. The driver accepts only
the known DLL export-redirection confirmation and fails on other modal dialogs.
Completion requires a final size report, Ready status and a changed input.
One session handles a batch; repeated launches can produce a stale single-instance
Reminder under forced job cleanup. Never terminate an unrelated tElock instance.
"""
from contextlib import contextmanager
import ctypes
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
G = load("telock_windows", "tools/win_gui.py")
I = load("telock_process", "fixtures/scripts/isolated_process.py")


def wait(test, process, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = test()
        if value:
            return value
        if process.poll() is not None:
            raise ValueError(f"tElock exited: {process.returncode:#x}")
        if time.monotonic() >= deadline:
            break
        time.sleep(0.03)
    dialogs = [G.caption(h) for h in G.windows(process.pid)]
    raise TimeoutError(f"tElock GUI deadline; owned windows: {dialogs}")


def log_lines(control):
    result = []
    for index in range(G.message(control, 0x18b)):
        buffer = ctypes.create_unicode_buffer(4096)
        G.message(control, 0x189, index, ctypes.addressof(buffer))
        result.append(buffer.value)
    return result


@contextmanager
def _session(tool, work):
    local = work / "telock.exe"
    shutil.copy2(tool, local)
    process = None
    try:
        with I.running([str(local)], cwd=work, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       startupinfo=G.startup_info()) as process:
            window = wait(lambda: next((h for h in G.windows(process.pid)
                          if G.caption(h) in ("Welcome", "Reminder") or
                          G.class_name(h) == "tEWinClass"), None), process)
            time.sleep(0.25)
            if G.caption(window) == "Reminder":
                raise ValueError("tElock reports another instance; close its earlier session and retry")
            if G.caption(window) == "Welcome":
                G.u.PostMessageW(G.controls(window)[(2, "Button")], 0xf5, 0, 0)
            main = wait(lambda: next((h for h in G.windows(process.pid)
                        if G.class_name(h) == "tEWinClass"), None), process)
            time.sleep(0.2)
            try:
                yield process, main, G.controls(main)
            finally:
                G.u.PostMessageW(main, 0x10, 0, 0)
                wait(lambda: main not in G.windows(process.pid), process, 5)
    finally:
        if process is not None and process.poll() is not None:
            process._handle.Close()


def pack(state, path, profile):
    process, main, controls = state
    desired = {7: 1, 8: 0, 9: 0, 10: 0, 11: int(profile == "default"),
               14: 0, 15: 0, 16: 1, 17: 1, 18: 0,
               19: int(profile == "default"), 20: 0, 21: 0,
               23: int(profile == "default"), 25: 0, 27: 0}
    for control, value in desired.items():
        button = controls[(control, "Button")]
        if G.message(button, 0xf0) != value:
            G.message(button, 0xf5)
    if any(G.message(controls[(key, "Button")], 0xf0) != value
           for key, value in desired.items()):
        raise ValueError("tElock option state mismatch")
    before = path.read_bytes()
    G.u.PostMessageW(controls[(2, "Button")], 0xf5, 0, 0)
    dialog = wait(lambda: next((h for h in G.windows(process.pid)
                  if (1148, "Edit") in G.controls(h) and
                  (1121, "SHELLDLL_DefView") in G.controls(h)), None), process)
    time.sleep(0.3)
    buffer = ctypes.create_unicode_buffer(str(path))
    G.message(G.controls(dialog)[(1148, "Edit")], 0xc, 0, ctypes.addressof(buffer))
    G.u.PostMessageW(dialog, 0x111, 1, 0)
    acknowledged = set()
    def finished():
        for h in G.windows(process.pid):
            if h == dialog or h in acknowledged or G.class_name(h) != "#32770":
                continue
            children = G.controls(h)
            message = " ".join(G.caption(c) for (key, cls), c in children.items() if cls == "Static")
            if G.caption(h) == "Confirm" and "export table" in message and (6, "Button") in children:
                G.u.PostMessageW(children[(6, "Button")], 0xf5, 0, 0)
                acknowledged.add(h)
            else:
                raise ValueError(f"tElock dialog: {G.caption(h)}: {message}")
        lines = log_lines(controls[(5, "ListBox")])
        return lines if (str(path) in lines and lines and lines[-1].startswith("Old size:") and
                         G.caption(controls[(105, "Static")]) == "Ready..." and
                         G.u.IsWindowEnabled(main) and path.read_bytes() != before) else None
    result = wait(finished, process, 30)
    print(result[-1], flush=True)
    return result


@contextmanager
def session(tool, work):
    # Retry only before any input is selected. Never close another app's window.
    for attempt in range(3):
        context = _session(tool, work)
        try:
            state = context.__enter__()
        except ValueError as error:
            if "reports another instance" not in str(error) or attempt == 2:
                raise
            time.sleep(0.5)
            continue
        try:
            yield state
        finally:
            context.__exit__(None, None, None)
        return


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--case", action="append", nargs=2, metavar=("PROFILE", "PATH"), required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    with session(args.tool.resolve(), work) as state:
        for profile, filename in args.case:
            path = Path(filename).resolve()
            if profile not in ("minimal", "default") or path.parent != work:
                raise ValueError("Expected a supported profile and a file in the temporary work directory")
            pack(state, path, profile)


if __name__ == "__main__":
    main()
