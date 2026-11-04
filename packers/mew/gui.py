"""Run MEW's CLI and read its transient progress dialog by owned process ID.

The recorded release exits zero even when packing fails. Its terminal status
and diagnostic are Static controls in an untitled dialog. Capture them before
automatic exit; never use desktop coordinates or dismiss unrelated windows.
All waits are bounded and only the process started here can be terminated.
"""
import ctypes as c
from ctypes import wintypes as w
import subprocess
import time

u = c.WinDLL("user32", use_last_error=True)
CB = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
for name, args, result in (
    ("EnumWindows", [CB, w.LPARAM], w.BOOL),
    ("EnumChildWindows", [w.HWND, CB, w.LPARAM], w.BOOL),
    ("GetWindowThreadProcessId", [w.HWND, c.POINTER(w.DWORD)], w.DWORD),
    ("GetWindowTextW", [w.HWND, w.LPWSTR, c.c_int], c.c_int),
    ("GetClassNameW", [w.HWND, w.LPWSTR, c.c_int], c.c_int),
    ("GetDlgCtrlID", [w.HWND], c.c_int),
):
    fn = getattr(u, name)
    fn.argtypes, fn.restype = args, result


def text(hwnd, class_name=False):
    buffer = c.create_unicode_buffer(4096)
    fn = u.GetClassNameW if class_name else u.GetWindowTextW
    fn(hwnd, buffer, len(buffer))
    return buffer.value


def windows(pid):
    found = []
    @CB
    def callback(hwnd, _):
        owner = w.DWORD()
        u.GetWindowThreadProcessId(hwnd, c.byref(owner))
        if owner.value == pid:
            found.append(hwnd)
        return True
    u.EnumWindows(callback, 0)
    return found


def status(hwnd):
    found = {}
    @CB
    def callback(child, _):
        identifier = u.GetDlgCtrlID(child)
        if identifier in (1031, 1032) and text(child, True) == "Static":
            found[identifier] = text(child)
        return True
    u.EnumChildWindows(hwnd, callback, 0)
    return found.get(1032, ""), found.get(1031, "")


def pack(tool, target, flags):
    """Return exit code, terminal status and diagnostic; always reap the child."""
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    # MEW's parser silently ignores some absolute/quoted input paths. Give it
    # simple argv[0] and an unquoted relative filename in a disposable directory.
    process = subprocess.Popen(["mew11.exe", target.name, *flags], executable=str(tool),
                               cwd=target.parent, startupinfo=startup,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    terminal, detail = "", ""
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for hwnd in windows(process.pid):
                if text(hwnd, True) == "#32770":
                    current, message = status(hwnd)
                    if current in ("Packing procedure ready!", "Packing procedure failed!"):
                        terminal, detail = current, message.strip()
            code = process.poll()
            if code is not None:
                return code, terminal, detail
            time.sleep(0.02)
        raise TimeoutError(f"MEW did not finish within 30 seconds: {terminal} {detail}")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
