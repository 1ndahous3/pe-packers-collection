"""Bound FSG's command-line GUI to the process started by this helper.

Both recorded releases exit with 0xffffffff after successful packing. Error
message boxes remain open. Read their Static control, then terminate only the
owned process. The caller validates PE output and execution independently.
No desktop coordinates, global window-title matching or saved settings are used.
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


def dialogs(pid):
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


def error_text(hwnd):
    found = []
    @CB
    def callback(child, _):
        if u.GetDlgCtrlID(child) == 65535 and text(child, True) == "Static":
            value = text(child)
            if value:
                found.append(value)
        return True
    u.EnumChildWindows(hwnd, callback, 0)
    return "\n".join(found)


def pack(tool, target, version):
    """Return (exit code, dialog text); always reap the owned process."""
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    expected = {"1.33": "FSG v1.33 by dulek/xt", "2.0": "FSG v2.0 - bart/xt"}[version]
    process = subprocess.Popen([str(tool), str(target)], cwd=tool.parent,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, startupinfo=startup)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for hwnd in dialogs(process.pid):
                if text(hwnd) == expected:
                    error = error_text(hwnd)
                    if error:
                        return None, error
            result = process.poll()
            if result is not None:
                return result, ""
            time.sleep(0.05)
        raise TimeoutError("FSG did not finish within 30 seconds.")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
