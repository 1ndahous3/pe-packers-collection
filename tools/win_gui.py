"""Bounded Win32 messages and PID-owned windows for packer GUI helpers.

Windows/Python standard library only. Imported by packer-specific gui.py files;
no desktop-wide matching, focus manipulation or process termination is provided.
startup_info() requests a hidden launch; callers own process lifetime and deadlines.
"""
import ctypes as c
from ctypes import wintypes as w
import subprocess
import time

u = c.WinDLL("user32", use_last_error=True)
CB = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
for name, arguments, result in (
    ("EnumWindows", [CB, w.LPARAM], w.BOOL),
    ("EnumChildWindows", [w.HWND, CB, w.LPARAM], w.BOOL),
    ("GetWindowThreadProcessId", [w.HWND, c.POINTER(w.DWORD)], w.DWORD),
    ("GetClassNameW", [w.HWND, w.LPWSTR, c.c_int], c.c_int),
    ("GetDlgCtrlID", [w.HWND], c.c_int),
    ("IsWindowEnabled", [w.HWND], w.BOOL),
    ("PostMessageW", [w.HWND, w.UINT, w.WPARAM, w.LPARAM], w.BOOL),
    ("SendMessageTimeoutW", [w.HWND, w.UINT, w.WPARAM, w.LPARAM,
                             w.UINT, w.UINT, c.POINTER(c.c_size_t)], c.c_size_t),
):
    function = getattr(u, name)
    function.argtypes, function.restype = arguments, result


def message(hwnd, msg, a=0, b=0):
    result = c.c_size_t()
    if not u.SendMessageTimeoutW(hwnd, msg, a, b, 2, 1000, c.byref(result)):
        raise TimeoutError("Owned GUI did not respond.")
    return c.c_ssize_t(result.value).value


def caption(hwnd):
    buffer = c.create_unicode_buffer(4096)
    message(hwnd, 0x0D, len(buffer), c.addressof(buffer))  # WM_GETTEXT
    return buffer.value


def class_name(hwnd):
    buffer = c.create_unicode_buffer(256)
    u.GetClassNameW(hwnd, buffer, len(buffer))
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


def controls(parent):
    found = {}
    @CB
    def callback(hwnd, _):
        found[(u.GetDlgCtrlID(hwnd), class_name(hwnd))] = hwnd
        return True
    u.EnumChildWindows(parent, callback, 0)
    return found


def startup_info():
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    return startup


u.GetParent.argtypes = [w.HWND]
u.GetParent.restype = w.HWND
