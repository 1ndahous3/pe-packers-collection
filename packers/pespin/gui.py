"""Process-owned GUI driver for the original PESpin 1.33 distribution.

Used by generate.py; no separate setup or third-party modules are needed.
The input filename is passed on the command line. The driver identifies the
main window by the launched PID and version title, then activates Protect file
by its checked control ID and label. It reads the ListBox log until the final
size message and an enabled button confirm completion. It uses no mouse,
keyboard focus, screenshot coordinates or saved user settings.

Window messages have bounded waits. The log can reset during packing, so a
transient missing item is retried. The process is closed on success or failure;
a timeout kills only the process that this driver started. GUI log text is
returned to the caller, never treated as commands. Other PESpin releases may
have different controls and require a separate adapter.
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
    ("IsWindowEnabled", [w.HWND], w.BOOL),
    ("PostMessageW", [w.HWND, w.UINT, w.WPARAM, w.LPARAM], w.BOOL),
    ("SendMessageTimeoutW", [w.HWND, w.UINT, w.WPARAM, w.LPARAM,
                             w.UINT, w.UINT, c.POINTER(c.c_size_t)], c.c_size_t),
):
    fn = getattr(u, name)
    fn.argtypes, fn.restype = args, result


def caption(hwnd):
    b = c.create_unicode_buffer(4096)
    u.GetWindowTextW(hwnd, b, len(b))
    return b.value


def class_name(hwnd):
    b = c.create_unicode_buffer(256)
    u.GetClassNameW(hwnd, b, len(b))
    return b.value


def message(hwnd, msg, a=0, b=0):
    result = c.c_size_t()
    if not u.SendMessageTimeoutW(hwnd, msg, a, b, 2, 1000, c.byref(result)):
        raise TimeoutError("PESpin GUI did not respond.")
    return c.c_ssize_t(result.value).value


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


def list_lines(hwnd):
    count = message(hwnd, 0x18b)  # LB_GETCOUNT
    if not 0 <= count < 10000:
        raise ValueError("Unexpected PESpin log length.")
    lines = []
    for index in range(count):
        size = message(hwnd, 0x18a, index)  # LB_GETTEXTLEN
        if size == -1:
            raise TimeoutError("PESpin log changed while reading.")
        if not 0 <= size < 100000:
            raise ValueError("Unexpected PESpin log item length.")
        buf = c.create_unicode_buffer(size + 1)
        message(hwnd, 0x189, index, c.addressof(buf))  # LB_GETTEXT
        lines.append(buf.value)
    return lines


def pack_x86(tool, target):
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen([str(tool), str(target)], cwd=tool.parent,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, startupinfo=startup)
    main = None
    log = []
    try:
        deadline = time.monotonic() + 30
        clicked = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError("PESpin exited before confirming packing.")
            candidates = windows(process.pid)
            if main is None:
                main = next((h for h in candidates
                             if caption(h) == "PESpin v1.33"), None)
            if main:
                items = controls(main)
                button = items.get((1, "Button"))
                logger = items.get((29, "ListBox"))
                if button and logger:
                    if caption(button) != "Protect file":
                        raise ValueError("Unexpected PESpin GUI control.")
                    if not clicked and u.IsWindowEnabled(button):
                        u.PostMessageW(button, 0xf5, 0, 0)  # BM_CLICK
                        clicked = True
                    try:
                        log = list_lines(logger)
                    except TimeoutError:
                        time.sleep(0.1)
                        continue
                    if any("New size:" in line for line in log) and u.IsWindowEnabled(button):
                        return "\n".join(log)
            time.sleep(0.05)
        dialogs = [caption(h) for h in windows(process.pid)]
        raise TimeoutError(f"PESpin did not finish: {dialogs}; log={log}")
    finally:
        owner = w.DWORD()
        if main and process.poll() is None:
            u.GetWindowThreadProcessId(main, c.byref(owner))
        if owner.value == process.pid:
            u.PostMessageW(main, 0x10, 0, 0)  # WM_CLOSE
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
