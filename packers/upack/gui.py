"""Pack through WinUpack 0.39final using only windows owned by its PID.

Apply the same profile as CLI -c3 -f128 -red: preserve exports/relocations,
keep overlay, no backup, force, relocation, icon exception or timestamp option.
Completion requires a terminal log message and re-enabled Pack button; exit
zero alone is insufficient. Unexpected dialogs and timeouts are failures.
No user preferences are saved. The caller supplies a disposable input copy.
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
        raise TimeoutError("WinUpack GUI did not respond.")
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


def pack(tool, target):
    process = subprocess.Popen([str(tool)], cwd=target.parent,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, startupinfo=startup_info())
    deadline = time.monotonic() + 30
    try:
        main = None
        while time.monotonic() < deadline and process.poll() is None:
            main = next((h for h in windows(process.pid) if caption(h) == 'WinUpack 0.39final'), None)
            if main:
                break
            time.sleep(.05)
        if not main:
            raise TimeoutError('WinUpack did not show its main window.')
        items = controls(main)
        for ident,value in {1019:0,1005:1,1012:0,1002:0,1007:0,1006:0,
                            1008:0,1020:0,1013:0}.items():
            message(items[ident,'Button'],0xf1,value)  # BM_SETCHECK
        for ident,value in {1001:str(target),1014:'3',1016:'128'}.items():
            text = c.create_unicode_buffer(value)
            message(items[ident,'Edit'],0x0c,0,c.addressof(text))
        button = items[1003,'Button']
        u.PostMessageW(main,0x111,1003,button)
        text = ''
        while time.monotonic() < deadline and process.poll() is None:
            for hwnd in windows(process.pid):
                if hwnd != main and class_name(hwnd) == '#32770':
                    words = [caption(v) for (_,cl),v in controls(hwnd).items() if cl == 'Static']
                    raise ValueError('WinUpack dialog: ' + ' | '.join(words))
            text = caption(items[1009,'Edit'])
            terminal = 'Completed!' in text or '[ERROR:' in text
            if terminal and u.IsWindowEnabled(button):
                u.PostMessageW(main,0x10,0,0)
                process.wait(timeout=5)
                return process.returncode,text
            time.sleep(.05)
        raise TimeoutError('WinUpack did not finish: ' + text[-2000:])
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
