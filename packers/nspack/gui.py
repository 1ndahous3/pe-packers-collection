"""Apply the NSPack 2.3/3.7 profiles and pack through its process-owned GUI.

Checkbox edits take effect when leaving Settings, not merely when their visual
state changes. TCM_SETCURFOCUS switches tabs with selection notifications.
No preferences are saved, no context-menu integration is enabled, and auto-run
is disabled. All files supplied here must be disposable copies of our fixtures.

A file argument instead invokes silent in-place CLI packing with saved/default
options. That CLI returns zero even for rejected amd64 inputs; generate.py uses
it only to reproduce the pinned edition's unchanged-file rejection.
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
        raise TimeoutError("NSPack GUI did not respond.")
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


def pack(tool, target, version="2.3"):
    before = target.read_bytes()
    process = subprocess.Popen([str(tool)], cwd=target.parent,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, startupinfo=startup_info())
    deadline = time.monotonic() + 30

    def until(predicate, description):
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError(f"NSPack exited before {description}: {process.returncode}")
            result = predicate()
            if result:
                return result
            time.sleep(0.1)
        raise TimeoutError("NSPack timed out waiting for " + description)

    try:
        main = until(lambda: next((h for h in windows(process.pid)
                                   if caption(h).startswith("NsPack By North Star")), None),
                     "main window")
        items = controls(main)
        tab = items[1001, "SysTabControl32"]
        message(tab, 0x1330, 2)  # TCM_SETCURFOCUS: Settings
        profile = {1006: 0, 1007: 1, 1008: 1, 1009: 0, 1010: 0, 1012: 0,
                   1014: 1, 1015: 0, 1031: 0, 1032: 1, 1058: 1, 1059: 0,
                   1017: 1, 1021: 0, 1019: 0}
        if version == "3.7-cracked":
            profile.update({1095: 0, 1096: 0})
        for identifier, value in profile.items():
            message(items[identifier, "Button"], 0xF1, value)  # BM_SETCHECK
        name = c.create_unicode_buffer("nsp")
        message(items[1018, "Edit"], 0x0C, 0, c.addressof(name))
        message(tab, 0x1330, 0)  # File; commits the Settings page values
        u.PostMessageW(main, 0x111, 1002, items[1002, "Button"])

        def ready_dialog():
            for hwnd in windows(process.pid):
                if hwnd == main or class_name(hwnd) != "#32770":
                    continue
                children = controls(hwnd)
                if ((1148, "Edit") in children
                        and (1121, "SHELLDLL_DefView") in children):
                    return hwnd, children
            return None

        dialog, children = until(ready_dialog, "initialized Open dialog")
        filename = c.create_unicode_buffer(str(target))
        message(children[1148, "Edit"], 0x0C, 0, c.addressof(filename))
        u.PostMessageW(dialog, 0x111, 1, children[1, "Button"])
        until(lambda: caption(items[1003, "Static"]) == str(target), "input selection")
        u.PostMessageW(main, 0x111, 1016, items[1016, "Button"])

        def finished():
            for hwnd in windows(process.pid):
                if hwnd != main and class_name(hwnd) == "#32770":
                    texts = [caption(h) for (_, cls), h in controls(hwnd).items()
                             if cls == "Static"]
                    raise ValueError("NSPack dialog: " + caption(hwnd) + " " + " | ".join(texts))
            try:
                changed = target.read_bytes() != before
            except PermissionError:
                return False
            return changed and u.IsWindowEnabled(items[1016, "Button"]) and u.IsWindowEnabled(items[2, "Button"])

        until(finished, "packed output")
        # Wait for the UI thread, then close normally and require successful exit.
        message(main, 0)
        u.PostMessageW(main, 0x10, 0, 0)
        process.wait(timeout=5)
        if process.returncode not in (0, 2):  # MFC dialog returns IDCANCEL on WM_CLOSE
            raise ValueError(f"NSPack exited with {process.returncode}.")
        if target.with_name(target.name + ".bak").exists():
            raise ValueError("NSPack did not apply the no-backup profile.")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
