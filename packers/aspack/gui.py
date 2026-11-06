"""Run ASPack with bounded, process-owned GUI handling.

The public editions may leave their GUI open even with /S. Wait for the
application's 100% completion title and output, then close the main window.
For 2.43, follow only the started process's pcnsl.exe child in the same tool
folder and use its enabled Trial period button. English.ini is a required
language resource.

Unexpected dialogs are reported, not dismissed. Cleanup terminates only the
started process and verified child handles. No mouse coordinates, keyboard
focus, screenshots or user's saved options are used to drive packing.
"""
import ctypes as c
from ctypes import wintypes as w
import subprocess
import time
from pathlib import Path

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
        raise TimeoutError("ASPack GUI did not respond.")
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


k = c.WinDLL("kernel32", use_last_error=True)


class ProcessEntry(c.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD),
                ("heap", c.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                ("parent", w.DWORD), ("priority", w.LONG), ("flags", w.DWORD),
                ("name", w.WCHAR * 260)]


for name, args, result in (
    ("CreateToolhelp32Snapshot", [w.DWORD, w.DWORD], w.HANDLE),
    ("Process32FirstW", [w.HANDLE, c.POINTER(ProcessEntry)], w.BOOL),
    ("Process32NextW", [w.HANDLE, c.POINTER(ProcessEntry)], w.BOOL),
    ("OpenProcess", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
    ("QueryFullProcessImageNameW", [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)], w.BOOL),
    ("GetExitCodeProcess", [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
    ("TerminateProcess", [w.HANDLE, w.UINT], w.BOOL),
    ("WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD),
    ("CloseHandle", [w.HANDLE], w.BOOL),
):
    fn = getattr(k, name)
    fn.argtypes, fn.restype = args, result


def capture_children(process, folder, known):
    snapshot = k.CreateToolhelp32Snapshot(2, 0)
    if snapshot == c.c_void_p(-1).value:
        raise OSError(c.get_last_error(), "Cannot enumerate ASPack children.")
    try:
        entry = ProcessEntry()
        entry.size = c.sizeof(entry)
        valid = k.Process32FirstW(snapshot, c.byref(entry))
        while valid:
            if (entry.parent == process.pid and entry.name.lower() == "pcnsl.exe"
                    and entry.pid not in known):
                handle = k.OpenProcess(0x101001, False, entry.pid)  # Query + terminate + synchronize
                if handle:
                    path = c.create_unicode_buffer(32768)
                    length = w.DWORD(len(path))
                    if (k.QueryFullProcessImageNameW(handle, 0, path, c.byref(length))
                            and Path(path.value).resolve() == folder / "pcnsl.exe"):
                        known[entry.pid] = handle
                    else:
                        k.CloseHandle(handle)
            valid = k.Process32NextW(snapshot, c.byref(entry))
    finally:
        k.CloseHandle(snapshot)


def pack(tool, original, output, version, arguments):
    """Return after completion; raise ValueError with a rejected-input diagnostic."""
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen([str(tool), str(original), "/O" + str(output)] + arguments,
                               cwd=tool.parent, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               startupinfo=startup)
    children, clicked = {}, {}
    deadline = time.monotonic() + 40
    completed = False
    try:
        while time.monotonic() < deadline:
            capture_children(process, tool.parent.resolve(), children)
            for pid in [process.pid] + list(children):
                for hwnd in windows(pid):
                    title = caption(hwnd)
                    child_controls = controls(hwnd)
                    if pid in children and title in ("ASPack - Activation", "ASPack - Warning"):
                        button = child_controls.get((2000, "Button"))
                        key = (hwnd, title)
                        if (button and caption(button) == "Trial period"
                                and u.IsWindowEnabled(button)
                                and time.monotonic() - clicked.get(key, 0) >= 1):
                            # BN_CLICKED: this dialog ignores BM_CLICK without focus.
                            u.PostMessageW(hwnd, 0x111, 2000, button)
                            clicked[key] = time.monotonic()
                        continue
                    if pid == process.pid and title == "ASPack - 100%" and output.is_file():
                        completed = True
                    if class_name(hwnd) == "#32770":
                        texts = [caption(h) for (_, cls), h in child_controls.items()
                                 if cls == "Static" and caption(h)]
                        if texts:
                            detail = title + ": " + " | ".join(texts)
                            if (version == "2.2" and completed and output.is_file()
                                    and title == "ASPack - 100%"
                                    and any(t.startswith("Access violation at address 004259F8 in module 'ASPack.exe'.") for t in texts)):
                                print("ASPack 2.2: recorded completion fault; checking written output independently.")
                                return
                            raise ValueError(detail)
            if completed:
                for hwnd in windows(process.pid):
                    if caption(hwnd) == "ASPack " + version:
                        u.PostMessageW(hwnd, 0x10, 0, 0)
                process.wait(timeout=5)
                if process.returncode != 0:
                    raise ValueError(f"ASPack exited with {process.returncode} after packing.")
                return
            if process.poll() is not None:
                # /S can exit before a progress title is observable.
                if process.returncode == 0 and output.is_file():
                    return
                raise ValueError(f"ASPack exited with {process.returncode} without output.")
            time.sleep(0.1)
        state = [(caption(h), [(cls, caption(control))
                  for (_, cls), control in controls(h).items() if caption(control)])
                 for pid in [process.pid] + list(children) for h in windows(pid)]
        raise TimeoutError("ASPack did not complete: " + repr(state)[:3000])
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for handle in children.values():
            code = w.DWORD()
            if k.GetExitCodeProcess(handle, c.byref(code)) and code.value == 259:
                k.TerminateProcess(handle, 1)
            k.WaitForSingleObject(handle, 5000)
            k.CloseHandle(handle)
