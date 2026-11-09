"""PID-scoped automation of the unmodified Protector 1.03.2/1.03.3 GUI.

pack(tool, version, path) processes a temporary fixture in place. It selects
compression level 10, .yP section name, and disables all thirteen option boxes.
Only the known warning about unrecognized fixture section names is accepted;
other errors are returned to the caller. All waits and child lifetime are bounded.

The program stores settings in HKCU Software\\yoda's Protector (32-bit view).
Snapshot its values, seed the explicit profile, then restore values/key absence
after the owned child exits, including on errors. Do not run another instance or
another generator concurrently: this application's settings are shared per user.
"""
from contextlib import contextmanager
import ctypes
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import winreg

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
KEY = r"Software\yoda's Protector"
BOXES = (2001, 2002, 2003, 2005, 2006, 2008, 1044, 1045, 1046, 1047, 1050, 1051, 1057)
WARNING = "Invalid PE file! It might be protected by another tool."


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


G = load("protector_windows", ROOT / "tools/win_gui.py")
I = load("protector_process", ROOT / "fixtures/scripts/isolated_process.py")


@contextmanager
def settings():
    access = winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_32KEY
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, access) as key:
            old = [winreg.EnumValue(key, i) for i in range(winreg.QueryInfoKey(key)[1])]
    except FileNotFoundError:
        old = None
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY, 0, access) as key:
            for name, value in (("ProtectionFlags", 0), ("AdvancedFlags", 0),
                                ("CompressLevel", 10), ("LanguageID", 0)):
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
            winreg.SetValueEx(key, "SectionName", 0, winreg.REG_SZ, ".yP")
        yield
    finally:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY, 0, access) as key:
            names = [winreg.EnumValue(key, i)[0] for i in range(winreg.QueryInfoKey(key)[1])]
            for name in names:
                winreg.DeleteValue(key, name)
            for name, value, kind in old or []:
                winreg.SetValueEx(key, name, 0, kind, value)
        if old is None:
            winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, KEY, winreg.KEY_WOW64_32KEY)


def wait_for(fn, process, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        if process.poll() is not None:
            raise RuntimeError(f"Protector GUI exited {process.returncode:#x}")
        time.sleep(0.03)
    raise TimeoutError("Protector GUI wait expired")


def pack(tool, version, path):
    process = None
    with settings():
        try:
            with I.running([str(tool)], cwd=path.parent, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           startupinfo=G.startup_info()) as process:
                main = wait_for(lambda: next((h for h in G.windows(process.pid)
                                             if G.class_name(h) == "yPClass"), None), process)
                if version not in G.caption(main):
                    raise ValueError("Unexpected Protector GUI version")
                time.sleep(0.2)
                G.u.PostMessageW(main, 0x111, 32803, 0)  # Options
                wait_for(lambda: all((i, "Button") in G.controls(main) for i in BOXES), process)
                time.sleep(0.2)
                controls = G.controls(main)
                for id in BOXES:
                    button = controls[id, "Button"]
                    if G.message(button, 0xF0):
                        G.message(button, 0xF5)  # BM_CLICK also updates internal state
                if any(G.message(controls[i, "Button"], 0xF0) for i in BOXES):
                    raise ValueError("Cannot clear Protector options")
                if G.message(controls[1042, "msctls_trackbar32"], 0x400) != 10:
                    raise ValueError("Unexpected compression level")
                if G.caption(controls[1031, "Edit"]) != ".yP":
                    raise ValueError("Unexpected loader section name")
                G.u.PostMessageW(main, 0x111, 1022, 0)  # File Open
                dialog = wait_for(lambda: next((h for h in G.windows(process.pid)
                    if (1148, "Edit") in G.controls(h) and
                       (1121, "SHELLDLL_DefView") in G.controls(h)), None), process)
                time.sleep(0.3)
                text = ctypes.create_unicode_buffer(str(path))
                G.message(G.controls(dialog)[1148, "Edit"], 0xC, 0, ctypes.addressof(text))
                G.u.PostMessageW(dialog, 0x111, 1, 0)
                wait_for(lambda: (1000, "Edit") in G.controls(main) and
                    G.caption(G.controls(main)[1000, "Edit"]).lower() == str(path).lower()
                    and G.u.IsWindowEnabled(main), process)
                G.u.PostMessageW(main, 0x111, 32796, 0)  # Protect
                accepted = set()

                def result_dialog():
                    for hwnd in G.windows(process.pid):
                        if hwnd == main or G.class_name(hwnd) != "#32770":
                            continue
                        children = G.controls(hwnd)
                        text = " ".join(G.caption(c) for (_, cls), c in children.items()
                                        if cls == "Static").strip()
                        if G.caption(hwnd) == "Warning" and text.startswith(WARNING):
                            if (6, "Button") in children and hwnd not in accepted:
                                G.u.PostMessageW(children[6, "Button"], 0xF5, 0, 0)
                                accepted.add(hwnd)
                            continue
                        button = next((c for (_, cls), c in children.items()
                                       if cls == "Button" and G.caption(c) == "OK"), None)
                        if button and text:
                            return hwnd, button, G.caption(hwnd), text
                    return None

                hwnd, button, title, text = wait_for(result_dialog, process)
                G.u.PostMessageW(button, 0xF5, 0, 0)
                wait_for(lambda: hwnd not in G.windows(process.pid), process)
                return title, text
        finally:
            if process is not None and process.poll() is not None:
                process._handle.Close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", type=Path)
    parser.add_argument("version", choices=("1.03.2", "1.03.3"))
    parser.add_argument("sample", type=Path)
    args = parser.parse_args()
    try:
        title, message = pack(args.tool.resolve(), args.version, args.sample.resolve())
        print(json.dumps({"title": title, "message": message}), flush=True)
    except (ValueError, RuntimeError, TimeoutError) as error:
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}), flush=True)
