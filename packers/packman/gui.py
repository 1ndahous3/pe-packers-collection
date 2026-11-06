"""Pack with the SUN DVD's early Packman GUI, using temporary fixture copies.

Compress Sections is enabled; all ripping/null-relocation options are off,
alignment is 0x200. Inputs/outputs use the edit controls, with change
notifications processed before packing. Only the launched process is controlled.
"""
import ctypes as c
import importlib.util
from pathlib import Path
import subprocess
import time
spec = importlib.util.spec_from_file_location('owned_gui', Path(__file__).resolve().parents[2]/'tools/win_gui.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def pack(tool, source, target):
    process = subprocess.Popen([str(tool)], cwd=source.parent, startupinfo=g.startup_info(),
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 25
    def until(predicate, label):
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError(f'Packman exited before {label}: {process.returncode:#x}')
            try:
                value = predicate()
            except TimeoutError:
                value = None
            if value:
                return value
            time.sleep(.05)
        raise TimeoutError('Packman timed out waiting for ' + label)
    try:
        main = until(lambda: next((h for h in g.windows(process.pid)
                                   if g.caption(h) == 'Packman Executable Image Packer'), None), 'main window')
        items = g.controls(main)
        for identifier, path in ((1002, source), (1004, target)):
            edit = items[identifier, 'Edit']
            name = c.create_unicode_buffer(str(path))
            g.message(edit, 0x0c, 0, c.addressof(name))
            g.message(g.u.GetParent(edit), 0x111, identifier | (0x300 << 16), edit)
            g.message(main, 0)
        for identifier, value in ((1009,1), (1010,0), (1011,0), (1012,0), (1013,0), (1014,0)):
            g.message(items[identifier,'Button'], 0xf1, value)
        require_output = g.caption(items[1004,'Edit'])
        if require_output != str(target):
            raise ValueError('Packman did not accept the requested output.')
        button = items[1025,'Button']
        g.u.PostMessageW(g.u.GetParent(button), 0x111, 1025, button)
        def finished():
            for hwnd in g.windows(process.pid):
                if hwnd != main and g.class_name(hwnd) == '#32770':
                    raise ValueError('Packman dialog: ' + g.caption(hwnd) + ' ' + repr(
                        [g.caption(v) for (_, cls),v in g.controls(hwnd).items() if cls == 'Static']))
            return target.is_file() and g.u.IsWindowEnabled(button)
        until(finished, 'packed output')
        g.message(main, 0)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
