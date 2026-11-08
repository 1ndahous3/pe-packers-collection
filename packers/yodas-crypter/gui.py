"""PID-scoped GUI driver for the unmodified Crypter 1.2/1.3 binaries.

pack() selects a temporary input through the file dialog, clears six optional
protection boxes, clicks Crypt and acknowledges the result. No CLI is assumed.
The one-process job closes after the result disappears, bounding legacy GUI exit.
All windows and messages belong to the child; no global window matching is used.
"""
import ctypes
import importlib.util
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
G = load('crypter_gui', ROOT / 'tools/win_gui.py')
I = load('crypter_process', ROOT / 'fixtures/scripts/isolated_process.py')

def wait_for(fn, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = fn()
        if result:
            return result
        time.sleep(0.03)
    raise TimeoutError('GUI wait')

def pack(tool, version, path, defaults=False):
    proc = None
    try:
        with I.running([str(tool)], cwd=path.parent, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=G.startup_info()) as proc:
            main = wait_for(lambda: next((h for h in G.windows(proc.pid) if (1003, 'Button') in G.controls(h) and (2006, 'Button') in G.controls(h)), None))
            time.sleep(0.2)
            ids = [2001, 2002, 2003, 2005, 2006, 2004 if version == '1.2' else 2008]
            controls = G.controls(main)
            if not defaults:
                for id in ids:
                    G.message(controls[id, 'Button'], 241, 0)
                if any((G.message(controls[id, 'Button'], 240) != 0 for id in ids)):
                    raise ValueError('Cannot clear protection options')
            G.u.PostMessageW(main, 273, 1001, controls[1001, 'Button'])
            dialog = wait_for(lambda: next((h for h in G.windows(proc.pid) if (1148, 'Edit') in G.controls(h) and (1, 'Button') in G.controls(h) and ((1121, 'SHELLDLL_DefView') in G.controls(h))), None))
            time.sleep(0.6)
            edit = G.controls(dialog)[1148, 'Edit']
            buf = ctypes.create_unicode_buffer(str(path))
            G.message(edit, 12, 0, ctypes.addressof(buf))
            G.u.PostMessageW(dialog, 273, 1, 0)
            wait_for(lambda: G.u.IsWindowEnabled(main) and G.caption(controls[1000, 'Edit']).lower() == str(path).lower())
            G.u.PostMessageW(main, 273, 1003, controls[1003, 'Button'])
            msg = wait_for(lambda: next((h for h in G.windows(proc.pid) if h != main and G.class_name(h) == '#32770' and any((k[1] == 'Button' and G.caption(c) == 'OK' for k, c in G.controls(h).items()))), None))
            text = ' | '.join((G.caption(c) for (id, cl), c in G.controls(msg).items() if cl == 'Static'))
            title = G.caption(msg)
            button = next(((k[0], c) for k, c in G.controls(msg).items() if k[1] == 'Button' and G.caption(c) == 'OK'))
            G.u.PostMessageW(button[1], 245, 0, 0)
            wait_for(lambda: msg not in G.windows(proc.pid))
            return (title, text)
    finally:
        if proc is not None and proc.poll() is not None:
            proc._handle.Close()
