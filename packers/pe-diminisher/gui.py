"""PID-owned GUI driver for PE Diminisher 0.1. Supply a disposable input.
File > Open (40001), filename edit 1148, then Commands > Encrypt File (40007).
The common dialog needs time to initialize before its filename can be assigned.
Return process status and status-bar text; packing success still needs runtime checks.
"""
import ctypes
import importlib.util
from pathlib import Path
import subprocess
import time
ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
G = load('ped_gui', ROOT / 'tools/win_gui.py')
ISOLATED = load('ped_job', ROOT / 'fixtures/scripts/isolated_process.py')


def pack(tool, sample):
    process = None
    try:
        with ISOLATED.running([str(tool)], cwd=sample.parent,
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, startupinfo=G.startup_info()) as process:
            deadline = time.monotonic() + 20; main = None; selected = False; encrypted = False
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    return process.returncode, ''
                for win in G.windows(process.pid):
                    try:
                        title = G.caption(win)
                    except TimeoutError:
                        continue
                    if title.startswith('PE Diminisher'):
                        if main is None:
                            main = win; G.u.PostMessageW(win, 0x111, 40001, 0)
                        controls = G.controls(win)
                        status = G.caption(controls[(1001, 'msctls_statusbar32')])
                        if selected and not encrypted and 'Sucessfully Opened' in status:
                            G.u.PostMessageW(main, 0x111, 40007, 0); encrypted = True
                        elif encrypted and ('Encrypted' in status or status.startswith('Error:')):
                            return None, status
                    elif title == 'Open' and not selected:
                        time.sleep(1)
                        controls = G.controls(win)
                        value = ctypes.create_unicode_buffer(str(sample))
                        G.message(controls[(1148, 'Edit')], 12, 0, ctypes.addressof(value))
                        G.u.PostMessageW(win, 0x111, 1, controls[(1, 'Button')]); selected = True
                time.sleep(.1)
            raise TimeoutError('PE Diminisher GUI timed out')
    finally:
        if process is not None:
            process._handle.Close()
