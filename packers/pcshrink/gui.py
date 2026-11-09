"""PCShrink GUI packing, using PID-owned controls and a bounded Windows job.

Supply a disposable input: the tool modifies it in place. Resource restructuring
stays enabled, export compression disabled, backups disabled, section merging is
selected explicitly. No registry preferences are written by this helper.
Returns (process_exit_or_None, dialog_texts). A successful compression dialog is
required by generate.py, followed by independent runtime checks. A process exit
alone never establishes successful compression. Only this tool process is closed.
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
G = load('pc_gui', ROOT / 'tools/win_gui.py')
ISOLATED = load('pc_job', ROOT / 'fixtures/scripts/isolated_process.py')


def pack(tool, sample, merge=True):
    process = None
    try:
        with ISOLATED.running([str(tool)], cwd=sample.parent,
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, startupinfo=G.startup_info()) as process:
            deadline = time.monotonic() + 20; main = None; clicked = False; messages = []
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    return process.returncode, messages
                for win in G.windows(process.pid):
                    title = G.caption(win)
                    if title.startswith('PCShrink v0.71') and not clicked:
                        main = win; controls = G.controls(win)
                        path_text = ctypes.create_unicode_buffer(str(sample))
                        G.message(controls[(1000, 'Edit')], 0x0c, 0, ctypes.addressof(path_text))
                        for control, value in ((1004, 1), (1005, int(merge)), (1012, 0), (1026, 0)):
                            G.message(controls[(control, 'Button')], 0xf1, value)
                            if G.message(controls[(control, 'Button')], 0xf0) != value:
                                raise ValueError('Unexpected GUI selection')
                        G.u.PostMessageW(main, 0x111, 1, controls[(1, 'Button')]); clicked = True
                    elif win != main and G.class_name(win) == '#32770':
                        controls = G.controls(win)
                        text = ' | '.join(G.caption(h) for key, h in controls.items() if key[1] == 'Static')
                        messages.append(text)
                        if (1, 'Button') in controls:
                            G.u.PostMessageW(win, 0x111, 1, controls[(1, 'Button')])
                        return process.poll(), messages
                time.sleep(.1)
            raise TimeoutError('PCShrink GUI timed out')
    finally:
        if process is not None:
            process._handle.Close()
