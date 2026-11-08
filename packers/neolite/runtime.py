"""Run NeoLite fixtures with bounded lifetime and the observed trial notice.

Windows x64 with WOW64 and an interactive desktop; standard library only.
Imported by generate.py. The exact NeoLite notice is answered No through a
window owned by the launched PID. Yes would open the vendor website and is
never selected. Unknown dialogs fail, including rundll32 loader errors.

Each fixture starts suspended inside the shared one-process Windows job.
Normal execution requires the exact success line, exit zero and empty stderr.
Wait mode requires the success line followed by 2.25 seconds alive, then kills
only this test process. All paths, including exceptions, close the job.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import time
import threading
from ctypes import wintypes as w

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUI = load('neolite_win_gui', ROOT/'tools/win_gui.py')
ISOLATED = load('neolite_process', ROOT/'fixtures/scripts/isolated_process.py')
GUI.u.IsWindowVisible.argtypes = [w.HWND]
GUI.u.IsWindowVisible.restype = w.BOOL
NOTICE = ('This program was compressed with the demonstration vesion of NeoLite. '
          'Click the Yes button to visit our web site (www.neoworx.com) to purchase '
          'the full product. Click No to run the compressed program.')


def acknowledge(pid, acknowledged):
    for hwnd in GUI.windows(pid):
        if not GUI.u.IsWindowVisible(hwnd) or GUI.class_name(hwnd) != '#32770':
            continue
        if hwnd in acknowledged:
            continue
        controls = GUI.controls(hwnd)
        text = ' '.join(' '.join(GUI.caption(h) for (_, cls), h in controls.items()
                                if cls == 'Static').split())
        button = controls.get((7, 'Button'))
        if text != NOTICE or not button or GUI.caption(button) != '&No':
            raise ValueError('Unexpected dialog: ' + GUI.caption(hwnd) + ': ' + text)
        if GUI.u.IsWindowEnabled(button):
            if not GUI.u.PostMessageW(hwnd, 0x111, 7, button):  # WM_COMMAND / IDNO
                raise OSError('Cannot acknowledge the NeoLite notice.')
            acknowledged.add(hwnd)


def check(path, arch, kind, entry=None, wait=False, expect_notice=False):
    path = Path(path).resolve()
    if kind == 'exe':
        command = [str(path)] + (['--wait'] if wait else [])
    else:
        windows = Path(os.environ['WINDIR'])
        native = 'Sysnative' if (windows/'Sysnative/rundll32.exe').exists() else 'System32'
        host = windows/('SysWOW64' if arch == 'x86' else native)/'rundll32.exe'
        command = [str(host), './'+path.name+','+(entry or 'RunFixture')]
    expected = f'pe-fixture:basic-{kind}:ok\n'.encode('ascii')
    notices = set()
    with ISOLATED.running(command, cwd=path.parent, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        stdout, stderr = bytearray(), bytearray()
        def collect(stream, buffer):
            while True:
                chunk = stream.read(1)
                if not chunk:
                    break
                buffer.extend(chunk)
        readers = [threading.Thread(target=collect, args=(process.stdout, stdout), daemon=True),
                   threading.Thread(target=collect, args=(process.stderr, stderr), daemon=True)]
        for thread in readers:
            thread.start()
        deadline, ready = time.monotonic() + 15, None
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    if wait:
                        raise ValueError(f'Wait mode exited early: {process.returncode:#x}')
                    break
                try:
                    acknowledge(process.pid, notices)
                except TimeoutError:
                    # A window can disappear between enumeration and WM_GETTEXT.
                    if process.poll() is None:
                        continue
                if bytes(stdout).replace(b'\r\n', b'\n') == expected and ready is None:
                    ready = time.monotonic()
                if wait and ready is not None and time.monotonic() - ready >= 2.25:
                    if process.poll() is not None:
                        raise ValueError('Wait mode exited after readiness.')
                    process.kill()
                    break
                time.sleep(.05)
            else:
                raise TimeoutError('Fixture did not reach the expected completion state.')
            process.wait(timeout=5)
            for thread in readers:
                thread.join(timeout=5)
            if any(thread.is_alive() for thread in readers):
                raise TimeoutError('Fixture output stream did not close.')
            if (not wait and process.returncode != 0) or bytes(stdout).replace(b'\r\n', b'\n') != expected or stderr:
                raise ValueError(f'Runtime exit={process.returncode:#x}; stdout={stdout!r}; stderr={stderr!r}')
            if len(notices) != int(expect_notice):
                raise ValueError(f'Unexpected number of trial notices: {len(notices)}')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for thread in readers:
                thread.join(timeout=5)
            process.stdout.close()
            process.stderr.close()


def verify(path, arch, kind, packed=False):
    expect_notice = packed and kind == 'exe'
    check(path, arch, kind, expect_notice=expect_notice)
    for entry in (('WaitFixture', '#4') if kind == 'dll' else (None,)):
        check(path, arch, kind, entry=entry, wait=True, expect_notice=expect_notice)
