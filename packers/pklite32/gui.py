"""Drive the unmodified PKLITE32 1.1 shareware GUI without installation.

The public distribution has no PKLIT32C.EXE; the manual reserves CLI/scripting
for Professional. This helper uses PID-owned Win32 controls, restores Defaults,
checks the actual section/relocation selections, and supplies a separate output.
Only visible standard preferences are changed: backups/logging/per-file settings
off, input file time retained, extra-data prompting on. Existing Defaults and
Settings registry values are restored after the owned process has ended.

Tree items use custom checked/unchecked images, not standard state checkboxes.
Reading their text/images requires a small buffer in this helper's own x86
packer process. No packer code, image data or license state is patched.
Child lifetime is bounded by the shared Windows job and a 30-second deadline.
"""
from contextlib import contextmanager
import ctypes as c
from ctypes import wintypes as w
import importlib.util
from pathlib import Path
import re
import struct
import subprocess
import time
import winreg

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


G = load('pklite_gui', ROOT/'tools/win_gui.py')
ISOLATED = load('pklite_process', ROOT/'fixtures/scripts/isolated_process.py')
K = c.WinDLL('kernel32', use_last_error=True)
for name, args, result in (
    ('VirtualAllocEx', [w.HANDLE, c.c_void_p, c.c_size_t, w.DWORD, w.DWORD], c.c_void_p),
    ('VirtualFreeEx', [w.HANDLE, c.c_void_p, c.c_size_t, w.DWORD], w.BOOL),
    ('WriteProcessMemory', [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p], w.BOOL),
    ('ReadProcessMemory', [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p], w.BOOL),
):
    fn = getattr(K, name)
    fn.argtypes, fn.restype = args, result
G.u.IsWindowVisible.argtypes, G.u.IsWindowVisible.restype = [w.HWND], w.BOOL
TITLE = 'PKLITE32(tm) - Executable File Compressor - Shareware Version'
NO_GAIN = 'The operation did not significantly reduce the file size.'


def require(condition, message):
    if not condition:
        raise ValueError(message)


@contextmanager
def preferences():
    saved = {}
    for suffix in ('Defaults', 'Settings'):
        path = 'Software\\PKWARE\\PKLITE32\\' + suffix
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                saved[path] = [winreg.EnumValue(key, i) for i in range(winreg.QueryInfoKey(key)[1])]
        except FileNotFoundError:
            saved[path] = None
    try:
        yield
    finally:
        for path, values in saved.items():
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                    current = [winreg.EnumValue(key, i)[0] for i in range(winreg.QueryInfoKey(key)[1])]
                    original_names = {v[0] for v in values or []}
                    for name in current:
                        if name not in original_names:
                            winreg.DeleteValue(key, name)
                    for name, data, kind in values or []:
                        winreg.SetValueEx(key, name, 0, kind, data)
                if values is None:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except FileNotFoundError:
                if values is not None:
                    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                        for name, data, kind in values:
                            winreg.SetValueEx(key, name, 0, kind, data)


def selections(process, tree):
    handle = int(process._handle)
    remote = K.VirtualAllocEx(handle, None, 1024, 0x3000, 4)
    require(remote and remote < 2**32, 'Cannot allocate the x86 tree-reading buffer.')
    found = {}
    try:
        def walk(item, depth=0):
            require(depth < 8, 'Unexpected tree depth.')
            visited = 0
            while item:
                visited += 1
                require(visited < 100, 'Unexpected tree size.')
                # TVITEMW, x86 layout: TEXT | IMAGE | SELECTEDIMAGE | STATE.
                data = struct.pack('<10I', 0x2b, item, 0, 0xffff, remote+64, 400, 0, 0, 0, 0)
                require(K.WriteProcessMemory(handle, remote, data, len(data), None), 'Cannot write tree buffer.')
                require(G.message(tree, 0x113e, 0, remote), 'Cannot read tree item.')
                buffer = c.create_string_buffer(1024)
                require(K.ReadProcessMemory(handle, remote, buffer, 1024, None), 'Cannot read tree buffer.')
                text = buffer.raw[64:].decode('utf-16le').split('\0')[0].strip()
                image = struct.unpack_from('<I', buffer.raw, 24)[0]
                if text.startswith('.'):
                    found[text.split()[0]] = image
                elif text == 'Preserve Relocation Information':
                    found['relocations'] = image
                child = G.message(tree, 0x110a, 4, item)
                if child:
                    walk(child, depth+1)
                item = G.message(tree, 0x110a, 1, item)
        walk(G.message(tree, 0x110a, 0))
    finally:
        K.VirtualFreeEx(handle, remote, 0, 0x8000)
    return found


@contextmanager
def owned_process(command, **kwargs):
    process = None
    try:
        with ISOLATED.running(command, **kwargs) as process:
            yield process
    finally:
        # Release the exited process object before deleting its working folder.
        # GUI callbacks can delay Python's normal Popen handle finalization.
        if process is not None:
            process._handle.Close()


def pack(tool, source, target, padded):
    require(not target.exists(), 'Packing requires a fresh output path.')
    source_bytes = source.read_bytes()
    with preferences(), owned_process([str(tool), str(source)], cwd=source.parent,
            startupinfo=G.startup_info(), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
        deadline = time.monotonic() + 30
        main = None
        def until(predicate, label):
            while time.monotonic() < deadline:
                require(process.poll() is None, f'Packer exited before {label}: {process.returncode}')
                try:
                    value = predicate()
                except TimeoutError:
                    value = None
                if value:
                    return value
                time.sleep(.05)
            raise TimeoutError('PKLITE32 timed out waiting for ' + label)
        def dialog():
            for hwnd in G.windows(process.pid):
                if hwnd != main and G.u.IsWindowVisible(hwnd) and G.class_name(hwnd) == '#32770':
                    items = G.controls(hwnd)
                    text = ' '.join(G.caption(h) for (_, cls), h in items.items() if cls == 'Static').strip()
                    return hwnd, G.caption(hwnd), text
        main = until(lambda: next((h for h in G.windows(process.pid) if G.caption(h) == TITLE), None), 'main window')
        controls = G.controls(main)
        status = until(lambda: G.caption(controls[1014, 'Static']), 'input status')
        require(dialog() is None, 'Unexpected startup dialog: ' + repr(dialog()))
        if status.endswith('it is not a valid 32 bit executable file'):
            require(not target.exists() and source.read_bytes() == source_bytes, 'Rejected input changed.')
            return 'unsupported', status
        require('Specified input file is ready to be compressed.' in status, 'Unexpected input status: ' + status)
        G.u.PostMessageW(main, 0x111, 1001, controls[1001, 'Button'])
        pref = until(lambda: next((h for h in G.windows(process.pid) if G.caption(h) == 'Preferences'), None), 'preferences')
        items = G.controls(pref)
        for identifier, state in {1016:0, 1018:0, 1023:0, 1031:1, 1041:1}.items():
            G.message(items[identifier, 'Button'], 0xf1, state)
        G.u.PostMessageW(pref, 0x111, 1, items[1, 'Button'])
        until(lambda: G.u.IsWindowEnabled(main), 'closed preferences')
        G.u.PostMessageW(main, 0x111, 1026, controls[1026, 'Button'])
        expected = {'relocations':1, '.text':1, '.rdata':0, '.data':1, '.secret':1, '.reloc':0}
        if padded:
            expected['.pad'] = 1
        until(lambda: selections(process, controls[1007, 'SysTreeView32']) == expected, 'default section selection')
        name = c.create_unicode_buffer(str(target))
        G.message(controls[1015, 'Edit'], 0xc, 0, c.addressof(name))
        require(G.caption(controls[1015, 'Edit']) == str(target), 'Wrong output filename.')
        G.u.PostMessageW(main, 0x111, 1000, controls[1000, 'Button'])
        def finished():
            notice = dialog()
            if notice:
                require(notice[1:] == ('PKLITE32', NO_GAIN), 'Unexpected packing dialog: ' + repr(notice))
                require(not target.exists(), 'Rejected packing created an output.')
                return 'no-gain', NO_GAIN
            if target.is_file() and G.u.IsWindowEnabled(controls[1000, 'Button']):
                text = G.caption(controls[1013, 'Static'])
                if re.fullmatch(r"The file was reduced to [0-9]+% of it's original size.\s*\([0-9]+ ==> [0-9]+\)", text):
                    return 'packed', text
        result = until(finished, 'compression result')
        require(source.read_bytes() == source_bytes, 'Packer modified input despite separate output.')
        return result
