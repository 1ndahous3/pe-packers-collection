"""Drive the retained WWPack32 1.20 GUIs without installing or patching them.

Used by generate.py; no independent command-line interface. Requires Windows
and an interactive desktop. Window/control discovery is scoped to the child
PID. Mouse messages target its controls directly and do not move the user's
pointer. Toolbar/row coordinates match the original classic GUI layout; control
classes, settings, item count and selection are checked before packing.

The public demo does not support filename command-line arguments. Launch it
without arguments in an isolated directory containing only probe.exe or probe.dll. A startup
registry-write warning may leave the file list uninitialized: acknowledge only
that exact warning and reselect the current drive to populate the working folder.
No registry permissions, trial state or system settings are changed by this helper.
A normal demo notice is accepted when its button becomes available. Unexpected
errors and registration dialogs fail the run.

Select automatic sections, resources enabled, relocation stripping disabled,
safe mode enabled, no file signature, and level 0 (fastest) or 20 (best). Wait for
the progress window to close and the main window to become enabled, not merely
for the output file to change. Verify the .BAK copy before terminating only the
owned packer process. All file work occurs on disposable copies.
"""
import ctypes as c
import subprocess
import time
from ctypes import wintypes as w
u=c.WinDLL('user32',use_last_error=True)
CB=c.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
u.GetWindowThreadProcessId.argtypes=[w.HWND,c.POINTER(w.DWORD)]
u.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,c.c_int]
u.GetClassNameW.argtypes=[w.HWND,w.LPWSTR,c.c_int]
u.GetWindowRect.argtypes=[w.HWND,c.POINTER(w.RECT)]
u.IsWindowVisible.argtypes=[w.HWND]
u.IsWindowEnabled.argtypes=[w.HWND]
u.GetDlgCtrlID.argtypes=[w.HWND]
u.EnumWindows.argtypes=[CB,w.LPARAM]
u.EnumChildWindows.argtypes=[w.HWND,CB,w.LPARAM]
u.SendMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM];u.SendMessageW.restype=w.LPARAM
u.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
def text(h):
    s=c.create_unicode_buffer(2048);u.GetWindowTextW(h,s,len(s));return s.value
def item(h):
    s=c.create_unicode_buffer(256);u.GetClassNameW(h,s,len(s));r=w.RECT();u.GetWindowRect(h,c.byref(r))
    return {'hwnd':h,'class':s.value,'text':text(h),'visible':bool(u.IsWindowVisible(h)),'enabled':bool(u.IsWindowEnabled(h)),'id':u.GetDlgCtrlID(h),'rect':[r.left,r.top,r.right,r.bottom]}
def windows(pid):
    result=[]
    @CB
    def visit(h,_):
        owner=w.DWORD();u.GetWindowThreadProcessId(h,c.byref(owner))
        if owner.value==pid:
            entry=item(h);children=[]
            @CB
            def child(ch,_):children.append(item(ch));return True
            u.EnumChildWindows(h,child,0);entry['children']=children;result.append(entry)
        return True
    u.EnumWindows(visit,0);return result


def click(hwnd, x, y):
    for message, state in ((0x201, 1), (0x202, 0)):
        if not u.PostMessageW(hwnd, message, state, (y << 16) | x):
            raise c.WinError(c.get_last_error())


def visible(pid, klass):
    return next((e for e in windows(pid) if e['class'] == klass and e['visible']), None)


def button(window, label):
    control = next(e for e in window['children'] if e['text'] == label and e['enabled'])
    u.PostMessageW(control['hwnd'], 0xf5, 0, 0)


def dismiss_notice(pid):
    nag = visible(pid, 'TF_SHAREWARE')
    if nag:
        if any(ch['text'] == 'Accept' and ch['enabled'] for ch in nag['children']):
            button(nag, 'Accept')
        return True
    dialog = visible(pid, '#32770')
    if dialog:
        messages = [ch['text'] for ch in dialog['children'] if ch['class'] == 'Static' and ch['text']]
        if messages == ["Failed to set data for 'Plus software 1'"]:
            button(dialog, 'OK')
            return True
        raise ValueError(f'Unexpected WWPack32 dialog: {messages}')
    for klass in ('TMessageForm', 'TF_ORDERFORM'):
        dialog = visible(pid, klass)
        if dialog:
            raise ValueError(f'WWPack32 reported {klass}: {dialog["text"]}')
    return False


def await_window(process, klass, opener=None, timeout=40):
    deadline = time.monotonic() + timeout
    last_attempt = 0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValueError(f'WWPack32 exited before {klass}: {process.returncode}')
        if dismiss_notice(process.pid):
            time.sleep(.1)
            continue
        result = visible(process.pid, klass)
        if result and result['enabled']:
            return result
        if opener and time.monotonic() - last_attempt > .5:
            main = visible(process.pid, 'TF_WWPACK')
            if main and main['enabled']:
                opener()
                last_attempt = time.monotonic()
        time.sleep(.05)
    raise TimeoutError(f'WWPack32 did not reach {klass}.')


def pack(tool, target, level):
    """Pack one isolated probe.exe or probe.dll at level 0 or 20."""
    if target.name not in ('probe.exe', 'probe.dll') or level not in (0, 20):
        raise ValueError('Unexpected WWPack32 GUI input.')
    original = target.read_bytes()
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen([str(tool)], cwd=target.parent,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, startupinfo=startup)
    try:
        main = await_window(process, 'TF_WWPACK')
        drive = next(ch for ch in main['children'] if ch['class'] == 'TDriveComboBox')
        # Re-run the folder selection event after the startup registry warning.
        # Retain the current drive and the process's disposable working directory.
        selected = u.SendMessageW(drive['hwnd'], 0x147, 0, 0)
        if selected < 0:
            raise ValueError('No current drive in WWPack32.')
        u.SendMessageW(drive['hwnd'], 0x14e, selected, 0)
        u.SendMessageW(main['hwnd'], 0x111, (1 << 16) | (drive['id'] & 0xffff), drive['hwnd'])
        toolbar = next(ch for ch in main['children'] if ch['class'] == 'TToolBar')
        setup = await_window(process, 'TF_SETUP', lambda: click(toolbar['hwnd'], 112, 20))
        expected = {'Compress resources': 1, 'Strip relocations': 0,
                    'Manual sections selection': 0,
                    'Do not compress files that may not work': 1, 'Use file signature': 0}
        controls = {ch['text']: ch for ch in setup['children'] if ch['class'] == 'TCheckBox'}
        for label, value in expected.items():
            control = controls[label]
            if u.SendMessageW(control['hwnd'], 0xf0, 0, 0) != value:
                if not control['enabled']:
                    raise ValueError(f'Cannot select setting: {label}')
                u.PostMessageW(control['hwnd'], 0xf5, 0, 0)
                deadline = time.monotonic() + 2
                while u.SendMessageW(control['hwnd'], 0xf0, 0, 0) != value:
                    if time.monotonic() > deadline:
                        raise ValueError(f'Setting did not apply: {label}')
                    time.sleep(.05)
        track = next(ch for ch in setup['children'] if ch['class'] == 'TTrackBar')
        if [u.SendMessageW(track['hwnd'], msg, 0, 0) for msg in (0x401, 0x402)] != [0, 20]:
            raise ValueError('Unexpected compression-level range.')
        u.SendMessageW(track['hwnd'], 0x405, 1, level)
        tab = next(ch for ch in setup['children'] if ch['class'] == 'TTabSheet' and ch['text'] == 'Compression')
        u.SendMessageW(tab['hwnd'], 0x114, 4 | (level << 16), track['hwnd'])
        # Confirm all choices before accepting the settings dialog.
        for label, value in expected.items():
            if u.SendMessageW(controls[label]['hwnd'], 0xf0, 0, 0) != value:
                raise ValueError(f'Setting did not apply: {label}')
        if u.SendMessageW(track['hwnd'], 0x400, 0, 0) != level:
            raise ValueError('Compression level did not apply.')
        button(setup, 'OK')
        main = await_window(process, 'TF_WWPACK')
        listing = next(ch for ch in main['children'] if ch['class'] == 'TListView')
        if u.SendMessageW(listing['hwnd'], 0x1004, 0, 0) != 2:
            raise ValueError('Expected only the parent directory and one input file.')
        # Stock classic layout: second row, inside its icon (not blank row space).
        click(listing['hwnd'], 20, 43)
        deadline = time.monotonic() + 2
        while u.SendMessageW(listing['hwnd'], 0x1032, 0, 0) != 1:
            if time.monotonic() > deadline:
                raise ValueError('Input file was not selected.')
            time.sleep(.05)
        click(toolbar['hwnd'], 24, 20)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError('WWPack32 exited during packing.')
            if dismiss_notice(process.pid):
                time.sleep(.1)
                continue
            main = visible(process.pid, 'TF_WWPACK')
            if (main and main['enabled'] and not visible(process.pid, 'TF_COMPRESS')
                    and target.is_file() and target.read_bytes() != original):
                backup = target.with_suffix('.BAK')
                if not backup.is_file() or backup.read_bytes() != original:
                    raise ValueError('Missing or altered original backup.')
                return target.read_bytes()
            time.sleep(.05)
        raise TimeoutError('WWPack32 did not finish packing.')
    finally:
        # Avoid saving GUI preferences on exit; affect only this owned process.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
