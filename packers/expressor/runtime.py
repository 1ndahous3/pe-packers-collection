"""Windows process support for eXPressor generation and fixture checks.

launch(..., version_fix=True) changes only the new WOW64 process's PEB OS
version to 6.1 before its first instruction. It requires an elevated caller
for the packer's own rights check. Executable bytes and global settings are
never changed. Visible startup is intentional: SW_HIDE stalls its splash.
Window operations are restricted to the launched process's PID.
"""
import ctypes as c
from ctypes import wintypes as w
import struct
import subprocess
import time
import threading

k = c.WinDLL('kernel32', use_last_error=True)
u = c.WinDLL('user32', use_last_error=True)
nt = c.WinDLL('ntdll')
CB = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
for lib, name, args, result in (
    (k, 'OpenProcess', [w.DWORD,w.BOOL,w.DWORD], w.HANDLE),
    (k, 'CloseHandle', [w.HANDLE], w.BOOL),
    (k, 'ReadProcessMemory', [w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)], w.BOOL),
    (k, 'WriteProcessMemory', [w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)], w.BOOL),
    (nt, 'NtQueryInformationProcess', [w.HANDLE,w.ULONG,c.c_void_p,w.ULONG,c.c_void_p], c.c_long),
    (nt, 'NtResumeProcess', [w.HANDLE], c.c_long),
    (u, 'EnumWindows', [CB,w.LPARAM], w.BOOL),
    (u, 'EnumChildWindows', [w.HWND,CB,w.LPARAM], w.BOOL),
    (u, 'GetWindowThreadProcessId', [w.HWND,c.POINTER(w.DWORD)], w.DWORD),
    (u, 'GetClassNameW', [w.HWND,w.LPWSTR,c.c_int], c.c_int),
    (u, 'GetDlgCtrlID', [w.HWND], c.c_int),
    (u, 'IsWindow', [w.HWND], w.BOOL),
    (u, 'IsWindowVisible', [w.HWND], w.BOOL),
    (u, 'IsWindowEnabled', [w.HWND], w.BOOL),
    (u, 'PostMessageW', [w.HWND,w.UINT,w.WPARAM,w.LPARAM], w.BOOL),
    (u, 'SendMessageTimeoutW', [w.HWND,w.UINT,w.WPARAM,w.LPARAM,w.UINT,w.UINT,c.POINTER(c.c_size_t)], c.c_size_t),
):
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = args, result


def message(hwnd, msg, a=0, b=0):
    value = c.c_size_t()
    if not u.SendMessageTimeoutW(hwnd, msg, a, b, 2, 500, c.byref(value)):
        raise TimeoutError('Window did not respond.')
    return value.value


def caption(hwnd):
    text = c.create_unicode_buffer(2048)
    try:
        message(hwnd, 13, len(text), c.addressof(text))
    except TimeoutError:
        return ''  # Busy/destroyed windows are retried within the outer deadline.
    return text.value


def class_name(hwnd):
    text = c.create_unicode_buffer(256)
    u.GetClassNameW(hwnd, text, len(text))
    return text.value


def windows(pid):
    found = []
    @CB
    def callback(hwnd, _):
        owner = w.DWORD()
        u.GetWindowThreadProcessId(hwnd, c.byref(owner))
        if owner.value == pid and u.IsWindowVisible(hwnd):
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


def snapshot(pid):
    return [(caption(h), [(key, caption(v)) for key,v in controls(h).items()])
            for h in windows(pid)]


def launch(command, cwd, version_fix=False):
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 5
    process = subprocess.Popen([str(x) for x in command], cwd=cwd,
        creationflags=4 if version_fix else 0, startupinfo=startup,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not version_fix:
        return process
    handle = None
    try:
        # Query, VM read/write/operation and PROCESS_SUSPEND_RESUME.
        handle = k.OpenProcess(0x1c38, False, process.pid)
        if not handle:
            raise c.WinError(c.get_last_error())
        peb = c.c_size_t()
        status = nt.NtQueryInformationProcess(handle, 26, c.byref(peb), c.sizeof(peb), None)
        if status or not peb.value:
            raise ValueError('Expected a WOW64 process for the packer.')
        old = c.create_string_buffer(8)
        done = c.c_size_t()
        if not k.ReadProcessMemory(handle, peb.value + 0xa4, old, 8, c.byref(done)):
            raise c.WinError(c.get_last_error())
        major, minor = struct.unpack('<II', old.raw)
        if major < 6:
            raise ValueError('Unexpected OS version in the new PEB.')
        data = struct.pack('<II', 6, 1)
        if not k.WriteProcessMemory(handle, peb.value + 0xa4, data, 8, c.byref(done)) or done.value != 8:
            raise c.WinError(c.get_last_error())
        if nt.NtResumeProcess(handle):
            raise OSError('Cannot resume the new packer process.')
        return process
    except BaseException:
        process.kill()
        process.communicate(timeout=5)
        raise
    finally:
        if handle:
            k.CloseHandle(handle)


def finish(process):
    if process.poll() is None:
        process.kill()
    return process.communicate(timeout=5)


NOTICE = ('This application was packed with an Unregistered version of eXPressor. '
          'For registration, please visit www.cgsoftlabs.ro')


def acknowledge_notice(pid):
    """Click only the observed vendor notice; never dismiss arbitrary errors."""
    clicked = 0
    for hwnd in windows(pid):
        if class_name(hwnd) != '#32770':
            continue
        items = controls(hwnd)
        texts = [caption(h) for (_, cl), h in items.items() if cl == 'Static']
        combined = ' '.join(' '.join(texts).split())
        button = items.get((2, 'Button'))
        if caption(hwnd) == 'Info' and combined == NOTICE and button and u.IsWindowEnabled(button):
            u.PostMessageW(hwnd, 0x111, 2, button)
            clicked += 1
        elif combined:
            raise ValueError('Unexpected fixture dialog: ' + caption(hwnd) + ': ' + combined)
    return clicked


def check_execution(path, arch, kind, entry=None, wait=False):
    """Require readiness, then normal exit or 2.25 seconds of wait-mode liveness.

    The timeout includes time for a visible splash. Only the exact known
    unregistered-build notice is acknowledged. No version fix is applied to
    fixtures. The caller can run this function without administrative rights.
    """
    from pathlib import Path
    import os
    path = Path(path).resolve()
    if kind == 'exe':
        command = [path] + (['--wait'] if wait else [])
    else:
        win = Path(os.environ['WINDIR'])
        host = win / ('SysWOW64' if arch == 'x86' else 'System32') / 'rundll32.exe'
        command = [host, './' + path.name + ',' + (entry or 'RunFixture')]
    process = launch(command, path.parent)
    stdout, stderr = bytearray(), bytearray()
    def collect(stream, data):
        while True:
            value = stream.read(1)
            if not value:
                return
            data.extend(value)
    readers = [threading.Thread(target=collect, args=(process.stdout, stdout), daemon=True),
               threading.Thread(target=collect, args=(process.stderr, stderr), daemon=True)]
    for thread in readers:
        thread.start()
    expected = ('pe-fixture:basic-' + kind + ':ok\n').encode('ascii')
    deadline = time.monotonic() + 60
    ready = None
    notices = 0
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                if wait:
                    raise ValueError('Wait process exited early: ' + hex(process.returncode))
                break
            notices += acknowledge_notice(process.pid)
            if bytes(stdout).replace(b'\r\n', b'\n') == expected and ready is None:
                ready = time.monotonic()
            if wait and ready is not None and time.monotonic() - ready >= 2.25:
                if process.poll() is not None:
                    raise ValueError('Wait process exited after readiness.')
                process.kill()
                break
            time.sleep(.05)
        else:
            raise TimeoutError('Fixture did not finish startup: ' + repr(snapshot(process.pid)))
        process.wait(timeout=5)
        for thread in readers:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in readers):
            raise TimeoutError('Fixture output stream did not close.')
        if (not wait and process.returncode != 0) or bytes(stdout).replace(b'\r\n', b'\n') != expected or stderr:
            raise ValueError(f'Fixture failed: exit={process.returncode:#x}, stdout={stdout!r}, stderr={stderr!r}')
        return notices
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for thread in readers:
            thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()


def pack(tool, source):
    """Full compression; return <stem>Pk output and the actual tool exit code."""
    log = source.parent / 'packing.log'
    output = source.with_name(source.stem + 'Pk' + source.suffix)
    if output.exists():
        raise ValueError('Packing requires an unused temporary output path.')
    args = [tool, source, '/s', '2', '/lm', '2', '/r', '2', '/++', '2', '/lg', log, '/e']
    process = launch(args, source.parent, version_fix=True)
    deadline = time.monotonic() + 60
    try:
        while process.poll() is None and time.monotonic() < deadline:
            for hwnd in windows(process.pid):
                title = caption(hwnd)
                if title == 'Info' or title == 'Error':
                    texts = [caption(v) for (_, cl), v in controls(hwnd).items() if cl == 'Static']
                    raise ValueError('Packer: ' + ' '.join(texts))
            time.sleep(.1)
        if process.poll() is None:
            raise TimeoutError('Packing timed out: ' + repr(snapshot(process.pid)))
        stdout, stderr = process.communicate(timeout=5)
        text = log.read_text(errors='replace') if log.exists() else ''
        if process.returncode not in (0, 0xc0000005) or not output.is_file() or 'Compression successfully done !' not in text:
            raise ValueError(f'Packing failed: exit={process.returncode}, log={text!r}, stderr={stderr!r}')
        # The pinned build faults during /e cleanup after completing the file.
        # The caller must independently validate output before publication.
        return output, process.returncode
    finally:
        finish(process)


class ShellExecuteInfo(c.Structure):
    _fields_ = [('size', w.DWORD), ('mask', w.ULONG), ('hwnd', w.HWND),
                ('verb', w.LPCWSTR), ('file', w.LPCWSTR), ('parameters', w.LPCWSTR),
                ('directory', w.LPCWSTR), ('show', c.c_int), ('instance', w.HANDLE),
                ('idlist', c.c_void_p), ('class_name', w.LPCWSTR), ('class_key', w.HANDLE),
                ('hotkey', w.DWORD), ('icon', w.HANDLE), ('process', w.HANDLE)]


def is_elevated():
    shell = c.WinDLL('shell32')
    shell.IsUserAnAdmin.restype = w.BOOL
    return bool(shell.IsUserAnAdmin())


def elevated_worker(script, work):
    """Run only the packing worker via UAC; keep fixture tests in the caller."""
    import sys
    shell = c.WinDLL('shell32', use_last_error=True)
    shell.ShellExecuteExW.argtypes = [c.POINTER(ShellExecuteInfo)]
    shell.ShellExecuteExW.restype = w.BOOL
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    k.WaitForSingleObject.restype = w.DWORD
    k.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    k.GetExitCodeProcess.restype = w.BOOL
    info = ShellExecuteInfo()
    info.size = c.sizeof(info)
    info.mask = 0x40  # SEE_MASK_NOCLOSEPROCESS
    info.verb = 'runas'
    info.file = sys.executable
    info.parameters = subprocess.list2cmdline([str(script), '--pack-worker', str(work)])
    info.directory = str(work)
    info.show = 0  # Hide the helper console, not the packer's GUI.
    if not shell.ShellExecuteExW(c.byref(info)):
        raise c.WinError(c.get_last_error())
    try:
        deadline = time.monotonic() + 300
        while k.WaitForSingleObject(info.process, 200) == 0x102:
            if time.monotonic() > deadline:
                raise TimeoutError('Elevated packing worker did not finish.')
        code = w.DWORD()
        if not k.GetExitCodeProcess(info.process, c.byref(code)):
            raise c.WinError(c.get_last_error())
        if code.value:
            raise ValueError('Packing worker failed; see its temporary worker.log.')
    finally:
        k.CloseHandle(info.process)
