"""Drive RLPack Full 1.21 with an explicit compression/CRC profile.

Called by generate.py. Uses temporary tools and fixture copies. Selects the
Full Edition stub, aPLib/LZMA, CRC and memory protection; optional anti-cracking,
iBox, import redirection, stripping, download and password features stay off.
Open/Save dialogs support both classic and current Windows filename controls.
Every window belongs to the launched PID; unexpected dialogs fail the run.
"""
import ctypes as c
import importlib.util
from pathlib import Path
import subprocess
import time

spec = importlib.util.spec_from_file_location('owned_gui', Path(__file__).resolve().parents[2]/'tools/win_gui.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def pack(tool, source, target, backend):
    process = subprocess.Popen([str(tool)], cwd=tool.parent, startupinfo=g.startup_info(),
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 30
    main = None

    def until(predicate, label):
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError(f'RLPack exited before {label}: {process.returncode:#x}')
            try:
                value = predicate()
            except TimeoutError:  # A control may disappear during a dialog transition.
                value = None
            if value:
                return value
            time.sleep(.05)
        raise TimeoutError('RLPack timed out waiting for ' + label)

    def check_dialogs():
        for hwnd in g.windows(process.pid):
            if hwnd != main and g.class_name(hwnd) == '#32770':
                title = g.caption(hwnd)
                if title in ('[Error]', 'Info:', 'LOCKED!'):
                    detail = [g.caption(v) for (_, cls), v in g.controls(hwnd).items()
                              if cls == 'Static' and g.caption(v)]
                    raise ValueError(f'RLPack dialog: {title}: {detail}')

    def filename_dialog(path, title=None):
        def ready():
            check_dialogs()
            for hwnd in g.windows(process.pid):
                if hwnd == main or (title and g.caption(hwnd) != title):
                    continue
                items = g.controls(hwnd)
                edit = items.get((1148, 'Edit'), items.get((1001, 'Edit')))
                if edit and (1121, 'SHELLDLL_DefView') in items and (1, 'Button') in items:
                    return hwnd, items, edit
        hwnd, items, edit = until(ready, title or 'Open dialog')
        name = c.create_unicode_buffer(str(path))
        g.message(edit, 0x0c, 0, c.addressof(name))
        g.u.PostMessageW(hwnd, 0x111, 1, items[1, 'Button'])

    try:
        main = until(lambda: next((h for h in g.windows(process.pid)
                                  if g.caption(h) == 'RLPack - FullEdition'), None), 'main window')
        check_dialogs()
        items = g.controls(main)
        if g.caption(items[1004, 'ComboBox']) != 'Full Edition':
            raise ValueError('Expected the Full Edition stub.')
        for identifier, value in {600:0, 601:0, 602:0, 623:0, 606:1, 607:0, 609:0,
                                  610:1, 611:1, 612:0, 615:0, 616:1, 617:0,
                                  618:0, 619:0, 1100:0, 620:0}.items():
            g.message(items[identifier, 'Button'], 0xf1, value)
        compressor = items[1001, 'ComboBox']
        g.message(compressor, 0x14e, 0 if backend == 'aplib' else 1)
        g.message(main, 0x111, 1001 | (1 << 16), compressor)
        if not g.caption(compressor).lower().startswith(backend):
            raise ValueError('Unexpected compressor selection.')
        g.u.PostMessageW(main, 0x111, 108, items[108, 'Button'])
        filename_dialog(source)
        until(lambda: g.caption(items[102, 'Edit']) == str(source), 'selected input')
        g.u.PostMessageW(main, 0x111, 107, items[107, 'Button'])
        filename_dialog(target, 'Save packed file...')
        def finished():
            check_dialogs()
            return target.is_file() and g.u.IsWindowEnabled(items[107, 'Button'])
        until(finished, 'written output')
        g.message(main, 0)
        logger = items[111, 'ListBox']
        lines = []
        count = g.message(logger, 0x18b)
        if not 0 <= count < 1000:
            raise ValueError('Unexpected RLPack log length.')
        for index in range(count):
            text = c.create_unicode_buffer(4096)
            size = g.message(logger, 0x18a, index)
            if not 0 <= size < len(text):
                raise ValueError('Unexpected RLPack log item.')
            g.message(logger, 0x189, index, c.addressof(text))
            lines.append(text.value)
        if 'File has been packed!' not in lines or 'Packing ended...' not in lines:
            raise ValueError('RLPack did not confirm success: ' + repr(lines))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
