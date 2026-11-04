"""Generate UPack / WinUpack fixtures with the retained public builds.

Acquisition and requirements
----------------------------
Windows x64 with WOW64, Python 3.8+; standard library only. GUI mode needs an
interactive desktop. Extract the executable members from these public archives:
  0.39-final CLI: https://www.sac.sk/download/pack/upack039.zip -> Upack.exe
  0.39-final GUI: https://www.sac.sk/download/pack/wupck039.zip -> WinUpackE.exe
  0.399 CLI: https://www.sac.sk/download/pack/upack399.rar -> Upack.exe
Put them under tools/<version>/bin/. No other runtime files are required.
The archives include the author's Readme.txt and no buildable packer sources.
0.399 is a later console-only correction, adding -brute for resource packing.

Examples, from the collection root:
  python packers/upack/generate.py --version 0.39-final
  python packers/upack/generate.py --version 0.399
  python packers/upack/generate.py --version 0.39-final --frontend gui
  python packers/upack/generate.py --version 0.399 --output C:/Temp/upack-check
Repeat --arch x86|amd64 or --kind exe|dll to select cases.

Profile and verification
------------------------
Packing modifies a disposable copy in place:
  Upack.exe <absolute-packed.exe-or-dll> -c3 -f128 -red
LC=3, FB=128, preserve overlay; keep exports and relocations. No -set, -srt,
-rlc, -force, -rai or -brute. gui.py applies the same options with backups off.
Do not run multiple packing jobs concurrently (the author's restriction).
No PE headers, input bytes or output bytes are patched.

CLI requires the matching version banner, exit zero and Completed!, not merely
exit zero. GUI mode requires its terminal log and closes through WM_CLOSE
(normal exit 2). PE32+ fixture rejection is recognized only for these pinned
builds, exact error 1018 (Exceptional image base) and unchanged input. Other
errors fail the case. These builds parse PE32+ as PE32; -force is not a fix
(see internals.md). No failed or unchanged output is published.

Check source hashes and markers against manifests and run temporary originals.
Packed machine, kind and DLL names/ordinals must survive. Normal execution must
print the exact success line, exit zero and leave stderr empty. The shared wait
checker requires --wait, or WaitFixture by name and ordinal 4, to print readiness
and remain alive for more than two sleep intervals. These runs exercise all four
runtime marker checksums. Full marker visibility is a separate static check.
The one-off exact memory-marker and observed-rebasing checks are described in
internals.md; generation does not claim to test forced relocation or an unpacker.

Only passing PE files go into packed-fixtures/<version>/fixture-<arch>-<kind>.
Different existing output is refused; byte-identical output is accepted, allowing
CLI/GUI equivalence checks against the retained fixtures. Logs, failed files and
original copies are temporary. Each child has a 30-second timeout; cleanup only
terminates owned processes. Exit 1 means a failed case, exit 2 an argument error.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
TOOLS = {
    '0.39-final': {
        'banner': '0.39',
        'cli': ('Upack.exe','4574b8b41869d79bbcadd98b0f2695d28c5f29d0aadc32bd62e83b0082d7898f'),
        'gui': ('WinUpackE.exe','7ae78bec94af597d27dd66b681300da0004945434e4ad2b11c60321ea0bd90e5'),
    },
    '0.399': {
        'banner': '0.399',
        'cli': ('Upack.exe','bbbf9630c2e0990e6d8cbb52b5842e7d7a1def8e844c2dcb01a1f8106d82bdd7'),
    },
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_execution(path, arch, kind):
    if kind == 'exe':
        command = [path]
    else:
        windows = Path(os.environ['WINDIR'])
        native = 'Sysnative' if (windows/'Sysnative/rundll32.exe').exists() else 'System32'
        host = windows/('SysWOW64' if arch == 'x86' else native)/'rundll32.exe'
        command = [host, './'+path.name+',RunFixture']
    result = subprocess.run([str(x) for x in command], cwd=path.parent,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    require(result.returncode == 0 and
            result.stdout.replace(b'\r\n',b'\n') == f'pe-fixture:basic-{kind}:ok\n'.encode('ascii') and
            not result.stderr,
            f'Runtime failure: exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')


def pack(args, tool, target, gui):
    if args.frontend == 'gui':
        code, text = gui.pack(tool,target)
        require(code == 2, f'Unexpected WinUpack exit: {code}')
        rejection = '[ERROR:1018] Exceptional image base'
    else:
        start = subprocess.STARTUPINFO()
        start.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        start.wShowWindow = 0
        result = subprocess.run([str(tool),str(target),'-c3','-f128','-red'],
            cwd=target.parent, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=30, startupinfo=start)
        text = result.stdout.decode('latin1')
        banner = re.search(r'Upack (\S+)\s+>',text)
        require(banner is not None and banner.group(1) == TOOLS[args.version]['banner'],
                'Unexpected UPack banner.')
        require(result.returncode == 0 and not result.stderr,
                f'UPack failed: exit={result.returncode:#x}, stderr={result.stderr!r}')
        rejection = 'Error:[1018] Exceptional image base'
    return text, rejection


def generate_case(args, source_tool, output, work, pe, wait, gui, arch, kind):
    folder = ROOT/'fixtures/bin'/arch
    manifest = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    ref = next(x for x in manifest['artifacts'] if x['id'] == f'basic-{kind}-{arch}')
    source = folder/ref['path']
    require(digest(source) == ref['sha256'], 'Shared original differs from its manifest.')
    original_bytes = source.read_bytes()
    try:
        original = work/f'original.{kind}'
        original.write_bytes(original_bytes)
        check_execution(original,arch,kind)
        original_pe = pe.inspect_pe(original)
        for marker in ref['secrets']:
            require(bytes.fromhex(marker['hex']) in original_bytes,
                    f'Original marker missing: {marker["id"]}')
        tool = work/source_tool.name
        shutil.copyfile(source_tool,tool)
        target = work/f'packed.{kind}'
        target.write_bytes(original_bytes)
        text, rejection = pack(args,tool,target,gui)
        packed_bytes = target.read_bytes()
        if arch == 'amd64' and rejection in text and 'Completed!' not in text and packed_bytes == original_bytes:
            print(f'{arch}/{kind}: UNSUPPORTED PE32+ (1018; unchanged input).',flush=True)
            return
        require('Completed!' in text and 'Error:[' not in text and '[ERROR:' not in text,
                'Packing did not complete: '+text[-1500:])
        require(packed_bytes != original_bytes, 'Packing left the input unchanged.')
        packed_pe = pe.inspect_pe(target)
        for field in ('machine','optional_header','kind','exports'):
            require(packed_pe[field] == original_pe[field], f'Packed PE differs in {field}.')
        check_execution(target,arch,kind)
        wait.check_fixture(target,arch,kind)
        require(target.read_bytes() == packed_bytes, 'Execution modified the packed file.')
        require(original.read_bytes() == original_bytes, 'Temporary original was modified.')
        visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in packed_bytes]
        destination = output/f'fixture-{arch}-{kind}'/target.name
        require(not destination.exists() or destination.read_bytes() == packed_bytes,
                f'Refusing to overwrite different output: {destination}')
        destination.parent.mkdir(parents=True,exist_ok=True)
        if not destination.exists():
            with destination.open('xb') as stream:
                stream.write(packed_bytes)
        print(f'{arch}/{kind}: PASS normal + wait; full markers visible={visible}; '
              f'bytes={len(original_bytes)}->{len(packed_bytes)}',flush=True)
        print(f'  DYNAMIC_BASE={packed_pe["dynamic_base"]}; NX_COMPAT={packed_pe["nx_compatible"]}; '
              f'relocations size={packed_pe["relocations_size"]}; sections='
              f'{[s["name"] for s in packed_pe["sections"]]}',flush=True)
    finally:
        require(digest(source) == ref['sha256'], 'Shared original was modified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version',required=True,choices=TOOLS)
    parser.add_argument('--frontend',choices=['cli','gui'],default='cli')
    parser.add_argument('--arch',choices=['x86','amd64'],action='append')
    parser.add_argument('--kind',choices=['exe','dll'],action='append')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows is required.')
    if args.frontend not in TOOLS[args.version]:
        parser.error('0.399 has no GUI build in its distribution.')
    name, expected = TOOLS[args.version][args.frontend]
    tool = PACKER/'tools'/args.version/'bin'/name
    require(tool.is_file() and digest(tool) == expected, 'Missing or unexpected UPack executable.')
    pe = load_module('fixture_pe',ROOT/'fixtures/scripts/manifest.py')
    wait = load_module('fixture_wait',ROOT/'fixtures/scripts/check_wait.py')
    gui = load_module('upack_gui',PACKER/'gui.py') if args.frontend == 'gui' else None
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    print(f'UPack {args.version}; {args.frontend}; LC=3 FB=128 preserve overlay/exports/relocations',flush=True)
    failures = 0
    with tempfile.TemporaryDirectory(prefix='pe-upack-') as temporary:
        work = Path(temporary).resolve()
        require(work.parent == Path(tempfile.gettempdir()).resolve(), 'Unexpected temporary directory.')
        for arch in dict.fromkeys(args.arch or ['x86','amd64']):
            for kind in dict.fromkeys(args.kind or ['exe','dll']):
                case = work/f'{arch}-{kind}'
                case.mkdir()
                try:
                    generate_case(args,tool,output,case,pe,wait,gui,arch,kind)
                except (ValueError,OSError,subprocess.TimeoutExpired,StopIteration) as error:
                    failures += 1
                    print(f'{arch}/{kind}: FAIL: {error}',file=sys.stderr,flush=True)
    require(digest(tool) == expected, 'Stored packer was modified.')
    return 1 if failures else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError,OSError,subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
