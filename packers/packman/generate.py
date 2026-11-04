"""Generate verified Packman fixtures using the retained local source build.

Requirements: Windows x64 with WOW64, Python 3.8+ (standard library only).
Tool acquisition/build and the direct CLI syntax: build.py --help.

From the collection root:
  python packers/packman/generate.py --version 1.0-msvc2022
  python packers/packman/generate.py --version 1.0-msvc2022 --backend aplib --kind dll --mode max-new
  python packers/packman/generate.py --version 1.0-msvc2022 --output C:/Temp/packman-check
Repeat --backend, --mode, --arch or --kind to select several values.

Each invocation is packman-cli.exe ORIGINAL OUTPUT PLUGIN MODE. The driver
sets code filtering and overlay retention, file alignment 512, section name
.PACKMAN, and no stripping, header restoration or resource filters. It uses the
published engine unchanged. Profiles are aplib/lzma x normal/max-old/max-new.
EXE Max outputs were quarantined on the research host before execution; those
profiles are skipped, including when explicitly selected. Normal EXEs and all
three DLL modes are generated. amd64 probes only the first backend/mode and
must return the driver's explicit PE32-only rejection, without an output file.
This guard is collection code, not an observed response of the original GUI.

Pin all three tools. Verify input hashes and markers against shared manifests;
run temporary originals, then require packing success, unchanged input, matching
machine/magic/kind/exports, hidden full markers, exact normal stdout, exit zero,
empty stderr and sustained wait mode. DLL waits use both name and ordinal 4.
The payload checksums exercise all secrets; exact memory-byte comparison and
forced DLL rebasing are separate research checks described in internals.md.

Publish only verified PE files, named <backend>-<mode>.<kind>, under
packed-fixtures/<version>/fixture-x86-<kind>/. Different existing bytes are not
overwritten. Inputs, intermediate files and logs stay temporary. Packing has a
45-second timeout, normal execution 10 seconds; the shared wait checker kills
only its own child. This generator does not test an external unpacker, resources,
TLS, managed PE, alternate filters or optional header restoration.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
TOOLS = {'1.0-msvc2022': {
    'packman-cli.exe': '7f1ba3e7cabb0f3a794d8c829bb4a2680d9f39de5edae9d629332e4481af2e88',
    'aPLib.dll': 'dd2174e0da8183af51a3c1430c03f32fd62cbe08163b44e9d272ba3c008cd05b',
    'lzma.dll': '6cce47fae411405e3d3a85bba5e39ea465ba83faf892bea7db7c3c53dfb83eef',
}}
BACKENDS = {'aplib': 'aPLib.dll', 'lzma': 'lzma.dll'}
MODES = ('normal', 'max-old', 'max-new')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, cwd, timeout):
    start = subprocess.STARTUPINFO()
    start.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    start.wShowWindow = 0
    return subprocess.run([str(x) for x in command], cwd=cwd,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=timeout, startupinfo=start)


def check_execution(path, arch, kind):
    if kind == 'exe':
        command = [path]
    else:
        windows = Path(os.environ['WINDIR'])
        native = 'Sysnative' if (windows/'Sysnative/rundll32.exe').exists() else 'System32'
        host = windows/('SysWOW64' if arch == 'x86' else native)/'rundll32.exe'
        command = [host, './'+path.name+',RunFixture']
    result = run(command, path.parent, 10)
    require(result.returncode == 0 and not result.stderr and
            result.stdout.replace(b'\r\n', b'\n') == f'pe-fixture:basic-{kind}:ok\n'.encode(),
            f'Runtime failure: exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')


def generate_case(tool, work, pe, wait, arch, kind, backends, modes):
    folder = ROOT/'fixtures/bin'/arch
    manifest = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    ref = next(x for x in manifest['artifacts'] if x['id'] == f'basic-{kind}-{arch}')
    source = folder/ref['path']
    require(digest(source) == ref['sha256'], 'Shared original differs from its manifest.')
    original_bytes = source.read_bytes()
    directory = work/f'{arch}-{kind}'
    directory.mkdir()
    original = directory/f'original.{kind}'
    original.write_bytes(original_bytes)
    verified = {}
    try:
        check_execution(original, arch, kind)
        original_pe = pe.inspect_pe(original)
        for marker in ref['secrets']:
            require(bytes.fromhex(marker['hex']) in original_bytes,
                    f'Original marker missing: {marker["id"]}')
        profiles = [(b, m) for b in backends for m in modes]
        if arch == 'amd64':
            profiles = profiles[:1]
        for backend, mode in profiles:
            if arch == 'x86' and kind == 'exe' and mode != 'normal':
                print(f'{arch}/{kind}/{backend}/{mode}: SKIP; host quarantined Max EXEs; runtime unverified.', flush=True)
                continue
            target = directory/f'{backend}-{mode}.{kind}'
            result = run([tool, original, target, tool.parent/BACKENDS[backend], mode], directory, 45)
            text = result.stdout.decode('ascii', errors='replace')
            require(text.startswith('Packman 1.0 - local MSVC source build / collection CLI\r\n'),
                    'Unexpected Packman CLI banner.')
            require(original.read_bytes() == original_bytes, 'Temporary original was modified.')
            if arch == 'amd64':
                require(result.returncode == 2 and not result.stderr and not target.exists() and
                        text.endswith('UNSUPPORTED: native i386 PE32 only (CLI guard)\r\n'),
                        f'Unexpected amd64 result: {result.returncode}, {text}, {result.stderr!r}')
                print(f'{arch}/{kind}: UNSUPPORTED; collection CLI rejects PE32+ before packing.', flush=True)
                continue
            require(result.returncode == 0 and not result.stderr and 'PACKED: ' in text and target.is_file(),
                    f'Packing failed: exit={result.returncode:#x}, {text[-1200:]}, {result.stderr!r}')
            packed_bytes = target.read_bytes()
            require(packed_bytes != original_bytes, 'Output is unchanged.')
            packed_pe = pe.inspect_pe(target)
            for field in ('machine', 'optional_header', 'kind', 'exports'):
                require(packed_pe[field] == original_pe[field], f'Packed PE differs in {field}.')
            visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in packed_bytes]
            require(not visible, f'Full secret markers remain visible: {visible}')
            check_execution(target, arch, kind)
            wait.check_fixture(target, arch, kind)
            require(target.read_bytes() == packed_bytes, 'Execution modified the packed file.')
            verified[Path(f'fixture-{arch}-{kind}')/target.name] = packed_bytes
            print(f'{arch}/{kind}/{backend}/{mode}: PASS normal + wait; markers hidden; '
                  f'{len(original_bytes)} -> {len(packed_bytes)} bytes.', flush=True)
    finally:
        require(digest(source) == ref['sha256'], 'Shared original was modified.')
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True, choices=TOOLS)
    parser.add_argument('--backend', action='append', choices=BACKENDS)
    parser.add_argument('--mode', action='append', choices=MODES)
    parser.add_argument('--arch', action='append', choices=['x86', 'amd64'])
    parser.add_argument('--kind', action='append', choices=['exe', 'dll'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows x64 with WOW64 is required.')
    tool_dir = PACKER/'tools'/args.version/'bin'
    for name, expected in TOOLS[args.version].items():
        require((tool_dir/name).is_file() and digest(tool_dir/name) == expected,
                f'Missing or unexpected Packman tool: {name}')
    pe = load_module('fixture_manifest', ROOT/'fixtures/scripts/manifest.py')
    wait = load_module('fixture_wait', ROOT/'fixtures/scripts/check_wait.py')
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    backends = list(dict.fromkeys(args.backend or BACKENDS))
    modes = list(dict.fromkeys(args.mode or MODES))
    with tempfile.TemporaryDirectory(prefix='pe-packman-') as temporary:
        work = Path(temporary)
        for name in TOOLS[args.version]:
            shutil.copyfile(tool_dir/name, work/name)
        verified = {}
        for arch in dict.fromkeys(args.arch or ['x86', 'amd64']):
            for kind in dict.fromkeys(args.kind or ['exe', 'dll']):
                verified.update(generate_case(work/'packman-cli.exe', work, pe, wait,
                                              arch, kind, backends, modes))
        # Preflight every path before publishing any file.
        for relative, data in verified.items():
            target = output/relative
            require(not target.exists() or target.read_bytes() == data,
                    f'Refusing to overwrite different output: {target}')
        for relative, data in verified.items():
            target = output/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                with target.open('xb') as stream:
                    stream.write(data)
        print(f'Published verified fixtures to {output}' if verified else 'No fixtures published.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(1)
