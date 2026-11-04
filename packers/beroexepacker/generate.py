"""Generate and verify BeRoEXEPacker fixtures from the shared originals.

Acquisition
-----------
Download https://www.rosseaux.net/downloads/bep.zip (password: beroexepacker).
Extract bep.exe with 7-Zip into tools/1.00.2017.01.27/bin/ beside this script.
The official archive contains only the executable; no buildable sources.
Requirements: Windows x64 with WOW64 and Python 3.8+; standard library only.

Usage from the collection root:
  python packers/beroexepacker/generate.py --version 1.00.2017.01.27
  python packers/beroexepacker/generate.py --version 1.00.2017.01.27 --algorithm lzbrr
  python packers/beroexepacker/generate.py --version 1.00.2017.01.27 --arch x86 --kind dll
  python packers/beroexepacker/generate.py --version 1.00.2017.01.27 --output C:/Temp/bep-check
Repeat --algorithm, --arch or --kind to select several values.

Profile
-------
For each temporary original, the exact command is:
  bep.exe original.exe output.exe +ca=ALGORITHM +x=0 +fuls +sd
      -set -srt -stls -so -srs -sph -sphe -ibh -ibo -f -t -64k
Use original.dll/output.dll for DLLs. All switches are separate arguments.
The six profiles are LZBRS, LZBRR, LZBRA, LZMAU, LZBRCM0 and CTX1. They cover
compression families, not every level or option. LZBRCM0 limits memory use.
Explicit +X=0 matches the automatic mode on these small fixtures; forcing
+X=1/2 hangs the tested DLL. No headers, inputs or outputs are patched.
Strip-debug is enabled; export/relocation/TLS/resource/overlay stripping,
special headers, import hashing, ordinal conversion and 64k mode are disabled.
Despite -srt, EXE outputs have no relocation directory. DLLs pass at their
preferred base but failed the separate forced-base-collision test. See internals.md.

Verification and storage
------------------------
Pin the packer hash and version banner. Verify source hashes and markers against
manifests, then run temporary originals. Require exit zero, Done... and an output
file. For x86, verify PE machine/magic/kind and export names/ordinals, exact normal
stdout and empty stderr, then --wait or WaitFixture by name and ordinal 4.
Full markers must be absent from the packed file; runtime checksums verify them.
Exact memory-byte verification is a separate research check in internals.md.

For amd64, probe the first selected algorithm only (LZBRR by default). The pinned
build falsely reports success but emits i386/PE32 with ImageBase 1. Recognize
only this specific incompatible output, discard it and never execute it. Other
unexpected behavior is a failure. --arch amd64 publishes no files.

Publish only passing files as packed-fixtures/<version>/fixture-x86-<kind>/
<algorithm>.<kind>. Refuse to replace different existing bytes. Tool, original,
failed output and logs stay temporary. Packing has a 45-second timeout; normal
runs have 10 seconds. Wait checks terminate only their own process. Exit 1 means
a failed check; exit 2 means invalid arguments. Generation does not test an
unpacker, forced relocation, resources, TLS or alternate filters.
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
TOOLS = {'1.00.2017.01.27': '3f81abdc1ec3971be78db8a8c38ced0970bc9eec3415046596e47a5ca85cd272'}
ALGORITHMS = ('lzbrr', 'lzbrs', 'lzbra', 'lzmau', 'lzbrcm0', 'ctx1')
OPTIONS = ['+x=0', '+fuls', '+sd', '-set', '-srt', '-stls', '-so', '-srs',
           '-sph', '-sphe', '-ibh', '-ibo', '-f', '-t', '-64k']


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


def generate_case(args, tool, output, work, pe, wait, arch, kind, algorithms):
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
    try:
        check_execution(original, arch, kind)
        original_pe = pe.inspect_pe(original)
        for marker in ref['secrets']:
            require(bytes.fromhex(marker['hex']) in original_bytes,
                    f'Original marker missing: {marker["id"]}')
        for algorithm in (algorithms[:1] if arch == 'amd64' else algorithms):
            target = directory/f'{algorithm}.{kind}'
            result = run([tool, original, target, '+ca='+algorithm, *OPTIONS], directory, 45)
            text = result.stdout.decode('latin1')
            require(text.startswith('BeRoEXEPacker - Version '+args.version+' - '),
                    'Unexpected BeRoEXEPacker banner.')
            require(result.returncode == 0 and not result.stderr and
                    'Done...' in text and target.is_file(),
                    f'Packing failed: exit={result.returncode:#x}, {text[-1200:]}, {result.stderr!r}')
            require(original.read_bytes() == original_bytes, 'Temporary original was modified.')
            packed_bytes = target.read_bytes()
            require(packed_bytes != original_bytes, 'Output is unchanged.')
            packed_pe = pe.inspect_pe(target)
            if arch == 'amd64':
                require(packed_pe['machine'] == '0x014c' and
                        packed_pe['optional_header'] == '0x010b' and
                        int(packed_pe['image_base'], 16) == 1 and
                        packed_pe['kind'] == original_pe['kind'] and not packed_pe['exports'],
                        'Unexpected PE32+ result; investigate before classifying it.')
                print(f'{arch}/{kind}/{algorithm}: UNSUPPORTED; false success emits i386/PE32; discarded.', flush=True)
                continue
            for field in ('machine', 'optional_header', 'kind', 'exports'):
                require(packed_pe[field] == original_pe[field], f'Packed PE differs in {field}.')
            visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in packed_bytes]
            require(not visible, f'Full secret markers remain visible: {visible}')
            check_execution(target, arch, kind)
            wait.check_fixture(target, arch, kind)
            require(target.read_bytes() == packed_bytes, 'Execution modified the packed file.')
            destination = output/f'fixture-{arch}-{kind}'/target.name
            require(not destination.exists() or destination.read_bytes() == packed_bytes,
                    f'Refusing to overwrite different output: {destination}')
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                with destination.open('xb') as stream:
                    stream.write(packed_bytes)
            print(f'{arch}/{kind}/{algorithm}: PASS normal + wait; markers hidden; '
                  f'{len(original_bytes)} -> {len(packed_bytes)} bytes; '
                  f'relocations={packed_pe["relocations_size"]}.', flush=True)
    finally:
        require(digest(source) == ref['sha256'], 'Shared original was modified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True, choices=TOOLS)
    parser.add_argument('--algorithm', action='append', choices=ALGORITHMS)
    parser.add_argument('--arch', action='append', choices=['x86', 'amd64'])
    parser.add_argument('--kind', action='append', choices=['exe', 'dll'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows x64 with WOW64 is required.')
    source_tool = PACKER/'tools'/args.version/'bin/bep.exe'
    require(source_tool.is_file() and digest(source_tool) == TOOLS[args.version],
            'Missing or unexpected BeRoEXEPacker executable.')
    pe = load_module('fixture_manifest', ROOT/'fixtures/scripts/manifest.py')
    wait = load_module('fixture_wait', ROOT/'fixtures/scripts/check_wait.py')
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    algorithms = list(dict.fromkeys(args.algorithm or ALGORITHMS))
    print(f'BeRoEXEPacker {args.version}; +X=0; algorithms={algorithms}', flush=True)
    with tempfile.TemporaryDirectory(prefix='pe-bep-') as temporary:
        work = Path(temporary)
        tool = work/'bep.exe'
        shutil.copyfile(source_tool, tool)
        for arch in dict.fromkeys(args.arch or ['x86', 'amd64']):
            for kind in dict.fromkeys(args.kind or ['exe', 'dll']):
                generate_case(args, tool, output, work, pe, wait, arch, kind, algorithms)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(1)
