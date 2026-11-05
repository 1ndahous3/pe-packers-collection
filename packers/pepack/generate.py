"""Generate PE-PaCK 1.0 fixtures with explicit header compatibility fixes.

Acquisition
-----------
Download https://www.sac.sk/download/pack/pepack10.zip
Mirror: https://ftpmirror.infania.net/pub/pc/pack/pepack10.zip
The two archives matched SHA256:
b4003ef13db83a6d4a789b71e8eb9d7c1d3d02c8dd0fa930554175bda1a7c4e2
Extract PEPACK.EXE to tools/1.0/bin/ beside this script. It has no non-system
DLL dependencies. PEPACK.TXT in the archive is the author's manual. The public
distribution has no packer sources; generation uses its unmodified executable.

Requirements: Windows x64 with WOW64, Python 3.8+; standard library only.
From the collection root:
  python packers/pepack/generate.py --version 1.0
  python packers/pepack/generate.py --version 1.0 --profile fast --kind dll
  python packers/pepack/generate.py --version 1.0 --output C:/Temp/pepack-check
Repeat --profile, --arch or --kind to select multiple values.

Packing and post-processing
---------------------------
Run from a disposable directory containing a manifest-checked original:
  PEPACK.EXE -o original.exe
  PEPACK.EXE -o -spd original.exe
Substitute original.dll for DLL input. -o preserves the input and writes
OUTPUT.EXE even for a DLL; the helper checks the PE kind and renames it.
The default profile uses normal compression; fast adds -spd. Resource compression
stays enabled with icons/version information retained. -rs-, -icn, -ver and
-aln are not selected. Our fixtures have no resources and already use file
alignment 512. The tool produced no captured stdout/stderr in these probes;
require exit zero and independently verify the output rather than trusting a log.

Stock outputs preserve NX_COMPAT/DYNAMIC_BASE but remove execute permission
from every section, and their private relocation handling fails when rebased.
repair_headers() restores IMAGE_SCN_MEM_EXECUTE on the original code section(s)
and the PEPACK!! loader section, then clears DYNAMIC_BASE so Windows requests
the preferred base. NX_COMPAT, relocation data and payload/stub bytes are kept.
This is not a relocation fix: a DLL base collision still fails. Original shared
fixtures and the packer binary are never patched. All retained cases use these
header fixes; unmodified outputs are not retained.

amd64 is skipped before invocation. Separate stock probes crashed the packer
(or timed out while handling a fault) without a usable output. No amd64 packed
file was executed. Generator selection of amd64 alone publishes nothing.

Checks and storage
------------------
Verify the tool and source hashes, source secret bytes and original execution.
Require an unchanged temporary input, matching machine/magic/kind and export
names/ordinals, hidden full markers, exact stdout, exit zero, empty stderr and
sustained wait mode (--wait or WaitFixture by name and ordinal 4). Payload
checksums cover the secrets. Exact memory-byte checks and the forced DLL base
collision experiment are documented in internals.md; they are not repeated here.

Publish only verified PEs as packed-fixtures/1.0/fixture-x86-<kind>/<profile>.<kind>.
Different existing bytes are not overwritten; use --output for another run.
Temporary inputs, raw outputs and logs are removed. Packing timeout: 30 seconds;
normal runtime timeout: 10 seconds. Wait checks terminate only their own child.
TLS, resources, external unpacking and arbitrary rebasing are outside this
passing baseline. Successful runtime does not establish exact disk recovery.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
TOOLS = {'1.0': 'aee70935a9c2f698aa7ebe1baf016bd57cb1371d8ef20c91cd743338c57b9ba1'}
PROFILES = ('default', 'fast')


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


def repair_headers(packed, original_pe):
    """Change only executable-section flags and DYNAMIC_BASE on known PE32 output."""
    data = bytearray(packed)
    require(data[:2] == b'MZ', 'Output lacks a DOS header.')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    opt = nt + 24
    require(data[nt:nt + 4] == b'PE\0\0' and
            struct.unpack_from('<H', data, nt + 4)[0] == 0x14c and
            struct.unpack_from('<H', data, opt)[0] == 0x10b, 'Unexpected output architecture.')
    require(struct.unpack_from('<I', data, opt + 64)[0] == 0, 'Unexpected nonzero PE checksum.')
    count = struct.unpack_from('<H', data, nt + 6)[0]
    table = opt + struct.unpack_from('<H', data, nt + 20)[0]
    require(count == len(original_pe['sections']) + 1, 'Unexpected packed section count.')
    expected = {(s['name'], s['rva']) for s in original_pe['sections']
                if int(s['characteristics'], 16) & 0x20000000}
    found = set()
    loaders = 0
    for i in range(count):
        at = table + 40 * i
        name = data[at:at + 8].rstrip(b'\0').decode('ascii')
        rva = struct.unpack_from('<I', data, at + 12)[0]
        key = (name, rva)
        if key in expected or name == 'PEPACK!!':
            flags = struct.unpack_from('<I', data, at + 36)[0]
            require(flags == 0xc0000040, 'Unexpected section flags; review the fix.')
            struct.pack_into('<I', data, at + 36, flags | 0x20000000)
            if name == 'PEPACK!!':
                loaders += 1
            else:
                found.add(key)
    require(found == expected and loaders == 1, 'Missing code or loader section.')
    flags = struct.unpack_from('<H', data, opt + 70)[0]
    require(bool(flags & 0x100) == original_pe['nx_compatible'] and
            bool(flags & 0x40) == original_pe['dynamic_base'], 'Unexpected input/output mitigation flags.')
    struct.pack_into('<H', data, opt + 70, flags & ~0x40)
    return bytes(data)


def generate_case(tool, work, pe, wait, kind, profiles):
    folder = ROOT/'fixtures/bin/x86'
    manifest = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    ref = next(x for x in manifest['artifacts'] if x['id'] == f'basic-{kind}-x86')
    source = folder/ref['path']
    require(digest(source) == ref['sha256'], 'Shared original differs from its manifest.')
    original_bytes = source.read_bytes()
    directory = work/kind
    directory.mkdir()
    original = directory/f'original.{kind}'
    original.write_bytes(original_bytes)
    verified = {}
    try:
        check_execution(original, 'x86', kind)
        original_pe = pe.inspect_pe(original)
        for marker in ref['secrets']:
            require(bytes.fromhex(marker['hex']) in original_bytes,
                    f'Original marker missing: {marker["id"]}')
        for profile in profiles:
            options = ['-o'] + (['-spd'] if profile == 'fast' else [])
            output = directory/'OUTPUT.EXE'
            require(not output.exists(), 'Unexpected stale packer output.')
            result = run([tool, *options, original.name], directory, 30)
            require(result.returncode == 0 and not result.stdout and not result.stderr and output.is_file(),
                    f'Packing failed: exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')
            require(original.read_bytes() == original_bytes, 'Temporary input was modified despite -o.')
            raw = output.read_bytes()
            require(raw != original_bytes, 'Output is unchanged.')
            raw_pe = pe.inspect_pe(output)
            for field in ('machine', 'optional_header', 'kind', 'exports'):
                require(raw_pe[field] == original_pe[field], f'Raw output differs in {field}.')
            fixed = repair_headers(raw, original_pe)
            target = directory/f'{profile}.{kind}'
            target.write_bytes(fixed)
            output.unlink()
            info = pe.inspect_pe(target)
            require(not info['dynamic_base'] and info['nx_compatible'] == original_pe['nx_compatible'],
                    'Header fix did not preserve NX_COMPAT or clear DYNAMIC_BASE.')
            visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in fixed]
            require(not visible, f'Full secret markers remain visible: {visible}')
            check_execution(target, 'x86', kind)
            wait.check_fixture(target, 'x86', kind)
            require(target.read_bytes() == fixed, 'Execution modified the packed file.')
            verified[Path(f'fixture-x86-{kind}')/target.name] = fixed
            print(f'x86/{kind}/{profile}: PASS with header fixes; normal + wait; markers hidden; '
                  f'{len(original_bytes)} -> {len(fixed)} bytes.', flush=True)
    finally:
        require(digest(source) == ref['sha256'], 'Shared original was modified.')
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True, choices=TOOLS)
    parser.add_argument('--profile', action='append', choices=PROFILES)
    parser.add_argument('--arch', action='append', choices=['x86', 'amd64'])
    parser.add_argument('--kind', action='append', choices=['exe', 'dll'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows x64 with WOW64 is required.')
    source_tool = PACKER/'tools'/args.version/'bin/PEPACK.EXE'
    require(source_tool.is_file() and digest(source_tool) == TOOLS[args.version],
            'Missing or unexpected PE-PaCK executable.')
    pe = load_module('fixture_manifest', ROOT/'fixtures/scripts/manifest.py')
    wait = load_module('fixture_wait', ROOT/'fixtures/scripts/check_wait.py')
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    profiles = list(dict.fromkeys(args.profile or PROFILES))
    with tempfile.TemporaryDirectory(prefix='pe-pepack-') as temporary:
        work = Path(temporary)
        tool = work/'PEPACK.EXE'
        shutil.copyfile(source_tool, tool)
        verified = {}
        for arch in dict.fromkeys(args.arch or ['x86', 'amd64']):
            if arch == 'amd64':
                print('amd64/EXE+DLL: UNSUPPORTED; skipped (stock probes crashed / timed out).', flush=True)
                continue
            for kind in dict.fromkeys(args.kind or ['exe', 'dll']):
                verified.update(generate_case(tool, work, pe, wait, kind, profiles))
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
