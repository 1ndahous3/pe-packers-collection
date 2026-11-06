"""Generate RLPack Basic and Full 1.21 fixtures with separate profiles.

Full Edition 1.21: https://archive.org/details/cracklb-2010,
ANALYZE_L@B/Packers/RLPack Full 1.21.rar. The retained ROGUE distribution contains
a repackaged Inno installer; use innoextract -e -d extracted setup.exe. Copy its
core runtime files into tools/1.21-full-rogue/bin/: RLPack.exe, Basic.dll, Box.dll,
iBox.dll, Protect.dll, Functions.dll, Hook.dll, Importer.dll and lzma.dll.
The retained license.reg key file and watermark.dat are runtime dependencies;
the bundled utility generated the former and the first tool launch the latter.
They are consumed as files, never imported as Registry settings. Demo plug-ins,
manuals and setup stay in the archive. Exact changes versus vendor Full are unknown.

Run --version 1.21-full-rogue --arch x86. gui.py uses the Full stub with CRC and
memory protection, aPLib/LZMA, dynamic imports, and no optional anti-cracking/VM,
iBox, download or stripping settings. Original inputs need no resource addition.
Only normal/wait/secret checksum checks were performed for Full; forced rebasing
and exact memory-byte comparisons below apply to Basic. Full PE64 probes emit
invalid mixed i386/PE32+ EXE headers or fail to complete DLL packing.

Acquisition / building
---------------------
Download the RLPack.zip distribution from:
https://www.stahuj.cz/utility_a_ostatni/komprese/rlpack-basic-edition/download/
Follow its generated download link (the direct URL has an expiring token).
Archive SHA256: 0918445d6fab5fdf4b92c74000a8522358a88e086eefed0ae01de13f7d133127
Extract RLPack.exe, lzma.dll and Importer.dll to tools/1.21-basic/bin/ beside
this script. The author site http://rlpack.jezgra.net/ is no longer available.
The archive also has Source/ and help.chm; keep the public link rather than
vendoring them. Source/makeit.bat expects a MASM32 installation at /MASM32 and
builds RLP.asm with its resources. That build was not exercised; generation uses
the original distributed binaries, pinned below. Basic has compression stubs;
the shared manual's Full/iBox protection features are outside this case.

Requirements: Windows x64 with WOW64, an interactive desktop, Python 3.8+;
standard library only. From the collection root:
  python packers/rlpack/generate.py --version 1.21-basic
  python packers/rlpack/generate.py --version 1.21-basic --backend aplib --loader dynamic
  python packers/rlpack/generate.py --version 1.21-basic --kind dll --output C:/Temp/rlpack-check
Repeat --backend, --loader, --arch or --kind for multiple selections.

Profile / input adaptation
--------------------------
The stock packer corrupts our resource-less originals. add_resource() appends
one RCDATA resource to each disposable x86 input, without changing existing
section contents, RVAs, code, secrets, entry point or exports. The original
manifest hash and behavior are checked first, then the adapted copy is checked
before packing. Shared originals remain untouched. See internals.md for the
source-level cause. No packer or packed-output patch is applied.

Commands, run from a temporary directory with a simple relative input name:
  RLPack.exe -acqmso original.exe    (aPLib, dynamic imports)
  RLPack.exe -lcqmso original.exe    (LZMA, dynamic imports)
Append w to enable "Use Windows DLL loader"; substitute original.dll for DLLs.
a/l selects the compressor, c closes the GUI, q suppresses dialogs, m minimizes
it, s preserves unimportant resources, o retains overlay. b/t/r/e are omitted:
no backup, TLS/relocation/export stripping requested. RLPack packs in place.
Its GUI needs WM_SHOWWINDOW to start; do not use STARTF_USESHOWWINDOW/SW_HIDE or
SW_SHOWMINNOACTIVE for the packer process. Use its own m switch. The parser uses
the last '-' in the command line: relative input names avoid path ambiguity.
A packer exit of zero is not sufficient evidence of a working output.

Both algorithms pass for EXE dynamic/windows-loader and DLL dynamic profiles.
DLL windows-loader packing crashes with 0xC0000005; skip that combination.
amd64 is skipped: stock probes emitted invalid mixed i386/PE32+ for EXE and
crashed packing DLL. Failed/unsupported outputs are never executed or retained
by this generator. The collected files lose DYNAMIC_BASE/NX_COMPAT flags; EXEs
also lose the public relocation directory, even without the strip switch.

Verification / storage
----------------------
Require unchanged shared sources, matching machine/magic/kind and DLL export
names/ordinals, hidden complete secret markers, exact normal stdout, exit zero,
empty stderr and sustained --wait/WaitFixture (name and ordinal 4). Runtime
checksums cover the secrets; exact memory bytes and forced DLL rebasing were
checked separately as described in internals.md. Publish only passing packed
PEs as <backend>-<loader>.<kind>, refusing to replace different existing bytes.
Packing has a 30-second timeout, normal runs 10 seconds; owned children are
terminated on timeout. Temporary copies and intermediates are removed. No TLS,
resource-compatibility matrix or external unpacker is tested by this helper.
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
_PROCESS_SPEC = importlib.util.spec_from_file_location('fixture_process', ROOT/'fixtures/scripts/isolated_process.py')
ISOLATED = importlib.util.module_from_spec(_PROCESS_SPEC)
_PROCESS_SPEC.loader.exec_module(ISOLATED)
TOOLS = {'1.21-basic': {
    'RLPack.exe': 'e2c33890901e9da48198fe4e425e39f81ba5385ccbe8e82cbc655f5d1aa454a4',
    'lzma.dll': 'c7851c07685a2f6c7d04640ccbd84d3ce925c9d5fcd1c9e2285533e45f530907',
    'Importer.dll': '5dd0d5ab568d2654222bb20c3962805f5726031dfb48fd9ae214ee275e56122e',
}}
TOOLS['1.21-full-rogue'] = {'Basic.dll': '2e93a2c1753ce61efaef34374decc7c44b077c621332d5ce871381d9f1302c37', 'Box.dll': 'fdad24e5d8d8b9342c5bee49a513e03aad38cdb642f20fc03cbfa5c8706eb19f', 'Functions.dll': 'acf7329787be8ddff19301614bba74c95a14597a7cb808b625b872698c38ebc4', 'Hook.dll': '1d0cc52d4eb315dab5bbac9a1df1cf2d65241c563ac22cf198e1feb5caaf50ba', 'iBox.dll': '406654d29eb50a42988e3b7d6040a43060ff0454ab709a7ac5b382f7b414ca54', 'Importer.dll': '39dde788d93a008cfa016d87381b3f33692c3c3fa5f1836f0148d75dfec86823', 'license.reg': '174d971a280a00f0f4fc6443fc2929ec48c3c792b9a9df3575aa07de4f62a18f', 'lzma.dll': 'c7851c07685a2f6c7d04640ccbd84d3ce925c9d5fcd1c9e2285533e45f530907', 'Protect.dll': 'dcf17f21bf19d86a9b468470d52fc32a18afd985e2b092dd27bd85a07588221f', 'RLPack.exe': '4985338e7e5536637e8f851e7d44131d5983d768f3c176c9ebfc3b768c2133a7', 'watermark.dat': '17de349d01767ef12f7e5e55c192870f65cfe6dcf75fba05bd6b177fc40280f4'}
BACKENDS = {'aplib': 'a', 'lzma': 'l'}
LOADERS = ('dynamic', 'windows')


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
    result = ISOLATED.run([str(x) for x in command], cwd=path.parent, timeout=10,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 0 and not result.stderr and
            result.stdout.replace(b'\r\n', b'\n') == f'pe-fixture:basic-{kind}:ok\n'.encode(),
            f'Runtime failure: exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')


def add_resource(original, info):
    """Append one valid RCDATA tree to a manifest-checked, resource-less PE32."""
    data = bytearray(original)
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    opt = nt + 24
    section_count = struct.unpack_from('<H', data, nt + 6)[0]
    table = opt + struct.unpack_from('<H', data, nt + 20)[0]
    require(info['machine'] == '0x014c' and info['optional_header'] == '0x010b',
            'Resource adaptation supports native i386/PE32 only.')
    require(struct.unpack_from('<II', data, opt + 112) == (0, 0),
            'Input already has resources; review the profile rather than replacing them.')
    section_alignment, file_alignment = struct.unpack_from('<II', data, opt + 32)
    require(all(x > 0 and not x & (x - 1) for x in (section_alignment, file_alignment)),
            'Unexpected PE alignments.')
    align = lambda value, alignment: (value + alignment - 1) // alignment * alignment
    sections = info['sections']
    rva = align(max(s['rva'] + max(s['virtual_size'], s['raw_size']) for s in sections), section_alignment)
    require(len(original) == max(s['raw_offset'] + s['raw_size'] for s in sections),
            'Unexpected input overlay.')
    raw = align(len(data), file_alignment)
    payload = b'RLPack Basic resource workaround\0'
    resource = bytearray(88 + len(payload))
    # Three directory levels: RT_RCDATA / ID 1 / language 0x409, then a data entry.
    for start in (0, 24, 48):
        struct.pack_into('<H', resource, start + 14, 1)
    for at, name, child in ((16, 10, 0x80000018), (40, 1, 0x80000030), (64, 0x409, 72)):
        struct.pack_into('<II', resource, at, name, child)
    struct.pack_into('<IIII', resource, 72, rva + 88, len(payload), 0, 0)
    resource[88:] = payload
    raw_size = align(len(resource), file_alignment)
    header = table + section_count * 40
    headers_size = struct.unpack_from('<I', data, opt + 60)[0]
    require(header + 40 <= headers_size and not any(data[header:header + 40]),
            'No unused section-header slot.')
    struct.pack_into('<8sIIIIIIHHI', data, header, b'.rsrc\0\0\0', len(resource),
                     rva, raw_size, raw, 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<H', data, nt + 6, section_count + 1)
    struct.pack_into('<I', data, opt + 56, align(rva + len(resource), section_alignment))
    initialized = struct.unpack_from('<I', data, opt + 8)[0]
    struct.pack_into('<I', data, opt + 8, initialized + raw_size)
    struct.pack_into('<I', data, opt + 64, 0)
    struct.pack_into('<II', data, opt + 112, rva, len(resource))
    data.extend(bytes(raw + raw_size - len(data)))
    data[raw:raw + len(resource)] = resource
    for section in sections:
        start, size = section['raw_offset'], section['raw_size']
        require(data[start:start + size] == original[start:start + size],
                'Resource adaptation changed an original section.')
    return bytes(data)


def generate_case(tool, work, pe, wait, kind, backends, loaders):
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
        prepared = add_resource(original_bytes, original_pe)
        original.write_bytes(prepared)
        adapted_pe = pe.inspect_pe(original)
        for field in ('machine', 'optional_header', 'kind', 'entry_point_rva', 'image_base', 'exports'):
            require(adapted_pe[field] == original_pe[field], f'Adaptation changed {field}.')
        require(adapted_pe['sections'][:-1] == original_pe['sections'], 'Adaptation changed original section headers.')
        check_execution(original, 'x86', kind)
        for backend in backends:
            for loader in loaders:
                if kind == 'dll' and loader == 'windows':
                    print(f'x86/dll/{backend}/{loader}: SKIP; known packer access violation.', flush=True)
                    continue
                original.write_bytes(prepared)
                options = '-'+BACKENDS[backend]+'cqmso'+('w' if loader == 'windows' else '')
                # GUI-backed CLI: hidden startup suppresses the event which starts packing.
                result = subprocess.run([str(tool), options, original.name], cwd=directory,
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
                require(result.returncode == 0 and not result.stdout and not result.stderr,
                        f'Packing failed: exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')
                packed_bytes = original.read_bytes()
                require(packed_bytes != prepared, 'Packer did not change the temporary input.')
                packed_pe = pe.inspect_pe(original)
                for field in ('machine', 'optional_header', 'kind', 'exports'):
                    require(packed_pe[field] == original_pe[field], f'Packed PE differs in {field}.')
                visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in packed_bytes]
                require(not visible, f'Full secret markers remain visible: {visible}')
                check_execution(original, 'x86', kind)
                wait.check_fixture(original, 'x86', kind)
                require(original.read_bytes() == packed_bytes, 'Execution modified the packed file.')
                verified[Path(f'fixture-x86-{kind}')/f'{backend}-{loader}.{kind}'] = packed_bytes
                print(f'x86/{kind}/{backend}/{loader}: PASS normal + wait; markers hidden; '
                      f'{len(original_bytes)} -> {len(prepared)} with resource -> {len(packed_bytes)} bytes.', flush=True)
    finally:
        require(digest(source) == ref['sha256'], 'Shared original was modified.')
    return verified


def generate_full_case(tool, work, pe, wait, kind, backends):
    folder = ROOT/'fixtures/bin/x86'
    manifest = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    ref = next(x for x in manifest['artifacts'] if x['id'] == f'basic-{kind}-x86')
    source = folder/ref['path']
    require(digest(source) == ref['sha256'], 'Shared input differs from manifest.')
    before = source.read_bytes()
    directory = work/kind
    directory.mkdir()
    original = directory/f'original.{kind}'
    original.write_bytes(before)
    check_execution(original, 'x86', kind)
    baseline = pe.inspect_pe(original)
    gui = load_module('rlpack_full_gui', PACKER/'gui.py')
    verified = {}
    try:
        for backend in backends:
            target = directory/f'{backend}-full.{kind}'
            gui.pack(tool, original, target, backend)
            data = target.read_bytes()
            require(data != before, 'Unchanged output.')
            info = pe.inspect_pe(target)
            for field in ('machine', 'optional_header', 'kind', 'exports'):
                require(info[field] == baseline[field], f'Packed PE differs in {field}.')
            visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in data]
            require(not visible, f'Visible markers: {visible}')
            check_execution(target, 'x86', kind)
            wait.check_fixture(target, 'x86', kind)
            require(target.read_bytes() == data, 'Execution changed output.')
            verified[Path(f'fixture-x86-{kind}')/target.name] = data
            print(f'x86/{kind}/{backend}/full: PASS normal + wait + secrets; {len(before)} -> {len(data)} bytes.', flush=True)
    finally:
        require(source.read_bytes() == before and original.read_bytes() == before, 'Input changed.')
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True, choices=TOOLS)
    parser.add_argument('--backend', action='append', choices=BACKENDS)
    parser.add_argument('--loader', action='append', choices=LOADERS)
    parser.add_argument('--arch', action='append', choices=['x86', 'amd64'])
    parser.add_argument('--kind', action='append', choices=['exe', 'dll'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows x64 with WOW64 and an interactive desktop are required.')
    tool_dir = PACKER/'tools'/args.version/'bin'
    for name, expected in TOOLS[args.version].items():
        require((tool_dir/name).is_file() and digest(tool_dir/name) == expected,
                f'Missing or unexpected RLPack tool: {name}')
    pe = load_module('fixture_manifest', ROOT/'fixtures/scripts/manifest.py')
    wait = load_module('fixture_wait', ROOT/'fixtures/scripts/check_wait.py')
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    backends = list(dict.fromkeys(args.backend or BACKENDS))
    full = args.version == '1.21-full-rogue'
    if full and args.loader and args.loader != ['dynamic']:
        parser.error('Full profile currently uses the dynamic loader only.')
    loaders = list(dict.fromkeys(args.loader or LOADERS))
    with tempfile.TemporaryDirectory(prefix='pe-rlpack-') as temporary:
        work = Path(temporary)
        for name in TOOLS[args.version]:
            shutil.copyfile(tool_dir/name, work/name)
        verified = {}
        for arch in dict.fromkeys(args.arch or ['x86', 'amd64']):
            if arch == 'amd64':
                print('amd64/EXE+DLL: UNSUPPORTED; skipped (PE64 probes produced invalid headers / no usable output).', flush=True)
                continue
            for kind in dict.fromkeys(args.kind or ['exe', 'dll']):
                if full:
                    verified.update(generate_full_case(work/'RLPack.exe', work, pe, wait, kind, backends))
                else:
                    verified.update(generate_case(work/'RLPack.exe', work, pe, wait, kind, backends, loaders))
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
