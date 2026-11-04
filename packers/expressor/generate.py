"""Generate and verify eXPressor 1.8.0.1 Standard Full-stub fixtures.

Requirements / acquisition
--------------------------
Windows x64 with WOW64, an interactive desktop and 64-bit Python 3.8+; standard
library only. Download https://www.cgsoftlabs.ro/zip/eXPressor.zip and extract
setup.exe with innoextract --collisions rename. Keep app/eXPressor.exe#program2
as tools/1.8.0.1/bin/program2/eXPressor.exe. The original binary is hash-pinned.
The distribution has no packer sources. See internals.md for extraction details.

From an ordinary terminal at the collection root:
  python packers/expressor/generate.py --version 1.8.0.1
  python packers/expressor/generate.py --version 1.8.0.1 --output C:/Temp/expressor-check
  python packers/expressor/generate.py --version 1.8.0.1 --verify-only
Repeat --arch x86|amd64 and --kind exe|dll to select a subset.

Packing requests UAC once for a temporary worker. Runtime checks stay in the
calling process's security context; use an ordinary terminal to test without
administrator rights. runtime.py creates each packer suspended, changes only
its WOW64 PEB OS version to 6.1 and resumes it with visible startup. Wait for
its splash; do not close its windows while generation is running.

The worker packs disposable, manifest-checked originals with:
  eXPressor.exe <absolute-original> /s 2 /lm 2 /r 2 /++ 2 /lg <temporary-log> /e
Full stub, compression level 2, standard resource compression and keep overlay.
The tested build writes <stem>Pk.<extension>; /d did not select the requested
filename in single-file probes, so it is omitted. /e faults with 0xC0000005
AFTER the success log and output. That known exit is reported, not converted
to exit zero; only independently verified output is published. Other errors
fail the case. Log and PE output are both required.

Post-processing: only x86 DLL output gets IMAGE_SCN_MEM_EXECUTE added to its
merged .data section, which contains the original entry point. Without this
single-bit header fix, DEP-enabled rundll32 reports DLL initialization failure.
No original fixture or packer executable is patched. Other outputs are kept
byte-for-byte as generated. --verify-only never rewrites files.

Validation requires architecture/kind and DLL names/ordinals to match, exact
success output, exit zero and empty stderr. All four runtime marker checksums
are exercised. Full marker visibility in packed bytes is reported separately.
The exact vendor notice is acknowledged through its own PID's enabled OK
button; unexpected dialogs fail. Wait tests start their 2.25-second liveness
interval AFTER the success line, testing --wait or WaitFixture by name and #4.
No PEB adjustment or elevation is applied to packed files by the verifier.

Only verified packed PEs go into packed-fixtures/<version>/fixture-<arch>-<kind>.
Existing different files are refused. Tool timestamps can make later generation
differ; use --output for another run. Temporary originals, tools and logs are
removed. Checks do not establish byte-exact recovery or forced relocation.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import traceback
import uuid

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
VERSION = '1.8.0.1'
TOOL_HASH = 'b70a589bd2d2dda5ac9092b658c18f24834e83324e2b580784921016e868ce94'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(arch, kind):
    folder = ROOT / 'fixtures/bin' / arch
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    ref = next(a for a in manifest['artifacts'] if a['id'] == f'basic-{kind}-{arch}')
    source = folder / ref['path']
    require(digest(source) == ref['sha256'], 'Shared original differs from its manifest.')
    return source, ref


def fix_dll(data, original):
    """Set just the missing execute bit on the merged original-code section."""
    blob = bytearray(data)
    pe = struct.unpack_from('<I', blob, 60)[0]
    original_pe = struct.unpack_from('<I', original, 60)[0]
    entry = struct.unpack_from('<I', original, original_pe + 24 + 16)[0]
    require(blob[pe:pe+4] == b'PE\0\0' and struct.unpack_from('<H', blob, pe+24)[0] == 0x10b,
            'DLL fix expects PE32 output.')
    count = struct.unpack_from('<H', blob, pe+6)[0]
    table = pe + 24 + struct.unpack_from('<H', blob, pe+20)[0]
    matches = []
    for n in range(count):
        pos = table + 40*n
        size, va = struct.unpack_from('<II', blob, pos+8)
        if blob[pos:pos+8].rstrip(b'\0') == b'.data' and va <= entry < va+size:
            matches.append(pos+36)
    require(len(matches) == 1, 'Expected one merged .data section containing the original entry.')
    flags = struct.unpack_from('<I', blob, matches[0])[0]
    require(flags == 0xc0000020, 'Unexpected .data flags; review this build before applying the fix.')
    struct.pack_into('<I', blob, matches[0], flags | 0x20000000)
    require(sum(a != b for a,b in zip(data, blob)) == 1, 'DLL preparation changed more than one byte.')
    return bytes(blob)


@contextmanager
def working_directory():
    # Python 3.13+ TemporaryDirectory uses OWNER RIGHTS on Windows. Files
    # created by an elevated worker can then be unreadable to the same user
    # without elevation. Normal TEMP inheritance grants that user directly.
    parent = Path(tempfile.gettempdir()).resolve()
    work = parent / ('pe-expressor-' + uuid.uuid4().hex)
    work.mkdir()
    try:
        yield work
    finally:
        require(work.resolve().parent == parent and work.name.startswith('pe-expressor-'),
                'Unexpected cleanup target.')
        shutil.rmtree(work)


def worker(work):
    import runtime
    work = work.resolve()
    require(work.parent == Path(tempfile.gettempdir()).resolve() and work.name.startswith('pe-expressor-'),
            'Worker expects a dedicated directory under TEMP.')
    require(runtime.is_elevated(), 'Packing worker requires elevation.')
    spec = json.loads((work/'request.json').read_text(encoding='utf-8'))
    source_tool = PACKER/'tools'/VERSION/'bin/program2/eXPressor.exe'
    require(digest(source_tool) == TOOL_HASH, 'Unexpected eXPressor executable.')
    results = []
    for arch, kind in spec:
        require(arch in ('x86','amd64') and kind in ('exe','dll'), 'Unexpected case.')
        case = work/f'{arch}-{kind}'
        source, ref = reference(arch,kind)
        local = case/f'original.{kind}'
        require(digest(local) == ref['sha256'], 'Temporary input differs from its manifest.')
        tool = case/'eXPressor.exe'
        shutil.copyfile(source_tool, tool)
        result = {'arch':arch, 'kind':kind}
        try:
            output, code = runtime.pack(tool, local)
            require(digest(local) == ref['sha256'], 'Packer modified its input.')
            result['exit'] = code
            result['output'] = output.name
        except Exception as error:
            result['error'] = str(error)
        results.append(result)
        print(json.dumps(result), flush=True)
    (work/'results.json').write_text(json.dumps(results), encoding='utf-8')


def verify(path, arch, kind, pe):
    import runtime
    source, ref = reference(arch, kind)
    original = source.read_bytes()
    data = path.read_bytes()
    require(data != original, 'Output is unchanged.')
    before, after = pe.inspect_pe(source), pe.inspect_pe(path)
    for field in ('machine','optional_header','kind','exports'):
        require(before[field] == after[field], f'Packed PE differs in {field}.')
    notices = runtime.check_execution(path, arch, kind)
    for entry in (('WaitFixture','#4') if kind == 'dll' else (None,)):
        notices += runtime.check_execution(path, arch, kind, entry=entry, wait=True)
    require(path.read_bytes() == data, 'Execution modified the packed file.')
    require(digest(source) == ref['sha256'], 'Shared original was modified.')
    visible = [s['id'] for s in ref['secrets'] if bytes.fromhex(s['hex']) in data]
    print(f'{arch}/{kind}: PASS normal + wait; full markers visible={visible}; notices acknowledged={notices}')
    print(f'  bytes={len(original)}->{len(data)}; DYNAMIC_BASE={after["dynamic_base"]}; '
          f'NX_COMPAT={after["nx_compatible"]}; relocations={bool(after["relocations_size"])}')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', choices=[VERSION], default=VERSION)
    parser.add_argument('--arch', choices=['x86','amd64'], action='append')
    parser.add_argument('--kind', choices=['exe','dll'], action='append')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--pack-worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(os.name == 'nt' and struct.calcsize('P') == 8, '64-bit Python on Windows is required.')
    if args.pack_worker:
        log = (args.pack_worker/'worker.log').open('w',encoding='utf-8',buffering=1)
        sys.stdout = sys.stderr = log
        try:
            worker(args.pack_worker)
            return 0
        except Exception:
            traceback.print_exc()
            return 1
    import runtime
    spec = importlib.util.spec_from_file_location('fixture_pe', ROOT/'fixtures/scripts/manifest.py')
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    cases = [(a,k) for a in dict.fromkeys(args.arch or ['x86','amd64'])
                   for k in dict.fromkeys(args.kind or ['exe','dll'])]
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    print(f'eXPressor {VERSION} Standard / Full; runtime checks elevated={runtime.is_elevated()}', flush=True)
    failures = 0
    if args.verify_only:
        for arch,kind in cases:
            try:
                verify(output/f'fixture-{arch}-{kind}'/f'packed.{kind}',arch,kind,pe)
            except Exception as error:
                print(f'{arch}/{kind}: FAIL: {error}', file=sys.stderr)
                failures += 1
        return bool(failures)
    with working_directory() as work:
        for arch,kind in cases:
            source, ref = reference(arch, kind)
            case = work/f'{arch}-{kind}'
            case.mkdir()
            local = case/f'original.{kind}'
            shutil.copyfile(source,local)
            runtime.check_execution(local, arch,kind)
            require(all(bytes.fromhex(s['hex']) in local.read_bytes() for s in ref['secrets']),
                    'Original marker missing.')
        (work/'request.json').write_text(json.dumps(cases),encoding='utf-8')
        print('Packing worker requests UAC; wait for the packer splash screens.',flush=True)
        try:
            runtime.elevated_worker(Path(__file__).resolve(),work)
        except Exception:
            if (work/'worker.log').exists():
                print((work/'worker.log').read_text(encoding='utf-8'),file=sys.stderr)
            raise
        results = json.loads((work/'results.json').read_text(encoding='utf-8'))
        for result in results:
            arch,kind = result['arch'],result['kind']
            try:
                require('error' not in result, result.get('error',''))
                case = work/f'{arch}-{kind}'
                raw = case/result['output']
                data = raw.read_bytes()
                if arch == 'x86' and kind == 'dll':
                    data = fix_dll(data,(case/'original.dll').read_bytes())
                    print('x86/dll: added EXECUTE to merged .data in packed output.')
                packed = case/f'packed.{kind}'
                packed.write_bytes(data)
                print(f'{arch}/{kind}: packer exit={result["exit"]:#x} after success log.',flush=True)
                verify(packed,arch,kind,pe)
                destination = output/f'fixture-{arch}-{kind}'/packed.name
                require(not destination.exists() or destination.read_bytes() == data,
                        f'Refusing to replace different output: {destination}')
                destination.parent.mkdir(parents=True,exist_ok=True)
                if not destination.exists():
                    with destination.open('xb') as stream:
                        stream.write(data)
            except Exception as error:
                print(f'{arch}/{kind}: FAIL: {error}',file=sys.stderr)
                failures += 1
        for arch,kind in cases:
            reference(arch,kind)
    return bool(failures)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, TimeoutError) as error:
        sys.exit(str(error))
