"""Generate and verify NeoLite 2.0 trial fixtures.

Acquisition / building
----------------------
Use prepare.py with the public SAC/Infania neolte20.zip distribution. It extracts
NeoLiteCli.exe and Pecomp.dll without running the 16-bit installer. No buildable
packer source was established. The two original binaries are hash-pinned.

Windows x64 with WOW64, an interactive desktop and Python 3.8+ are required;
standard library only. From the collection root:
  python packers/neolite/generate.py --version 2.0-trial
  python packers/neolite/generate.py --version 2.0-trial --verify-only
  python packers/neolite/generate.py --version 2.0-trial --output C:/Temp/neolite-check
Repeat --arch x86|amd64, --kind exe|dll or --profile reversible|irreversible to
select cases. --output names a version-level directory, preferably fresh.

Commands in each disposable directory:
  NeoLiteCli.exe -q -j -r original.exe reversible.exe
  NeoLiteCli.exe -q -j -r -e original.exe irreversible.exe
  NeoLiteCli.exe -q -x reversible.exe restored.exe
Substitute .dll for DLL inputs. -j permits growth of these tiny inputs; -r
preserves EXE relocation data. Imports/resources and NeoDataSim retain their
defaults. -e omits reversible recovery information. amd64 inputs are attempted
and must give exit 4, the explicit Win32 rejection, no output and unchanged input.

Compatibility / recovery
------------------------
Raw output fails after an ASLR rebase: restored code still uses preferred-base
absolute addresses. The sole output edit clears IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE.
NX_COMPAT, relocations, code and compressed data stay unchanged. Shared fixtures
and packer binaries are never patched. Corrected DLLs also passed a separate
forced address-conflict rebase check; this generator does not force an address.
EXE forced rebasing and system-wide mandatory ASLR were not tested. No machine-wide
mitigation setting is changed.

Native -x on raw reversible output must recover the exact shared original.
On retained output it must recover that original with only DYNAMIC_BASE cleared;
all other bytes, including headers and full secret sequences, must match. Native
-x must explicitly refuse irreversible output with exit 13 and no restored file.
Restored reversible files also pass execution and wait checks. External unpackers
are optional research tools and are not invoked by this generator.

Validation / publication
------------------------
Validate tool hashes, input manifest hashes and full markers, original behavior,
architecture/kind, DLL export names/ordinals, packed execution and wait readiness
(--wait, or WaitFixture by name and ordinal 4). All runtime secret checksums must
pass; full marker visibility on disk is reported separately. runtime.py answers
only the exact EXE trial notice with No. DLL runs showed no such notice. Each
child has a one-process job and bounded lifetime; unexpected dialogs fail.

Only verified packed PEs are published after all selected supported cases pass.
Different existing bytes are refused; --verify-only does not regenerate or write
artifacts. Originals, raw outputs, restorations and reports stay temporary.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
PROFILES = ('reversible', 'irreversible')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def without_aslr(data):
    blob = bytearray(data)
    require(blob[:2] == b'MZ', 'Expected MZ image.')
    nt = struct.unpack_from('<I', blob, 60)[0]
    require(blob[nt:nt+4] == b'PE\0\0' and
            struct.unpack_from('<H', blob, nt+4)[0] == 0x14c and
            struct.unpack_from('<H', blob, nt+24)[0] == 0x10b, 'Expected x86 PE32.')
    position = nt + 24 + 70
    flags = struct.unpack_from('<H', blob, position)[0]
    require(flags & 0x40 and flags & 0x100, 'Expected DYNAMIC_BASE and NX_COMPAT.')
    struct.pack_into('<H', blob, position, flags & ~0x40)
    require(sum(a != b for a, b in zip(data, blob)) == 1, 'Expected one changed flag byte.')
    return bytes(blob)


def invoke(runtime, tool, flags, source, destination):
    result = runtime.ISOLATED.run([str(tool), '-q', *flags, source.name, destination.name],
        cwd=source.parent, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30)
    return result.returncode, (result.stdout + result.stderr).decode('cp1252', errors='replace')


def recover(runtime, tool, path, profile, expected, arch, kind, verify_runtime):
    original_packed = path.read_bytes()
    suffix = '-restored' if verify_runtime else '-raw-restored'
    restored = path.with_name(path.stem + suffix + path.suffix)
    code, text = invoke(runtime, tool, ['-x'], path, restored)
    require(path.read_bytes() == original_packed, 'Decompression changed its packed input.')
    if profile == 'irreversible':
        require(code == 13 and 'cannot be uncompressed.' in text and not restored.exists(),
                'Unexpected irreversible recovery result: ' + text)
        return
    require(code == 0 and restored.is_file(), 'Native decompression failed: ' + text)
    require(restored.read_bytes() == expected, 'Recovered bytes differ from the expected original.')
    if verify_runtime:
        runtime.verify(restored, arch, kind)
    require(restored.read_bytes() == expected, 'Restored file changed during execution.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True, choices=['2.0-trial'])
    parser.add_argument('--arch', action='append', choices=['x86', 'amd64'])
    parser.add_argument('--kind', action='append', choices=['exe', 'dll'])
    parser.add_argument('--profile', action='append', choices=PROFILES)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows with WOW64 is required.')
    runtime = load('neolite_runtime', PACKER/'runtime.py')
    prepare = load('neolite_prepare', PACKER/'prepare.py')
    pe = load('fixture_pe', ROOT/'fixtures/scripts/manifest.py')
    bin_dir = PACKER/'tools'/args.version/'bin'
    for name, (_, _, expected_hash) in prepare.MEMBERS.items():
        require((bin_dir/name).is_file() and digest(bin_dir/name) == expected_hash,
                'Missing or unexpected tool: ' + name)
    tool = bin_dir/'NeoLiteCli.exe'
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    results, originals, failures = {}, {}, []
    with tempfile.TemporaryDirectory(prefix='pe-neolite-') as temporary:
        work = Path(temporary)
        for arch in dict.fromkeys(args.arch or ['x86', 'amd64']):
            manifest = ROOT/'fixtures/bin'/arch/'manifest.json'
            artifacts = json.loads(manifest.read_text(encoding='utf-8'))['artifacts']
            for kind in dict.fromkeys(args.kind or ['exe', 'dll']):
                ref = next(a for a in artifacts if a['id'] == f'basic-{kind}-{arch}')
                source = manifest.parent/ref['path']
                original = source.read_bytes()
                originals[source] = ref['sha256']
                require(digest(source) == ref['sha256'], 'Shared input differs from manifest.')
                require(all(bytes.fromhex(m['hex']) in original for m in ref['secrets']),
                        'Missing full marker in shared input.')
                baseline = work/f'baseline-{arch}.{kind}'
                baseline.write_bytes(original)
                runtime.verify(baseline, arch, kind)
                before = pe.inspect_pe(baseline)
                for profile in dict.fromkeys(args.profile or PROFILES):
                    label = f'{arch}/{kind}/{profile}'
                    case = work/f'{arch}-{kind}-{profile}'
                    case.mkdir()
                    local = case/f'original.{kind}'
                    local.write_bytes(original)
                    path = case/f'{profile}.{kind}'
                    destination = output/f'fixture-{arch}-{kind}'/path.name
                    try:
                        if args.verify_only and arch == 'amd64':
                            require(not (output/f'fixture-{arch}-{kind}').exists(),
                                    'Unexpected artifacts for unsupported architecture.')
                            print(label + ': unsupported; packing rejection not rerun in verify-only')
                            continue
                        if args.verify_only:
                            require(destination.is_file(), 'Missing packed fixture: ' + str(destination))
                            path.write_bytes(destination.read_bytes())
                        else:
                            flags = ['-j', '-r'] + (['-e'] if profile == 'irreversible' else [])
                            code, text = invoke(runtime, tool, flags, local, path)
                            require(local.read_bytes() == original, 'Packer modified its temporary input.')
                            if arch == 'amd64':
                                require(code == 4 and 'is not a Win32 Portable Executable file.' in text
                                        and not path.exists(), 'Unexpected amd64 result: ' + text)
                                print(label + ': UNSUPPORTED (explicit Win32 rejection, no output)')
                                continue
                            require(code == 0 and path.is_file(), 'Packing failed: ' + text)
                            require(path.read_bytes() != original, 'Packer produced unchanged input.')
                            recover(runtime, tool, path, profile, original, arch, kind, False)
                            path.write_bytes(without_aslr(path.read_bytes()))
                        packed = path.read_bytes()
                        after = pe.inspect_pe(path)
                        for field in ('machine', 'optional_header', 'kind', 'exports'):
                            require(after[field] == before[field], 'Changed PE field: ' + field)
                        require(not after['dynamic_base'] and after['nx_compatible'] and
                                after['relocations_size'] > 0, 'Unexpected mitigation/relocation flags.')
                        require(any(s['name'] == '.neolit' for s in after['sections']), 'Missing NeoLite section.')
                        runtime.verify(path, arch, kind, packed=True)
                        recover(runtime, tool, path, profile, without_aslr(original), arch, kind, True)
                        require(path.read_bytes() == packed, 'Execution modified packed file.')
                        visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in packed]
                        print(f'{label}: PASS normal + wait; full markers visible={visible}; '
                              f'bytes={len(original)}->{len(packed)}; native -x='
                              + ('original except DYNAMIC_BASE' if profile == 'reversible' else 'explicit refusal'))
                        results[destination] = packed
                    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                        failures.append(label + ': ' + str(error))
                    finally:
                        require(local.read_bytes() == original and digest(source) == ref['sha256'],
                                'Original input changed.')
        for source, expected_hash in originals.items():
            require(digest(source) == expected_hash, 'Shared original changed.')
        for name, (_, _, expected_hash) in prepare.MEMBERS.items():
            require(digest(bin_dir/name) == expected_hash, 'Tool changed during generation.')
        require(not failures, 'No artifacts published.\n' + '\n'.join(failures))
        if not args.verify_only:
            for path, data in results.items():
                require(not path.exists() or path.read_bytes() == data,
                        'Refusing to replace different output: ' + str(path))
            for path, data in results.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    with path.open('xb') as stream:
                        stream.write(data)
    print('Verified existing fixtures.' if args.verify_only else 'Published verified fixtures.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
