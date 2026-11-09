"""Generate Windows PE Packer cases with the retained local source build.

  python packers/windows-pe-packer/generate.py --output C:/Temp/czs-new
  python packers/windows-pe-packer/generate.py --verify-only
  python packers/windows-pe-packer/generate.py --probe-failed --output C:/Temp/czs-probe
  PE-Packer.exe input.exe output.exe

build.py pins the upstream commit and documents the MSVC/MASM build adaptations.
No release is identified, so tool and fixture version directories use 0.
Default uses the unchanged shared x86 EXE. secret-as-data changes only the eight
section-name bytes from .secret to DATA on a temporary input and validates it
before packing. This exercises the upstream name-based encryption selection;
no algorithm, code, data, protection flags or packed output is patched.

Both cases require normal execution, wait readiness/liveness, all four runtime
secret checksums, expected marker visibility and blank original section names.
--probe-failed checks both DLL kinds and amd64 EXE rejection with no output.
Upstream returns zero on those errors, so diagnostics and absence of output are
checked independently. All execution is in bounded one-process Windows jobs.
"""
import argparse
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
TOOL = PACKER / 'tools/0/bin/PE-Packer.exe'
TOOL_HASH = '07307ef22474272710dc8b6a0bc5da555afb77b91f3a6234e8942753a9e26f77'
PROFILES = ('default', 'secret-as-data')


def rename_secret(data):
    result = bytearray(data); nt = struct.unpack_from('<I', result, 60)[0]
    count = struct.unpack_from('<H', result, nt+6)[0]
    table = nt + 24 + struct.unpack_from('<H', result, nt+20)[0]
    matches = [table+i*40 for i in range(count) if result[table+i*40:table+i*40+8] == b'.secret\0']
    CHECK.require(len(matches) == 1, 'Expected one .secret section')
    result[matches[0]:matches[0]+8] = b'DATA\0\0\0\0'
    return bytes(result)


def verify(path, profile):
    info = CHECK.verify(path, 'x86', 'exe'); _, ref = CHECK.reference('x86', 'exe')
    data = path.read_bytes()
    visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in data]
    CHECK.require(visible == (['secret-repeat'] if profile == 'default' else []), 'Unexpected marker visibility')
    CHECK.require([s['name'] for s in info['sections']] == [''] * len(ref['pe']['sections']) + ['.shell'],
                  'Unexpected section names')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    CHECK.require(CHECK.sha256(TOOL) == TOOL_HASH, 'Unexpected tool; review a rebuild before changing the pin')
    output = (args.output or PACKER / 'packed-fixtures/0').resolve(); saved = {}
    with tempfile.TemporaryDirectory(prefix='pe-czs-') as temp:
        work = Path(temp); original, _ = CHECK.reference('x86', 'exe')
        for profile in PROFILES:
            target = output / f'fixture-x86-exe/{profile}.exe'
            if args.verify_only:
                verify(target, profile); continue
            CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
            source = work / f'{profile}-input.exe'; packed = work / f'{profile}.exe'
            data = original.read_bytes()
            source.write_bytes(rename_secret(data) if profile == 'secret-as-data' else data)
            CHECK.verify(source, 'x86', 'exe'); before = source.read_bytes()
            result = CHECK.run([TOOL, source, packed], work, 20)
            CHECK.require(result.returncode == 0 and not result.stderr and b'The packing has finished' in result.stdout
                          and packed.exists() and source.read_bytes() == before, 'Packing failed: ' + repr(result.stdout))
            verify(packed, profile); saved[target] = packed.read_bytes()
        if args.probe_failed and not args.verify_only:
            for arch, kind in [('x86','dll'), ('amd64','exe'), ('amd64','dll')]:
                source, _ = CHECK.reference(arch, kind); target = work / f'failed-{arch}.{kind}'
                result = CHECK.run([TOOL, source, target], work, 20)
                expected = b'cannot process a DLL' if kind == 'dll' else b"doesn't match the program platform"
                CHECK.require(expected in result.stdout and not result.stderr and not target.exists(), 'Unexpected rejection')
                CHECK.reference(arch, kind); print(f'{arch}/{kind}: rejected without output', flush=True)
        CHECK.reference('x86', 'exe')
        for target, data in saved.items():
            CHECK.publish(data, target)


if __name__ == '__main__':
    main()
