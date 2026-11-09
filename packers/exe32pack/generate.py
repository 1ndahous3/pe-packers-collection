"""Generate EXE32Pack 1.42 fixtures on Windows x64/WOW64.

Download https://ftpmirror.infania.net/pub/pc/pack/exe32pck.zip and extract only
exe32pack.exe into tools/1.42/bin. Version is confirmed by its own help banner.
No source build was found; the stable public archive is linked, not retained.

  exe32pack /M:1 /F input.exe output.exe
  exe32pack /M:2 /F input.dll output.dll
  exe32pack /M:1 /F /NE input.dll output.dll
  python packers/exe32pack/generate.py --output C:/Temp/exe32-new
  python packers/exe32pack/generate.py --verify-only
  python packers/exe32pack/generate.py --probe-failed --output C:/Temp/exe32-probe

/M:1 uses the smaller loader, /M:2 stronger compression with larger overhead.
/F permits growth on tiny fixtures; /NE leaves the export-bearing section raw.
Both methods and both DLL export modes are retained; /M:0 automatic selection
and /R realignment-only are not separate cases. Inputs are unchanged shared PEs.

Compressed-export DLLs cannot be checked with the static export parser. Validate
raw PE architecture/kind, RunFixture by name and ordinal 3, WaitFixture by name
and ordinal 4, runtime marker checksums, and unchanged bytes instead. This does
not claim verification of every restored export-table entry. /NE cases use the
full shared static checks as well. All execution uses bounded one-process jobs.
--probe-failed requires both amd64 kinds to be rejected with no output; the tool
returns zero even on these failures, so exit status alone is insufficient.
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
TOOL_HASH = 'e81d42faae9cd704f678d400d71caae0e252ea500c7daf5920ceeb66d039ddf5'


def verify(path, kind, compressed_exports):
    if not compressed_exports:
        CHECK.verify(path, 'x86', kind); return
    before = path.read_bytes(); nt = struct.unpack_from('<I', before, 60)[0]
    CHECK.require(before[nt:nt+4] == b'PE\0\0' and struct.unpack_from('<H', before, nt+4)[0] == 0x14c
                  and struct.unpack_from('<H', before, nt+24)[0] == 0x10b
                  and struct.unpack_from('<H', before, nt+22)[0] & 0x2000,
                  'Expected PE32 x86 DLL')
    CHECK.normal(path, 'x86', 'dll')
    result = CHECK.run(CHECK.command(path, 'x86', 'dll', '#3'), path.parent, 10)
    CHECK.require(result.returncode == 0 and result.stdout.replace(b'\r\n', b'\n') == b'pe-fixture:basic-dll:ok\n'
                  and not result.stderr, 'RunFixture ordinal 3 failed')
    CHECK.WAIT.check_fixture(path, 'x86', 'dll')
    CHECK.require(path.read_bytes() == before, 'Execution modified the file')
    _, ref = CHECK.reference('x86', 'dll')
    visible = [s['id'] for s in ref['secrets'] if bytes.fromhex(s['hex']) in before]
    print(f'{path.name}: PASS runtime exports/normal/wait/secret checks; full disk markers={visible}', flush=True)


def pack(tool, source, output, method, ne=False):
    result = CHECK.run([tool, f'/M:{method}', '/F', *(['/NE'] if ne else []), source, output], output.parent)
    CHECK.require(result.returncode == 0 and not result.stderr and b'failed' not in result.stdout.lower()
                  and output.exists() and output.read_bytes() != source.read_bytes(),
                  'Packing failed: ' + repr(result.stdout))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    tool = PACKER / 'tools/1.42/bin/exe32pack.exe'
    CHECK.require(CHECK.sha256(tool) == TOOL_HASH, 'Unexpected packer')
    output = (args.output or PACKER / 'packed-fixtures/1.42').resolve(); saved = {}
    with tempfile.TemporaryDirectory(prefix='pe-exe32pack-') as temp:
        work = Path(temp)
        for kind in ('exe', 'dll'):
            source, _ = CHECK.reference('x86', kind)
            for method in (1, 2):
                for ne in ((False, True) if kind == 'dll' else (False,)):
                    name = f'm{method}' + ('-ne' if ne else '') + '.' + kind
                    target = output / f'fixture-x86-{kind}' / name
                    if args.verify_only:
                        verify(target, kind, kind == 'dll' and not ne); continue
                    CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
                    sample = work / name
                    pack(tool, source, sample, method, ne)
                    verify(sample, kind, kind == 'dll' and not ne); saved[target] = sample.read_bytes()
            CHECK.reference('x86', kind)
        if args.probe_failed and not args.verify_only:
            for kind in ('exe', 'dll'):
                source, _ = CHECK.reference('amd64', kind)
                for method in (1, 2):
                    target = work / f'amd64-m{method}.{kind}'
                    result = CHECK.run([tool, f'/M:{method}', '/F', source, target], work)
                    CHECK.require(b'failed repack' in result.stdout and not target.exists(), 'Unexpected amd64 result')
                    print(f'amd64/{kind}/M:{method}: rejected without output', flush=True)
                CHECK.reference('amd64', kind)
        for target, data in saved.items():
            CHECK.publish(data, target)


if __name__ == '__main__':
    main()
