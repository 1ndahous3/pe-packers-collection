"""Generate AlushPacker 1.0.0 fixtures using its official release binary.

Download https://github.com/Alon-Alush/AlushPacker/releases/download/v1.0.0/AlushPacker.zip
Keep only packer.exe in tools/1.0.0/bin. Source:
https://github.com/Alon-Alush/AlushPacker (Visual Studio projects).
Rebuilding upstream and binary/source equivalence were not established. Runtime
requirements: Windows x64/WOW64 and both x86/amd64 VC++ 2015-2022 runtimes/UCRT.

  python packers/alushpacker/generate.py --output C:/Temp/alush-new
  python packers/alushpacker/generate.py --verify-only
  python packers/alushpacker/generate.py --probe-failed --output C:/Temp/alush-probe

Command: packer.exe fixture-input.exe
The generated filename is fixture-input_packed.exe. Do not use -o: the released
binary opens that output twice and leaves it empty on this host. Password locking
is not enabled. Both architectures pack unchanged inputs without output patches.

The official loader writes diagnostics to stdout. Verification requires one exact
fixture success line, exit zero, empty stderr and an explicit allowlist of loader
messages. Wait mode still produces only the fixture line (CRT diagnostics remain
buffered) and uses the shared readiness/liveness test. PE architecture/kind/exports,
complete marker visibility and unchanged packed bytes are checked separately.

--probe-failed reproduces -o failure and DLL-to-EXE wrapping. DLL copies get an
.exe filename because the CLI requires that suffix; their PE headers are unchanged.
The result is an EXE without exports, not a standalone packed DLL. It is inspected
but not executed or saved. All tool/fixture runs have one-process Windows jobs.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
HASH = '56458d9ffd7e11e329a5962cd5cde279f7ad635c1673e6657a51195bc8ef02fe'
LOG = re.compile(r'(?:Allocation success! allocated image: [0-9A-F]+|Module: KERNEL32\.dll|'
                 r'\[\+\] Resolved function address for (?:GetCommandLineW|WriteFile|Sleep|ExitProcess|GetStdHandle): [0-9A-F]+|'
                 r'Editing section protections\.\.\.|Success!\.\.\.|'
                 r'Registered [0-9]+ entries in runtime function table: [0-9A-F]+|'
                 r'Original entry point address: [0-9A-F]+)')


def verify(path, arch):
    before = path.read_bytes(); info = CHECK.PE.inspect_pe(path)
    _, ref = CHECK.reference(arch, 'exe')
    for field in ('machine', 'optional_header', 'kind', 'exports'):
        CHECK.require(info[field] == ref['pe'][field], 'Unexpected PE ' + field)
    result = CHECK.run([path], path.parent, 10)
    CHECK.require(result.returncode == 0 and not result.stderr, 'Runtime failed: ' + repr(result))
    lines = result.stdout.decode('ascii').splitlines()
    CHECK.require(lines.count('pe-fixture:basic-exe:ok') == 1, 'Missing/duplicate fixture success')
    CHECK.require(all(not x.strip() or x == 'pe-fixture:basic-exe:ok' or LOG.fullmatch(x.strip()) for x in lines),
                  'Unknown loader output: ' + repr(lines))
    CHECK.WAIT.check_fixture(path, arch, 'exe')
    CHECK.require(path.read_bytes() == before, 'Packed file changed')
    visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in before]
    print(f'{arch}: PASS normal/wait/secrets; full disk markers={visible}; '
          f'ASLR={info["dynamic_base"]}, DEP={info["nx_compatible"]}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    tool = PACKER / 'tools/1.0.0/bin/packer.exe'
    CHECK.require(CHECK.sha256(tool) == HASH, 'Unexpected tool')
    output = (args.output or PACKER / 'packed-fixtures/1.0.0').resolve(); outputs = {}
    with tempfile.TemporaryDirectory(prefix='pe-alush-') as temp:
        work = Path(temp)
        for arch in ('x86', 'amd64'):
            for kind in (('exe', 'dll') if args.probe_failed and not args.verify_only else ('exe',)):
                source, ref = CHECK.reference(arch, kind)
                target = output / f'fixture-{arch}-{kind}/default.{kind}'
                if args.verify_only:
                    verify(target, arch); continue
                CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
                directory = work / f'{arch}-{kind}'; directory.mkdir()
                sample = directory / 'fixture-input.exe'; sample.write_bytes(source.read_bytes())
                packed = directory / 'fixture-input_packed.exe'
                if args.probe_failed and kind == 'exe':
                    broken = directory / 'explicit.exe'
                    result = CHECK.run([tool, sample, '-o', broken], directory, 30)
                    CHECK.require(result.returncode != 0 and broken.exists() and broken.stat().st_size == 0,
                                  'Unexpected explicit-output behavior')
                result = CHECK.run([tool, sample], directory, 30)
                CHECK.require(result.returncode == 0 and packed.exists(), 'Packer failed')
                if kind == 'exe':
                    verify(packed, arch); outputs[target] = packed.read_bytes()
                else:
                    info = CHECK.PE.inspect_pe(packed)
                    CHECK.require(info['kind'] == 'EXE' and not info['exports'], 'Unexpected DLL result')
                    print(f'{arch} DLL: EXE wrapper without exports; not executed', flush=True)
                CHECK.require(CHECK.sha256(sample) == ref['sha256'], 'Temporary input changed')
                CHECK.reference(arch, kind)
        for target, data in outputs.items():
            CHECK.publish(data, target)


if __name__ == '__main__':
    main()
