"""Build/use Fatpack 1.5.2 and verify fixtures (Windows, Python standard library).

Source: https://github.com/Fatmike-GH/Fatpack
Pinned revision: 0d04dfa2011a1173dda30b0ff2d6095b6c8261a8
No upstream binary release was found. The retained tool was built unmodified with
Visual Studio 2022 v143 (14.44.35207), Windows SDK 10.0.26100.0, Release x64.

Build in a fresh temporary checkout from a VS developer shell:
  git clone https://github.com/Fatmike-GH/Fatpack.git
  cd Fatpack
  git checkout 0d04dfa2011a1173dda30b0ff2d6095b6c8261a8
  msbuild Fatpack.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.26100.0 /p:PostBuildEventUseInBuild=false /m
Then from build/x64/Release run:
  ResourceAdder.exe Loader_Console_Resource.exe Fatpack.exe 1000
  ResourceAdder.exe Loader_Windows_Resource.exe Fatpack.exe 1001
  ResourceAdder.exe Loader_Console_Section.exe Fatpack.exe 1002
  ResourceAdder.exe Loader_Windows_Section.exe Fatpack.exe 1003
These are the upstream post-build embedding steps, performed synchronously without
its START commands/delays. Keep only the resulting Fatpack.exe in tools/1.5.2/bin;
its four stubs are embedded RCDATA resources. A rebuild can have different bytes;
the hash below identifies the tested retained tool, not a bit-reproducible build.

  python packers/fatpack/generate.py
  python packers/fatpack/generate.py --verify-only
  python packers/fatpack/generate.py --probe-failed --output C:/Temp/fatpack-new

Commands: Fatpack.exe original.exe packed.exe -r (resource) or -s (section).
Inputs and outputs are unmodified by this helper. Exit zero also occurs on errors,
and WriteConsoleW messages are not available through redirected pipes. Require a
new output plus normal/wait/secret and PE checks. Wrong-architecture probes must
produce no output. amd64 DLL probes produce EXE wrappers, not callable DLLs, and
are inspected without executing them. Only passing amd64 EXEs are published.
Use --output <fresh-directory> to regenerate; no different file is overwritten.
"""
import argparse
import importlib.util
from pathlib import Path
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
HASH = '36e9c6e3563e691717b7515b7ac373cbc7513b2da6d23c4ae544e116d0a43aca'
PROFILES = {'resource': '-r', 'section': '-s'}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    tool = PACKER / 'tools/1.5.2/bin/Fatpack.exe'
    CHECK.require(CHECK.sha256(tool) == HASH, 'Unexpected Fatpack binary')
    output = (args.output or PACKER / 'packed-fixtures/1.5.2').resolve()
    cases = [('amd64', 'exe')]
    if args.probe_failed and not args.verify_only:
        cases += [('x86', 'exe'), ('x86', 'dll'), ('amd64', 'dll')]
    for arch, kind in cases:
        source, ref = CHECK.reference(arch, kind)
        for profile, flag in PROFILES.items():
            target = output / f'fixture-{arch}-{kind}' / f'{profile}.{kind}'
            if args.verify_only:
                CHECK.verify(target, arch, kind); continue
            CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
            with tempfile.TemporaryDirectory(prefix='pe-fatpack-') as temp:
                work = Path(temp); sample = work / f'fixture-input.{kind}'; packed = work / f'packed.{kind}'
                sample.write_bytes(source.read_bytes())
                result = CHECK.run([tool, sample, packed, flag], work, 30)
                CHECK.require(result.returncode == 0, 'Packer crashed')
                if arch == 'x86':
                    CHECK.require(not packed.exists(), 'Unexpected x86 output')
                    print(f'{arch}/{kind}/{profile}: no output')
                elif kind == 'dll':
                    info = CHECK.PE.inspect_pe(packed)
                    CHECK.require(info['kind'] == 'EXE' and not info['exports'], 'Unexpected DLL probe result')
                    print(f'{arch}/{kind}/{profile}: EXE wrapper without exports; not executed')
                else:
                    CHECK.verify(packed, arch, kind)
                    CHECK.publish(packed.read_bytes(), target)
                CHECK.require(CHECK.sha256(sample) == ref['sha256'], 'Temporary input changed')
            CHECK.require(CHECK.sha256(source) == ref['sha256'], 'Shared original changed')


if __name__ == '__main__':
    main()
